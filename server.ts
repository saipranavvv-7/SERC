import "dotenv/config";
import express from "express";
import multer from "multer";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer as createViteServer } from "vite";
import type {
  AlertAnalysisResult,
  AllowlistType,
  CanonicalAlert,
  ChatMessage,
  EvalScenario,
  EvalScenarioResult,
  FeedbackDecisionType,
  IrColumnTarget,
  KBCollection,
  PipelineStageTrace,
} from "./src/types.ts";
import {
  normalizePlainTextAlert,
  parseCsvPreview,
  parseJsonAlertsText,
} from "./src/utils/intake.ts";
import { MODEL_CONFIG, PIPELINE_CONFIG } from "./server/config.ts";
import { formatGeminiError } from "./server/gemini.ts";
import { kbManager } from "./server/kb.ts";
import {
  cleanupStagedUpload,
  getStagedUpload,
  repreviewStagedIrUpload,
  stageAndParseKbFile,
} from "./server/kbImporters.ts";
import {
  answerFollowUpChat,
  generateGuidance,
  refineAlert,
  validateGuidance,
} from "./server/pipeline.ts";
import {
  addAllowlistEntry,
  addFeedbackRecord,
  getAllowlist,
  getFeedbackSummary,
  removeAllowlistEntry,
  runTriageAssessment,
} from "./server/triage.ts";
import {
  runSingleEvalModel,
  SAMPLE_EVAL_SCENARIOS,
} from "./server/evalScenarios.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3000;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: PIPELINE_CONFIG.MAX_FILE_BYTES,
  },
});

const kbUpload = multer({
  dest: os.tmpdir(),
  limits: {
    fileSize: PIPELINE_CONFIG.KB_MAX_FILE_BYTES,
  },
});

const VALID_COLLECTIONS = new Set<KBCollection>([
  "mitre_attack",
  "nist_csf",
  "ir_incidents",
]);

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "8mb" }));

  // Start KB initialization in background so server boots promptly on port 3000
  void kbManager.init();

  app.get("/api/config", (_req, res) => {
    const kbStatus = kbManager.getStatus();
    res.json({
      extractor_model: MODEL_CONFIG.EXTRACTOR_MODEL,
      generation_model_a: MODEL_CONFIG.GENERATION_MODEL_A,
      generation_model_b: MODEL_CONFIG.GENERATION_MODEL_B,
      embedding_model: MODEL_CONFIG.EMBEDDING_MODEL,
      embed_dim: MODEL_CONFIG.EMBED_DIM,
      default_threshold: PIPELINE_CONFIG.DEFAULT_SIMILARITY_THRESHOLD,
      max_file_bytes: PIPELINE_CONFIG.MAX_FILE_BYTES,
      max_batch_rows: PIPELINE_CONFIG.MAX_BATCH_ROWS,
      ...kbStatus,
    });
  });

  // Server-side file intake endpoint (validates <= 5 MB via multer)
  app.post("/api/intake/upload", upload.single("file"), (req, res) => {
    try {
      const file = req.file;
      if (!file) {
        res.status(400).json({ error: "No file uploaded." });
        return;
      }

      const name = file.originalname.toLowerCase();
      if (
        file.mimetype.startsWith("image/") ||
        /\.(png|jpe?g|webp)$/i.test(name)
      ) {
        const mime = file.mimetype || "image/png";
        const base64 = file.buffer.toString("base64");
        const alert: CanonicalAlert = {
          id: `img-${Date.now().toString(36)}`,
          timestamp: null,
          rule_id: null,
          rule_level: null,
          rule_description: null,
          agent_name: null,
          agent_ip: null,
          source_ip: null,
          dest_ip: null,
          user: null,
          process: null,
          command: null,
          file_path: null,
          mitre_ids: [],
          mitre_tactics: [],
          compliance_tags: [],
          raw_text: `[Image uploaded: ${file.originalname}]`,
          source_type: "image",
          image_data_url: `data:${mime};base64,${base64}`,
        };
        res.json({ kind: "alerts", alerts: [alert] });
        return;
      }

      const text = file.buffer.toString("utf-8");
      if (name.endsWith(".json") || name.endsWith(".ndjson")) {
        const alerts = parseJsonAlertsText(text);
        res.json({ kind: "alerts", alerts });
        return;
      }
      if (name.endsWith(".csv")) {
        const preview = parseCsvPreview(text);
        res.json({ kind: "csv_preview", ...preview });
        return;
      }
      if (name.endsWith(".txt") || name.endsWith(".log")) {
        const alert = normalizePlainTextAlert(text);
        res.json({ kind: "alerts", alerts: [alert] });
        return;
      }

      res.status(400).json({
        error:
          "Unsupported file type. Accepted: .json, .csv, .txt, .log, .png, .jpg, .webp.",
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // Step 2 only (used for image extraction before analyst confirms)
  app.post("/api/refine", async (req, res) => {
    const start = Date.now();
    try {
      const { alert } = req.body as { alert?: CanonicalAlert };
      if (!alert) {
        res.status(400).json({ error: "Missing alert payload." });
        return;
      }
      const refined = await refineAlert(alert);
      const ms = Date.now() - start;
      res.json({
        ...refined,
        ms,
      });
    } catch (err) {
      const msg = formatGeminiError(err);
      res.status(500).json({ error: msg });
    }
  });

  // Full pipeline (Refine -> Retrieve -> Generate -> Validate), or skipRefine when image already confirmed
  app.post("/api/analyze", async (req, res) => {
    const trace: PipelineStageTrace[] = [];
    try {
      const {
        alert,
        skipRefine = false,
        eventSummaryOverride,
        modelChoice = "A",
        threshold = PIPELINE_CONFIG.DEFAULT_SIMILARITY_THRESHOLD,
      } = req.body as {
        alert?: CanonicalAlert;
        skipRefine?: boolean;
        eventSummaryOverride?: string;
        modelChoice?: "A" | "B";
        threshold?: number;
      };

      if (!alert) {
        res.status(400).json({ error: "Missing alert payload." });
        return;
      }

      trace.push({
        stage: "Intake",
        status: "ok",
        ms: 1,
        detail: `source=${alert.source_type ?? "unknown"}`,
      });

      let workingAlert = alert;
      let eventSummary = eventSummaryOverride?.trim() || "";
      let droppedFields: AlertAnalysisResult["dropped_fields"] = [];

      // Step 2: Refine
      const refineStart = Date.now();
      if (skipRefine) {
        trace.push({
          stage: "Refine",
          status: "ok",
          ms: 0,
          detail: "Analyst-confirmed extraction",
        });
        if (!eventSummary) {
          eventSummary =
            workingAlert.rule_description ||
            `Alert ${workingAlert.id} confirmed by analyst.`;
        }
      } else {
        const refined = await refineAlert(workingAlert);
        workingAlert = refined.alert;
        eventSummary = refined.event_summary;
        droppedFields = refined.dropped_fields;
        trace.push({
          stage: "Refine",
          status: droppedFields.length > 0 ? "warning" : "ok",
          ms: Date.now() - refineStart,
          detail:
            droppedFields.length > 0
              ? `${droppedFields.length} unverified field(s) dropped`
              : `Model ${MODEL_CONFIG.EXTRACTOR_MODEL}`,
        });
      }

      // Step 4: Retrieve
      const retrieveStart = Date.now();
      const retrieval = await kbManager.retrieve({
        eventSummary,
        ruleDescription: workingAlert.rule_description,
        mitreIds: workingAlert.mitre_ids,
        threshold: Number(threshold) || PIPELINE_CONFIG.DEFAULT_SIMILARITY_THRESHOLD,
      });
      trace.push({
        stage: "Retrieve",
        status: retrieval.low_confidence ? "warning" : "ok",
        ms: Date.now() - retrieveStart,
        detail: `${retrieval.chunks.length} chunks, best=${retrieval.best_score.toFixed(
          3
        )}${retrieval.low_confidence ? " (low_confidence)" : ""}`,
      });

      // Triage / False-Positive Control
      const triageStart = Date.now();
      const triage = await runTriageAssessment({
        alert: workingAlert,
        eventSummary,
        retrievedChunks: retrieval.chunks,
        lowConfidence: retrieval.low_confidence,
        modelChoice,
      });
      trace.push({
        stage: "Triage",
        status: triage.verdict === "likely_malicious" || triage.guardrails_applied.length > 0 ? "warning" : "ok",
        ms: Date.now() - triageStart,
        detail: `${triage.verdict} (${Math.round(triage.confidence * 100)}%)`,
      });

      // Step 5: Generate
      const genStart = Date.now();
      const generated = await generateGuidance({
        alert: workingAlert,
        eventSummary,
        retrievedChunks: retrieval.chunks,
        lowConfidence: retrieval.low_confidence,
        modelChoice,
      });
      trace.push({
        stage: "Generate",
        status: "ok",
        ms: Date.now() - genStart,
        detail: generated.modelUsed,
      });

      // Step 6: Validate
      const valStart = Date.now();
      const validation = validateGuidance(
        generated.guidance,
        workingAlert,
        retrieval.chunks
      );
      trace.push({
        stage: "Validate",
        status: validation.unsupported_count > 0 ? "warning" : "ok",
        ms: Date.now() - valStart,
        detail: `${validation.checked_count} claims checked, ${validation.unsupported_count} unsupported`,
      });

      const result: AlertAnalysisResult = {
        alert: workingAlert,
        event_summary: eventSummary,
        dropped_fields: droppedFields,
        retrieved_chunks: retrieval.chunks,
        low_confidence: retrieval.low_confidence,
        best_score: retrieval.best_score,
        threshold: Number(threshold) || PIPELINE_CONFIG.DEFAULT_SIMILARITY_THRESHOLD,
        triage,
        guidance: generated.guidance,
        validation,
        trace,
        model_used: generated.modelUsed,
      };

      res.json(result);
    } catch (err) {
      const msg = formatGeminiError(err);
      res.status(500).json({ error: msg, trace });
    }
  });

  // Grounded follow-up chat
  app.post("/api/chat", async (req, res) => {
    try {
      const {
        alert,
        eventSummary,
        retrievedChunks,
        guidance,
        history = [],
        message,
        modelChoice = "A",
      } = req.body as {
        alert?: CanonicalAlert;
        eventSummary?: string;
        retrievedChunks?: AlertAnalysisResult["retrieved_chunks"];
        guidance?: string;
        history?: ChatMessage[];
        message?: string;
        modelChoice?: "A" | "B";
      };

      if (!alert || !guidance || !message?.trim()) {
        res.status(400).json({ error: "Missing alert, guidance, or question." });
        return;
      }

      const reply = await answerFollowUpChat({
        alert,
        eventSummary: eventSummary ?? "",
        retrievedChunks: retrievedChunks ?? [],
        guidance,
        history,
        message: message.trim(),
        modelChoice,
      });

      res.json(reply);
    } catch (err) {
      const msg = formatGeminiError(err);
      res.status(500).json({ error: msg });
    }
  });

  // Knowledge Base endpoints
  app.get("/api/kb", (_req, res) => {
    res.json({
      ...kbManager.getStatus(),
      records: kbManager.listRecords(),
    });
  });

  app.post("/api/kb/demo-starter", async (_req, res) => {
    try {
      await kbManager.seedStarter();
      res.json({
        ok: true,
        ...kbManager.getStatus(),
        records: kbManager.listRecords(),
      });
    } catch (err) {
      res.status(500).json({ error: formatGeminiError(err) });
    }
  });

  app.post("/api/kb/parse", kbUpload.single("file"), async (req, res) => {
    try {
      const file = req.file;
      if (!file) {
        res.status(400).json({ error: "No Knowledge Base file uploaded." });
        return;
      }
      const collection = String(req.body?.collection ?? "") as KBCollection;
      if (!VALID_COLLECTIONS.has(collection)) {
        try {
          fs.unlinkSync(file.path);
        } catch {
          // ignore
        }
        res.status(400).json({
          error: "Invalid collection. Must be mitre_attack, nist_csf, or ir_incidents.",
        });
        return;
      }

      const importLimit = req.body?.import_limit
        ? Number(req.body.import_limit)
        : PIPELINE_CONFIG.IR_DEFAULT_IMPORT_LIMIT;

      const preview = await stageAndParseKbFile({
        tempFilePath: file.path,
        originalName: file.originalname,
        collection,
        importLimit,
      });

      res.json(preview);
    } catch (err) {
      if (req.file?.path && fs.existsSync(req.file.path)) {
        try {
          fs.unlinkSync(req.file.path);
        } catch {
          // ignore
        }
      }
      res.status(400).json({ error: formatGeminiError(err) });
    }
  });

  app.post("/api/kb/repreview", async (req, res) => {
    try {
      const { upload_id, mapping, import_limit } = req.body as {
        upload_id?: string;
        mapping?: Record<string, IrColumnTarget>;
        import_limit?: number;
      };
      if (!upload_id || !mapping) {
        res.status(400).json({ error: "upload_id and mapping are required." });
        return;
      }
      const preview = await repreviewStagedIrUpload({
        uploadId: upload_id,
        mapping,
        importLimit:
          import_limit && import_limit > 0
            ? Number(import_limit)
            : PIPELINE_CONFIG.IR_DEFAULT_IMPORT_LIMIT,
      });
      res.json(preview);
    } catch (err) {
      res.status(400).json({ error: formatGeminiError(err) });
    }
  });

  app.post("/api/kb/import", async (req, res) => {
    res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");

    const abortController = new AbortController();
    req.on("close", () => {
      if (!res.writableEnded) {
        abortController.abort();
      }
    });

    const sendEvent = (payload: Record<string, unknown>) => {
      if (!res.writableEnded) {
        res.write(`${JSON.stringify(payload)}\n`);
      }
    };

    try {
      const { upload_id, resume = true } = req.body as {
        upload_id?: string;
        resume?: boolean;
      };
      if (!upload_id) {
        sendEvent({ type: "error", error: "upload_id is required." });
        res.end();
        return;
      }

      const staged = getStagedUpload(upload_id);
      if (!staged) {
        sendEvent({
          type: "error",
          error: "Staged upload expired or not found. Re-upload the file.",
        });
        res.end();
        return;
      }

      const summary = await kbManager.indexRecords(staged.records, {
        mode: "add",
        resume,
        abortSignal: abortController.signal,
        onProgress: (done, total, stage) => {
          sendEvent({ type: "progress", done, total, stage });
        },
      });

      if (!summary.cancelled) {
        cleanupStagedUpload(upload_id);
      }

      sendEvent({
        type: "done",
        summary,
        status: kbManager.getStatus(),
        records: kbManager.listRecords(),
      });
      res.end();
    } catch (err) {
      sendEvent({
        type: "error",
        error: formatGeminiError(err),
      });
      res.end();
    }
  });

  app.delete("/api/kb/collection/:collection", (req, res) => {
    const col = req.params.collection as KBCollection;
    if (!VALID_COLLECTIONS.has(col)) {
      res.status(400).json({ error: "Invalid collection." });
      return;
    }
    kbManager.clearCollection(col);
    res.json({
      ok: true,
      ...kbManager.getStatus(),
      records: kbManager.listRecords(),
    });
  });

  app.get("/api/kb/export", (_req, res) => {
    const exported = kbManager.exportIndex();
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="serc-kb-index-${new Date().toISOString().slice(0, 10)}.json"`
    );
    res.send(JSON.stringify(exported));
  });

  app.post("/api/kb/import-index", kbUpload.single("file"), (req, res) => {
    const file = req.file;
    try {
      if (!file) {
        res.status(400).json({ error: "No index file uploaded." });
        return;
      }
      const raw = fs.readFileSync(file.path, "utf-8");
      const parsed = JSON.parse(raw) as unknown;
      const summary = kbManager.importIndex(parsed);
      res.json({
        ok: true,
        summary,
        ...kbManager.getStatus(),
        records: kbManager.listRecords(),
      });
    } catch (err) {
      res.status(400).json({ error: formatGeminiError(err) });
    } finally {
      if (file?.path && fs.existsSync(file.path)) {
        try {
          fs.unlinkSync(file.path);
        } catch {
          // ignore
        }
      }
    }
  });

  // Allowlist endpoints
  app.get("/api/allowlist", (_req, res) => {
    res.json({ entries: getAllowlist() });
  });

  app.post("/api/allowlist", (req, res) => {
    try {
      const { type, value, note } = req.body as {
        type?: AllowlistType;
        value?: string;
        note?: string;
      };
      if (!type || !value?.trim()) {
        res.status(400).json({ error: "Allowlist type and value are required." });
        return;
      }
      const entry = addAllowlistEntry({ type, value, note });
      res.json({ entry, entries: getAllowlist() });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  app.delete("/api/allowlist/:id", (req, res) => {
    const entries = removeAllowlistEntry(req.params.id);
    res.json({ entries });
  });

  // Feedback endpoints
  app.get("/api/feedback", (_req, res) => {
    res.json(getFeedbackSummary());
  });

  app.post("/api/feedback", (req, res) => {
    try {
      const { alert_id, rule_id, rule_description, decision, note } = req.body as {
        alert_id?: string;
        rule_id?: string | null;
        rule_description?: string | null;
        decision?: FeedbackDecisionType;
        note?: string;
      };
      if (!alert_id || !decision) {
        res.status(400).json({ error: "alert_id and decision are required." });
        return;
      }
      const record = addFeedbackRecord({
        alert_id,
        rule_id: rule_id ?? null,
        rule_description: rule_description ?? null,
        decision,
        note,
      });
      res.json({ record, ...getFeedbackSummary() });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  // Evaluation endpoints
  app.get("/api/eval/scenarios", (_req, res) => {
    res.json({ scenarios: SAMPLE_EVAL_SCENARIOS });
  });

  app.post("/api/eval/run-one", async (req, res) => {
    try {
      const {
        scenario,
        mode = "A",
        threshold = PIPELINE_CONFIG.DEFAULT_SIMILARITY_THRESHOLD,
      } = req.body as {
        scenario?: EvalScenario;
        mode?: "A" | "B" | "both";
        threshold?: number;
      };
      if (!scenario || !scenario.alert) {
        res.status(400).json({ error: "Missing evaluation scenario payload." });
        return;
      }

      const result: EvalScenarioResult = {
        scenario_id: scenario.id,
        name: scenario.name,
        label: scenario.label,
        expected_mitre: scenario.expected_mitre,
      };

      if (mode === "A" || mode === "both") {
        result.run_a = await runSingleEvalModel({
          scenario,
          modelChoice: "A",
          threshold: Number(threshold) || PIPELINE_CONFIG.DEFAULT_SIMILARITY_THRESHOLD,
        });
      }
      if (mode === "B" || mode === "both") {
        result.run_b = await runSingleEvalModel({
          scenario,
          modelChoice: "B",
          threshold: Number(threshold) || PIPELINE_CONFIG.DEFAULT_SIMILARITY_THRESHOLD,
        });
      }

      res.json(result);
    } catch (err) {
      res.status(500).json({ error: formatGeminiError(err) });
    }
  });

  // Multer file-size error handler
  app.use(
    (
      err: unknown,
      _req: express.Request,
      res: express.Response,
      next: express.NextFunction
    ) => {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
          res.status(400).json({
            error: "Uploaded file exceeds maximum allowed size limit.",
          });
          return;
        }
        res.status(400).json({ error: err.message });
        return;
      }
      next(err);
    }
  );

  // Vite middleware in dev, static dist in production
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, "dist");
    app.use(express.static(distDir));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distDir, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`SERC server listening on http://localhost:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start SERC server:", err);
  process.exit(1);
});
