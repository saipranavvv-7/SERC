import React, { useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  FileUp,
  Loader2,
  Play,
  Send,
  ShieldAlert,
  Trash2,
  XCircle,
} from "lucide-react";
import type {
  AlertAnalysisResult,
  AppConfigSummary,
  CanonicalAlert,
  ChatMessage,
  DroppedField,
  FeedbackDecisionType,
} from "../types.ts";
import {
  CSV_TARGET_FIELDS,
  MAX_BATCH_ROWS,
  MAX_FILE_BYTES,
  normalizeCsvRows,
  normalizePlainTextAlert,
  parseCsvPreview,
  parseJsonAlertsText,
  type CsvTargetField,
} from "../utils/intake.ts";
import { aggregateAlerts } from "../utils/triage.ts";

interface Props {
  config: AppConfigSummary | null;
}

interface PendingImageReview {
  alert: CanonicalAlert;
  event_summary: string;
  dropped_fields: DroppedField[];
  ms: number;
}

export default function CopilotTab({ config }: Props) {
  const [pasteInput, setPasteInput] = useState("");
  const [intakeError, setIntakeError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const [csvPreview, setCsvPreview] = useState<{
    headers: string[];
    rows: Record<string, string>[];
    mapping: Record<string, CsvTargetField>;
    filename: string;
  } | null>(null);

  const [queue, setQueue] = useState<CanonicalAlert[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, AlertAnalysisResult>>({});
  const [analyzingIds, setAnalyzingIds] = useState<Record<string, boolean>>({});
  const [batchRunning, setBatchRunning] = useState(false);

  const [modelChoice, setModelChoice] = useState<"A" | "B">("A");
  const [threshold, setThreshold] = useState<number>(
    config?.default_threshold ?? 0.55
  );

  const [pendingImageReview, setPendingImageReview] =
    useState<PendingImageReview | null>(null);
  const [expandedChunkId, setExpandedChunkId] = useState<string | null>(null);

  const [chatHistoryByAlert, setChatHistoryByAlert] = useState<
    Record<string, ChatMessage[]>
  >({});
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [feedbackState, setFeedbackState] = useState<
    Record<string, { decision?: FeedbackDecisionType; saving?: boolean; error?: string }>
  >({});

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const selectedAlert = useMemo(
    () => queue.find((a) => a.id === selectedId) ?? null,
    [queue, selectedId]
  );
  const activeResult = selectedId ? results[selectedId] ?? null : null;
  const activeChat = selectedId ? chatHistoryByAlert[selectedId] ?? [] : [];

  function enqueueAlerts(newAlerts: CanonicalAlert[]) {
    const combined = aggregateAlerts([...queue, ...newAlerts]);
    if (combined.length > MAX_BATCH_ROWS) {
      setIntakeError(
        `Queue limit exceeded: total alerts would be ${combined.length} (max ${MAX_BATCH_ROWS}). Clear queue or upload fewer rows.`
      );
      return;
    }
    setQueue(combined);
    if (!selectedId && combined.length > 0) {
      setSelectedId(combined[0].id);
    }
  }

  async function handleFeedback(
    alert: CanonicalAlert,
    decision: FeedbackDecisionType
  ) {
    setFeedbackState((prev) => ({
      ...prev,
      [alert.id]: { ...prev[alert.id], saving: true, error: undefined },
    }));
    try {
      const resp = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert_id: alert.id,
          rule_id: alert.rule_id,
          rule_description: alert.rule_description,
          decision,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Feedback failed (${resp.status}).`);
      }
      setFeedbackState((prev) => ({
        ...prev,
        [alert.id]: { decision, saving: false },
      }));
    } catch (err) {
      setFeedbackState((prev) => ({
        ...prev,
        [alert.id]: {
          ...prev[alert.id],
          saving: false,
          error: err instanceof Error ? err.message : String(err),
        },
      }));
    }
  }

  function handlePasteSubmit() {
    setIntakeError(null);
    const trimmed = pasteInput.trim();
    if (!trimmed) {
      setIntakeError("Paste JSON, NDJSON, CSV, or raw log text first.");
      return;
    }
    if (new Blob([trimmed]).size > MAX_FILE_BYTES) {
      setIntakeError("Pasted content exceeds 5 MB limit.");
      return;
    }

    // Try JSON / NDJSON first
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        const alerts = parseJsonAlertsText(trimmed);
        enqueueAlerts(alerts);
        setPasteInput("");
        return;
      } catch (err) {
        setIntakeError(err instanceof Error ? err.message : String(err));
        return;
      }
    }

    // Detect CSV if first line has commas and multiple lines
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length >= 2 && lines[0].includes(",") && lines[1].includes(",")) {
      try {
        const preview = parseCsvPreview(trimmed);
        setCsvPreview({ ...preview, filename: "pasted.csv" });
        setPasteInput("");
        return;
      } catch {
        // Fall back to plain log text if CSV heuristic fails
      }
    }

    try {
      const alert = normalizePlainTextAlert(trimmed);
      enqueueAlerts([alert]);
      setPasteInput("");
    } catch (err) {
      setIntakeError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleFileSelected(file: File) {
    setIntakeError(null);
    setCsvPreview(null);

    if (file.size > MAX_FILE_BYTES) {
      setIntakeError(
        `File "${file.name}" is ${(file.size / (1024 * 1024)).toFixed(
          2
        )} MB (limit is 5 MB).`
      );
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const resp = await fetch("/api/intake/upload", {
        method: "POST",
        body: formData,
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Upload failed (${resp.status}).`);
      }

      if (data.kind === "csv_preview") {
        setCsvPreview({
          headers: data.headers,
          rows: data.rows,
          mapping: data.mapping,
          filename: file.name,
        });
      } else if (data.kind === "alerts" && Array.isArray(data.alerts)) {
        enqueueAlerts(data.alerts);
      } else {
        throw new Error("Unexpected response from intake parser.");
      }
    } catch (err) {
      setIntakeError(err instanceof Error ? err.message : String(err));
    }
  }

  function confirmCsvMapping() {
    if (!csvPreview) return;
    setIntakeError(null);
    try {
      const alerts = normalizeCsvRows(csvPreview.rows, csvPreview.mapping);
      enqueueAlerts(alerts);
      setCsvPreview(null);
    } catch (err) {
      setIntakeError(err instanceof Error ? err.message : String(err));
    }
  }

  async function analyzeSingleAlert(alert: CanonicalAlert) {
    setSelectedId(alert.id);
    setChatError(null);

    if (alert.source_type === "image") {
      setAnalyzingIds((prev) => ({ ...prev, [alert.id]: true }));
      setPendingImageReview(null);
      try {
        const resp = await fetch("/api/refine", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ alert }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          throw new Error(data.error || `Image extraction failed (${resp.status}).`);
        }
        setPendingImageReview({
          alert: data.alert,
          event_summary: data.event_summary,
          dropped_fields: data.dropped_fields ?? [],
          ms: data.ms ?? 0,
        });
      } catch (err) {
        setResults((prev) => ({
          ...prev,
          [alert.id]: {
            alert,
            event_summary: "",
            dropped_fields: [],
            retrieved_chunks: [],
            low_confidence: true,
            best_score: 0,
            threshold,
            guidance: "",
            validation: null,
            trace: [
              { stage: "Intake", status: "ok", ms: 1 },
              {
                stage: "Refine",
                status: "error",
                ms: 0,
                detail: err instanceof Error ? err.message : String(err),
              },
            ],
            model_used: config?.extractor_model ?? "",
            error: err instanceof Error ? err.message : String(err),
          },
        }));
      } finally {
        setAnalyzingIds((prev) => ({ ...prev, [alert.id]: false }));
      }
      return;
    }

    await executeAnalysis(alert, false);
  }

  async function executeAnalysis(
    alert: CanonicalAlert,
    skipRefine: boolean,
    eventSummaryOverride?: string
  ) {
    setAnalyzingIds((prev) => ({ ...prev, [alert.id]: true }));
    try {
      const resp = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert,
          skipRefine,
          eventSummaryOverride,
          modelChoice,
          threshold,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        const errMsg = data.error || `Analysis failed (${resp.status}).`;
        setResults((prev) => ({
          ...prev,
          [alert.id]: {
            alert,
            event_summary: eventSummaryOverride ?? "",
            dropped_fields: [],
            retrieved_chunks: [],
            low_confidence: true,
            best_score: 0,
            threshold,
            guidance: "",
            validation: null,
            trace: data.trace ?? [{ stage: "Intake", status: "error", ms: 0, detail: errMsg }],
            model_used:
              modelChoice === "B"
                ? config?.generation_model_b ?? ""
                : config?.generation_model_a ?? "",
            error: errMsg,
          },
        }));
        return;
      }
      setResults((prev) => ({ ...prev, [alert.id]: data as AlertAnalysisResult }));
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setResults((prev) => ({
        ...prev,
        [alert.id]: {
          alert,
          event_summary: eventSummaryOverride ?? "",
          dropped_fields: [],
          retrieved_chunks: [],
          low_confidence: true,
          best_score: 0,
          threshold,
          guidance: "",
          validation: null,
          trace: [{ stage: "Intake", status: "error", ms: 0, detail: errMsg }],
          model_used: "",
          error: errMsg,
        },
      }));
    } finally {
      setAnalyzingIds((prev) => ({ ...prev, [alert.id]: false }));
    }
  }

  async function handleConfirmImageReview(e: React.FormEvent) {
    e.preventDefault();
    if (!pendingImageReview) return;
    const confirmedAlert = pendingImageReview.alert;
    const confirmedSummary = pendingImageReview.event_summary;
    setQueue((prev) =>
      prev.map((item) => (item.id === confirmedAlert.id ? confirmedAlert : item))
    );
    setPendingImageReview(null);
    await executeAnalysis(confirmedAlert, true, confirmedSummary);
  }

  async function handleAnalyzeAll() {
    if (queue.length === 0 || batchRunning) return;
    setBatchRunning(true);
    try {
      for (const alert of queue) {
        if (alert.source_type === "image") {
          setSelectedId(alert.id);
          await analyzeSingleAlert(alert);
          // Stop batch so analyst can confirm image extraction manually
          break;
        }
        setSelectedId(alert.id);
        await executeAnalysis(alert, false);
      }
    } finally {
      setBatchRunning(false);
    }
  }

  async function handleSendChat(e: React.FormEvent) {
    e.preventDefault();
    if (!activeResult || !selectedId || !chatInput.trim() || chatLoading) return;
    const userMsg: ChatMessage = { role: "user", content: chatInput.trim() };
    const prevHistory = chatHistoryByAlert[selectedId] ?? [];
    const nextHistory = [...prevHistory, userMsg];

    setChatHistoryByAlert((prev) => ({ ...prev, [selectedId]: nextHistory }));
    setChatInput("");
    setChatError(null);
    setChatLoading(true);

    try {
      const resp = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert: activeResult.alert,
          eventSummary: activeResult.event_summary,
          retrievedChunks: activeResult.retrieved_chunks,
          guidance: activeResult.guidance,
          history: prevHistory.slice(-6),
          message: userMsg.content,
          modelChoice,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Chat failed (${resp.status}).`);
      }
      setChatHistoryByAlert((prev) => ({
        ...prev,
        [selectedId]: [
          ...nextHistory,
          { role: "assistant", content: data.reply },
        ],
      }));
    } catch (err) {
      setChatError(err instanceof Error ? err.message : String(err));
    } finally {
      setChatLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Intake + Config Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Intake Panel */}
        <section
          aria-label="Alert Intake"
          className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-3"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900">
              1. Intake Alerts (JSON, NDJSON, CSV, Log/Text, or Image)
            </h2>
            <span className="text-xs text-slate-500">
              Limits: &le; 5 MB, &le; {MAX_BATCH_ROWS} rows
            </span>
          </div>

          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragActive(false);
              const f = e.dataTransfer.files?.[0];
              if (f) void handleFileSelected(f);
            }}
            className={`border-2 border-dashed rounded-md p-4 text-center transition-colors ${
              dragActive
                ? "border-blue-600 bg-blue-50"
                : "border-slate-300 bg-slate-50 hover:border-slate-400"
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,.ndjson,.csv,.txt,.log,.png,.jpg,.jpeg,.webp"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void handleFileSelected(f);
                e.target.value = "";
              }}
            />
            <div className="flex flex-col items-center gap-1.5">
              <FileUp className="w-5 h-5 text-slate-500" />
              <p className="text-xs text-slate-700">
                Drag and drop an alert file here, or{" "}
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="font-medium text-blue-700 underline hover:text-blue-800 cursor-pointer"
                >
                  browse files
                </button>
              </p>
              <p className="text-[11px] text-slate-500">
                Accepted: .json (single, array, NDJSON), .csv, .txt, .log, .png, .jpg, .webp
              </p>
            </div>
          </div>

          <div>
            <label
              htmlFor="alert-paste-box"
              className="block text-xs font-medium text-slate-700 mb-1"
            >
              Or paste alert JSON / CSV / raw syslog text
            </label>
            <textarea
              id="alert-paste-box"
              rows={4}
              value={pasteInput}
              onChange={(e) => setPasteInput(e.target.value)}
              placeholder='Paste Wazuh JSON, NDJSON, CSV rows, or raw log line (e.g. "2025-02-14T08:12:44Z host01 sshd: Failed password for invalid user admin from 198.51.100.42")'
              className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-1 focus:ring-blue-600"
            />
            <div className="mt-2 flex items-center justify-between gap-3">
              <button
                type="button"
                onClick={handlePasteSubmit}
                className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800 cursor-pointer"
              >
                Add to Queue
              </button>
              {intakeError && (
                <p
                  role="alert"
                  className="text-xs font-medium text-red-700 bg-red-50 border border-red-200 rounded px-2.5 py-1 flex-1"
                >
                  {intakeError}
                </p>
              )}
            </div>
          </div>

          {/* CSV Column Mapping Preview */}
          {csvPreview && (
            <div className="border border-blue-200 bg-blue-50/50 rounded-md p-3 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-slate-900">
                    CSV Column Mapping Preview ({csvPreview.filename} &mdash;{" "}
                    {csvPreview.rows.length} rows)
                  </h3>
                  <p className="text-[11px] text-slate-600">
                    Verify auto-detected fields. Columns mapped to{" "}
                    <code className="font-mono">raw_text</code> are preserved in raw telemetry.
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setCsvPreview(null)}
                    className="rounded border border-slate-300 bg-white px-2.5 py-1 text-xs text-slate-700 hover:bg-slate-50 cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={confirmCsvMapping}
                    className="rounded bg-blue-700 px-2.5 py-1 text-xs font-medium text-white hover:bg-blue-800 cursor-pointer"
                  >
                    Queue {csvPreview.rows.length} Alerts
                  </button>
                </div>
              </div>

              <div className="overflow-x-auto max-h-56 border border-slate-200 rounded bg-white">
                <table className="min-w-full text-left text-xs">
                  <thead className="bg-slate-100 border-b border-slate-200">
                    <tr>
                      {csvPreview.headers.map((h) => (
                        <th key={h} className="px-2.5 py-2 align-top min-w-[140px]">
                          <div className="font-mono text-[11px] text-slate-800 mb-1">
                            {h}
                          </div>
                          <select
                            aria-label={`Map column ${h}`}
                            value={csvPreview.mapping[h] ?? "raw_text"}
                            onChange={(e) => {
                              const val = e.target.value as CsvTargetField;
                              setCsvPreview((prev) =>
                                prev
                                  ? {
                                      ...prev,
                                      mapping: { ...prev.mapping, [h]: val },
                                    }
                                  : null
                              );
                            }}
                            className="w-full rounded border border-slate-300 bg-white px-1.5 py-1 text-[11px] font-normal text-slate-800"
                          >
                            {CSV_TARGET_FIELDS.map((field) => (
                              <option key={field} value={field}>
                                {field}
                              </option>
                            ))}
                          </select>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {csvPreview.rows.slice(0, 3).map((row, idx) => (
                      <tr key={idx}>
                        {csvPreview.headers.map((h) => (
                          <td
                            key={h}
                            className="px-2.5 py-1.5 font-mono text-[11px] text-slate-700 max-w-[200px] truncate"
                          >
                            {row[h] ?? ""}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>

        {/* Alert Queue + Run Controls */}
        <section
          aria-label="Alert Queue"
          className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-4 shadow-xs flex flex-col justify-between space-y-3"
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold text-slate-900">
                Alert Queue ({queue.length})
              </h2>
              <div className="flex items-center gap-2">
                {queue.length > 0 && (
                  <>
                    <button
                      type="button"
                      disabled={batchRunning}
                      onClick={handleAnalyzeAll}
                      className="inline-flex items-center gap-1 rounded-md bg-blue-700 px-2.5 py-1.5 text-xs font-medium text-white hover:bg-blue-800 disabled:opacity-50 cursor-pointer"
                    >
                      {batchRunning ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Play className="w-3.5 h-3.5" />
                      )}
                      Analyze All
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setQueue([]);
                        setSelectedId(null);
                        setResults({});
                        setPendingImageReview(null);
                      }}
                      title="Clear queue"
                      className="inline-flex items-center gap-1 rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-700 hover:bg-slate-50 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Clear
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Model & Threshold Controls */}
            <div className="grid grid-cols-2 gap-2.5 bg-slate-50 border border-slate-200 rounded-md p-2.5">
              <div>
                <label
                  htmlFor="gen-model-select"
                  className="block text-[11px] font-medium text-slate-700 mb-1"
                >
                  Generation Model
                </label>
                <select
                  id="gen-model-select"
                  value={modelChoice}
                  onChange={(e) => setModelChoice(e.target.value as "A" | "B")}
                  className="w-full rounded border border-slate-300 bg-white px-2 py-1 text-xs text-slate-900"
                >
                  <option value="A">
                    Model A ({config?.generation_model_a ?? "gemini-4-hydrogen"})
                  </option>
                  <option value="B">
                    Model B ({config?.generation_model_b ?? "gemini-3.1-flash-lite"})
                  </option>
                </select>
              </div>
              <div>
                <label
                  htmlFor="threshold-input"
                  className="block text-[11px] font-medium text-slate-700 mb-1"
                >
                  Low-Confidence Threshold
                </label>
                <input
                  id="threshold-input"
                  type="number"
                  min={0}
                  max={1}
                  step={0.05}
                  value={threshold}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                  className="w-full rounded border border-slate-300 bg-white px-2 py-1 font-mono text-xs text-slate-900"
                />
              </div>
            </div>

            {/* Queue List */}
            {queue.length === 0 ? (
              <div className="border border-dashed border-slate-200 rounded-md p-6 text-center text-xs text-slate-500">
                No alerts queued yet. Paste or upload alerts on the left to begin.
              </div>
            ) : (
              <ul className="divide-y divide-slate-200 border border-slate-200 rounded-md max-h-64 overflow-y-auto">
                {queue.map((item) => {
                  const res = results[item.id];
                  const isRunning = Boolean(analyzingIds[item.id]);
                  const isSelected = item.id === selectedId;
                  return (
                    <li
                      key={item.id}
                      className={`p-2.5 flex items-center justify-between gap-2 ${
                        isSelected ? "bg-blue-50/70" : "bg-white hover:bg-slate-50"
                      }`}
                    >
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedId(item.id);
                          setPendingImageReview(null);
                        }}
                        className="flex-1 text-left min-w-0 cursor-pointer"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold text-slate-900 truncate">
                            {item.id}
                          </span>
                          <span className="rounded bg-slate-100 border border-slate-200 px-1.5 py-0.5 text-[10px] font-medium text-slate-700">
                            {item.source_type ?? "alert"}
                          </span>
                          {item.rule_level !== null && (
                            <span className="rounded bg-amber-50 border border-amber-200 px-1.5 py-0.5 text-[10px] font-mono text-amber-800">
                              lvl {item.rule_level}
                            </span>
                          )}
                          {(item.collapsed_count ?? 1) > 1 && (
                            <span className="rounded bg-blue-50 border border-blue-200 px-1.5 py-0.5 text-[10px] font-mono text-blue-800">
                              &times;{item.collapsed_count}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-600 truncate mt-0.5">
                          {item.rule_description || item.raw_text.slice(0, 90)}
                        </p>
                      </button>

                      <div className="flex items-center gap-2 shrink-0">
                        {isRunning && (
                          <Loader2 className="w-4 h-4 animate-spin text-blue-700" />
                        )}
                        {!isRunning && res && !res.error && (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        )}
                        {!isRunning && res?.error && (
                          <XCircle className="w-4 h-4 text-red-600" />
                        )}
                        <button
                          type="button"
                          disabled={isRunning || batchRunning}
                          onClick={() => void analyzeSingleAlert(item)}
                          className="rounded border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-800 hover:bg-slate-100 disabled:opacity-50 cursor-pointer"
                        >
                          {res ? "Re-run" : "Analyze"}
                        </button>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </section>
      </div>

      {/* Image Confirmation Form (Mandatory before Retrieval) */}
      {pendingImageReview && (
        <section
          aria-label="Confirm Image Extraction"
          className="bg-white border-2 border-amber-400 rounded-lg p-5 shadow-xs space-y-4"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                Step 2 Image Extraction Review &mdash; Analyst Confirmation Required
              </h2>
              <p className="text-xs text-slate-600 mt-0.5">
                Verify and edit the fields extracted from the image before running retrieval and guidance generation ({pendingImageReview.ms} ms).
              </p>
            </div>
            <button
              type="button"
              onClick={() => setPendingImageReview(null)}
              className="text-xs text-slate-600 hover:text-slate-900 underline cursor-pointer"
            >
              Cancel
            </button>
          </div>

          <form onSubmit={handleConfirmImageReview} className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {pendingImageReview.alert.image_data_url && (
              <div className="lg:col-span-4 border border-slate-200 rounded-md p-2 bg-slate-50 flex items-center justify-center">
                <img
                  src={pendingImageReview.alert.image_data_url}
                  alt="Uploaded alert screenshot"
                  className="max-h-72 object-contain rounded"
                />
              </div>
            )}

            <div className="lg:col-span-8 space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Event Summary
                </label>
                <textarea
                  rows={2}
                  value={pendingImageReview.event_summary}
                  onChange={(e) =>
                    setPendingImageReview((prev) =>
                      prev ? { ...prev, event_summary: e.target.value } : null
                    )
                  }
                  className="w-full rounded border border-slate-300 px-2.5 py-1.5 text-xs text-slate-900"
                />
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                {(
                  [
                    ["timestamp", "Timestamp"],
                    ["rule_id", "Rule ID"],
                    ["rule_level", "Rule Level"],
                    ["rule_description", "Rule Description"],
                    ["agent_name", "Agent Name"],
                    ["agent_ip", "Agent IP"],
                    ["source_ip", "Source IP"],
                    ["dest_ip", "Dest IP"],
                    ["user", "User"],
                    ["process", "Process"],
                    ["command", "Command"],
                    ["file_path", "File Path"],
                  ] as const
                ).map(([field, label]) => (
                  <div key={field}>
                    <label className="block text-[11px] font-medium text-slate-600 mb-0.5">
                      {label}
                    </label>
                    <input
                      type={field === "rule_level" ? "number" : "text"}
                      value={pendingImageReview.alert[field] ?? ""}
                      onChange={(e) => {
                        const val = e.target.value;
                        setPendingImageReview((prev) => {
                          if (!prev) return null;
                          return {
                            ...prev,
                            alert: {
                              ...prev.alert,
                              [field]:
                                field === "rule_level"
                                  ? val === ""
                                    ? null
                                    : Number(val)
                                  : val === ""
                                  ? null
                                  : val,
                            },
                          };
                        });
                      }}
                      className="w-full rounded border border-slate-300 px-2 py-1 font-mono text-xs text-slate-900"
                    />
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                {(
                  [
                    ["mitre_ids", "MITRE IDs (comma-separated)"],
                    ["mitre_tactics", "MITRE Tactics"],
                    ["compliance_tags", "Compliance Tags"],
                  ] as const
                ).map(([field, label]) => (
                  <div key={field}>
                    <label className="block text-[11px] font-medium text-slate-600 mb-0.5">
                      {label}
                    </label>
                    <input
                      type="text"
                      value={pendingImageReview.alert[field].join(", ")}
                      onChange={(e) => {
                        const arr = e.target.value
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean);
                        setPendingImageReview((prev) =>
                          prev
                            ? {
                                ...prev,
                                alert: { ...prev.alert, [field]: arr },
                              }
                            : null
                        );
                      }}
                      className="w-full rounded border border-slate-300 px-2 py-1 font-mono text-xs text-slate-900"
                    />
                  </div>
                ))}
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  type="submit"
                  className="inline-flex items-center gap-1.5 rounded-md bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800 cursor-pointer"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  Confirm &amp; Retrieve Guidance
                </button>
              </div>
            </div>
          </form>
        </section>
      )}

      {/* Result Panel */}
      {selectedAlert && !pendingImageReview && (
        <section aria-label="Analysis Result" className="space-y-5">
          {analyzingIds[selectedAlert.id] && (
            <div className="bg-white border border-slate-200 rounded-lg p-6 flex items-center gap-3 text-sm text-slate-700">
              <Loader2 className="w-5 h-5 animate-spin text-blue-700" />
              Running SERC pipeline (Refine &rarr; Retrieve &rarr; Generate &rarr; Validate) for{" "}
              <span className="font-mono font-semibold">{selectedAlert.id}</span>...
            </div>
          )}

          {!analyzingIds[selectedAlert.id] && !activeResult && (
            <div className="bg-white border border-slate-200 rounded-lg p-6 flex items-center justify-between">
              <div className="text-xs text-slate-600">
                Selected alert{" "}
                <span className="font-mono font-semibold text-slate-900">
                  {selectedAlert.id}
                </span>{" "}
                has not been analyzed yet.
              </div>
              <button
                type="button"
                onClick={() => void analyzeSingleAlert(selectedAlert)}
                className="inline-flex items-center gap-1.5 rounded-md bg-blue-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-800 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                Run Pipeline
              </button>
            </div>
          )}

          {activeResult && (
            <>
              {/* Error Banner */}
              {activeResult.error && (
                <div
                  role="alert"
                  className="bg-red-50 border border-red-300 rounded-lg p-4 flex items-start gap-2.5 text-xs text-red-800"
                >
                  <XCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-semibold">Pipeline Error</div>
                    <p className="mt-0.5">{activeResult.error}</p>
                  </div>
                </div>
              )}

              {/* Pipeline Trace */}
              <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-3">
                  Pipeline Trace
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-6 gap-2.5">
                  {activeResult.trace.map((step) => {
                    const color =
                      step.status === "ok"
                        ? "border-emerald-200 bg-emerald-50/70 text-emerald-900"
                        : step.status === "warning"
                        ? "border-amber-200 bg-amber-50/70 text-amber-900"
                        : step.status === "error"
                        ? "border-red-200 bg-red-50/70 text-red-900"
                        : "border-slate-200 bg-slate-50 text-slate-700";
                    return (
                      <div
                        key={step.stage}
                        className={`rounded-md border p-2.5 ${color}`}
                      >
                        <div className="flex items-center justify-between text-xs font-semibold">
                          <span>{step.stage}</span>
                          <span className="font-mono text-[11px] flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {step.ms}ms
                          </span>
                        </div>
                        <div className="mt-1 text-[11px] opacity-90 truncate" title={step.detail}>
                          {step.status.toUpperCase()}
                          {step.detail ? ` • ${step.detail}` : ""}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Canonical Schema + Dropped Fields Cross-Check */}
              <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Canonical Alert &amp; Input Cross-Check
                  </h3>
                  {activeResult.event_summary && (
                    <span className="text-xs text-slate-700 font-medium">
                      {activeResult.event_summary}
                    </span>
                  )}
                </div>

                {activeResult.dropped_fields.length > 0 && (
                  <div className="rounded-md border border-amber-300 bg-amber-50 p-2.5 text-xs text-amber-900 space-y-1">
                    <div className="font-semibold">
                      Cross-Check Dropped Unverified Extracted Fields:
                    </div>
                    <ul className="list-disc pl-5 space-y-0.5 font-mono text-[11px]">
                      {activeResult.dropped_fields.map((d, i) => (
                        <li key={i}>
                          {d.field} = &quot;{d.value}&quot; ({d.reason})
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  {(
                    [
                      ["timestamp", activeResult.alert.timestamp],
                      ["rule_id", activeResult.alert.rule_id],
                      [
                        "rule_level",
                        activeResult.alert.rule_level !== null
                          ? String(activeResult.alert.rule_level)
                          : null,
                      ],
                      ["agent_name", activeResult.alert.agent_name],
                      ["agent_ip", activeResult.alert.agent_ip],
                      ["source_ip", activeResult.alert.source_ip],
                      ["dest_ip", activeResult.alert.dest_ip],
                      ["user", activeResult.alert.user],
                      ["process", activeResult.alert.process],
                      ["command", activeResult.alert.command],
                      ["file_path", activeResult.alert.file_path],
                      ["mitre_ids", activeResult.alert.mitre_ids.join(", ") || null],
                    ] as const
                  ).map(([k, v]) => (
                    <div
                      key={k}
                      className="rounded border border-slate-200 bg-slate-50 px-2.5 py-1.5"
                    >
                      <div className="text-[10px] font-medium uppercase text-slate-500">
                        {k}
                      </div>
                      <div
                        className="font-mono text-xs text-slate-900 truncate"
                        title={v ?? "null"}
                      >
                        {v ?? <span className="text-slate-400">null</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Retrieved Evidence Table */}
              <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Retrieved Knowledge Base Evidence ({activeResult.retrieved_chunks.length})
                  </h3>
                  <div className="flex items-center gap-2 text-xs">
                    <span className="font-mono text-slate-600">
                      best_score={activeResult.best_score.toFixed(3)} / threshold=
                      {activeResult.threshold.toFixed(2)}
                    </span>
                    {activeResult.low_confidence && (
                      <span className="inline-flex items-center gap-1 rounded bg-amber-100 border border-amber-300 px-2 py-0.5 text-xs font-semibold text-amber-900">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        low_confidence
                      </span>
                    )}
                  </div>
                </div>

                <div className="overflow-x-auto border border-slate-200 rounded-md">
                  <table className="min-w-full text-left text-xs">
                    <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
                      <tr>
                        <th className="px-3 py-2 font-semibold">Collection</th>
                        <th className="px-3 py-2 font-semibold">Record ID</th>
                        <th className="px-3 py-2 font-semibold">Score</th>
                        <th className="px-3 py-2 font-semibold">Method</th>
                        <th className="px-3 py-2 font-semibold">Source</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {activeResult.retrieved_chunks.map((chunk) => {
                        const isExpanded = expandedChunkId === chunk.chunk_id;
                        return (
                          <React.Fragment key={chunk.chunk_id}>
                            <tr
                              onClick={() =>
                                setExpandedChunkId(isExpanded ? null : chunk.chunk_id)
                              }
                              className="hover:bg-slate-50 cursor-pointer"
                            >
                              <td className="px-3 py-2 font-mono text-slate-700 flex items-center gap-1">
                                {isExpanded ? (
                                  <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
                                ) : (
                                  <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                                )}
                                {chunk.collection}
                              </td>
                              <td className="px-3 py-2 font-mono font-medium text-slate-900">
                                {chunk.record_id}
                              </td>
                              <td className="px-3 py-2 font-mono text-slate-900">
                                {chunk.score.toFixed(3)}
                              </td>
                              <td className="px-3 py-2 font-mono text-slate-700">
                                {chunk.method}
                              </td>
                              <td className="px-3 py-2 text-slate-600">{chunk.source}</td>
                            </tr>
                            {isExpanded && (
                              <tr className="bg-slate-50/80">
                                <td colSpan={5} className="px-4 py-2.5 text-xs text-slate-700">
                                  <div className="font-semibold text-slate-900 mb-1">
                                    {chunk.title}{" "}
                                    <span className="font-mono text-[11px] font-normal text-slate-500">
                                      ({chunk.chunk_id})
                                    </span>
                                  </div>
                                  <p className="whitespace-pre-wrap leading-relaxed">
                                    {chunk.text}
                                  </p>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Triage / False-Positive Control Badge & Reasons (Above Guidance) */}
              {activeResult.triage && (
                <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`inline-flex items-center rounded-md border px-2.5 py-1 text-xs font-semibold font-mono ${
                          activeResult.triage.verdict === "likely_malicious"
                            ? "bg-red-50 border-red-300 text-red-900"
                            : activeResult.triage.verdict === "likely_benign"
                            ? "bg-emerald-50 border-emerald-300 text-emerald-900"
                            : "bg-amber-50 border-amber-300 text-amber-900"
                        }`}
                      >
                        Triage: {activeResult.triage.verdict} (
                        {Math.round(activeResult.triage.confidence * 100)}%)
                      </span>
                      {activeResult.triage.pre_checks.collapsed_count > 1 && (
                        <span className="rounded bg-blue-50 border border-blue-200 px-2 py-0.5 text-[11px] font-mono text-blue-800">
                          Aggregated &times;{activeResult.triage.pre_checks.collapsed_count} (10m window)
                        </span>
                      )}
                      {activeResult.triage.pre_checks.low_rule_level && (
                        <span className="rounded bg-slate-100 border border-slate-300 px-2 py-0.5 text-[11px] font-mono text-slate-700">
                          rule_level &le; 3
                        </span>
                      )}
                      {activeResult.triage.pre_checks.allowlist_matches.length > 0 && (
                        <span className="rounded bg-emerald-50 border border-emerald-200 px-2 py-0.5 text-[11px] font-mono text-emerald-800">
                          Allowlist matched ({activeResult.triage.pre_checks.allowlist_matches.map((m) => `${m.type}:${m.value}`).join(", ")})
                        </span>
                      )}
                      {activeResult.triage.pre_checks.high_impact_category && (
                        <span className="rounded bg-red-50 border border-red-200 px-2 py-0.5 text-[11px] font-mono text-red-800">
                          High-impact: {activeResult.triage.pre_checks.high_impact_category}
                        </span>
                      )}
                    </div>

                    {/* Analyst Feedback Buttons */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      {(
                        [
                          ["true_positive", "Confirm true positive"],
                          ["false_positive", "Mark false positive"],
                          ["false_negative", "Report missed (false negative)"],
                        ] as const
                      ).map(([decision, label]) => {
                        const fb = feedbackState[activeResult.alert.id];
                        const isSelected = fb?.decision === decision;
                        return (
                          <button
                            key={decision}
                            type="button"
                            disabled={fb?.saving}
                            onClick={() => void handleFeedback(activeResult.alert, decision)}
                            className={`rounded border px-2 py-1 text-[11px] font-medium cursor-pointer transition-colors ${
                              isSelected
                                ? "bg-slate-900 border-slate-900 text-white"
                                : "bg-white border-slate-300 text-slate-700 hover:bg-slate-50"
                            }`}
                          >
                            {label}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {feedbackState[activeResult.alert.id]?.error && (
                    <p className="text-xs text-red-700">
                      Feedback error: {feedbackState[activeResult.alert.id]?.error}
                    </p>
                  )}

                  {activeResult.triage.guardrails_applied.length > 0 && (
                    <div className="rounded border border-amber-200 bg-amber-50 px-3 py-1.5 text-[11px] text-amber-900">
                      <strong>Guardrails applied:</strong>{" "}
                      {activeResult.triage.guardrails_applied.join(" | ")}
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                    <div className="rounded border border-slate-200 bg-slate-50 p-2.5">
                      <div className="font-semibold text-slate-800 mb-1">Reasons For</div>
                      <ul className="list-disc pl-4 space-y-0.5 text-slate-700">
                        {activeResult.triage.reasons_for.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="rounded border border-slate-200 bg-slate-50 p-2.5">
                      <div className="font-semibold text-slate-800 mb-1">Reasons Against</div>
                      <ul className="list-disc pl-4 space-y-0.5 text-slate-700">
                        {activeResult.triage.reasons_against.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="rounded border border-slate-200 bg-slate-50 p-2.5">
                      <div className="font-semibold text-slate-800 mb-1">Corroboration To Check</div>
                      <ul className="list-disc pl-4 space-y-0.5 text-slate-700">
                        {activeResult.triage.corroboration_to_check.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="rounded border border-slate-200 bg-slate-50 p-2.5">
                      <div className="font-semibold text-slate-800 mb-1">What Would Change My Mind</div>
                      <ul className="list-disc pl-4 space-y-0.5 text-slate-700">
                        {activeResult.triage.what_would_change_my_mind.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* Guidance + Validation + Follow-up Chat */}
              {activeResult.guidance && (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  {/* Guidance Markdown & Validation */}
                  <div className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 pb-3">
                      <div>
                        <h3 className="text-sm font-semibold text-slate-900">
                          Generated Response Guidance
                        </h3>
                        <p className="text-[11px] text-slate-500">
                          Model: <span className="font-mono">{activeResult.model_used}</span> &bull; Advisory only (never executes actions)
                        </p>
                      </div>

                      {activeResult.validation && (
                        <div
                          className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold ${
                            activeResult.validation.unsupported_count > 0
                              ? "border-amber-300 bg-amber-50 text-amber-900"
                              : "border-emerald-300 bg-emerald-50 text-emerald-900"
                          }`}
                        >
                          {activeResult.validation.unsupported_count > 0 ? (
                            <ShieldAlert className="w-3.5 h-3.5" />
                          ) : (
                            <CheckCircle2 className="w-3.5 h-3.5" />
                          )}
                          {activeResult.validation.checked_count} claims checked,{" "}
                          {activeResult.validation.unsupported_count} unsupported
                        </div>
                      )}
                    </div>

                    {activeResult.validation &&
                      activeResult.validation.unsupported_claims.length > 0 && (
                        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-950 space-y-1">
                          <div className="font-semibold">
                            Flagged Unsupported Claims (not found in alert or retrieved chunks):
                          </div>
                          <ul className="list-disc pl-5 font-mono text-[11px] space-y-0.5">
                            {activeResult.validation.unsupported_claims.map((c, idx) => (
                              <li key={idx}>
                                [{c.type}] {c.value} &mdash; {c.reason}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                    <div className="serc-markdown">
                      <ReactMarkdown>{activeResult.guidance}</ReactMarkdown>
                    </div>
                  </div>

                  {/* Grounded Follow-Up Chat */}
                  <div className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-4 shadow-xs flex flex-col h-[600px]">
                    <div className="border-b border-slate-200 pb-2.5 mb-3">
                      <h3 className="text-sm font-semibold text-slate-900">
                        Grounded Follow-Up Chat
                      </h3>
                      <p className="text-[11px] text-slate-500">
                        Scoped strictly to this alert, retrieved chunks, and guidance (last 6 turns).
                      </p>
                    </div>

                    <div className="flex-1 overflow-y-auto space-y-3 pr-1">
                      {activeChat.length === 0 && (
                        <p className="text-xs text-slate-500 italic">
                          Ask a follow-up question about observed facts, MITRE context, or recommended investigation steps.
                        </p>
                      )}
                      {activeChat.map((msg, i) => (
                        <div
                          key={i}
                          className={`rounded-md p-2.5 text-xs ${
                            msg.role === "user"
                              ? "bg-slate-900 text-white ml-6"
                              : "bg-slate-100 text-slate-900 mr-4 border border-slate-200"
                          }`}
                        >
                          <div className="text-[10px] font-semibold uppercase opacity-75 mb-1">
                            {msg.role === "user" ? "Analyst" : "SERC"}
                          </div>
                          {msg.role === "assistant" ? (
                            <div className="serc-markdown">
                              <ReactMarkdown>{msg.content}</ReactMarkdown>
                            </div>
                          ) : (
                            <p className="whitespace-pre-wrap">{msg.content}</p>
                          )}
                        </div>
                      ))}
                      {chatLoading && (
                        <div className="flex items-center gap-2 text-xs text-slate-600 p-2">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          Generating grounded answer...
                        </div>
                      )}
                    </div>

                    {chatError && (
                      <div
                        role="alert"
                        className="mt-2 rounded border border-red-200 bg-red-50 px-2.5 py-1.5 text-xs text-red-700"
                      >
                        {chatError}
                      </div>
                    )}

                    <form onSubmit={handleSendChat} className="mt-3 flex gap-2">
                      <input
                        type="text"
                        aria-label="Follow-up question"
                        value={chatInput}
                        onChange={(e) => setChatInput(e.target.value)}
                        placeholder="Ask about this alert..."
                        className="flex-1 rounded-md border border-slate-300 px-3 py-1.5 text-xs text-slate-900 focus:border-blue-600 focus:outline-none focus:ring-1 focus:ring-blue-600"
                      />
                      <button
                        type="submit"
                        disabled={chatLoading || !chatInput.trim()}
                        className="inline-flex items-center gap-1 rounded-md bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
                      >
                        <Send className="w-3.5 h-3.5" />
                        Send
                      </button>
                    </form>
                  </div>
                </div>
              )}
            </>
          )}
        </section>
      )}
    </div>
  );
}
