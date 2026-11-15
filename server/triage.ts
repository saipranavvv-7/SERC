import fs from "node:fs";
import path from "node:path";
import { Type } from "@google/genai";
import type {
  AllowlistEntry,
  AllowlistType,
  CanonicalAlert,
  FeedbackDecisionType,
  FeedbackRecord,
  RetrievedChunk,
  RuleFeedbackStats,
  TriagePreChecks,
  TriageResult,
  TriageVerdict,
} from "../src/types.ts";
import { MODEL_CONFIG } from "./config.ts";
import { getGeminiClient, withRetry429 } from "./gemini.ts";

const DATA_DIR = path.resolve(process.cwd(), "data");
const ALLOWLIST_PATH = path.join(DATA_DIR, "allowlist.json");
const FEEDBACK_PATH = path.join(DATA_DIR, "feedback.json");

const TRIAGE_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    verdict: {
      type: Type.STRING,
      description: 'Must be one of: "likely_benign", "needs_review", "likely_malicious".',
    },
    confidence: {
      type: Type.NUMBER,
      description: "Confidence score between 0.0 and 1.0.",
    },
    reasons_for: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: "Evidence supporting the verdict.",
    },
    reasons_against: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: "Counter-evidence or alternative benign/malicious explanations.",
    },
    corroboration_to_check: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: "Concrete telemetry or context an analyst should verify.",
    },
    what_would_change_my_mind: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: "Specific findings that would flip the verdict.",
    },
  },
  required: [
    "verdict",
    "confidence",
    "reasons_for",
    "reasons_against",
    "corroboration_to_check",
    "what_would_change_my_mind",
  ],
};

function readJsonFile<T>(filePath: string, fallback: T): T {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
    }
  } catch {
    // Fall through to default
  }
  return fallback;
}

function writeJsonFile(filePath: string, data: unknown): void {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}

// --- Allowlist Storage ---
export function getAllowlist(): AllowlistEntry[] {
  return readJsonFile<AllowlistEntry[]>(ALLOWLIST_PATH, []);
}

export function addAllowlistEntry(params: {
  type: AllowlistType;
  value: string;
  note?: string;
}): AllowlistEntry {
  const cleanVal = params.value.trim();
  if (!cleanVal) {
    throw new Error("Allowlist value cannot be empty.");
  }
  const list = getAllowlist();
  const entry: AllowlistEntry = {
    id: `al-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    type: params.type,
    value: cleanVal,
    note: params.note?.trim() || undefined,
    created_at: new Date().toISOString(),
  };
  list.push(entry);
  writeJsonFile(ALLOWLIST_PATH, list);
  return entry;
}

export function removeAllowlistEntry(id: string): AllowlistEntry[] {
  const list = getAllowlist().filter((e) => e.id !== id);
  writeJsonFile(ALLOWLIST_PATH, list);
  return list;
}

export function matchAllowlist(alert: CanonicalAlert): AllowlistEntry[] {
  const list = getAllowlist();
  const matches: AllowlistEntry[] = [];
  const lower = (s: string | null | undefined) => (s ?? "").trim().toLowerCase();

  const ips = [alert.source_ip, alert.dest_ip, alert.agent_ip]
    .map(lower)
    .filter(Boolean);
  const user = lower(alert.user);
  const host = lower(alert.agent_name);
  const ruleId = lower(alert.rule_id);
  const jobText = [
    alert.rule_description,
    alert.command,
    alert.process,
    alert.raw_text,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  for (const entry of list) {
    const val = entry.value.trim().toLowerCase();
    if (!val) continue;
    if (entry.type === "ip" && ips.includes(val)) {
      matches.push(entry);
    } else if (entry.type === "user" && user === val) {
      matches.push(entry);
    } else if (entry.type === "host" && host === val) {
      matches.push(entry);
    } else if (entry.type === "rule_id" && ruleId === val) {
      matches.push(entry);
    } else if (entry.type === "scheduled_job" && jobText.includes(val)) {
      matches.push(entry);
    }
  }
  return matches;
}

// --- Feedback Storage ---
export function getFeedbackRecords(): FeedbackRecord[] {
  return readJsonFile<FeedbackRecord[]>(FEEDBACK_PATH, []);
}

export function addFeedbackRecord(params: {
  alert_id: string;
  rule_id: string | null;
  rule_description: string | null;
  decision: FeedbackDecisionType;
  note?: string;
}): FeedbackRecord {
  const records = getFeedbackRecords();
  const rec: FeedbackRecord = {
    id: `fb-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    alert_id: params.alert_id,
    rule_id: params.rule_id,
    rule_description: params.rule_description,
    decision: params.decision,
    note: params.note?.trim() || undefined,
    created_at: new Date().toISOString(),
  };
  records.push(rec);
  writeJsonFile(FEEDBACK_PATH, records);
  return rec;
}

export function getFeedbackSummary(): {
  records: FeedbackRecord[];
  per_rule: RuleFeedbackStats[];
} {
  const records = getFeedbackRecords();
  const map = new Map<string, RuleFeedbackStats>();

  for (const rec of records) {
    const key = rec.rule_id?.trim() || "(unassigned)";
    const stat = map.get(key) ?? {
      rule_id: key,
      true_positive: 0,
      false_positive: 0,
      false_negative: 0,
      total: 0,
      fp_rate: 0,
    };
    if (rec.decision === "true_positive") stat.true_positive += 1;
    if (rec.decision === "false_positive") stat.false_positive += 1;
    if (rec.decision === "false_negative") stat.false_negative += 1;
    stat.total += 1;
    stat.fp_rate = Number((stat.false_positive / stat.total).toFixed(3));
    map.set(key, stat);
  }

  return {
    records: [...records].reverse(),
    per_rule: Array.from(map.values()).sort((a, b) => b.total - a.total),
  };
}

export function getRecentFeedbackForRule(
  ruleId: string | null,
  limit = 3
): FeedbackRecord[] {
  if (!ruleId?.trim()) return [];
  const target = ruleId.trim().toLowerCase();
  return getFeedbackRecords()
    .filter((r) => (r.rule_id ?? "").trim().toLowerCase() === target)
    .slice(-limit);
}

// --- High-Impact Category Detection ---
export function detectHighImpactCategory(alert: CanonicalAlert): string | null {
  const ids = alert.mitre_ids.map((m) => m.toUpperCase());
  const tactics = alert.mitre_tactics.map((t) => t.toLowerCase());
  const text = [
    alert.rule_description,
    alert.process,
    alert.command,
    alert.file_path,
    alert.raw_text,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (
    ids.some((id) => id.startsWith("T1486") || id.startsWith("T1490")) ||
    tactics.includes("impact") ||
    /ransomware|vssadmin\s+delete\s+shadows|mass\s+file\s+encrypt/.test(text)
  ) {
    return "ransomware/impact";
  }
  if (
    ids.some((id) => id.startsWith("T1041") || id.startsWith("T1048")) ||
    tactics.includes("exfiltration") ||
    /exfiltrat/.test(text)
  ) {
    return "exfiltration";
  }
  if (
    ids.some((id) => id.startsWith("T1505.003")) ||
    /webshell|web\s*shell/.test(text)
  ) {
    return "webshell";
  }
  if (
    ids.some((id) => id.startsWith("T1003")) ||
    /lsass|mimikatz|comsvcs\.dll.*minidump|credential\s+dump/.test(text)
  ) {
    return "successful_credential_access";
  }
  return null;
}

export async function runTriageAssessment(params: {
  alert: CanonicalAlert;
  eventSummary: string;
  retrievedChunks: RetrievedChunk[];
  lowConfidence: boolean;
  modelChoice: "A" | "B";
  ignoreAllowlist?: boolean;
}): Promise<TriageResult> {
  const ai = getGeminiClient();
  const modelUsed =
    params.modelChoice === "B"
      ? MODEL_CONFIG.GENERATION_MODEL_B
      : MODEL_CONFIG.GENERATION_MODEL_A;

  const allowlistMatches = params.ignoreAllowlist
    ? []
    : matchAllowlist(params.alert);
  const lowRuleLevel =
    params.alert.rule_level !== null && params.alert.rule_level <= 3;
  const collapsedCount = params.alert.collapsed_count ?? 1;
  const highImpactCategory = detectHighImpactCategory(params.alert);

  const preChecks: TriagePreChecks = {
    allowlist_matches: allowlistMatches,
    low_rule_level: lowRuleLevel,
    collapsed_count: collapsedCount,
    high_impact_category: highImpactCategory,
  };

  const recentDecisions = getRecentFeedbackForRule(params.alert.rule_id, 3);
  const historyExamples =
    recentDecisions.length > 0
      ? recentDecisions
          .map(
            (d) =>
              `- [${d.created_at}] rule_id=${d.rule_id}: analyst marked ${d.decision}${
                d.note ? ` (${d.note})` : ""
              }`
          )
          .join("\n")
      : "None.";

  const chunkContext = params.retrievedChunks
    .slice(0, 6)
    .map((c) => `[${c.chunk_id}] (${c.collection}): ${c.title}`)
    .join("\n");

  const prompt = `Perform conservative SOC false-positive triage on this security alert.
Return strict JSON matching the schema.

DETERMINISTIC PRE-CHECKS:
- Allowlist matches: ${
    allowlistMatches.length > 0
      ? allowlistMatches.map((a) => `${a.type}=${a.value}`).join(", ")
      : "none"
  }
- Rule level <= 3 flag: ${lowRuleLevel} (rule_level=${params.alert.rule_level})
- Aggregated count (same rule_id+agent+source_ip in 10m): ${collapsedCount}
- High-impact category: ${highImpactCategory ?? "none"}
- Low-confidence retrieval: ${params.lowConfidence}

RECENT ANALYST FEEDBACK FOR RULE_ID (${params.alert.rule_id ?? "none"}, up to last 3):
${historyExamples}

EVENT SUMMARY: ${params.eventSummary}

CANONICAL ALERT:
${JSON.stringify({ ...params.alert, image_data_url: undefined }, null, 2)}

TOP RETRIEVED EVIDENCE:
${chunkContext || "none"}`;

  const response = await withRetry429(async () => {
    return await ai.models.generateContent({
      model: modelUsed,
      contents: prompt,
      config: {
        systemInstruction:
          "You are a cautious SOC triage classifier. Never auto-close or ignore high-impact threats. Provide balanced reasons_for, reasons_against, corroboration_to_check, and what_would_change_my_mind.",
        responseMimeType: "application/json",
        responseSchema: TRIAGE_SCHEMA,
      },
    });
  });

  const rawText = (response.text ?? "").trim();
  if (!rawText) {
    throw new Error("Triage model returned empty JSON.");
  }

  const parsed = JSON.parse(rawText) as {
    verdict?: string;
    confidence?: number;
    reasons_for?: string[];
    reasons_against?: string[];
    corroboration_to_check?: string[];
    what_would_change_my_mind?: string[];
  };

  let verdict: TriageVerdict =
    parsed.verdict === "likely_benign" ||
    parsed.verdict === "needs_review" ||
    parsed.verdict === "likely_malicious"
      ? parsed.verdict
      : "needs_review";

  const confidence = Math.max(0, Math.min(1, Number(parsed.confidence ?? 0.5)));
  const reasonsFor = Array.isArray(parsed.reasons_for) ? parsed.reasons_for : [];
  const reasonsAgainst = Array.isArray(parsed.reasons_against)
    ? parsed.reasons_against
    : [];
  const corroboration = Array.isArray(parsed.corroboration_to_check)
    ? [...parsed.corroboration_to_check]
    : [];
  const changeMind = Array.isArray(parsed.what_would_change_my_mind)
    ? parsed.what_would_change_my_mind
    : [];

  const guardrailsApplied: string[] = [];

  // Guardrail 1: High-impact categories can never be likely_benign unless allowlisted
  if (
    highImpactCategory &&
    verdict === "likely_benign" &&
    allowlistMatches.length === 0
  ) {
    verdict = "needs_review";
    guardrailsApplied.push(
      `High-impact category (${highImpactCategory}) without allowlist match cannot be likely_benign -> forced needs_review.`
    );
  }

  // Guardrail 2: Low-confidence retrieval forces needs_review
  if (params.lowConfidence && verdict !== "needs_review") {
    verdict = "needs_review";
    guardrailsApplied.push(
      "Low-confidence KB retrieval -> forced needs_review."
    );
  }

  // Guardrail 3: Single weak signal cannot yield likely_malicious without listing corroboration_to_check
  const isWeakSignal =
    lowRuleLevel ||
    (params.alert.mitre_ids.length === 0 && reasonsFor.length <= 1);
  if (
    verdict === "likely_malicious" &&
    isWeakSignal &&
    corroboration.length === 0
  ) {
    verdict = "needs_review";
    corroboration.push(
      "Corroborate with host process tree, auth logs, and asset owner confirmation."
    );
    guardrailsApplied.push(
      "Single weak signal without corroboration_to_check cannot yield likely_malicious -> downgraded to needs_review."
    );
  }

  return {
    verdict,
    confidence: Number(confidence.toFixed(2)),
    reasons_for: reasonsFor,
    reasons_against: reasonsAgainst,
    corroboration_to_check: corroboration,
    what_would_change_my_mind: changeMind,
    pre_checks: preChecks,
    guardrails_applied: guardrailsApplied,
  };
}
