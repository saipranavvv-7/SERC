import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import AdmZip from "adm-zip";
import { parse as parseCsvStream } from "csv-parse";
import * as XLSX from "xlsx";
import type {
  IrColumnTarget,
  KBCollection,
  KBParsePreview,
  KBRecord,
} from "../src/types.ts";
import { PIPELINE_CONFIG } from "./config.ts";

export interface StagedUpload {
  upload_id: string;
  file_path: string;
  ext: ".csv" | ".json" | ".xlsx";
  filename: string;
  collection: KBCollection;
  headers?: string[];
  mapping?: Record<string, IrColumnTarget>;
  import_limit: number;
  records: KBRecord[];
  total_rows: number;
  skipped_empty: number;
  skipped_duplicates: number;
  created_at: number;
}

const stagedUploads = new Map<string, StagedUpload>();

export function getStagedUpload(uploadId: string): StagedUpload | undefined {
  return stagedUploads.get(uploadId);
}

export function cleanupStagedUpload(uploadId: string): void {
  const entry = stagedUploads.get(uploadId);
  if (!entry) return;
  try {
    if (fs.existsSync(entry.file_path)) {
      fs.unlinkSync(entry.file_path);
    }
  } catch {
    // Ignore temp cleanup failures
  }
  stagedUploads.delete(uploadId);
}

export function sha256Text(text: string): string {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function formatProvenanceSource(filename: string): string {
  const date = new Date().toISOString().slice(0, 10);
  return `${filename} (${date})`;
}

function resolveUploadedFile(
  rawFilePath: string,
  originalName: string
): { filePath: string; ext: ".csv" | ".json" | ".xlsx"; displayName: string } {
  const lower = originalName.toLowerCase();
  if (lower.endsWith(".zip")) {
    const zip = new AdmZip(rawFilePath);
    const dataEntries = zip.getEntries().filter((entry) => {
      if (entry.isDirectory) return false;
      const name = entry.entryName;
      if (name.startsWith("__MACOSX/") || path.basename(name).startsWith("._")) {
        return false;
      }
      return /\.(csv|json|xlsx)$/i.test(name);
    });

    if (dataEntries.length !== 1) {
      throw new Error(
        `ZIP archive must contain exactly one CSV, JSON, or XLSX file (found ${dataEntries.length}).`
      );
    }

    const chosen = dataEntries[0];
    const innerName = path.basename(chosen.entryName);
    const innerLower = innerName.toLowerCase();
    const ext: ".csv" | ".json" | ".xlsx" = innerLower.endsWith(".csv")
      ? ".csv"
      : innerLower.endsWith(".xlsx")
      ? ".xlsx"
      : ".json";

    const extractedPath = path.join(
      os.tmpdir(),
      `serc-unzip-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`
    );
    fs.writeFileSync(extractedPath, chosen.getData());
    try {
      fs.unlinkSync(rawFilePath);
    } catch {
      // ignore
    }
    return {
      filePath: extractedPath,
      ext,
      displayName: `${originalName}/${innerName}`,
    };
  }

  if (lower.endsWith(".csv")) {
    return { filePath: rawFilePath, ext: ".csv", displayName: originalName };
  }
  if (lower.endsWith(".json") || lower.endsWith(".ndjson")) {
    return { filePath: rawFilePath, ext: ".json", displayName: originalName };
  }
  if (lower.endsWith(".xlsx") || lower.endsWith(".xls")) {
    return { filePath: rawFilePath, ext: ".xlsx", displayName: originalName };
  }

  throw new Error(
    "Unsupported file type. Accepted: .csv, .json, .xlsx, or .zip containing exactly one CSV/JSON/XLSX."
  );
}

async function streamCsvRows(
  filePath: string,
  onRow: (row: Record<string, string>, index: number) => void
): Promise<{ headers: string[]; totalRows: number }> {
  return await new Promise((resolve, reject) => {
    let headers: string[] = [];
    let totalRows = 0;

    const parser = parseCsvStream({
      columns: true,
      bom: true,
      skip_empty_lines: true,
      relax_quotes: true,
      relax_column_count: true,
      trim: true,
    });

    const stream = fs.createReadStream(filePath, { encoding: "utf-8" });

    stream.on("error", (err) => reject(err));
    parser.on("error", (err) => reject(err));
    parser.on("data", (record: Record<string, string>) => {
      if (headers.length === 0) {
        headers = Object.keys(record);
      }
      onRow(record, totalRows);
      totalRows += 1;
    });
    parser.on("end", () => {
      resolve({ headers, totalRows });
    });

    stream.pipe(parser);
  });
}

function readXlsxRows(filePath: string): {
  headers: string[];
  rows: Record<string, string>[];
} {
  const wb = XLSX.readFile(filePath, { cellDates: true });
  for (const sheetName of wb.SheetNames) {
    const sheet = wb.Sheets[sheetName];
    const rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, {
      defval: "",
    });
    if (rows.length > 0) {
      const headers = Object.keys(rows[0]);
      const strRows = rows.map((r) => {
        const out: Record<string, string> = {};
        for (const k of headers) {
          out[k] = r[k] !== undefined && r[k] !== null ? String(r[k]).trim() : "";
        }
        return out;
      });
      return { headers, rows: strRows };
    }
  }
  return { headers: [], rows: [] };
}

function pickCol(
  row: Record<string, string>,
  candidates: string[]
): string {
  const keys = Object.keys(row);
  for (const cand of candidates) {
    const exact = keys.find((k) => k.trim().toLowerCase() === cand);
    if (exact && row[exact]?.trim()) return row[exact].trim();
  }
  for (const cand of candidates) {
    const fuzzy = keys.find((k) =>
      k.trim().toLowerCase().replace(/[\s_-]+/g, "").includes(cand.replace(/[\s_-]+/g, ""))
    );
    if (fuzzy && row[fuzzy]?.trim()) return row[fuzzy].trim();
  }
  return "";
}

// =========================================================================
// 1. MITRE ATT&CK IMPORTER (STIX 2.x Bundle JSON or CSV/XLSX)
// =========================================================================
function parseStixMitreBundle(
  json: Record<string, unknown>,
  sourceLabel: string
): { records: KBRecord[]; totalRows: number; skippedEmpty: number } {
  const objects = json.objects as Array<Record<string, unknown>>;
  const coaMap = new Map<string, { mid: string; name: string; summary: string }>();
  const mitigatesMap = new Map<string, string[]>();

  for (const obj of objects) {
    if (obj.revoked === true || obj.x_mitre_deprecated === true) continue;
    if (obj.type === "course-of-action") {
      const refs = Array.isArray(obj.external_references)
        ? (obj.external_references as Array<Record<string, unknown>>)
        : [];
      const mitreRef = refs.find((r) => r.source_name === "mitre-attack");
      const mid = mitreRef?.external_id ? String(mitreRef.external_id).trim() : "";
      const name = String(obj.name ?? "").trim();
      const desc = String(obj.description ?? "").replace(/\s+/g, " ").trim();
      const firstSentence = desc.split(/(?<=\.)\s+/)[0] ?? desc;
      const summary =
        firstSentence.length > 160
          ? `${firstSentence.slice(0, 157)}...`
          : firstSentence;
      if (obj.id && name) {
        coaMap.set(String(obj.id), { mid: mid || "M-?", name, summary });
      }
    } else if (
      obj.type === "relationship" &&
      obj.relationship_type === "mitigates" &&
      obj.source_ref &&
      obj.target_ref
    ) {
      const target = String(obj.target_ref);
      const list = mitigatesMap.get(target) ?? [];
      list.push(String(obj.source_ref));
      mitigatesMap.set(target, list);
    }
  }

  const records: KBRecord[] = [];
  let totalAttackPatterns = 0;
  let skipped = 0;

  for (const obj of objects) {
    if (obj.type !== "attack-pattern") continue;
    totalAttackPatterns += 1;
    if (obj.revoked === true || obj.x_mitre_deprecated === true) {
      skipped += 1;
      continue;
    }

    const refs = Array.isArray(obj.external_references)
      ? (obj.external_references as Array<Record<string, unknown>>)
      : [];
    const mitreRef = refs.find((r) => r.source_name === "mitre-attack");
    const techniqueId = mitreRef?.external_id
      ? String(mitreRef.external_id).trim()
      : "";
    const name = String(obj.name ?? "").trim();
    if (!techniqueId || !name) {
      skipped += 1;
      continue;
    }

    const description = String(obj.description ?? "").replace(/\s+/g, " ").trim();
    const phases = Array.isArray(obj.kill_chain_phases)
      ? (obj.kill_chain_phases as Array<Record<string, unknown>>)
          .map((p) => String(p.phase_name ?? "").trim())
          .filter(Boolean)
      : [];
    const tacticsStr = phases.join(", ");
    const platforms = Array.isArray(obj.x_mitre_platforms)
      ? obj.x_mitre_platforms.map((p) => String(p).trim()).filter(Boolean)
      : [];
    const detection = String(obj.x_mitre_detection ?? "")
      .replace(/\s+/g, " ")
      .trim();

    const coaIds = mitigatesMap.get(String(obj.id)) ?? [];
    const mitigations = coaIds
      .map((cid) => coaMap.get(cid))
      .filter((m): m is { mid: string; name: string; summary: string } => Boolean(m))
      .map((m) => `${m.mid} ${m.name}: ${m.summary}`);

    const parts = [
      `${techniqueId} ${name}`,
      tacticsStr ? `Tactic: ${tacticsStr}` : "",
      description,
      detection ? `Detection: ${detection}` : "",
      mitigations.length > 0 ? `Mitigations: ${mitigations.join("; ")}` : "",
    ].filter(Boolean);

    const text = parts.join(" | ");
    records.push({
      id: `MITRE ${techniqueId}`,
      collection: "mitre_attack",
      technique_id: techniqueId,
      tactic: tacticsStr || undefined,
      platforms: platforms.length > 0 ? platforms : undefined,
      title: name,
      text,
      source: sourceLabel,
      text_hash: sha256Text(text),
    });
  }

  return { records, totalRows: totalAttackPatterns, skippedEmpty: skipped };
}

function mitreRowToRecord(
  row: Record<string, string>,
  sourceLabel: string
): KBRecord | null {
  const tid = pickCol(row, [
    "technique_id",
    "external_id",
    "mitre_id",
    "id",
    "technique id",
  ]);
  const name = pickCol(row, ["name", "title", "technique_name", "technique"]);
  const tactic = pickCol(row, ["tactic", "tactics", "kill_chain_phases"]);
  const description = pickCol(row, ["description", "text", "summary"]);
  const detection = pickCol(row, ["detection", "x_mitre_detection"]);
  const mitigation = pickCol(row, ["mitigation", "mitigations"]);
  if (!tid && !name && !description) return null;

  const cleanTid = tid || name;
  const parts = [
    `${cleanTid}${name && name !== cleanTid ? ` ${name}` : ""}`,
    tactic ? `Tactic: ${tactic}` : "",
    description,
    detection ? `Detection: ${detection}` : "",
    mitigation ? `Mitigations: ${mitigation}` : "",
  ].filter(Boolean);
  const text = parts.join(" | ");
  if (!text) return null;

  return {
    id: cleanTid.toUpperCase().startsWith("MITRE ") ? cleanTid : `MITRE ${cleanTid}`,
    collection: "mitre_attack",
    technique_id: tid || undefined,
    tactic: tactic || undefined,
    title: name || cleanTid,
    text,
    source: sourceLabel,
    text_hash: sha256Text(text),
  };
}

async function parseMitreFile(
  filePath: string,
  ext: ".csv" | ".json" | ".xlsx",
  sourceLabel: string
): Promise<{ records: KBRecord[]; totalRows: number; skippedEmpty: number }> {
  if (ext === ".json") {
    const raw = fs.readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    if (
      parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      (parsed as Record<string, unknown>).type === "bundle" &&
      Array.isArray((parsed as Record<string, unknown>).objects)
    ) {
      return parseStixMitreBundle(parsed as Record<string, unknown>, sourceLabel);
    }
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    const records: KBRecord[] = [];
    let skipped = 0;
    for (const item of arr) {
      if (!item || typeof item !== "object") {
        skipped += 1;
        continue;
      }
      const strRow: Record<string, string> = {};
      for (const [k, v] of Object.entries(item as Record<string, unknown>)) {
        strRow[k] = v !== undefined && v !== null ? String(v) : "";
      }
      const rec = mitreRowToRecord(strRow, sourceLabel);
      if (rec) records.push(rec);
      else skipped += 1;
    }
    return { records, totalRows: arr.length, skippedEmpty: skipped };
  }

  if (ext === ".xlsx") {
    const { rows } = readXlsxRows(filePath);
    const records: KBRecord[] = [];
    let skipped = 0;
    for (const r of rows) {
      const rec = mitreRowToRecord(r, sourceLabel);
      if (rec) records.push(rec);
      else skipped += 1;
    }
    return { records, totalRows: rows.length, skippedEmpty: skipped };
  }

  const records: KBRecord[] = [];
  let skipped = 0;
  const { totalRows } = await streamCsvRows(filePath, (row) => {
    const rec = mitreRowToRecord(row, sourceLabel);
    if (rec) records.push(rec);
    else skipped += 1;
  });
  return { records, totalRows, skippedEmpty: skipped };
}

// =========================================================================
// 2. NIST CSF 2.0 IMPORTER (XLSX, CSV, JSON)
// =========================================================================
const NIST_SUBCAT_REGEX = /^([A-Z]{2}\.[A-Z]{2}-\d{2})\s*[:\-–]?\s*(.*)$/;

function extractNistFromRows(
  rows: Record<string, string>[],
  sourceLabel: string
): { records: KBRecord[]; totalRows: number; skippedEmpty: number } {
  const records: KBRecord[] = [];
  let skipped = 0;
  let lastFunc = "";
  let lastCat = "";

  for (const row of rows) {
    const funcVal = pickCol(row, ["function", "nist_function", "csf_function"]);
    const catVal = pickCol(row, ["category", "nist_category", "csf_category"]);
    if (funcVal) lastFunc = funcVal;
    if (catVal) lastCat = catVal;

    let subId = pickCol(row, [
      "subcategory_id",
      "subcategory id",
      "id",
      "element_identifier",
    ]);
    let outcome = pickCol(row, [
      "outcome",
      "subcategory_text",
      "description",
      "text",
      "title",
    ]);
    const subCol = pickCol(row, ["subcategory", "sub_category"]);

    if (subCol) {
      const m = subCol.match(NIST_SUBCAT_REGEX);
      if (m) {
        if (!subId) subId = m[1].trim();
        if (!outcome && m[2]) outcome = m[2].trim();
      } else if (!outcome) {
        outcome = subCol;
      }
    }

    if (subId && !outcome) {
      const m = subId.match(NIST_SUBCAT_REGEX);
      if (m) {
        subId = m[1].trim();
        outcome = m[2].trim();
      }
    }

    const examples = pickCol(row, [
      "implementation examples",
      "implementation_examples",
      "examples",
      "informative references",
      "informative_references",
      "references",
    ]);

    if (!subId || !outcome) {
      skipped += 1;
      continue;
    }

    const funcLabel = funcVal || lastFunc || "CSF";
    const catLabel = catVal || lastCat || "General";
    const text = `${subId} (${funcLabel} > ${catLabel}): ${outcome}${
      examples ? ` | Examples: ${examples}` : ""
    }`;

    records.push({
      id: subId.toUpperCase().startsWith("NIST ") ? subId : `NIST ${subId}`,
      collection: "nist_csf",
      function: funcLabel,
      category: catLabel,
      subcategory_id: subId,
      title: `${subId}: ${outcome.slice(0, 100)}`,
      text,
      source: sourceLabel,
      text_hash: sha256Text(text),
    });
  }

  return { records, totalRows: rows.length, skippedEmpty: skipped };
}

function parseNistJson(
  rawJson: unknown,
  sourceLabel: string
): { records: KBRecord[]; totalRows: number; skippedEmpty: number } {
  // Support NIST CPRT JSON ({ response: { elements: { elements: [...] } } })
  const obj = rawJson as Record<string, unknown>;
  const cprtElements =
    ((obj?.response as Record<string, unknown>)?.elements as Record<string, unknown>)
      ?.elements ??
    (obj?.elements as unknown[]);

  if (Array.isArray(cprtElements)) {
    const elemMap = new Map<string, Record<string, unknown>>();
    for (const el of cprtElements) {
      if (el && typeof el === "object") {
        const rec = el as Record<string, unknown>;
        if (rec.element_identifier) {
          elemMap.set(String(rec.element_identifier), rec);
        }
      }
    }

    const records: KBRecord[] = [];
    let total = 0;
    let skipped = 0;

    for (const el of cprtElements) {
      if (!el || typeof el !== "object") continue;
      const rec = el as Record<string, unknown>;
      const etype = String(rec.element_type ?? "").toLowerCase();
      const eid = String(rec.element_identifier ?? "").trim();
      if (etype !== "subcategory" && !NIST_SUBCAT_REGEX.test(eid)) continue;
      total += 1;
      const outcome = String(rec.text ?? rec.title ?? "").trim();
      if (!eid || !outcome) {
        skipped += 1;
        continue;
      }

      const catId = eid.split("-")[0]; // e.g. PR.AA
      const funcId = eid.split(".")[0]; // e.g. PR
      const catEl = elemMap.get(catId);
      const funcEl = elemMap.get(funcId);
      const funcLabel = funcEl ? `${funcEl.title ?? funcId} (${funcId})` : funcId;
      const catLabel = catEl ? `${catEl.title ?? catId} (${catId})` : catId;

      const text = `${eid} (${funcLabel} > ${catLabel}): ${outcome}`;
      records.push({
        id: `NIST ${eid}`,
        collection: "nist_csf",
        function: funcLabel,
        category: catLabel,
        subcategory_id: eid,
        title: `${eid}: ${outcome.slice(0, 100)}`,
        text,
        source: sourceLabel,
        text_hash: sha256Text(text),
      });
    }
    return { records, totalRows: total, skippedEmpty: skipped };
  }

  const arr = Array.isArray(rawJson) ? rawJson : [rawJson];
  const strRows = arr
    .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object"))
    .map((item) => {
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(item)) {
        out[k] = v !== undefined && v !== null ? String(v) : "";
      }
      return out;
    });
  return extractNistFromRows(strRows, sourceLabel);
}

async function parseNistFile(
  filePath: string,
  ext: ".csv" | ".json" | ".xlsx",
  sourceLabel: string
): Promise<{ records: KBRecord[]; totalRows: number; skippedEmpty: number }> {
  if (ext === ".json") {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf-8")) as unknown;
    return parseNistJson(parsed, sourceLabel);
  }
  if (ext === ".xlsx") {
    const { rows } = readXlsxRows(filePath);
    return extractNistFromRows(rows, sourceLabel);
  }
  const rows: Record<string, string>[] = [];
  await streamCsvRows(filePath, (row) => {
    rows.push(row);
  });
  return extractNistFromRows(rows, sourceLabel);
}

// =========================================================================
// 3. IR INCIDENTS IMPORTER (CSV, JSON, XLSX, ZIP; up to 100k rows x 49 cols)
// =========================================================================
const IR_TARGET_ALIASES: Record<string, IrColumnTarget> = {
  incident_id: "incident_id",
  incidentid: "incident_id",
  case_id: "incident_id",
  id: "incident_id",
  alert_id: "incident_id",
  ticket_id: "incident_id",
  attack_type: "attack_type",
  attacktype: "attack_type",
  attack_category: "attack_type",
  incident_type: "attack_type",
  threat_type: "attack_type",
  category: "attack_type",
  description: "description",
  incident_description: "description",
  summary: "description",
  details: "description",
  mitre_technique_id: "mitre_technique_id",
  mitre_id: "mitre_technique_id",
  technique_id: "mitre_technique_id",
  mitre_technique: "mitre_technique_id",
  mitre_technique_name: "mitre_technique_name",
  technique_name: "mitre_technique_name",
  mitre_name: "mitre_technique_name",
  nist_function: "nist_function",
  csf_function: "nist_function",
  nist_category: "nist_category",
  csf_category: "nist_category",
  nist_subcategory: "nist_subcategory",
  csf_subcategory: "nist_subcategory",
  subcategory_id: "nist_subcategory",
  detection_indicators: "detection_indicators",
  indicators: "detection_indicators",
  iocs: "detection_indicators",
  detection: "detection_indicators",
  signals: "detection_indicators",
  investigation_steps: "investigation_steps",
  investigation: "investigation_steps",
  triage_steps: "investigation_steps",
  analysis_steps: "investigation_steps",
  recommended_response: "recommended_response",
  response: "recommended_response",
  remediation: "recommended_response",
  containment: "recommended_response",
  playbook: "recommended_response",
  mitigation: "recommended_response",
  source_reference: "source_reference",
  reference: "source_reference",
  source: "source_reference",
};

export function autoGuessIrMapping(
  headers: string[]
): Record<string, IrColumnTarget> {
  const mapping: Record<string, IrColumnTarget> = {};
  for (const h of headers) {
    const lower = h.trim().toLowerCase();
    const compact = lower.replace(/[\s-]+/g, "_");
    const squashed = lower.replace(/[\s_-]+/g, "");
    mapping[h] =
      IR_TARGET_ALIASES[lower] ??
      IR_TARGET_ALIASES[compact] ??
      IR_TARGET_ALIASES[squashed] ??
      "ignore";
  }
  return mapping;
}

function buildIrRecordFromMappedRow(
  row: Record<string, string>,
  mapping: Record<string, IrColumnTarget>,
  rowIndex: number,
  sourceLabel: string
): { record: KBRecord; normalizedText: string; stratum: string } | null {
  const fields: Partial<Record<IrColumnTarget, string>> = {};
  for (const [col, target] of Object.entries(mapping)) {
    if (target === "ignore") continue;
    const val = (row[col] ?? "").trim();
    if (!val) continue;
    fields[target] = fields[target] ? `${fields[target]}; ${val}` : val;
  }

  // Embedded text built ONLY from description + indicators + investigation steps + recommended response (never from IDs)
  const embeddedParts = [
    fields.description ? `Description: ${fields.description}` : "",
    fields.detection_indicators
      ? `Detection indicators: ${fields.detection_indicators}`
      : "",
    fields.investigation_steps
      ? `Investigation steps: ${fields.investigation_steps}`
      : "",
    fields.recommended_response
      ? `Recommended response: ${fields.recommended_response}`
      : "",
  ].filter(Boolean);

  const embeddedText = embeddedParts.join(" | ").trim();
  if (!embeddedText) {
    return null;
  }

  const normalizedText = embeddedText.toLowerCase().replace(/\s+/g, " ").trim();
  const rawIncidentId =
    fields.incident_id || `INC-${String(rowIndex + 1).padStart(6, "0")}`;
  const recordId = rawIncidentId.toUpperCase().startsWith("IR ")
    ? rawIncidentId
    : `IR ${rawIncidentId}`;

  const attackType = fields.attack_type || "Uncategorized";
  const titleParts = [
    rawIncidentId,
    attackType !== "Uncategorized" ? attackType : "",
    fields.mitre_technique_name || "",
  ].filter(Boolean);

  const provenanceSource = fields.source_reference
    ? `${sourceLabel} | ${fields.source_reference}`
    : sourceLabel;

  return {
    normalizedText,
    stratum: attackType,
    record: {
      id: recordId,
      collection: "ir_incidents",
      title: titleParts.join(" — ").slice(0, 140),
      text: embeddedText,
      attack_type: attackType,
      technique_id: fields.mitre_technique_id || undefined,
      nist_function: fields.nist_function || undefined,
      nist_category: fields.nist_category || undefined,
      nist_subcategory: fields.nist_subcategory || undefined,
      source: provenanceSource,
      text_hash: sha256Text(embeddedText),
    },
  };
}

function stratifiedSample<T>(
  strata: Map<string, T[]>,
  limit: number
): T[] {
  const keys = Array.from(strata.keys());
  if (keys.length === 0) return [];
  const totalAvailable = keys.reduce(
    (sum, k) => sum + (strata.get(k)?.length ?? 0),
    0
  );
  if (totalAvailable <= limit) {
    return keys.flatMap((k) => strata.get(k) ?? []);
  }

  // Proportional allocation + round-robin top-up across strata
  const selected: T[] = [];
  const cursors = new Map<string, number>();

  for (const k of keys) {
    const items = strata.get(k) ?? [];
    const quota = Math.max(1, Math.floor((items.length / totalAvailable) * limit));
    const take = Math.min(items.length, quota);
    for (let i = 0; i < take && selected.length < limit; i += 1) {
      selected.push(items[i]);
    }
    cursors.set(k, take);
  }

  let progress = true;
  while (selected.length < limit && progress) {
    progress = false;
    for (const k of keys) {
      if (selected.length >= limit) break;
      const items = strata.get(k) ?? [];
      const cur = cursors.get(k) ?? 0;
      if (cur < items.length) {
        selected.push(items[cur]);
        cursors.set(k, cur + 1);
        progress = true;
      }
    }
  }

  return selected;
}

async function parseIrIncidentsFile(params: {
  filePath: string;
  ext: ".csv" | ".json" | ".xlsx";
  sourceLabel: string;
  mappingOverride?: Record<string, IrColumnTarget>;
  importLimit: number;
}): Promise<{
  records: KBRecord[];
  headers: string[];
  mapping: Record<string, IrColumnTarget>;
  totalRows: number;
  skippedEmpty: number;
  skippedDuplicates: number;
}> {
  const seenNormalized = new Set<string>();
  const strata = new Map<string, KBRecord[]>();
  const stratumSeenCounts = new Map<string, number>();

  let headers: string[] = [];
  let activeMapping: Record<string, IrColumnTarget> | undefined =
    params.mappingOverride;
  let totalRows = 0;
  let skippedEmpty = 0;
  let skippedDuplicates = 0;

  // Bounded reservoir per stratum prevents OOM on 100k x 49 datasets
  const handleRow = (row: Record<string, string>, idx: number) => {
    if (headers.length === 0) {
      headers = Object.keys(row);
    }
    if (!activeMapping) {
      activeMapping = autoGuessIrMapping(headers);
    }
    const built = buildIrRecordFromMappedRow(
      row,
      activeMapping,
      idx,
      params.sourceLabel
    );
    if (!built) {
      skippedEmpty += 1;
      return;
    }
    if (seenNormalized.has(built.normalizedText)) {
      skippedDuplicates += 1;
      return;
    }
    seenNormalized.add(built.normalizedText);

    const sKey = built.stratum;
    const seenInStratum = (stratumSeenCounts.get(sKey) ?? 0) + 1;
    stratumSeenCounts.set(sKey, seenInStratum);

    const bucket = strata.get(sKey) ?? [];
    if (bucket.length < params.importLimit) {
      bucket.push(built.record);
      strata.set(sKey, bucket);
    } else {
      // Reservoir replacement
      const j = Math.floor(Math.random() * seenInStratum);
      if (j < params.importLimit) {
        bucket[j] = built.record;
      }
    }
  };

  if (params.ext === ".csv") {
    const csvInfo = await streamCsvRows(params.filePath, (row, idx) => {
      totalRows += 1;
      handleRow(row, idx);
    });
    if (headers.length === 0) headers = csvInfo.headers;
  } else if (params.ext === ".xlsx") {
    const xlsxInfo = readXlsxRows(params.filePath);
    headers = xlsxInfo.headers;
    totalRows = xlsxInfo.rows.length;
    xlsxInfo.rows.forEach((row, idx) => handleRow(row, idx));
  } else {
    const raw = fs.readFileSync(params.filePath, "utf-8").trim();
    let arr: unknown[] = [];
    if (raw.startsWith("[") || raw.startsWith("{")) {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed)) arr = parsed;
      else if (parsed && typeof parsed === "object") {
        const obj = parsed as Record<string, unknown>;
        arr = Array.isArray(obj.records)
          ? obj.records
          : Array.isArray(obj.incidents)
          ? obj.incidents
          : [obj];
      }
    } else {
      arr = raw
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => JSON.parse(l) as unknown);
    }
    totalRows = arr.length;
    arr.forEach((item, idx) => {
      if (!item || typeof item !== "object") {
        skippedEmpty += 1;
        return;
      }
      const strRow: Record<string, string> = {};
      for (const [k, v] of Object.entries(item as Record<string, unknown>)) {
        strRow[k] = v !== undefined && v !== null ? String(v) : "";
      }
      handleRow(strRow, idx);
    });
  }

  const sampled = stratifiedSample(strata, params.importLimit);
  return {
    records: sampled,
    headers,
    mapping: activeMapping ?? autoGuessIrMapping(headers),
    totalRows,
    skippedEmpty,
    skippedDuplicates,
  };
}

// =========================================================================
// PUBLIC ENTRYPOINTS: STAGE & PARSE / RE-PREVIEW
// =========================================================================
export async function stageAndParseKbFile(params: {
  tempFilePath: string;
  originalName: string;
  collection: KBCollection;
  importLimit?: number;
}): Promise<KBParsePreview> {
  const resolved = resolveUploadedFile(params.tempFilePath, params.originalName);
  const uploadId = `kbup-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 7)}`;
  const sourceLabel = formatProvenanceSource(resolved.displayName);
  const importLimit =
    params.importLimit && params.importLimit > 0
      ? params.importLimit
      : PIPELINE_CONFIG.IR_DEFAULT_IMPORT_LIMIT;

  try {
    if (params.collection === "mitre_attack") {
      const parsed = await parseMitreFile(
        resolved.filePath,
        resolved.ext,
        sourceLabel
      );
      stagedUploads.set(uploadId, {
        upload_id: uploadId,
        file_path: resolved.filePath,
        ext: resolved.ext,
        filename: resolved.displayName,
        collection: params.collection,
        import_limit: importLimit,
        records: parsed.records,
        total_rows: parsed.totalRows,
        skipped_empty: parsed.skippedEmpty,
        skipped_duplicates: 0,
        created_at: Date.now(),
      });
      return {
        upload_id: uploadId,
        filename: resolved.displayName,
        collection: params.collection,
        total_rows: parsed.totalRows,
        parsed_count: parsed.records.length,
        skipped_empty: parsed.skippedEmpty,
        skipped_duplicates: 0,
        preview: parsed.records.slice(0, 5),
      };
    }

    if (params.collection === "nist_csf") {
      const parsed = await parseNistFile(
        resolved.filePath,
        resolved.ext,
        sourceLabel
      );
      stagedUploads.set(uploadId, {
        upload_id: uploadId,
        file_path: resolved.filePath,
        ext: resolved.ext,
        filename: resolved.displayName,
        collection: params.collection,
        import_limit: importLimit,
        records: parsed.records,
        total_rows: parsed.totalRows,
        skipped_empty: parsed.skippedEmpty,
        skipped_duplicates: 0,
        created_at: Date.now(),
      });
      return {
        upload_id: uploadId,
        filename: resolved.displayName,
        collection: params.collection,
        total_rows: parsed.totalRows,
        parsed_count: parsed.records.length,
        skipped_empty: parsed.skippedEmpty,
        skipped_duplicates: 0,
        preview: parsed.records.slice(0, 5),
      };
    }

    const parsed = await parseIrIncidentsFile({
      filePath: resolved.filePath,
      ext: resolved.ext,
      sourceLabel,
      importLimit,
    });
    stagedUploads.set(uploadId, {
      upload_id: uploadId,
      file_path: resolved.filePath,
      ext: resolved.ext,
      filename: resolved.displayName,
      collection: params.collection,
      headers: parsed.headers,
      mapping: parsed.mapping,
      import_limit: importLimit,
      records: parsed.records,
      total_rows: parsed.totalRows,
      skipped_empty: parsed.skippedEmpty,
      skipped_duplicates: parsed.skippedDuplicates,
      created_at: Date.now(),
    });
    return {
      upload_id: uploadId,
      filename: resolved.displayName,
      collection: params.collection,
      total_rows: parsed.totalRows,
      parsed_count: parsed.records.length,
      skipped_empty: parsed.skippedEmpty,
      skipped_duplicates: parsed.skippedDuplicates,
      preview: parsed.records.slice(0, 5),
      headers: parsed.headers,
      mapping: parsed.mapping,
      import_limit: importLimit,
    };
  } catch (err) {
    try {
      if (fs.existsSync(resolved.filePath)) fs.unlinkSync(resolved.filePath);
    } catch {
      // ignore
    }
    throw err;
  }
}

export async function repreviewStagedIrUpload(params: {
  uploadId: string;
  mapping: Record<string, IrColumnTarget>;
  importLimit: number;
}): Promise<KBParsePreview> {
  const staged = stagedUploads.get(params.uploadId);
  if (!staged) {
    throw new Error("Staged upload not found or expired. Re-upload the file.");
  }
  if (staged.collection !== "ir_incidents") {
    throw new Error("Column mapping only applies to ir_incidents.");
  }
  const sourceLabel = formatProvenanceSource(staged.filename);
  const parsed = await parseIrIncidentsFile({
    filePath: staged.file_path,
    ext: staged.ext,
    sourceLabel,
    mappingOverride: params.mapping,
    importLimit: params.importLimit,
  });

  staged.mapping = parsed.mapping;
  staged.import_limit = params.importLimit;
  staged.records = parsed.records;
  staged.total_rows = parsed.totalRows;
  staged.skipped_empty = parsed.skippedEmpty;
  staged.skipped_duplicates = parsed.skippedDuplicates;

  return {
    upload_id: staged.upload_id,
    filename: staged.filename,
    collection: staged.collection,
    total_rows: parsed.totalRows,
    parsed_count: parsed.records.length,
    skipped_empty: parsed.skippedEmpty,
    skipped_duplicates: parsed.skippedDuplicates,
    preview: parsed.records.slice(0, 5),
    headers: parsed.headers,
    mapping: parsed.mapping,
    import_limit: params.importLimit,
  };
}
