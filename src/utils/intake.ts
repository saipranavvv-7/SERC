import Papa from "papaparse";
import type { CanonicalAlert } from "../types.ts";

export const MAX_FILE_BYTES = 5 * 1024 * 1024;
export const MAX_BATCH_ROWS = 200;

export type CsvTargetField =
  | "id"
  | "timestamp"
  | "rule_id"
  | "rule_level"
  | "rule_description"
  | "agent_name"
  | "agent_ip"
  | "source_ip"
  | "dest_ip"
  | "user"
  | "process"
  | "command"
  | "file_path"
  | "mitre_ids"
  | "mitre_tactics"
  | "compliance_tags"
  | "raw_text";

export const CSV_TARGET_FIELDS: CsvTargetField[] = [
  "id",
  "timestamp",
  "rule_id",
  "rule_level",
  "rule_description",
  "agent_name",
  "agent_ip",
  "source_ip",
  "dest_ip",
  "user",
  "process",
  "command",
  "file_path",
  "mitre_ids",
  "mitre_tactics",
  "compliance_tags",
  "raw_text",
];

function getNested(obj: unknown, pathParts: string[]): unknown {
  let curr: unknown = obj;
  for (const part of pathParts) {
    if (curr && typeof curr === "object" && part in (curr as Record<string, unknown>)) {
      curr = (curr as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return curr;
}

function asString(val: unknown): string | null {
  if (val === null || val === undefined) return null;
  const s = String(val).trim();
  return s.length > 0 ? s : null;
}

function asStringArray(val: unknown): string[] {
  if (Array.isArray(val)) {
    return val.map((v) => String(v).trim()).filter(Boolean);
  }
  if (typeof val === "string" && val.trim()) {
    return val
      .split(/[,;|]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return [];
}

export function normalizeWazuhObject(
  raw: Record<string, unknown>,
  index: number
): CanonicalAlert {
  const source = (raw._source && typeof raw._source === "object"
    ? (raw._source as Record<string, unknown>)
    : raw) as Record<string, unknown>;

  const rule = (source.rule && typeof source.rule === "object"
    ? (source.rule as Record<string, unknown>)
    : {}) as Record<string, unknown>;

  const compliance: string[] = [];
  const complianceKeys = [
    ["gdpr", "GDPR"],
    ["hipaa", "HIPAA"],
    ["pci_dss", "PCI-DSS"],
    ["nist_800_53", "NIST-800-53"],
    ["tsc", "TSC"],
    ["gpg13", "GPG13"],
  ];
  for (const [key, label] of complianceKeys) {
    const vals = asStringArray(rule[key]);
    for (const v of vals) {
      compliance.push(`${label}:${v}`);
    }
  }
  for (const directTag of asStringArray(source.compliance_tags)) {
    if (!compliance.includes(directTag)) compliance.push(directTag);
  }

  const ruleLevelRaw =
    getNested(source, ["rule", "level"]) ?? source.rule_level ?? null;
  const ruleLevelNum =
    ruleLevelRaw !== null && !Number.isNaN(Number(ruleLevelRaw))
      ? Number(ruleLevelRaw)
      : null;

  const id =
    asString(source.id) ??
    asString(raw._id) ??
    `wazuh-${index + 1}-${Date.now().toString(36)}`;

  return {
    id,
    timestamp: asString(source.timestamp ?? source["@timestamp"]),
    rule_id: asString(getNested(source, ["rule", "id"]) ?? source.rule_id),
    rule_level: ruleLevelNum,
    rule_description: asString(
      getNested(source, ["rule", "description"]) ?? source.rule_description
    ),
    agent_name: asString(
      getNested(source, ["agent", "name"]) ?? source.agent_name
    ),
    agent_ip: asString(getNested(source, ["agent", "ip"]) ?? source.agent_ip),
    source_ip: asString(
      getNested(source, ["data", "srcip"]) ??
        getNested(source, ["data", "src_ip"]) ??
        getNested(source, ["data", "win", "eventdata", "ipAddress"]) ??
        source.source_ip ??
        source.srcip
    ),
    dest_ip: asString(
      getNested(source, ["data", "dstip"]) ??
        getNested(source, ["data", "dst_ip"]) ??
        source.dest_ip ??
        source.dstip
    ),
    user: asString(
      getNested(source, ["data", "dstuser"]) ??
        getNested(source, ["data", "srcuser"]) ??
        getNested(source, ["data", "user"]) ??
        getNested(source, ["data", "win", "eventdata", "targetUserName"]) ??
        getNested(source, ["data", "win", "eventdata", "subjectUserName"]) ??
        source.user
    ),
    process: asString(
      getNested(source, ["data", "process"]) ??
        getNested(source, ["data", "win", "eventdata", "image"]) ??
        getNested(source, ["predecoder", "program_name"]) ??
        source.process
    ),
    command: asString(
      getNested(source, ["data", "command"]) ??
        getNested(source, ["data", "win", "eventdata", "commandLine"]) ??
        source.command
    ),
    file_path: asString(
      getNested(source, ["syscheck", "path"]) ??
        getNested(source, ["data", "file_path"]) ??
        getNested(source, ["data", "win", "eventdata", "targetFilename"]) ??
        source.file_path
    ),
    mitre_ids: asStringArray(
      getNested(source, ["rule", "mitre", "id"]) ?? source.mitre_ids
    ),
    mitre_tactics: asStringArray(
      getNested(source, ["rule", "mitre", "tactic"]) ?? source.mitre_tactics
    ),
    compliance_tags: compliance,
    raw_text: JSON.stringify(raw),
    source_type: "wazuh_json",
  };
}

export function parseJsonAlertsText(text: string): CanonicalAlert[] {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("Input JSON is empty.");
  }

  let objects: Record<string, unknown>[] = [];

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (Array.isArray(parsed)) {
      objects = parsed.filter(
        (item): item is Record<string, unknown> =>
          Boolean(item) && typeof item === "object" && !Array.isArray(item)
      );
    } else if (parsed && typeof parsed === "object") {
      objects = [parsed as Record<string, unknown>];
    } else {
      throw new Error("JSON must be an alert object, array of alerts, or NDJSON.");
    }
  } catch (err) {
    // Try NDJSON (one JSON object per line)
    const lines = trimmed
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length <= 1) {
      throw new Error(
        err instanceof Error ? `Invalid JSON: ${err.message}` : "Invalid JSON input."
      );
    }
    for (let i = 0; i < lines.length; i += 1) {
      try {
        const lineObj = JSON.parse(lines[i]) as unknown;
        if (!lineObj || typeof lineObj !== "object" || Array.isArray(lineObj)) {
          throw new Error(`Line ${i + 1} is not a JSON object.`);
        }
        objects.push(lineObj as Record<string, unknown>);
      } catch (lineErr) {
        throw new Error(
          `NDJSON parse failed on line ${i + 1}: ${
            lineErr instanceof Error ? lineErr.message : String(lineErr)
          }`
        );
      }
    }
  }

  if (objects.length === 0) {
    throw new Error("No valid JSON alert objects found.");
  }
  if (objects.length > MAX_BATCH_ROWS) {
    throw new Error(
      `Batch limit exceeded: ${objects.length} alerts found (max ${MAX_BATCH_ROWS}).`
    );
  }

  return objects.map((obj, idx) => normalizeWazuhObject(obj, idx));
}

const COLUMN_ALIASES: Record<string, CsvTargetField> = {
  id: "id",
  alertid: "id",
  eventid: "id",
  timestamp: "timestamp",
  time: "timestamp",
  datetime: "timestamp",
  "@timestamp": "timestamp",
  ruleid: "rule_id",
  "rule.id": "rule_id",
  rulelevel: "rule_level",
  "rule.level": "rule_level",
  severity: "rule_level",
  level: "rule_level",
  ruledescription: "rule_description",
  "rule.description": "rule_description",
  description: "rule_description",
  message: "rule_description",
  agentname: "agent_name",
  "agent.name": "agent_name",
  hostname: "agent_name",
  host: "agent_name",
  agentip: "agent_ip",
  "agent.ip": "agent_ip",
  sourceip: "source_ip",
  srcip: "source_ip",
  "data.srcip": "source_ip",
  src: "source_ip",
  destip: "dest_ip",
  dstip: "dest_ip",
  "data.dstip": "dest_ip",
  dst: "dest_ip",
  user: "user",
  username: "user",
  dstuser: "user",
  srcuser: "user",
  account: "user",
  process: "process",
  processname: "process",
  program: "process",
  image: "process",
  command: "command",
  commandline: "command",
  cmd: "command",
  filepath: "file_path",
  path: "file_path",
  filename: "file_path",
  mitreid: "mitre_ids",
  mitreids: "mitre_ids",
  "rule.mitre.id": "mitre_ids",
  techniqueid: "mitre_ids",
  mitretactic: "mitre_tactics",
  mitretactics: "mitre_tactics",
  "rule.mitre.tactic": "mitre_tactics",
  tactic: "mitre_tactics",
  compliancetags: "compliance_tags",
  compliance: "compliance_tags",
  rawtext: "raw_text",
  raw: "raw_text",
  full_log: "raw_text",
  fulllog: "raw_text",
  log: "raw_text",
};

export function autoDetectCsvMapping(
  headers: string[]
): Record<string, CsvTargetField> {
  const mapping: Record<string, CsvTargetField> = {};
  for (const h of headers) {
    const lower = h.trim().toLowerCase();
    const compact = lower.replace(/[\s_-]+/g, "");
    mapping[h] =
      COLUMN_ALIASES[lower] ?? COLUMN_ALIASES[compact] ?? "raw_text";
  }
  return mapping;
}

export function parseCsvPreview(csvText: string): {
  headers: string[];
  rows: Record<string, string>[];
  mapping: Record<string, CsvTargetField>;
} {
  const result = Papa.parse<Record<string, string>>(csvText.trim(), {
    header: true,
    skipEmptyLines: true,
  });

  if (result.errors.length > 0 && result.data.length === 0) {
    throw new Error(`CSV parse error: ${result.errors[0].message}`);
  }

  const headers = result.meta.fields ?? [];
  if (headers.length === 0) {
    throw new Error("CSV has no header columns.");
  }
  if (result.data.length === 0) {
    throw new Error("CSV contains no data rows.");
  }
  if (result.data.length > MAX_BATCH_ROWS) {
    throw new Error(
      `Batch limit exceeded: ${result.data.length} CSV rows found (max ${MAX_BATCH_ROWS}).`
    );
  }

  return {
    headers,
    rows: result.data,
    mapping: autoDetectCsvMapping(headers),
  };
}

export function normalizeCsvRows(
  rows: Record<string, string>[],
  mapping: Record<string, CsvTargetField>
): CanonicalAlert[] {
  if (rows.length > MAX_BATCH_ROWS) {
    throw new Error(
      `Batch limit exceeded: ${rows.length} rows (max ${MAX_BATCH_ROWS}).`
    );
  }

  return rows.map((row, idx) => {
    const alert: CanonicalAlert = {
      id: `csv-${idx + 1}-${Date.now().toString(36)}`,
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
      raw_text: "",
      source_type: "csv",
    };

    const extraParts: string[] = [];

    for (const [col, rawVal] of Object.entries(row)) {
      const val = asString(rawVal);
      if (!val) continue;
      const target = mapping[col] ?? "raw_text";
      if (target === "raw_text") {
        extraParts.push(`${col}=${val}`);
      } else if (target === "id") {
        alert.id = val;
      } else if (target === "rule_level") {
        const n = Number(val);
        if (!Number.isNaN(n)) alert.rule_level = n;
      } else if (
        target === "mitre_ids" ||
        target === "mitre_tactics" ||
        target === "compliance_tags"
      ) {
        const items = asStringArray(val);
        for (const item of items) {
          if (!alert[target].includes(item)) alert[target].push(item);
        }
      } else {
        alert[target] = val;
      }
    }

    const fullRowStr = Object.entries(row)
      .filter(([, v]) => v !== undefined && String(v).trim() !== "")
      .map(([k, v]) => `${k}: ${v}`)
      .join(" | ");

    alert.raw_text =
      extraParts.length > 0
        ? `${extraParts.join(" | ")} || ${fullRowStr}`
        : fullRowStr;

    return alert;
  });
}

export function normalizePlainTextAlert(
  text: string,
  idx = 0
): CanonicalAlert {
  const clean = text.trim();
  if (!clean) {
    throw new Error("Alert text cannot be empty.");
  }
  return {
    id: `txt-${idx + 1}-${Date.now().toString(36)}`,
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
    raw_text: clean,
    source_type: "text",
  };
}
