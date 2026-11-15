export type InputSourceType = "wazuh_json" | "csv" | "text" | "image";

export interface CanonicalAlert {
  id: string;
  timestamp: string | null;
  rule_id: string | null;
  rule_level: number | null;
  rule_description: string | null;
  agent_name: string | null;
  agent_ip: string | null;
  source_ip: string | null;
  dest_ip: string | null;
  user: string | null;
  process: string | null;
  command: string | null;
  file_path: string | null;
  mitre_ids: string[];
  mitre_tactics: string[];
  compliance_tags: string[];
  raw_text: string;
  source_type?: InputSourceType;
  image_data_url?: string;
  collapsed_count?: number;
}

export type KBCollection = "mitre_attack" | "nist_csf" | "ir_incidents";

export interface KBRecord {
  id: string;
  collection: KBCollection;
  title: string;
  text: string;
  technique_id?: string;
  tactic?: string;
  platforms?: string[];
  function?: string;
  category?: string;
  subcategory_id?: string;
  attack_type?: string;
  nist_function?: string;
  nist_category?: string;
  nist_subcategory?: string;
  source: string;
  text_hash?: string;
}

export interface KBChunk {
  chunk_id: string;
  record_id: string;
  collection: KBCollection;
  title: string;
  text: string;
  technique_id?: string;
  tactic?: string;
  subcategory_id?: string;
  nist_subcategory?: string;
  source: string;
  text_hash: string;
  embedding: number[];
}

export type RetrievalMethod = "direct" | "semantic" | "nist-expansion";

export interface RetrievedChunk {
  chunk_id: string;
  record_id: string;
  collection: KBCollection;
  title: string;
  text: string;
  technique_id?: string;
  tactic?: string;
  subcategory_id?: string;
  nist_subcategory?: string;
  source: string;
  score: number;
  method: RetrievalMethod;
}

export type IrColumnTarget =
  | "ignore"
  | "incident_id"
  | "attack_type"
  | "description"
  | "mitre_technique_id"
  | "mitre_technique_name"
  | "nist_function"
  | "nist_category"
  | "nist_subcategory"
  | "detection_indicators"
  | "investigation_steps"
  | "recommended_response"
  | "source_reference";

export interface KBParsePreview {
  upload_id: string;
  filename: string;
  collection: KBCollection;
  total_rows: number;
  parsed_count: number;
  skipped_empty: number;
  skipped_duplicates: number;
  preview: KBRecord[];
  headers?: string[];
  mapping?: Record<string, IrColumnTarget>;
  import_limit?: number;
}

export interface DroppedField {
  field: string;
  value: string;
  reason: "removed: not in input";
}

export interface PipelineStageTrace {
  stage: "Intake" | "Refine" | "Retrieve" | "Triage" | "Generate" | "Validate";
  status: "ok" | "warning" | "error" | "skipped" | "pending_confirmation";
  ms: number;
  detail?: string;
}

export interface ValidationClaim {
  type: "ip" | "username" | "hostname" | "rule_id" | "chunk_id";
  value: string;
  supported: boolean;
  reason?: string;
}

export interface ValidationResult {
  checked_count: number;
  unsupported_count: number;
  unsupported_claims: ValidationClaim[];
  checked_claims: ValidationClaim[];
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export type AllowlistType = "ip" | "user" | "host" | "rule_id" | "scheduled_job";

export interface AllowlistEntry {
  id: string;
  type: AllowlistType;
  value: string;
  note?: string;
  created_at: string;
}

export type FeedbackDecisionType =
  | "true_positive"
  | "false_positive"
  | "false_negative";

export interface FeedbackRecord {
  id: string;
  alert_id: string;
  rule_id: string | null;
  rule_description: string | null;
  decision: FeedbackDecisionType;
  note?: string;
  created_at: string;
}

export interface RuleFeedbackStats {
  rule_id: string;
  true_positive: number;
  false_positive: number;
  false_negative: number;
  total: number;
  fp_rate: number;
}

export type TriageVerdict = "likely_benign" | "needs_review" | "likely_malicious";

export interface TriagePreChecks {
  allowlist_matches: AllowlistEntry[];
  low_rule_level: boolean;
  collapsed_count: number;
  high_impact_category: string | null;
}

export interface TriageResult {
  verdict: TriageVerdict;
  confidence: number;
  reasons_for: string[];
  reasons_against: string[];
  corroboration_to_check: string[];
  what_would_change_my_mind: string[];
  pre_checks: TriagePreChecks;
  guardrails_applied: string[];
}

export interface AlertAnalysisResult {
  alert: CanonicalAlert;
  event_summary: string;
  dropped_fields: DroppedField[];
  retrieved_chunks: RetrievedChunk[];
  low_confidence: boolean;
  best_score: number;
  threshold: number;
  triage?: TriageResult;
  guidance: string;
  validation: ValidationResult | null;
  trace: PipelineStageTrace[];
  model_used: string;
  requires_confirmation?: boolean;
  error?: string;
}

export interface EvalScenario {
  id: string;
  name: string;
  alert: CanonicalAlert;
  label: "benign" | "malicious";
  expected_mitre: string | null;
  reference_text: string;
}

export interface EvalModelRun {
  model_choice: "A" | "B";
  model_used: string;
  verdict: TriageVerdict;
  confidence: number;
  flagged: boolean;
  precision_at_3: number | null;
  recall_at_3: number | null;
  response_similarity: number | null;
  guidance: string;
  ms: number;
  error?: string;
}

export interface EvalScenarioResult {
  scenario_id: string;
  name: string;
  label: "benign" | "malicious";
  expected_mitre: string | null;
  run_a?: EvalModelRun;
  run_b?: EvalModelRun;
}

export interface AppConfigSummary {
  extractor_model: string;
  generation_model_a: string;
  generation_model_b: string;
  embedding_model: string;
  embed_dim: number;
  default_threshold: number;
  max_file_bytes: number;
  max_batch_rows: number;
  vector_count: number;
  collection_counts: Record<KBCollection, number>;
  record_counts: Record<KBCollection, number>;
  last_import_at: Record<KBCollection, string | null>;
  kb_status: "ready" | "indexing" | "error";
  kb_error: string | null;
}
