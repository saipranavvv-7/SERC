import fs from "node:fs";
import path from "node:path";
import type {
  KBChunk,
  KBCollection,
  KBRecord,
  RetrievedChunk,
} from "../src/types.ts";
import { MODEL_CONFIG, PIPELINE_CONFIG } from "./config.ts";
import { formatGeminiError, getGeminiClient, withRetry429 } from "./gemini.ts";
import { sha256Text } from "./kbImporters.ts";
import { STARTER_KB_RECORDS } from "./starterKb.ts";

const DATA_DIR = path.resolve(process.cwd(), "data");
const INDEX_PATH = path.join(DATA_DIR, "kb-index.json");

const FIXED_COLLECTIONS: KBCollection[] = [
  "mitre_attack",
  "nist_csf",
  "ir_incidents",
];

interface PersistedIndex {
  embedding_model: string;
  embed_dim: number;
  updated_at: string;
  last_import_at?: Record<KBCollection, string | null>;
  records: KBRecord[];
  chunks: KBChunk[];
}

export class KnowledgeBaseManager {
  private records: KBRecord[] = [];
  private chunks: KBChunk[] = [];
  private lastImportAt: Record<KBCollection, string | null> = {
    mitre_attack: null,
    nist_csf: null,
    ir_incidents: null,
  };
  private status: "ready" | "indexing" | "error" = "ready";
  private lastError: string | null = null;
  private initPromise: Promise<void> | null = null;

  async init(): Promise<void> {
    if (this.initPromise) return this.initPromise;
    this.initPromise = this._initInternal();
    return this.initPromise;
  }

  private async _initInternal(): Promise<void> {
    try {
      if (fs.existsSync(INDEX_PATH)) {
        const raw = fs.readFileSync(INDEX_PATH, "utf-8");
        const parsed = JSON.parse(raw) as PersistedIndex;
        if (
          parsed.embedding_model === MODEL_CONFIG.EMBEDDING_MODEL &&
          parsed.embed_dim === MODEL_CONFIG.EMBED_DIM &&
          Array.isArray(parsed.chunks) &&
          Array.isArray(parsed.records)
        ) {
          // Only keep records belonging to the 3 fixed collections
          const validSet = new Set<string>(FIXED_COLLECTIONS);
          this.records = parsed.records.filter((r) => validSet.has(r.collection));
          this.chunks = parsed.chunks.filter((c) => validSet.has(c.collection));
          if (parsed.last_import_at) {
            this.lastImportAt = {
              mitre_attack: parsed.last_import_at.mitre_attack ?? null,
              nist_csf: parsed.last_import_at.nist_csf ?? null,
              ir_incidents: parsed.last_import_at.ir_incidents ?? null,
            };
          }
          this.status = "ready";
          this.lastError = null;
          return;
        }
      }
      // Start clean (empty) unless user loads demo starter set or imports data
      this.status = "ready";
    } catch (err) {
      this.status = "error";
      this.lastError = formatGeminiError(err);
      console.error("KB startup reload failed:", this.lastError);
    }
  }

  async seedStarter(
    onProgress?: (done: number, total: number, stage: string) => void
  ): Promise<void> {
    await this.indexRecords(STARTER_KB_RECORDS, {
      mode: "add",
      resume: true,
      onProgress,
    });
  }

  getStatus() {
    const collectionCounts: Record<KBCollection, number> = {
      mitre_attack: 0,
      nist_csf: 0,
      ir_incidents: 0,
    };
    const recordCounts: Record<KBCollection, number> = {
      mitre_attack: 0,
      nist_csf: 0,
      ir_incidents: 0,
    };

    for (const c of this.chunks) {
      if (c.collection in collectionCounts) {
        collectionCounts[c.collection] += 1;
      }
    }
    for (const r of this.records) {
      if (r.collection in recordCounts) {
        recordCounts[r.collection] += 1;
      }
    }

    return {
      vector_count: this.chunks.length,
      collection_counts: collectionCounts,
      record_counts: recordCounts,
      last_import_at: this.lastImportAt,
      kb_status: this.status,
      kb_error: this.lastError,
    };
  }

  listRecords(): KBRecord[] {
    return this.records;
  }

  clearCollection(collection: KBCollection): void {
    this.records = this.records.filter((r) => r.collection !== collection);
    this.chunks = this.chunks.filter((c) => c.collection !== collection);
    this.lastImportAt[collection] = null;
    this.persistIndex();
  }

  exportIndex(): PersistedIndex {
    return {
      embedding_model: MODEL_CONFIG.EMBEDDING_MODEL,
      embed_dim: MODEL_CONFIG.EMBED_DIM,
      updated_at: new Date().toISOString(),
      last_import_at: this.lastImportAt,
      records: this.records,
      chunks: this.chunks,
    };
  }

  importIndex(rawJson: unknown): { records: number; chunks: number } {
    if (!rawJson || typeof rawJson !== "object") {
      throw new Error("Invalid index JSON format.");
    }
    const parsed = rawJson as PersistedIndex;
    if (
      !Array.isArray(parsed.records) ||
      !Array.isArray(parsed.chunks) ||
      parsed.embed_dim !== MODEL_CONFIG.EMBED_DIM
    ) {
      throw new Error(
        `Invalid index file: expected records[], chunks[], and embed_dim=${MODEL_CONFIG.EMBED_DIM}.`
      );
    }
    if (parsed.embedding_model !== MODEL_CONFIG.EMBEDDING_MODEL) {
      throw new Error(
        `Index embedding model mismatch: expected ${MODEL_CONFIG.EMBEDDING_MODEL}, got ${parsed.embedding_model}.`
      );
    }

    const validSet = new Set<string>(FIXED_COLLECTIONS);
    this.records = parsed.records.filter((r) => validSet.has(r.collection));
    this.chunks = parsed.chunks.filter((c) => validSet.has(c.collection));
    this.lastImportAt = {
      mitre_attack: parsed.last_import_at?.mitre_attack ?? new Date().toISOString(),
      nist_csf: parsed.last_import_at?.nist_csf ?? new Date().toISOString(),
      ir_incidents: parsed.last_import_at?.ir_incidents ?? new Date().toISOString(),
    };
    this.status = "ready";
    this.lastError = null;
    this.persistIndex();
    return { records: this.records.length, chunks: this.chunks.length };
  }

  chunkRecord(record: KBRecord): Omit<KBChunk, "embedding">[] {
    const cleanText = record.text.trim();
    const maxLen = PIPELINE_CONFIG.CHUNK_SIZE_CHARS;
    const overlap = PIPELINE_CONFIG.CHUNK_OVERLAP_CHARS;
    const recHash = record.text_hash || sha256Text(cleanText);

    if (cleanText.length <= maxLen) {
      return [
        {
          chunk_id: record.id,
          record_id: record.id,
          collection: record.collection,
          title: record.title,
          text: cleanText,
          technique_id: record.technique_id,
          tactic: record.tactic,
          subcategory_id: record.subcategory_id,
          nist_subcategory: record.nist_subcategory,
          source: record.source,
          text_hash: recHash,
        },
      ];
    }

    const results: Omit<KBChunk, "embedding">[] = [];
    let start = 0;
    let idx = 1;
    while (start < cleanText.length) {
      const end = Math.min(start + maxLen, cleanText.length);
      const slice = cleanText.slice(start, end).trim();
      if (slice.length > 0) {
        results.push({
          chunk_id: `${record.id}#${idx}`,
          record_id: record.id,
          collection: record.collection,
          title: record.title,
          text: slice,
          technique_id: record.technique_id,
          tactic: record.tactic,
          subcategory_id: record.subcategory_id,
          nist_subcategory: record.nist_subcategory,
          source: record.source,
          text_hash: sha256Text(slice),
        });
        idx += 1;
      }
      if (end >= cleanText.length) break;
      start = Math.max(0, end - overlap);
    }
    return results;
  }

  private async embedTexts(
    texts: string[],
    taskType: "RETRIEVAL_DOCUMENT" | "RETRIEVAL_QUERY"
  ): Promise<number[][]> {
    const ai = getGeminiClient();
    const response = await withRetry429(async () => {
      return await ai.models.embedContent({
        model: MODEL_CONFIG.EMBEDDING_MODEL,
        contents: texts,
        config: {
          taskType,
          outputDimensionality: MODEL_CONFIG.EMBED_DIM,
        },
      });
    });

    const embeddings = response.embeddings;
    if (!embeddings || embeddings.length !== texts.length) {
      throw new Error(
        `Embedding response mismatch: expected ${texts.length} vectors, got ${embeddings?.length ?? 0}.`
      );
    }
    return embeddings.map((e, i) => {
      if (!e.values || e.values.length === 0) {
        throw new Error(`Empty embedding vector returned at batch index ${i}.`);
      }
      return e.values;
    });
  }

  async indexRecords(
    incoming: KBRecord[],
    options: {
      mode: "add" | "replace";
      resume?: boolean;
      abortSignal?: AbortSignal;
      onProgress?: (done: number, total: number, stage: string) => void;
    }
  ): Promise<{
    records_indexed: number;
    chunks_indexed: number;
    skipped_cached: number;
    cancelled: boolean;
  }> {
    if (incoming.length === 0) {
      throw new Error("No valid Knowledge Base records provided.");
    }

    this.status = "indexing";
    this.lastError = null;

    // De-duplicate incoming by record id (last wins)
    const dedupMap = new Map<string, KBRecord>();
    for (const rec of incoming) {
      const hash = rec.text_hash || sha256Text(rec.text);
      dedupMap.set(rec.id, { ...rec, text_hash: hash });
    }
    const uniqueIncoming = Array.from(dedupMap.values());

    try {
      // Cache existing embeddings by (record_id + text_hash + chunk_id) for resume/dedup
      const existingByChunkKey = new Map<string, KBChunk>();
      for (const c of this.chunks) {
        existingByChunkKey.set(`${c.chunk_id}::${c.text_hash}`, c);
      }

      const pendingToEmbed: Omit<KBChunk, "embedding">[] = [];
      const reusedChunks: KBChunk[] = [];

      for (const rec of uniqueIncoming) {
        const parts = this.chunkRecord(rec);
        for (const part of parts) {
          const cached = existingByChunkKey.get(`${part.chunk_id}::${part.text_hash}`);
          if (options.resume !== false && cached) {
            reusedChunks.push({ ...part, embedding: cached.embedding });
          } else {
            pendingToEmbed.push(part);
          }
        }
      }

      const newlyEmbedded: KBChunk[] = [];
      const batchSize = PIPELINE_CONFIG.EMBED_BATCH_SIZE;
      const totalToEmbed = pendingToEmbed.length;
      let cancelled = false;

      options.onProgress?.(
        0,
        totalToEmbed,
        totalToEmbed === 0
          ? "All records already embedded (resumed from cache)"
          : `Embedding ${totalToEmbed} chunks (${reusedChunks.length} cached skipped)...`
      );

      for (let i = 0; i < totalToEmbed; i += batchSize) {
        if (options.abortSignal?.aborted) {
          cancelled = true;
          break;
        }
        const batch = pendingToEmbed.slice(i, i + batchSize);
        const vectors = await this.embedTexts(
          batch.map((c) => c.text),
          "RETRIEVAL_DOCUMENT"
        );
        for (let j = 0; j < batch.length; j += 1) {
          newlyEmbedded.push({
            ...batch[j],
            embedding: vectors[j],
          });
        }
        options.onProgress?.(
          Math.min(i + batch.length, totalToEmbed),
          totalToEmbed,
          `Embedded ${Math.min(i + batch.length, totalToEmbed)} / ${totalToEmbed} chunks`
        );
      }

      const combinedNewChunks = [...reusedChunks, ...newlyEmbedded];
      const embeddedRecordIds = new Set(combinedNewChunks.map((c) => c.record_id));
      const completedRecords = uniqueIncoming.filter((r) =>
        embeddedRecordIds.has(r.id)
      );

      if (options.mode === "replace" && !cancelled) {
        this.records = completedRecords;
        this.chunks = combinedNewChunks;
      } else {
        const upsertedIds = new Set(completedRecords.map((r) => r.id));
        this.records = [
          ...this.records.filter((r) => !upsertedIds.has(r.id)),
          ...completedRecords,
        ];
        this.chunks = [
          ...this.chunks.filter((c) => !upsertedIds.has(c.record_id)),
          ...combinedNewChunks,
        ];
      }

      const nowIso = new Date().toISOString();
      for (const r of completedRecords) {
        this.lastImportAt[r.collection] = nowIso;
      }

      this.persistIndex();
      this.status = "ready";

      return {
        records_indexed: completedRecords.length,
        chunks_indexed: combinedNewChunks.length,
        skipped_cached: reusedChunks.length,
        cancelled,
      };
    } catch (err) {
      this.status = "error";
      this.lastError = formatGeminiError(err);
      throw err;
    }
  }

  private persistIndex(): void {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const payload: PersistedIndex = {
      embedding_model: MODEL_CONFIG.EMBEDDING_MODEL,
      embed_dim: MODEL_CONFIG.EMBED_DIM,
      updated_at: new Date().toISOString(),
      last_import_at: this.lastImportAt,
      records: this.records,
      chunks: this.chunks,
    };
    fs.writeFileSync(INDEX_PATH, JSON.stringify(payload), "utf-8");
  }

  getMitreNamesForIds(mitreIds: string[]): string[] {
    if (!mitreIds.length) return [];
    const normalized = new Set(mitreIds.map((m) => m.trim().toUpperCase()));
    const names: string[] = [];
    for (const r of this.records) {
      if (r.collection === "mitre_attack" && r.technique_id) {
        const tid = r.technique_id.toUpperCase();
        if (normalized.has(tid)) {
          names.push(`${tid} ${r.title}`);
        }
      }
    }
    return names;
  }

  async retrieve(params: {
    eventSummary: string;
    ruleDescription: string | null;
    mitreIds: string[];
    threshold: number;
  }): Promise<{
    chunks: RetrievedChunk[];
    low_confidence: boolean;
    best_score: number;
    query_text: string;
  }> {
    if (this.chunks.length === 0) {
      throw new Error(
        "Knowledge Base is empty. Import records or load the demo starter set in the Knowledge Base tab."
      );
    }

    const mitreNames = this.getMitreNamesForIds(params.mitreIds);
    const queryParts = [
      params.eventSummary,
      params.ruleDescription ?? "",
      ...params.mitreIds,
      ...mitreNames,
    ]
      .map((s) => s.trim())
      .filter(Boolean);

    const queryText = queryParts.join(" | ").slice(0, 1800) || "security event";
    const [queryVec] = await this.embedTexts([queryText], "RETRIEVAL_QUERY");

    const scoredChunks = this.chunks.map((chunk) => ({
      chunk,
      score: cosineSimilarity(queryVec, chunk.embedding),
    }));

    const selected = new Map<string, RetrievedChunk>();

    const toRetrieved = (
      chunk: KBChunk,
      score: number,
      method: RetrievedChunk["method"]
    ): RetrievedChunk => ({
      chunk_id: chunk.chunk_id,
      record_id: chunk.record_id,
      collection: chunk.collection,
      title: chunk.title,
      text: chunk.text,
      technique_id: chunk.technique_id,
      tactic: chunk.tactic,
      subcategory_id: chunk.subcategory_id,
      nist_subcategory: chunk.nist_subcategory,
      source: chunk.source,
      score,
      method,
    });

    // 1. Direct lookup: fetch matching mitre_attack records by technique_id (exact and parent)
    if (params.mitreIds.length > 0) {
      const exactIds = new Set(params.mitreIds.map((id) => id.trim().toUpperCase()));
      const parentIds = new Set(
        params.mitreIds
          .map((id) => id.trim().toUpperCase().split(".")[0])
          .filter(Boolean)
      );

      for (const { chunk, score } of scoredChunks) {
        if (chunk.collection !== "mitre_attack" || !chunk.technique_id) continue;
        const tid = chunk.technique_id.toUpperCase();
        if (exactIds.has(tid) || parentIds.has(tid)) {
          selected.set(chunk.chunk_id, toRetrieved(chunk, score, "direct"));
        }
      }
    }

    // 2. Top 3 per collection by cosine similarity, merge and de-duplicate
    for (const col of FIXED_COLLECTIONS) {
      const topK = scoredChunks
        .filter((item) => item.chunk.collection === col)
        .sort((a, b) => b.score - a.score)
        .slice(0, PIPELINE_CONFIG.TOP_K_PER_COLLECTION);

      for (const { chunk, score } of topK) {
        if (!selected.has(chunk.chunk_id)) {
          selected.set(chunk.chunk_id, toRetrieved(chunk, score, "semantic"));
        }
      }
    }

    // 3. NIST expansion: collect nist_subcategory values from retrieved ir_incidents and include matching nist_csf records
    const expandedSubcats = new Set<string>();
    for (const item of selected.values()) {
      if (item.collection === "ir_incidents" && item.nist_subcategory) {
        for (const sub of item.nist_subcategory.split(/[,;|]/)) {
          const clean = sub.trim().toUpperCase();
          if (clean) expandedSubcats.add(clean);
        }
      }
    }

    if (expandedSubcats.size > 0) {
      for (const { chunk, score } of scoredChunks) {
        if (chunk.collection !== "nist_csf") continue;
        const subId = (chunk.subcategory_id ?? "").trim().toUpperCase();
        const recIdUpper = chunk.record_id.toUpperCase();
        const matches =
          (subId && expandedSubcats.has(subId)) ||
          Array.from(expandedSubcats).some((s) => recIdUpper.includes(s));
        if (matches && !selected.has(chunk.chunk_id)) {
          selected.set(chunk.chunk_id, toRetrieved(chunk, score, "nist-expansion"));
        }
      }
    }

    const merged = Array.from(selected.values()).sort((a, b) => {
      const rank = (m: RetrievedChunk["method"]) =>
        m === "direct" ? 2 : m === "nist-expansion" ? 1 : 0;
      const rDiff = rank(b.method) - rank(a.method);
      if (rDiff !== 0) return rDiff;
      return b.score - a.score;
    });

    const bestScore = merged.reduce((max, c) => Math.max(max, c.score), 0);
    const lowConfidence = merged.length === 0 || bestScore < params.threshold;

    return {
      chunks: merged,
      low_confidence: lowConfidence,
      best_score: Number(bestScore.toFixed(4)),
      query_text: queryText,
    };
  }

  async computeTextSimilarity(textA: string, textB: string): Promise<number> {
    const a = textA.trim().slice(0, 6000);
    const b = textB.trim().slice(0, 6000);
    if (!a || !b) return 0;
    const [vecA, vecB] = await this.embedTexts([a, b], "RETRIEVAL_DOCUMENT");
    return Number(cosineSimilarity(vecA, vecB).toFixed(4));
  }
}

function cosineSimilarity(a: number[], b: number[]): number {
  const len = Math.min(a.length, b.length);
  if (len === 0) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < len; i += 1) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}

export const kbManager = new KnowledgeBaseManager();
