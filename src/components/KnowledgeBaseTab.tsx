import React, { useEffect, useRef, useState } from "react";
import {
  Database,
  Download,
  Loader2,
  Sparkles,
  Trash2,
  Upload,
  XCircle,
} from "lucide-react";
import type {
  IrColumnTarget,
  KBCollection,
  KBParsePreview,
  KBRecord,
} from "../types.ts";

interface KBStatusPayload {
  vector_count: number;
  collection_counts: Record<KBCollection, number>;
  record_counts: Record<KBCollection, number>;
  last_import_at: Record<KBCollection, string | null>;
  kb_status: "ready" | "indexing" | "error";
  kb_error: string | null;
  records: KBRecord[];
}

interface CardProgress {
  done: number;
  total: number;
  stage: string;
}

interface CollectionCardState {
  parsing: boolean;
  preview: KBParsePreview | null;
  mappingDraft: Record<string, IrColumnTarget>;
  importLimitDraft: number;
  repreviewing: boolean;
  confirmingEmbed: boolean;
  confirmingClear: boolean;
  resume: boolean;
  importing: boolean;
  progress: CardProgress | null;
  notice: string | null;
  error: string | null;
  dragOver: boolean;
}

const COLLECTION_META: Array<{
  key: KBCollection;
  label: string;
  acceptedText: string;
  acceptAttr: string;
}> = [
  {
    key: "mitre_attack",
    label: "MITRE ATT&CK (mitre_attack)",
    acceptedText: "STIX 2.x bundle .json, .csv, .xlsx, or .zip (<= 120 MB)",
    acceptAttr: ".json,.csv,.xlsx,.zip",
  },
  {
    key: "nist_csf",
    label: "NIST CSF 2.0 (nist_csf)",
    acceptedText: "NIST CSF 2.0 .xlsx, .csv, .json, or .zip (<= 120 MB)",
    acceptAttr: ".xlsx,.csv,.json,.zip",
  },
  {
    key: "ir_incidents",
    label: "IR Incidents (ir_incidents)",
    acceptedText: "Incident dataset .csv, .json, or .zip (<= 120 MB)",
    acceptAttr: ".csv,.json,.zip",
  },
];

const IR_COLUMN_TARGETS: IrColumnTarget[] = [
  "ignore",
  "incident_id",
  "attack_type",
  "description",
  "mitre_technique_id",
  "mitre_technique_name",
  "nist_function",
  "nist_category",
  "nist_subcategory",
  "detection_indicators",
  "investigation_steps",
  "recommended_response",
  "source_reference",
];

function createEmptyCardState(): CollectionCardState {
  return {
    parsing: false,
    preview: null,
    mappingDraft: {},
    importLimitDraft: 2000,
    repreviewing: false,
    confirmingEmbed: false,
    confirmingClear: false,
    resume: true,
    importing: false,
    progress: null,
    notice: null,
    error: null,
    dragOver: false,
  };
}

function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

interface Props {
  onKbUpdated: () => void;
}

export default function KnowledgeBaseTab({ onKbUpdated }: Props) {
  const [kb, setKb] = useState<KBStatusPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [globalError, setGlobalError] = useState<string | null>(null);
  const [globalNotice, setGlobalNotice] = useState<string | null>(null);
  const [globalBusy, setGlobalBusy] = useState(false);

  const [cards, setCards] = useState<Record<KBCollection, CollectionCardState>>({
    mitre_attack: createEmptyCardState(),
    nist_csf: createEmptyCardState(),
    ir_incidents: createEmptyCardState(),
  });

  const abortControllersRef = useRef<
    Partial<Record<KBCollection, AbortController>>
  >({});
  const importIndexInputRef = useRef<HTMLInputElement | null>(null);

  const [collectionFilter, setCollectionFilter] = useState<KBCollection | "all">(
    "all"
  );

  function updateCard(
    col: KBCollection,
    updater:
      | Partial<CollectionCardState>
      | ((prev: CollectionCardState) => CollectionCardState)
  ) {
    setCards((prev) => ({
      ...prev,
      [col]:
        typeof updater === "function"
          ? updater(prev[col])
          : { ...prev[col], ...updater },
    }));
  }

  async function fetchKb() {
    setLoading(true);
    setGlobalError(null);
    try {
      const resp = await fetch("/api/kb");
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Failed to load KB (${resp.status}).`);
      }
      setKb(data as KBStatusPayload);
    } catch (err) {
      setGlobalError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void fetchKb();
  }, []);

  async function handleLoadStarter() {
    setGlobalError(null);
    setGlobalNotice(null);
    setGlobalBusy(true);
    try {
      const resp = await fetch("/api/kb/demo-starter", { method: "POST" });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Failed to load demo starter set (${resp.status}).`);
      }
      setKb(data as KBStatusPayload);
      setGlobalNotice(
        `Demo starter set loaded (${data.record_counts?.mitre_attack ?? 0} MITRE, ${
          data.record_counts?.nist_csf ?? 0
        } NIST CSF, ${data.record_counts?.ir_incidents ?? 0} IR incidents).`
      );
      onKbUpdated();
    } catch (err) {
      setGlobalError(err instanceof Error ? err.message : String(err));
    } finally {
      setGlobalBusy(false);
    }
  }

  async function handleImportIndexFile(file: File | null) {
    if (!file) return;
    setGlobalError(null);
    setGlobalNotice(null);
    setGlobalBusy(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const resp = await fetch("/api/kb/import-index", {
        method: "POST",
        body: fd,
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Index import failed (${resp.status}).`);
      }
      setKb(data as KBStatusPayload);
      setGlobalNotice(
        `Imported index JSON: ${data.summary?.records ?? 0} records, ${
          data.summary?.chunks ?? 0
        } vectors.`
      );
      onKbUpdated();
    } catch (err) {
      setGlobalError(err instanceof Error ? err.message : String(err));
    } finally {
      setGlobalBusy(false);
      if (importIndexInputRef.current) {
        importIndexInputRef.current.value = "";
      }
    }
  }

  async function handleParseFile(col: KBCollection, file: File | null) {
    if (!file) return;
    updateCard(col, {
      parsing: true,
      error: null,
      notice: null,
      confirmingEmbed: false,
      confirmingClear: false,
    });
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("collection", col);
      if (col === "ir_incidents") {
        fd.append("import_limit", String(cards[col].importLimitDraft || 2000));
      }

      const resp = await fetch("/api/kb/parse", {
        method: "POST",
        body: fd,
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Failed to parse file (${resp.status}).`);
      }
      const preview = data as KBParsePreview;
      updateCard(col, {
        parsing: false,
        preview,
        mappingDraft: preview.mapping ?? {},
        importLimitDraft: preview.import_limit ?? 2000,
        notice: `Parsed ${preview.parsed_count} records from ${preview.filename}.`,
      });
    } catch (err) {
      updateCard(col, {
        parsing: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async function handleRepreviewIr() {
    const card = cards.ir_incidents;
    if (!card.preview) return;
    updateCard("ir_incidents", {
      repreviewing: true,
      error: null,
      notice: null,
      confirmingEmbed: false,
    });
    try {
      const resp = await fetch("/api/kb/repreview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          upload_id: card.preview.upload_id,
          mapping: card.mappingDraft,
          import_limit: card.importLimitDraft || 2000,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Re-preview failed (${resp.status}).`);
      }
      const preview = data as KBParsePreview;
      updateCard("ir_incidents", {
        repreviewing: false,
        preview,
        mappingDraft: preview.mapping ?? card.mappingDraft,
        importLimitDraft: preview.import_limit ?? card.importLimitDraft,
        notice: `Updated preview: ${preview.parsed_count} sampled records ready.`,
      });
    } catch (err) {
      updateCard("ir_incidents", {
        repreviewing: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  async function handleImportConfirm(col: KBCollection) {
    const card = cards[col];
    if (!card.preview || card.importing) return;

    const controller = new AbortController();
    abortControllersRef.current[col] = controller;

    updateCard(col, {
      confirmingEmbed: false,
      importing: true,
      error: null,
      notice: null,
      progress: { done: 0, total: 1, stage: "Starting embedding..." },
    });

    try {
      const resp = await fetch("/api/kb/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          upload_id: card.preview.upload_id,
          resume: card.resume,
        }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(text || `Import failed (${resp.status}).`);
      }
      if (!resp.body) {
        throw new Error("Streaming response unavailable.");
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          const evt = JSON.parse(trimmed) as {
            type: "progress" | "done" | "error";
            done?: number;
            total?: number;
            stage?: string;
            error?: string;
            summary?: {
              records_indexed: number;
              chunks_indexed: number;
              skipped_cached: number;
              cancelled: boolean;
            };
            status?: Omit<KBStatusPayload, "records">;
            records?: KBRecord[];
          };

          if (evt.type === "progress") {
            updateCard(col, {
              progress: {
                done: evt.done ?? 0,
                total: Math.max(evt.total ?? 1, 1),
                stage: evt.stage ?? "Embedding...",
              },
            });
          } else if (evt.type === "error") {
            throw new Error(evt.error || "Knowledge Base import failed.");
          } else if (evt.type === "done" && evt.status && evt.records) {
            setKb({
              ...evt.status,
              records: evt.records,
            });
            const s = evt.summary;
            updateCard(col, {
              importing: false,
              progress: null,
              preview: s?.cancelled ? card.preview : null,
              notice: s?.cancelled
                ? `Import cancelled (${s.records_indexed} records saved; resume enabled).`
                : `Imported ${s?.records_indexed ?? 0} records (${
                    s?.chunks_indexed ?? 0
                  } chunks, ${s?.skipped_cached ?? 0} cached skipped).`,
            });
            onKbUpdated();
          }
        }
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        updateCard(col, {
          importing: false,
          progress: null,
          notice: "Import cancelled. Completed batches are saved and can be resumed.",
        });
        await fetchKb();
        onKbUpdated();
      } else {
        updateCard(col, {
          importing: false,
          progress: null,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    } finally {
      delete abortControllersRef.current[col];
    }
  }

  function handleCancelImport(col: KBCollection) {
    abortControllersRef.current[col]?.abort();
  }

  async function handleClearCollection(col: KBCollection) {
    updateCard(col, { confirmingClear: false, error: null, notice: null });
    try {
      const resp = await fetch(`/api/kb/collection/${col}`, {
        method: "DELETE",
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Failed to clear ${col}.`);
      }
      setKb(data as KBStatusPayload);
      updateCard(col, { notice: `Cleared collection "${col}".` });
      onKbUpdated();
    } catch (err) {
      updateCard(col, {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const filteredRecords =
    kb?.records.filter((r) =>
      collectionFilter === "all" ? true : r.collection === collectionFilter
    ) ?? [];
  const visibleRecords = filteredRecords.slice(0, 200);

  return (
    <div className="space-y-6">
      {(globalError || kb?.kb_error) && (
        <div
          role="alert"
          className="bg-red-50 border border-red-300 rounded-lg p-4 flex items-start gap-2 text-xs text-red-800"
        >
          <XCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">Knowledge Base Error</div>
            <p className="mt-0.5">{globalError || kb?.kb_error}</p>
          </div>
        </div>
      )}

      {globalNotice && (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-2.5 text-xs text-emerald-900">
          {globalNotice}
        </div>
      )}

      {/* Top Actions & Collection Summary */}
      <section className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Database className="w-4 h-4 text-slate-600" />
              Knowledge Base Index ({kb?.vector_count ?? (loading ? "..." : 0)} vectors)
            </h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Three fixed collections: mitre_attack, nist_csf, ir_incidents. Max 120 MB per file.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={globalBusy}
              onClick={() => void handleLoadStarter()}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
            >
              {globalBusy ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Sparkles className="w-3.5 h-3.5" />
              )}
              Load demo starter set
            </button>

            <a
              href="/api/kb/export"
              download
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              <Download className="w-3.5 h-3.5" />
              Export index
            </a>

            <label className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer">
              <Upload className="w-3.5 h-3.5" />
              Import index
              <input
                ref={importIndexInputRef}
                type="file"
                accept=".json"
                className="hidden"
                disabled={globalBusy}
                onChange={(e) =>
                  void handleImportIndexFile(e.target.files?.[0] ?? null)
                }
              />
            </label>
          </div>
        </div>

        {/* Counts per collection */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {COLLECTION_META.map((meta) => (
            <div
              key={meta.key}
              className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 flex items-center justify-between"
            >
              <div>
                <div className="text-xs font-semibold text-slate-800">
                  {meta.key}
                </div>
                <div className="text-[11px] text-slate-500">
                  Last import: {formatTimestamp(kb?.last_import_at?.[meta.key])}
                </div>
              </div>
              <div className="text-right font-mono">
                <div className="text-sm font-bold text-slate-900">
                  {kb?.record_counts?.[meta.key] ?? 0} rec
                </div>
                <div className="text-[11px] text-slate-500">
                  {kb?.collection_counts?.[meta.key] ?? 0} vec
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Three Collection Importer Cards */}
      <div className="grid grid-cols-1 gap-5">
        {COLLECTION_META.map((meta) => {
          const card = cards[meta.key];
          const pct =
            card.progress && card.progress.total > 0
              ? Math.round((card.progress.done / card.progress.total) * 100)
              : 0;

          return (
            <section
              key={meta.key}
              aria-label={meta.label}
              className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">
                    {meta.label}
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Records:{" "}
                    <strong className="font-mono text-slate-800">
                      {kb?.record_counts?.[meta.key] ?? 0}
                    </strong>{" "}
                    &middot; Vectors:{" "}
                    <strong className="font-mono text-slate-800">
                      {kb?.collection_counts?.[meta.key] ?? 0}
                    </strong>{" "}
                    &middot; Last import:{" "}
                    <span className="font-mono text-slate-700">
                      {formatTimestamp(kb?.last_import_at?.[meta.key])}
                    </span>
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  {card.confirmingClear ? (
                    <div className="inline-flex items-center gap-1.5 rounded border border-red-300 bg-red-50 px-2.5 py-1 text-xs">
                      <span className="text-red-800 font-medium">Clear all?</span>
                      <button
                        type="button"
                        onClick={() => void handleClearCollection(meta.key)}
                        className="font-semibold text-red-700 hover:underline cursor-pointer"
                      >
                        Yes
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          updateCard(meta.key, { confirmingClear: false })
                        }
                        className="text-slate-600 hover:underline cursor-pointer"
                      >
                        No
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      disabled={
                        card.importing ||
                        (kb?.record_counts?.[meta.key] ?? 0) === 0
                      }
                      onClick={() =>
                        updateCard(meta.key, { confirmingClear: true })
                      }
                      className="inline-flex items-center gap-1 rounded border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-red-50 hover:text-red-700 hover:border-red-300 disabled:opacity-40 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Clear collection
                    </button>
                  )}
                </div>
              </div>

              {/* Drop zone */}
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  updateCard(meta.key, { dragOver: true });
                }}
                onDragLeave={() => updateCard(meta.key, { dragOver: false })}
                onDrop={(e) => {
                  e.preventDefault();
                  updateCard(meta.key, { dragOver: false });
                  const dropped = e.dataTransfer.files?.[0] ?? null;
                  void handleParseFile(meta.key, dropped);
                }}
                className={`border-2 border-dashed rounded-md p-4 text-center transition-colors ${
                  card.dragOver
                    ? "border-blue-500 bg-blue-50"
                    : "border-slate-300 bg-slate-50/70"
                }`}
              >
                <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
                  <div className="text-left">
                    <div className="text-xs font-medium text-slate-800">
                      Drop file here or choose from disk
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      {meta.acceptedText}
                    </div>
                  </div>
                  <label className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-100 cursor-pointer shrink-0">
                    {card.parsing ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Upload className="w-3.5 h-3.5" />
                    )}
                    {card.parsing ? "Parsing..." : "Select file"}
                    <input
                      type="file"
                      accept={meta.acceptAttr}
                      disabled={card.parsing || card.importing}
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0] ?? null;
                        e.target.value = "";
                        void handleParseFile(meta.key, f);
                      }}
                    />
                  </label>
                </div>
              </div>

              {card.error && (
                <div className="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-800">
                  {card.error}
                </div>
              )}

              {card.notice && (
                <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-900">
                  {card.notice}
                </div>
              )}

              {/* Parsed Preview + Optional IR Mapping */}
              {card.preview && (
                <div className="space-y-3 rounded-md border border-slate-200 bg-slate-50/60 p-3.5">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                    <div className="font-medium text-slate-900">
                      File:{" "}
                      <span className="font-mono">{card.preview.filename}</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-3 font-mono text-slate-700">
                      <span>total_rows: {card.preview.total_rows}</span>
                      <span>
                        parsed_count: <strong>{card.preview.parsed_count}</strong>
                      </span>
                      {card.preview.skipped_empty > 0 && (
                        <span>skipped_empty: {card.preview.skipped_empty}</span>
                      )}
                      {card.preview.skipped_duplicates > 0 && (
                        <span>
                          skipped_duplicates: {card.preview.skipped_duplicates}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* IR Column Mapping + Import Limit */}
                  {meta.key === "ir_incidents" &&
                    card.preview.headers &&
                    card.preview.headers.length > 0 && (
                      <div className="rounded border border-slate-200 bg-white p-3 space-y-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="text-xs font-semibold text-slate-800">
                            IR Incident Column Mapping &amp; Sampling
                          </div>
                          <div className="flex items-center gap-2 text-xs">
                            <label
                              htmlFor="ir-import-limit"
                              className="text-slate-600"
                            >
                              Import limit (stratified):
                            </label>
                            <input
                              id="ir-import-limit"
                              type="number"
                              min={1}
                              max={50000}
                              value={card.importLimitDraft}
                              onChange={(e) =>
                                updateCard("ir_incidents", {
                                  importLimitDraft:
                                    Number(e.target.value) || 2000,
                                })
                              }
                              className="w-24 rounded border border-slate-300 px-2 py-1 text-xs font-mono"
                            />
                            <button
                              type="button"
                              disabled={card.repreviewing || card.importing}
                              onClick={() => void handleRepreviewIr()}
                              className="rounded border border-slate-300 bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-800 hover:bg-slate-200 disabled:opacity-50 cursor-pointer"
                            >
                              {card.repreviewing
                                ? "Updating..."
                                : "Apply Mapping & Re-preview"}
                            </button>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-56 overflow-y-auto pr-1">
                          {card.preview.headers.map((header) => (
                            <div
                              key={header}
                              className="flex items-center justify-between gap-2 rounded border border-slate-200 bg-slate-50 px-2 py-1 text-[11px]"
                            >
                              <span
                                className="font-mono text-slate-700 truncate"
                                title={header}
                              >
                                {header}
                              </span>
                              <select
                                value={card.mappingDraft[header] ?? "ignore"}
                                onChange={(e) => {
                                  const nextVal = e.target.value as IrColumnTarget;
                                  updateCard("ir_incidents", (prev) => ({
                                    ...prev,
                                    mappingDraft: {
                                      ...prev.mappingDraft,
                                      [header]: nextVal,
                                    },
                                  }));
                                }}
                                className="rounded border border-slate-300 bg-white px-1.5 py-0.5 text-[11px] text-slate-900"
                              >
                                {IR_COLUMN_TARGETS.map((tgt) => (
                                  <option key={tgt} value={tgt}>
                                    {tgt}
                                  </option>
                                ))}
                              </select>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  {/* First 5 parsed records preview */}
                  <div>
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1.5">
                      Preview (first {card.preview.preview.length} of{" "}
                      {card.preview.parsed_count} parsed records)
                    </div>
                    <div className="overflow-x-auto border border-slate-200 rounded bg-white">
                      <table className="min-w-full text-left text-xs">
                        <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
                          <tr>
                            <th className="px-2.5 py-1.5 font-semibold">ID</th>
                            <th className="px-2.5 py-1.5 font-semibold">Title</th>
                            <th className="px-2.5 py-1.5 font-semibold">Key Meta</th>
                            <th className="px-2.5 py-1.5 font-semibold">Text Preview</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {card.preview.preview.map((rec) => (
                            <tr key={rec.id}>
                              <td className="px-2.5 py-1.5 font-mono font-medium text-slate-900 whitespace-nowrap">
                                {rec.id}
                              </td>
                              <td className="px-2.5 py-1.5 text-slate-800 max-w-[200px] truncate">
                                {rec.title}
                              </td>
                              <td className="px-2.5 py-1.5 font-mono text-[11px] text-slate-600 whitespace-nowrap">
                                {rec.technique_id ||
                                  rec.subcategory_id ||
                                  rec.nist_subcategory ||
                                  rec.attack_type ||
                                  "-"}
                              </td>
                              <td className="px-2.5 py-1.5 text-slate-600 max-w-md truncate">
                                {rec.text}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Import Controls + Pre-embed confirmation + Progress */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                    <label className="inline-flex items-center gap-1.5 text-xs text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={card.resume}
                        disabled={card.importing}
                        onChange={(e) =>
                          updateCard(meta.key, { resume: e.target.checked })
                        }
                        className="rounded border-slate-300"
                      />
                      Resume (skip already-embedded id + text_hash)
                    </label>

                    <div className="flex flex-wrap items-center gap-2">
                      {!card.importing && !card.confirmingEmbed && (
                        <button
                          type="button"
                          disabled={card.preview.parsed_count === 0}
                          onClick={() =>
                            updateCard(meta.key, { confirmingEmbed: true })
                          }
                          className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3.5 py-1.5 text-xs font-medium text-white hover:bg-slate-800 disabled:opacity-40 cursor-pointer"
                        >
                          <Upload className="w-3.5 h-3.5" />
                          Import ({card.preview.parsed_count})
                        </button>
                      )}

                      {!card.importing && card.confirmingEmbed && (
                        <div className="inline-flex flex-wrap items-center gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs text-amber-950">
                          <span className="font-medium">
                            This will embed about {card.preview.parsed_count}{" "}
                            records; continue?
                          </span>
                          <button
                            type="button"
                            onClick={() => void handleImportConfirm(meta.key)}
                            className="rounded bg-slate-900 px-2.5 py-1 text-xs font-medium text-white hover:bg-slate-800 cursor-pointer"
                          >
                            Continue
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              updateCard(meta.key, { confirmingEmbed: false })
                            }
                            className="rounded border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
                          >
                            Back
                          </button>
                        </div>
                      )}

                      {card.importing && (
                        <button
                          type="button"
                          onClick={() => handleCancelImport(meta.key)}
                          className="inline-flex items-center gap-1 rounded-md border border-red-300 bg-red-50 px-3 py-1.5 text-xs font-medium text-red-800 hover:bg-red-100 cursor-pointer"
                        >
                          Cancel
                        </button>
                      )}
                    </div>
                  </div>

                  {card.importing && card.progress && (
                    <div className="space-y-1">
                      <div className="flex justify-between text-xs text-slate-600">
                        <span>{card.progress.stage}</span>
                        <span className="font-mono">
                          {card.progress.done} / {card.progress.total} ({pct}%)
                        </span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-slate-200 overflow-hidden">
                        <div
                          className="h-full bg-blue-700 transition-all duration-200"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}
            </section>
          );
        })}
      </div>

      {/* Indexed Records Table */}
      <section
        aria-label="Indexed Records"
        className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-3"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-slate-900">
            Indexed Records ({filteredRecords.length}
            {filteredRecords.length > visibleRecords.length
              ? `, showing first ${visibleRecords.length}`
              : ""}
            )
          </h3>
          <div className="flex items-center gap-2">
            <label htmlFor="kb-filter" className="text-xs text-slate-600">
              Collection:
            </label>
            <select
              id="kb-filter"
              value={collectionFilter}
              onChange={(e) =>
                setCollectionFilter(e.target.value as KBCollection | "all")
              }
              className="rounded border border-slate-300 bg-white px-2.5 py-1 text-xs text-slate-800"
            >
              <option value="all">All Collections</option>
              <option value="mitre_attack">mitre_attack</option>
              <option value="nist_csf">nist_csf</option>
              <option value="ir_incidents">ir_incidents</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto border border-slate-200 rounded-md max-h-[420px]">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 sticky top-0">
              <tr>
                <th className="px-3 py-2 font-semibold">ID</th>
                <th className="px-3 py-2 font-semibold">Collection</th>
                <th className="px-3 py-2 font-semibold">MITRE / NIST</th>
                <th className="px-3 py-2 font-semibold">Title</th>
                <th className="px-3 py-2 font-semibold">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visibleRecords.map((rec) => (
                <tr key={rec.id} className="hover:bg-slate-50">
                  <td className="px-3 py-2 font-mono font-medium text-slate-900 whitespace-nowrap">
                    {rec.id}
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-700 whitespace-nowrap">
                    {rec.collection}
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-700 whitespace-nowrap">
                    {rec.technique_id ||
                      rec.subcategory_id ||
                      rec.nist_subcategory ||
                      "-"}
                  </td>
                  <td className="px-3 py-2 text-slate-900">{rec.title}</td>
                  <td className="px-3 py-2 text-slate-600 whitespace-nowrap">
                    {rec.source}
                  </td>
                </tr>
              ))}
              {visibleRecords.length === 0 && !loading && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                    No records indexed in this collection yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
