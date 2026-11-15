import React, { useMemo, useRef, useState } from "react";
import Papa from "papaparse";
import { Download, Loader2, Play, Square, Upload, XCircle } from "lucide-react";
import type {
  AppConfigSummary,
  CanonicalAlert,
  EvalModelRun,
  EvalScenario,
  EvalScenarioResult,
} from "../types.ts";
import {
  normalizePlainTextAlert,
  normalizeWazuhObject,
} from "../utils/intake.ts";

interface Props {
  config: AppConfigSummary | null;
}

interface SummaryStats {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  fpr: number;
  fnr: number;
  meanP3: number | null;
  meanR3: number | null;
  meanSim: number | null;
  count: number;
}

function computeSummaryStats(
  scenarios: EvalScenario[],
  results: Record<string, EvalScenarioResult>,
  which: "run_a" | "run_b"
): SummaryStats {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const p3s: number[] = [];
  const r3s: number[] = [];
  const sims: number[] = [];
  let count = 0;

  for (const s of scenarios) {
    const res = results[s.id];
    const run: EvalModelRun | undefined = res?.[which];
    if (!run || run.error) continue;
    count += 1;

    if (s.label === "malicious") {
      if (run.flagged) tp += 1;
      else fn += 1;
    } else {
      if (run.flagged) fp += 1;
      else tn += 1;
    }

    if (run.precision_at_3 !== null) p3s.push(run.precision_at_3);
    if (run.recall_at_3 !== null) r3s.push(run.recall_at_3);
    if (run.response_similarity !== null) sims.push(run.response_similarity);
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const fnr = fn + tp > 0 ? fn / (fn + tp) : 0;
  const avg = (arr: number[]) =>
    arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : null;

  return {
    tp,
    fp,
    tn,
    fn,
    precision,
    recall,
    fpr,
    fnr,
    meanP3: avg(p3s),
    meanR3: avg(r3s),
    meanSim: avg(sims),
    count,
  };
}

function parseUploadedEvalSet(filename: string, rawText: string): EvalScenario[] {
  const lower = filename.toLowerCase();
  let rows: Record<string, unknown>[] = [];

  if (lower.endsWith(".csv")) {
    const parsed = Papa.parse<Record<string, string>>(rawText.trim(), {
      header: true,
      skipEmptyLines: true,
    });
    if (parsed.errors.length > 0 && parsed.data.length === 0) {
      throw new Error(`CSV parse error: ${parsed.errors[0].message}`);
    }
    rows = parsed.data;
  } else {
    const json = JSON.parse(rawText) as unknown;
    if (!Array.isArray(json)) {
      throw new Error("Uploaded JSON evaluation set must be an array.");
    }
    rows = json as Record<string, unknown>[];
  }

  if (rows.length === 0) {
    throw new Error("Evaluation test set is empty.");
  }

  return rows.map((row, idx) => {
    const rawLabel = String(row.label ?? "").trim().toLowerCase();
    if (rawLabel !== "benign" && rawLabel !== "malicious") {
      throw new Error(
        `Row ${idx + 1}: label must be "benign" or "malicious" (got "${rawLabel}").`
      );
    }

    let alert: CanonicalAlert;
    if (row.alert && typeof row.alert === "object") {
      alert = normalizeWazuhObject(
        row.alert as Record<string, unknown>,
        idx
      );
    } else if (typeof row.alert === "string" && row.alert.trim()) {
      const trimmed = row.alert.trim();
      if (trimmed.startsWith("{")) {
        alert = normalizeWazuhObject(
          JSON.parse(trimmed) as Record<string, unknown>,
          idx
        );
      } else {
        alert = normalizePlainTextAlert(trimmed, idx);
      }
    } else {
      alert = normalizeWazuhObject(row, idx);
    }

    const expectedMitreRaw = String(row.expected_mitre ?? "").trim();
    const referenceText = String(row.reference_text ?? "").trim();

    return {
      id: String(row.id ?? `UPLOAD-${idx + 1}`),
      name:
        String(row.name ?? "").trim() ||
        alert.rule_description ||
        `Scenario ${idx + 1}`,
      alert,
      label: rawLabel,
      expected_mitre: expectedMitreRaw || null,
      reference_text: referenceText,
    };
  });
}

export default function EvaluationTab({ config }: Props) {
  const [scenarios, setScenarios] = useState<EvalScenario[]>([]);
  const [results, setResults] = useState<Record<string, EvalScenarioResult>>({});
  const [mode, setMode] = useState<"A" | "B" | "both">("A");
  const [threshold, setThreshold] = useState<number>(
    config?.default_threshold ?? 0.55
  );

  const [running, setRunning] = useState(false);
  const [doneCount, setDoneCount] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const cancelledRef = useRef(false);
  const abortControllersRef = useRef<Set<AbortController>>(new Set());

  async function handleLoadSample12() {
    setError(null);
    try {
      const resp = await fetch("/api/eval/scenarios");
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Failed to load scenarios.");
      setScenarios(data.scenarios ?? []);
      setResults({});
      setDoneCount(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setError(null);
    try {
      const text = await file.text();
      const parsed = parseUploadedEvalSet(file.name, text);
      setScenarios(parsed);
      setResults({});
      setDoneCount(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleRunAll() {
    if (scenarios.length === 0 || running) return;
    setRunning(true);
    setError(null);
    setResults({});
    setDoneCount(0);
    cancelledRef.current = false;

    let cursor = 0;
    const concurrency = 2;

    async function worker() {
      while (!cancelledRef.current) {
        const idx = cursor;
        cursor += 1;
        if (idx >= scenarios.length) return;
        const scenario = scenarios[idx];

        const controller = new AbortController();
        abortControllersRef.current.add(controller);

        try {
          const resp = await fetch("/api/eval/run-one", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario, mode, threshold }),
            signal: controller.signal,
          });
          const data = await resp.json();
          if (!resp.ok) {
            throw new Error(data.error || `Eval failed (${resp.status})`);
          }
          setResults((prev) => ({
            ...prev,
            [scenario.id]: data as EvalScenarioResult,
          }));
        } catch (err) {
          if (!controller.signal.aborted) {
            setError(err instanceof Error ? err.message : String(err));
          }
        } finally {
          abortControllersRef.current.delete(controller);
          setDoneCount((prev) => prev + 1);
        }
      }
    }

    await Promise.all([worker(), worker()].slice(0, Math.min(concurrency, scenarios.length)));
    setRunning(false);
  }

  function handleCancel() {
    cancelledRef.current = true;
    for (const ctrl of abortControllersRef.current) {
      ctrl.abort();
    }
    abortControllersRef.current.clear();
    setRunning(false);
  }

  const statsA = useMemo(
    () => computeSummaryStats(scenarios, results, "run_a"),
    [scenarios, results]
  );
  const statsB = useMemo(
    () => computeSummaryStats(scenarios, results, "run_b"),
    [scenarios, results]
  );

  function handleExportCsv() {
    const csvRows = scenarios.map((s) => {
      const r = results[s.id];
      return {
        scenario_id: s.id,
        name: s.name,
        label: s.label,
        expected_mitre: s.expected_mitre ?? "",
        a_verdict: r?.run_a?.verdict ?? "",
        a_flagged: r?.run_a?.flagged ?? "",
        a_precision_at_3: r?.run_a?.precision_at_3 ?? "",
        a_recall_at_3: r?.run_a?.recall_at_3 ?? "",
        a_response_similarity: r?.run_a?.response_similarity ?? "",
        a_ms: r?.run_a?.ms ?? "",
        b_verdict: r?.run_b?.verdict ?? "",
        b_flagged: r?.run_b?.flagged ?? "",
        b_precision_at_3: r?.run_b?.precision_at_3 ?? "",
        b_recall_at_3: r?.run_b?.recall_at_3 ?? "",
        b_response_similarity: r?.run_b?.response_similarity ?? "",
        b_ms: r?.run_b?.ms ?? "",
      };
    });
    const csv = Papa.unparse(csvRows);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `serc-evaluation-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const pct =
    scenarios.length > 0
      ? Math.min(100, Math.round((doneCount / scenarios.length) * 100))
      : 0;

  return (
    <div className="space-y-6">
      {error && (
        <div
          role="alert"
          className="bg-red-50 border border-red-300 rounded-lg p-3 flex items-center gap-2 text-xs text-red-800"
        >
          <XCircle className="w-4 h-4 text-red-600 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Controls */}
      <section
        aria-label="Evaluation Controls"
        className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              Evaluation Suite (Concurrency 2)
            </h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Treating <code className="font-mono">needs_review</code> and{" "}
              <code className="font-mono">likely_malicious</code> as{" "}
              <strong>flagged</strong>.{" "}
              <span className="italic">
                Response similarity is embedding cosine text similarity — not proof that the advice is correct or safe.
              </span>
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={running}
              onClick={() => void handleLoadSample12()}
              className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
            >
              Load 12 sample scenarios
            </button>

            <label className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-50 cursor-pointer">
              <Upload className="w-3.5 h-3.5" />
              Upload CSV / JSON
              <input
                type="file"
                accept=".csv,.json"
                disabled={running}
                onChange={(e) => void handleFileUpload(e)}
                className="hidden"
              />
            </label>
          </div>
        </div>

        <div className="flex flex-wrap items-end gap-4 bg-slate-50 border border-slate-200 rounded-md p-3">
          <div>
            <label
              htmlFor="eval-mode"
              className="block text-[11px] font-medium text-slate-700 mb-1"
            >
              Model Run Mode
            </label>
            <select
              id="eval-mode"
              disabled={running}
              value={mode}
              onChange={(e) => setMode(e.target.value as "A" | "B" | "both")}
              className="rounded border border-slate-300 bg-white px-2.5 py-1 text-xs text-slate-900"
            >
              <option value="A">
                Model A ({config?.generation_model_a ?? "gemini-4-hydrogen"})
              </option>
              <option value="B">
                Model B ({config?.generation_model_b ?? "gemini-3.1-flash-lite"})
              </option>
              <option value="both">Both (Side by Side)</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="eval-threshold"
              className="block text-[11px] font-medium text-slate-700 mb-1"
            >
              Similarity Threshold
            </label>
            <input
              id="eval-threshold"
              type="number"
              min={0}
              max={1}
              step={0.05}
              disabled={running}
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
              className="w-24 rounded border border-slate-300 bg-white px-2 py-1 font-mono text-xs text-slate-900"
            />
          </div>

          <div className="flex items-center gap-2 ml-auto">
            {running ? (
              <button
                type="button"
                onClick={handleCancel}
                className="inline-flex items-center gap-1.5 rounded-md bg-red-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-800 cursor-pointer"
              >
                <Square className="w-3.5 h-3.5" />
                Cancel
              </button>
            ) : (
              <button
                type="button"
                disabled={scenarios.length === 0}
                onClick={() => void handleRunAll()}
                className="inline-flex items-center gap-1.5 rounded-md bg-blue-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-800 disabled:opacity-50 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                Run All ({scenarios.length})
              </button>
            )}

            <button
              type="button"
              disabled={Object.keys(results).length === 0}
              onClick={handleExportCsv}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              Export CSV
            </button>
          </div>
        </div>

        {(running || doneCount > 0) && scenarios.length > 0 && (
          <div className="space-y-1">
            <div className="flex justify-between text-xs text-slate-600">
              <span className="flex items-center gap-1.5">
                {running && <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-700" />}
                {running ? "Evaluating scenarios (concurrency 2)..." : "Evaluation complete"}
              </span>
              <span className="font-mono">
                {doneCount} / {scenarios.length} ({pct}%)
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
      </section>

      {/* Metrics & Confusion Matrix Cards */}
      {(statsA.count > 0 || statsB.count > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {(mode === "A" || mode === "both") && statsA.count > 0 && (
            <MetricsSummaryCard
              title={`Model A (${config?.generation_model_a ?? "gemini-4-hydrogen"})`}
              stats={statsA}
            />
          )}
          {(mode === "B" || mode === "both") && statsB.count > 0 && (
            <MetricsSummaryCard
              title={`Model B (${config?.generation_model_b ?? "gemini-3.1-flash-lite"})`}
              stats={statsB}
            />
          )}
        </div>
      )}

      {/* Per-Scenario Table */}
      <section
        aria-label="Evaluation Scenarios Table"
        className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs"
      >
        <div className="overflow-x-auto border border-slate-200 rounded-md">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
              <tr>
                <th className="px-3 py-2 font-semibold">ID</th>
                <th className="px-3 py-2 font-semibold">Scenario</th>
                <th className="px-3 py-2 font-semibold">Label</th>
                <th className="px-3 py-2 font-semibold">Exp. MITRE</th>
                {(mode === "A" || mode === "both") && (
                  <>
                    <th className="px-3 py-2 font-semibold">A Verdict</th>
                    <th className="px-3 py-2 font-semibold">A P@3 / R@3</th>
                    <th className="px-3 py-2 font-semibold">A Resp. Sim*</th>
                  </>
                )}
                {(mode === "B" || mode === "both") && (
                  <>
                    <th className="px-3 py-2 font-semibold">B Verdict</th>
                    <th className="px-3 py-2 font-semibold">B P@3 / R@3</th>
                    <th className="px-3 py-2 font-semibold">B Resp. Sim*</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {scenarios.map((s) => {
                const res = results[s.id];
                return (
                  <tr key={s.id} className="hover:bg-slate-50">
                    <td className="px-3 py-2 font-mono font-medium text-slate-900">
                      {s.id}
                    </td>
                    <td className="px-3 py-2 text-slate-900">{s.name}</td>
                    <td className="px-3 py-2 font-mono">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[11px] ${
                          s.label === "malicious"
                            ? "bg-red-50 text-red-800 border border-red-200"
                            : "bg-emerald-50 text-emerald-800 border border-emerald-200"
                        }`}
                      >
                        {s.label}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-700">
                      {s.expected_mitre ?? "-"}
                    </td>

                    {(mode === "A" || mode === "both") && (
                      <RunCells run={res?.run_a} label={s.label} />
                    )}
                    {(mode === "B" || mode === "both") && (
                      <RunCells run={res?.run_b} label={s.label} />
                    )}
                  </tr>
                );
              })}

              {scenarios.length > 0 && (statsA.count > 0 || statsB.count > 0) && (
                <tr className="bg-slate-100 font-semibold border-t-2 border-slate-300">
                  <td colSpan={4} className="px-3 py-2 text-slate-900">
                    SUMMARY ({Math.max(statsA.count, statsB.count)}/{scenarios.length} completed)
                  </td>
                  {(mode === "A" || mode === "both") && (
                    <>
                      <td className="px-3 py-2 font-mono text-slate-900">
                        P={(statsA.precision * 100).toFixed(0)}% R=
                        {(statsA.recall * 100).toFixed(0)}%
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-900">
                        {statsA.meanP3 !== null ? statsA.meanP3.toFixed(2) : "-"} /{" "}
                        {statsA.meanR3 !== null ? statsA.meanR3.toFixed(2) : "-"}
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-900">
                        {statsA.meanSim !== null ? statsA.meanSim.toFixed(3) : "-"}
                      </td>
                    </>
                  )}
                  {(mode === "B" || mode === "both") && (
                    <>
                      <td className="px-3 py-2 font-mono text-slate-900">
                        P={(statsB.precision * 100).toFixed(0)}% R=
                        {(statsB.recall * 100).toFixed(0)}%
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-900">
                        {statsB.meanP3 !== null ? statsB.meanP3.toFixed(2) : "-"} /{" "}
                        {statsB.meanR3 !== null ? statsB.meanR3.toFixed(2) : "-"}
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-900">
                        {statsB.meanSim !== null ? statsB.meanSim.toFixed(3) : "-"}
                      </td>
                    </>
                  )}
                </tr>
              )}

              {scenarios.length === 0 && (
                <tr>
                  <td colSpan={10} className="px-3 py-6 text-center text-slate-500">
                    Click &ldquo;Load 12 sample scenarios&rdquo; or upload a CSV/JSON test set to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">
          *Response similarity = embedding cosine similarity between generated guidance and reference text (text similarity only — not proof the advice is correct or safe).
        </p>
      </section>
    </div>
  );
}

function RunCells({
  run,
  label,
}: {
  run?: EvalModelRun;
  label: "benign" | "malicious";
}) {
  if (!run) {
    return (
      <>
        <td className="px-3 py-2 text-slate-400">-</td>
        <td className="px-3 py-2 text-slate-400">-</td>
        <td className="px-3 py-2 text-slate-400">-</td>
      </>
    );
  }
  if (run.error) {
    return (
      <td colSpan={3} className="px-3 py-2 text-red-700 font-mono text-[11px]">
        Error: {run.error}
      </td>
    );
  }
  const correct =
    (label === "malicious" && run.flagged) ||
    (label === "benign" && !run.flagged);
  return (
    <>
      <td className="px-3 py-2 font-mono">
        <span
          className={`rounded px-1.5 py-0.5 text-[11px] border ${
            correct
              ? "bg-emerald-50 text-emerald-800 border-emerald-200"
              : "bg-amber-50 text-amber-900 border-amber-300"
          }`}
        >
          {run.verdict}
        </span>
      </td>
      <td className="px-3 py-2 font-mono text-slate-800">
        {run.precision_at_3 !== null ? run.precision_at_3.toFixed(2) : "-"} /{" "}
        {run.recall_at_3 !== null ? run.recall_at_3.toFixed(2) : "-"}
      </td>
      <td className="px-3 py-2 font-mono text-slate-800">
        {run.response_similarity !== null
          ? run.response_similarity.toFixed(3)
          : "-"}
      </td>
    </>
  );
}

function MetricsSummaryCard({
  title,
  stats,
}: {
  title: string;
  stats: SummaryStats;
}) {
  return (
    <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-xs space-y-3">
      <h3 className="text-xs font-semibold text-slate-900">{title}</h3>
      <div className="grid grid-cols-4 gap-2 text-center font-mono text-xs">
        <div className="rounded bg-emerald-50 border border-emerald-200 p-2">
          <div className="text-[10px] text-emerald-700">TP</div>
          <div className="font-semibold text-emerald-950">{stats.tp}</div>
        </div>
        <div className="rounded bg-amber-50 border border-amber-200 p-2">
          <div className="text-[10px] text-amber-700">FP</div>
          <div className="font-semibold text-amber-950">{stats.fp}</div>
        </div>
        <div className="rounded bg-slate-50 border border-slate-200 p-2">
          <div className="text-[10px] text-slate-600">TN</div>
          <div className="font-semibold text-slate-900">{stats.tn}</div>
        </div>
        <div className="rounded bg-red-50 border border-red-200 p-2">
          <div className="text-[10px] text-red-700">FN</div>
          <div className="font-semibold text-red-950">{stats.fn}</div>
        </div>
      </div>
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 text-xs font-mono">
        <div>
          <span className="text-slate-500">Prec:</span>{" "}
          <strong>{(stats.precision * 100).toFixed(1)}%</strong>
        </div>
        <div>
          <span className="text-slate-500">Rec:</span>{" "}
          <strong>{(stats.recall * 100).toFixed(1)}%</strong>
        </div>
        <div>
          <span className="text-slate-500">FPR:</span>{" "}
          <strong>{(stats.fpr * 100).toFixed(1)}%</strong>
        </div>
        <div>
          <span className="text-slate-500">FNR:</span>{" "}
          <strong>{(stats.fnr * 100).toFixed(1)}%</strong>
        </div>
        <div>
          <span className="text-slate-500">P@3/R@3:</span>{" "}
          <strong>
            {stats.meanP3 !== null ? stats.meanP3.toFixed(2) : "-"} /{" "}
            {stats.meanR3 !== null ? stats.meanR3.toFixed(2) : "-"}
          </strong>
        </div>
        <div>
          <span className="text-slate-500">Sim*:</span>{" "}
          <strong>
            {stats.meanSim !== null ? stats.meanSim.toFixed(3) : "-"}
          </strong>
        </div>
      </div>
    </div>
  );
}
