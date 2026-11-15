import React, { useEffect, useState } from "react";
import { Plus, Trash2, XCircle } from "lucide-react";
import type {
  AllowlistEntry,
  AllowlistType,
  FeedbackRecord,
  RuleFeedbackStats,
} from "../types.ts";

export default function SettingsTab() {
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([]);
  const [entryType, setEntryType] = useState<AllowlistType>("ip");
  const [entryValue, setEntryValue] = useState("");
  const [entryNote, setEntryNote] = useState("");

  const [perRuleStats, setPerRuleStats] = useState<RuleFeedbackStats[]>([]);
  const [feedbackRecords, setFeedbackRecords] = useState<FeedbackRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function loadAll() {
    setError(null);
    try {
      const [alRes, fbRes] = await Promise.all([
        fetch("/api/allowlist"),
        fetch("/api/feedback"),
      ]);
      const alData = await alRes.json();
      const fbData = await fbRes.json();
      if (!alRes.ok) throw new Error(alData.error || "Failed to load allowlist.");
      if (!fbRes.ok) throw new Error(fbData.error || "Failed to load feedback.");
      setAllowlist(alData.entries ?? []);
      setPerRuleStats(fbData.per_rule ?? []);
      setFeedbackRecords(fbData.records ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    void loadAll();
  }, []);

  async function handleAddAllowlist(e: React.FormEvent) {
    e.preventDefault();
    if (!entryValue.trim() || saving) return;
    setSaving(true);
    setError(null);
    try {
      const resp = await fetch("/api/allowlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: entryType,
          value: entryValue.trim(),
          note: entryNote.trim() || undefined,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Failed to add allowlist entry.");
      setAllowlist(data.entries ?? []);
      setEntryValue("");
      setEntryNote("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  async function handleRemoveAllowlist(id: string) {
    setError(null);
    try {
      const resp = await fetch(`/api/allowlist/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Failed to remove entry.");
      setAllowlist(data.entries ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

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

      {/* Analyst Allowlist */}
      <section
        aria-label="Analyst Allowlist"
        className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4"
      >
        <div>
          <h2 className="text-sm font-semibold text-slate-900">
            Analyst Allowlist (Deterministic Pre-Check)
          </h2>
          <p className="text-xs text-slate-600 mt-0.5">
            Allowlisted IPs, users, hosts, rule IDs, or scheduled-job descriptions inform triage without hiding alerts.
          </p>
        </div>

        <form onSubmit={handleAddAllowlist} className="flex flex-wrap items-end gap-3">
          <div>
            <label
              htmlFor="al-type"
              className="block text-xs font-medium text-slate-700 mb-1"
            >
              Type
            </label>
            <select
              id="al-type"
              value={entryType}
              onChange={(e) => setEntryType(e.target.value as AllowlistType)}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs text-slate-900"
            >
              <option value="ip">IP Address</option>
              <option value="user">User</option>
              <option value="host">Host / Agent</option>
              <option value="rule_id">Rule ID</option>
              <option value="scheduled_job">Scheduled Job Description</option>
            </select>
          </div>

          <div className="flex-1 min-w-[180px]">
            <label
              htmlFor="al-value"
              className="block text-xs font-medium text-slate-700 mb-1"
            >
              Value
            </label>
            <input
              id="al-value"
              type="text"
              value={entryValue}
              onChange={(e) => setEntryValue(e.target.value)}
              placeholder={
                entryType === "ip"
                  ? "e.g. 10.10.0.5"
                  : entryType === "scheduled_job"
                  ? "e.g. nightly backup rsync"
                  : "Enter exact value..."
              }
              className="w-full rounded-md border border-slate-300 px-3 py-1.5 font-mono text-xs text-slate-900"
            />
          </div>

          <div className="flex-1 min-w-[160px]">
            <label
              htmlFor="al-note"
              className="block text-xs font-medium text-slate-700 mb-1"
            >
              Note (optional)
            </label>
            <input
              id="al-note"
              type="text"
              value={entryNote}
              onChange={(e) => setEntryNote(e.target.value)}
              placeholder="e.g. Corporate bastion"
              className="w-full rounded-md border border-slate-300 px-3 py-1.5 text-xs text-slate-900"
            />
          </div>

          <button
            type="submit"
            disabled={!entryValue.trim() || saving}
            className="inline-flex items-center gap-1 rounded-md bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            Add
          </button>
        </form>

        <div className="overflow-x-auto border border-slate-200 rounded-md">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
              <tr>
                <th className="px-3 py-2 font-semibold">Type</th>
                <th className="px-3 py-2 font-semibold">Value</th>
                <th className="px-3 py-2 font-semibold">Note</th>
                <th className="px-3 py-2 font-semibold">Added</th>
                <th className="px-3 py-2 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {allowlist.map((entry) => (
                <tr key={entry.id}>
                  <td className="px-3 py-2 font-mono text-slate-700">{entry.type}</td>
                  <td className="px-3 py-2 font-mono font-medium text-slate-900">
                    {entry.value}
                  </td>
                  <td className="px-3 py-2 text-slate-600">{entry.note ?? "-"}</td>
                  <td className="px-3 py-2 font-mono text-[11px] text-slate-500">
                    {entry.created_at.slice(0, 19).replace("T", " ")}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => void handleRemoveAllowlist(entry.id)}
                      className="inline-flex items-center gap-1 rounded border border-slate-300 px-2 py-0.5 text-[11px] text-red-700 hover:bg-red-50 cursor-pointer"
                    >
                      <Trash2 className="w-3 h-3" />
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
              {allowlist.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-5 text-center text-slate-500">
                    No allowlist entries configured.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Analyst Feedback Panel */}
      <section
        aria-label="Analyst Feedback History"
        className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4"
      >
        <div>
          <h2 className="text-sm font-semibold text-slate-900">
            Feedback &amp; Per-Rule False-Positive Rate
          </h2>
          <p className="text-xs text-slate-600 mt-0.5">
            Stored on the server. Up to the last 3 decisions for a matching{" "}
            <code className="font-mono">rule_id</code> are passed to the triage model as examples.
          </p>
        </div>

        <div className="overflow-x-auto border border-slate-200 rounded-md">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-600">
              <tr>
                <th className="px-3 py-2 font-semibold">Rule ID</th>
                <th className="px-3 py-2 font-semibold">True Positive</th>
                <th className="px-3 py-2 font-semibold">False Positive</th>
                <th className="px-3 py-2 font-semibold">Missed (FN)</th>
                <th className="px-3 py-2 font-semibold">Total</th>
                <th className="px-3 py-2 font-semibold">FP Rate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {perRuleStats.map((stat) => (
                <tr key={stat.rule_id}>
                  <td className="px-3 py-2 font-mono font-medium text-slate-900">
                    {stat.rule_id}
                  </td>
                  <td className="px-3 py-2 font-mono text-emerald-700">
                    {stat.true_positive}
                  </td>
                  <td className="px-3 py-2 font-mono text-amber-700">
                    {stat.false_positive}
                  </td>
                  <td className="px-3 py-2 font-mono text-red-700">
                    {stat.false_negative}
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-900">{stat.total}</td>
                  <td className="px-3 py-2 font-mono text-slate-900">
                    {(stat.fp_rate * 100).toFixed(1)}%
                  </td>
                </tr>
              ))}
              {perRuleStats.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-5 text-center text-slate-500">
                    No analyst feedback recorded yet. Use the feedback buttons on analyzed alerts in the Copilot tab.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {feedbackRecords.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-slate-700">
              Recent Decisions ({feedbackRecords.length})
            </h3>
            <div className="overflow-x-auto border border-slate-200 rounded-md max-h-56">
              <table className="min-w-full text-left text-xs">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 sticky top-0">
                  <tr>
                    <th className="px-3 py-1.5 font-semibold">Time</th>
                    <th className="px-3 py-1.5 font-semibold">Alert ID</th>
                    <th className="px-3 py-1.5 font-semibold">Rule ID</th>
                    <th className="px-3 py-1.5 font-semibold">Decision</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {feedbackRecords.slice(0, 30).map((rec) => (
                    <tr key={rec.id}>
                      <td className="px-3 py-1.5 font-mono text-[11px] text-slate-500">
                        {rec.created_at.slice(0, 19).replace("T", " ")}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-slate-900">
                        {rec.alert_id}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-slate-700">
                        {rec.rule_id ?? "-"}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-slate-900">
                        {rec.decision}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
