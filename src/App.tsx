import { useCallback, useEffect, useState } from "react";
import { Shield } from "lucide-react";
import CopilotTab from "./components/CopilotTab.tsx";
import EvaluationTab from "./components/EvaluationTab.tsx";
import KnowledgeBaseTab from "./components/KnowledgeBaseTab.tsx";
import SettingsTab from "./components/SettingsTab.tsx";
import type { AppConfigSummary } from "./types.ts";

export default function App() {
  const [activeTab, setActiveTab] = useState<
    "copilot" | "kb" | "eval" | "settings"
  >("copilot");
  const [config, setConfig] = useState<AppConfigSummary | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);

  const loadConfig = useCallback(async () => {
    try {
      const resp = await fetch("/api/config");
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Failed to load config (${resp.status})`);
      }
      setConfig(data as AppConfigSummary);
      setConfigError(null);
    } catch (err) {
      setConfigError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  useEffect(() => {
    if (config?.kb_status === "indexing") {
      const timer = setTimeout(() => {
        void loadConfig();
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [config?.kb_status, loadConfig]);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-md bg-slate-900 text-white flex items-center justify-center">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-slate-900">
                SERC &mdash; Security Event Response Copilot
              </h1>
              <p className="text-[11px] text-slate-500">
                RAG-Driven Wazuh Event Response (Ismail et al., Sensors 2025)
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-[11px]">
            {config && (
              <div className="flex flex-wrap items-center gap-2 font-mono text-slate-700 bg-slate-100 border border-slate-200 rounded-md px-2.5 py-1">
                <span>
                  Ext: <strong>{config.extractor_model}</strong>
                </span>
                <span className="text-slate-300">|</span>
                <span>
                  Gen A: <strong>{config.generation_model_a}</strong>
                </span>
                <span className="text-slate-300">|</span>
                <span>
                  Gen B: <strong>{config.generation_model_b}</strong>
                </span>
                <span className="text-slate-300">|</span>
                <span>
                  Embed: <strong>{config.embedding_model}</strong>
                </span>
                <span className="text-slate-300">|</span>
                <span>
                  Vectors:{" "}
                  <strong>
                    {config.kb_status === "indexing"
                      ? "indexing..."
                      : config.vector_count}
                  </strong>{" "}
                  <span className="text-slate-500">
                    (MITRE {config.record_counts?.mitre_attack ?? 0} / NIST{" "}
                    {config.record_counts?.nist_csf ?? 0} / IR{" "}
                    {config.record_counts?.ir_incidents ?? 0})
                  </span>
                </span>
              </div>
            )}

            <nav aria-label="Primary tabs" className="flex rounded-md border border-slate-300 bg-slate-100 p-0.5">
              <button
                type="button"
                onClick={() => setActiveTab("copilot")}
                className={`px-3 py-1 rounded text-xs font-medium cursor-pointer transition-colors ${
                  activeTab === "copilot"
                    ? "bg-white text-slate-900 shadow-xs"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                Copilot
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("kb")}
                className={`px-3 py-1 rounded text-xs font-medium cursor-pointer transition-colors ${
                  activeTab === "kb"
                    ? "bg-white text-slate-900 shadow-xs"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                Knowledge Base
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("eval")}
                className={`px-3 py-1 rounded text-xs font-medium cursor-pointer transition-colors ${
                  activeTab === "eval"
                    ? "bg-white text-slate-900 shadow-xs"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                Evaluation
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("settings")}
                className={`px-3 py-1 rounded text-xs font-medium cursor-pointer transition-colors ${
                  activeTab === "settings"
                    ? "bg-white text-slate-900 shadow-xs"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                Settings
              </button>
            </nav>
          </div>
        </div>
      </header>

      {/* Global Config / KB Error Banner */}
      {(configError || config?.kb_error) && (
        <div className="max-w-7xl mx-auto w-full px-4 sm:px-6 pt-4">
          <div
            role="alert"
            className="rounded-md border border-red-300 bg-red-50 px-4 py-2.5 text-xs text-red-800"
          >
            <strong>System Error:</strong> {configError || config?.kb_error}
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === "copilot" && <CopilotTab config={config} />}
        {activeTab === "kb" && (
          <KnowledgeBaseTab onKbUpdated={() => void loadConfig()} />
        )}
        {activeTab === "eval" && <EvaluationTab config={config} />}
        {activeTab === "settings" && <SettingsTab />}
      </main>
    </div>
  );
}
