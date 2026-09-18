import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { casesApi, extractErrorMessage } from "../api/client";
import { useCases } from "../context/CasesContext";
import { useToast } from "../context/ToastContext";
import StatusPill from "../components/StatusPill";
import UploadPanel from "../components/UploadPanel";
import Tabs from "../components/Tabs";
import ProcessTable from "../components/ProcessTable";
import ProcessTree from "../components/ProcessTree";
import NetworkTable from "../components/NetworkTable";
import IOCTable from "../components/IOCTable";
import ModuleTable from "../components/ModuleTable";
import AuditLogTimeline from "../components/AuditLogTimeline";
import ConfirmDialog from "../components/ConfirmDialog";

export default function CaseDetailPage() {
  const { caseId } = useParams();
  const navigate = useNavigate();
  const { refresh: refreshDocket } = useCases();
  const { showToast } = useToast();

  const [caseData, setCaseData] = useState(null);
  const [results, setResults] = useState(null);
  const [auditLog, setAuditLog] = useState([]);
  const [chainVerification, setChainVerification] = useState(null);
  const [tab, setTab] = useState("overview");
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadError, setUploadError] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeError, setAnalyzeError] = useState(null);
  const [analysisWarnings, setAnalysisWarnings] = useState([]);

  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [savingName, setSavingName] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const c = await casesApi.get(caseId);
      setCaseData(c);
      const log = await casesApi.auditLog(caseId).catch(() => []);
      setAuditLog(log);
      const verification = await casesApi.auditChainVerify(caseId).catch(() => null);
      setChainVerification(verification);
      if (c.status === "completed") {
        const r = await casesApi.results(caseId);
        setResults(r);
      } else {
        setResults(null);
      }
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    setTab("overview");
    setEditingName(false);
    load();
  }, [caseId, load]);

  async function handleUpload(file) {
    setUploading(true);
    setUploadError(null);
    setUploadProgress(0);
    try {
      await casesApi.upload(caseId, file, setUploadProgress);
      await load();
      await refreshDocket();
      showToast("Memory image uploaded and validated.", { type: "success" });
    } catch (err) {
      const msg = extractErrorMessage(err);
      setUploadError(msg);
      showToast(msg, { type: "error" });
    } finally {
      setUploading(false);
    }
  }

  async function handleAnalyze() {
    setAnalyzing(true);
    setAnalyzeError(null);
    setAnalysisWarnings([]);
    try {
      const result = await casesApi.analyze(caseId);
      setAnalysisWarnings(result.warnings || []);
      await load();
      await refreshDocket();
      setTab("processes");
      showToast(
        result.warnings?.length ? `Analysis completed with ${result.warnings.length} warning(s).` : "Analysis completed.",
        { type: result.warnings?.length ? "info" : "success" }
      );
    } catch (err) {
      const msg = extractErrorMessage(err);
      setAnalyzeError(msg);
      showToast("Analysis failed.", { type: "error" });
      await load();
      await refreshDocket();
    } finally {
      setAnalyzing(false);
    }
  }

  function startEditingName() {
    setNameDraft(caseData.case_name);
    setEditingName(true);
  }

  async function saveNameEdit() {
    const trimmed = nameDraft.trim();
    if (!trimmed || trimmed === caseData.case_name) {
      setEditingName(false);
      return;
    }
    setSavingName(true);
    try {
      await casesApi.rename(caseId, trimmed);
      await load();
      await refreshDocket();
      showToast("Case renamed.", { type: "success" });
    } catch (err) {
      showToast(extractErrorMessage(err), { type: "error" });
    } finally {
      setSavingName(false);
      setEditingName(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await casesApi.delete(caseId);
      await refreshDocket();
      showToast("Case deleted.", { type: "success" });
      navigate("/");
    } catch (err) {
      showToast(extractErrorMessage(err), { type: "error" });
      setDeleting(false);
      setConfirmingDelete(false);
    }
  }

  if (loading && !caseData) {
    return <Workspace>Loading case…</Workspace>;
  }
  if (!caseData) {
    return <Workspace>Case not found.</Workspace>;
  }

  const processesById = new Map((results?.processes || []).map((p) => [p.process_id, p]));
  const hiddenCount = (results?.processes || []).filter((p) => p.is_hidden).length;
  const suspiciousCount = (results?.processes || []).filter((p) => p.suspicion_flag).length;

  return (
    <Workspace>
      <header style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
            <span className="mono" style={{ color: "var(--text-faint)", fontSize: 12 }}>
              CASE-{String(caseData.case_id).padStart(4, "0")}
            </span>
            <StatusPill status={caseData.status} />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={() => setConfirmingDelete(true)} className="danger-outline" style={{ fontSize: 12 }}>
              Delete case
            </button>
          </div>
        </div>

        {editingName ? (
          <div style={{ display: "flex", gap: 8, margin: "6px 0 4px", alignItems: "center" }}>
            <input
              id="case-rename-input"
              type="text"
              value={nameDraft}
              onChange={(e) => setNameDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") saveNameEdit();
                if (e.key === "Escape") setEditingName(false);
              }}
              autoFocus
              style={{ fontSize: 20, fontWeight: 600, padding: "4px 8px", width: 360 }}
            />
            <button onClick={saveNameEdit} disabled={savingName} className="primary" style={{ fontSize: 12 }}>
              Save
            </button>
            <button onClick={() => setEditingName(false)} style={{ fontSize: 12 }}>
              Cancel
            </button>
          </div>
        ) : (
          <h1
            onClick={startEditingName}
            title="Click to rename"
            style={{ fontSize: 22, fontWeight: 600, margin: "6px 0 4px", cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 8 }}
          >
            {caseData.case_name}
            <span style={{ fontSize: 12, color: "var(--text-faint)", fontWeight: 400 }}>✎</span>
          </h1>
        )}

        <div style={{ fontSize: 12, color: "var(--text-faint)" }}>
          OS Profile: {caseData.os_profile || "Not yet detected"}
        </div>
        {caseData.system_info && Object.keys(caseData.system_info).length > 0 && (
          <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 4, display: "flex", gap: 14, flexWrap: "wrap" }}>
            {caseData.system_info.system_root && <span>System root: {caseData.system_info.system_root}</span>}
            {caseData.system_info.processor_count != null && <span>CPUs: {caseData.system_info.processor_count}</span>}
            {caseData.system_info.system_time && <span>System time: {caseData.system_info.system_time}</span>}
            {caseData.system_info.kernel_banner && <span title={caseData.system_info.kernel_banner}>Kernel: {caseData.system_info.kernel_banner.slice(0, 60)}…</span>}
          </div>
        )}
        {caseData.sha256_hash && (
          <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 4 }}>
            SHA-256: {caseData.sha256_hash}
          </div>
        )}
        {caseData.md5_hash && (
          <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>
            MD5: {caseData.md5_hash}
          </div>
        )}
      </header>

      {!caseData.has_memory_image && (
        <Section title="Upload memory image">
          <UploadPanel
            onUpload={handleUpload}
            uploading={uploading}
            progress={uploadProgress}
            error={uploadError}
          />
        </Section>
      )}

      {caseData.has_memory_image && (caseData.status === "pending" || caseData.status === "analyzing") && (
        <Section title="Run analysis">
          <p style={{ color: "var(--text-secondary)", fontSize: 13, marginBottom: 12 }}>
            Memory image uploaded. Run the full acquisition → analysis → detection pipeline to
            extract processes, modules, network connections, and indicators of compromise.
          </p>
          <button className="primary" onClick={handleAnalyze} disabled={analyzing || caseData.status === "analyzing"}>
            {analyzing || caseData.status === "analyzing" ? "Analyzing…" : "Run analysis"}
          </button>
          {analyzeError && (
            <div style={{ marginTop: 12, fontSize: 13, color: "var(--accent-red)" }}>{analyzeError}</div>
          )}
        </Section>
      )}

      {caseData.status === "completed" && results && (
        <>
          {analysisWarnings.length > 0 && (
            <div
              style={{
                marginBottom: 16,
                padding: "10px 14px",
                border: "1px solid var(--accent-amber-dim)",
                borderRadius: "var(--radius)",
                background: "rgba(201, 154, 63, 0.08)",
              }}
            >
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-amber)", marginBottom: 4 }}>
                Completed with {analysisWarnings.length} warning{analysisWarnings.length > 1 ? "s" : ""}
              </div>
              {analysisWarnings.map((w, i) => (
                <div key={i} className="mono" style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                  {w}
                </div>
              ))}
            </div>
          )}
          <div style={{ display: "flex", gap: 24, marginBottom: 4 }}>
            <Stat label="Processes" value={results.processes.length} />
            <Stat label="Hidden" value={hiddenCount} color="var(--accent-red)" />
            <Stat label="Suspicious" value={suspiciousCount} color="var(--accent-amber)" />
            <Stat label="IOCs" value={results.iocs.length} />
            <Stat label="Connections" value={results.network_connections.length} />
            <Stat label="Modules" value={results.modules.length} />
          </div>

          <Tabs
            tabs={[
              { key: "overview", label: "Overview" },
              { key: "processes", label: "Processes", count: results.processes.length },
              { key: "tree", label: "Process tree" },
              { key: "network", label: "Network", count: results.network_connections.length },
              { key: "modules", label: "Modules", count: results.modules.length },
              { key: "iocs", label: "IOCs", count: results.iocs.length },
              { key: "activity", label: "Activity" },
              { key: "report", label: "Report" },
            ]}
            active={tab}
            onChange={setTab}
          />

          {tab === "overview" && (
            <p style={{ color: "var(--text-secondary)", maxWidth: 640 }}>
              Analysis completed for this case. {hiddenCount} hidden process(es) and{" "}
              {suspiciousCount} suspicious process(es) were identified out of {results.processes.length}{" "}
              total. Review the Processes and Process tree tabs for detail, IOCs for indicators of
              compromise, and Report to export findings.
            </p>
          )}
          {tab === "processes" && <ProcessTable processes={results.processes} />}
          {tab === "tree" && <ProcessTree processes={results.processes} />}
          {tab === "network" && (
            <NetworkTable connections={results.network_connections} processesById={processesById} />
          )}
          {tab === "modules" && <ModuleTable modules={results.modules} processesById={processesById} />}
          {tab === "iocs" && <IOCTable iocs={results.iocs} processesById={processesById} />}
          {tab === "activity" && <AuditLogTimeline entries={auditLog} chainVerification={chainVerification} />}
          {tab === "report" && (
            <div>
              <p style={{ color: "var(--text-secondary)", marginBottom: 16 }}>
                Export a structured forensic report summarizing this case's findings.
              </p>
              <div style={{ display: "flex", gap: 10 }}>
                <a href={casesApi.reportUrl(caseId, "pdf")} target="_blank" rel="noreferrer">
                  <button className="primary">Download PDF report</button>
                </a>
                <a href={casesApi.reportUrl(caseId, "json")} target="_blank" rel="noreferrer">
                  <button>Download JSON report</button>
                </a>
              </div>
            </div>
          )}
        </>
      )}

      {caseData.status === "failed" && (
        <Section title="Analysis failed">
          <p
            style={{
              color: "var(--accent-red)",
              fontSize: 13,
              fontFamily: analyzeError ? "var(--font-mono)" : "inherit",
              whiteSpace: "pre-wrap",
            }}
          >
            {analyzeError ||
              "The last analysis attempt for this case failed. Click Retry analysis to see the detailed error, or check the file is a valid, supported memory image."}
          </p>
          <button className="primary" onClick={handleAnalyze} disabled={analyzing} style={{ marginTop: 8 }}>
            {analyzing ? "Retrying…" : "Retry analysis"}
          </button>
        </Section>
      )}

      {caseData.status === "failed" && (
        <Section title="Activity">
          <AuditLogTimeline entries={auditLog} chainVerification={chainVerification} />
        </Section>
      )}

      {confirmingDelete && (
        <ConfirmDialog
          title="Delete this case?"
          message={`This permanently deletes "${caseData.case_name}" and all its processes, IOCs, reports, and the uploaded memory image. This cannot be undone.`}
          confirmLabel={deleting ? "Deleting…" : "Delete permanently"}
          danger
          onConfirm={handleDelete}
          onCancel={() => setConfirmingDelete(false)}
        />
      )}
    </Workspace>
  );
}

function Workspace({ children }) {
  return <div style={{ flex: 1, padding: "28px 36px", overflowY: "auto", height: "100vh" }}>{children}</div>;
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 28, border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: 20 }}>
      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div className="mono" style={{ fontSize: 22, fontWeight: 600, color: color || "var(--text)" }}>
        {value}
      </div>
      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</div>
    </div>
  );
}
