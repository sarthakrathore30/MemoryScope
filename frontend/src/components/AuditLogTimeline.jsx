const ACTION_ICONS = {
  case_created: "●",
  case_renamed: "✎",
  image_uploaded_and_validated: "↑",
  image_validation_failed: "✕",
  os_profile_detected: "◆",
  analysis_started: "▸",
  analysis_completed: "✓",
  analysis_failed: "✕",
  analysis_warning: "!",
  detection_pipeline_completed: "✓",
};

function iconFor(action) {
  const key = Object.keys(ACTION_ICONS).find((k) => action.startsWith(k));
  return ACTION_ICONS[key] || "·";
}

function colorFor(action) {
  if (action.includes("failed")) return "var(--accent-red)";
  if (action.includes("warning")) return "var(--accent-amber)";
  if (action.includes("completed") || action.includes("validated")) return "var(--accent-green)";
  return "var(--text-secondary)";
}

export default function AuditLogTimeline({ entries, chainVerification }) {
  if (entries.length === 0) {
    return (
      <div style={{ color: "var(--text-faint)", padding: 24 }}>
        No activity recorded for this case yet.
      </div>
    );
  }

  return (
    <div>
      {chainVerification && (
        <div
          style={{
            marginBottom: 16,
            padding: "8px 12px",
            border: `1px solid ${chainVerification.is_valid ? "var(--accent-green-dim)" : "var(--accent-red-dim)"}`,
            borderRadius: "var(--radius)",
            fontSize: 12,
            color: chainVerification.is_valid ? "var(--accent-green)" : "var(--accent-red)",
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          {chainVerification.is_valid
            ? `✓ Chain-of-custody verified — ${chainVerification.entry_count} entries, no tampering detected`
            : `✕ Integrity check FAILED — ${chainVerification.broken_log_ids.length} entr${chainVerification.broken_log_ids.length === 1 ? "y" : "ies"} may have been altered`}
        </div>
      )}
      {entries.map((entry, i) => {
        const isBroken = chainVerification?.broken_log_ids?.includes(entry.log_id);
        return (
          <div
            key={entry.log_id}
            style={{
              display: "flex",
              gap: 12,
              paddingBottom: 16,
              position: "relative",
            }}
          >
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 16 }}>
              <span
                className="mono"
                style={{
                  color: isBroken ? "var(--accent-red)" : colorFor(entry.action),
                  fontSize: 13,
                  lineHeight: "16px",
                }}
              >
                {isBroken ? "⚠" : iconFor(entry.action)}
              </span>
              {i < entries.length - 1 && (
                <div style={{ flex: 1, width: 1, background: "var(--border)", marginTop: 4 }} />
              )}
            </div>
            <div style={{ paddingBottom: 4 }}>
              <div style={{ fontSize: 13, color: isBroken ? "var(--accent-red)" : "var(--text)" }}>
                {formatAction(entry.action)}
                {isBroken && <span style={{ marginLeft: 8, fontSize: 11 }}>(integrity check failed)</span>}
              </div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 2 }}>
                {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : ""}
                {entry.performed_by ? ` · ${entry.performed_by}` : ""}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function formatAction(action) {
  // Actions are logged as e.g. "os_profile_detected:Windows (10.0.19041, x64)"
  // or "analysis_warning:Network connection extraction unavailable: ...".
  // Split on the first colon to separate the action type from its detail.
  const idx = action.indexOf(":");
  if (idx === -1) {
    return action.replace(/_/g, " ");
  }
  const type = action.slice(0, idx).replace(/_/g, " ");
  const detail = action.slice(idx + 1);
  return (
    <>
      {type}
      <span style={{ color: "var(--text-secondary)" }}>: {detail}</span>
    </>
  );
}
