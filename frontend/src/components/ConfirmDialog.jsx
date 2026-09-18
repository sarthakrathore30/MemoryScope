export default function ConfirmDialog({ title, message, confirmLabel = "Confirm", danger, onConfirm, onCancel }) {
  return (
    <div
      onClick={onCancel}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.5)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 2000,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "var(--surface-raised)",
          border: "1px solid var(--border-strong)",
          borderRadius: "var(--radius)",
          padding: 24,
          width: 380,
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        }}
      >
        <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>{title}</div>
        <div style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 20, lineHeight: 1.5 }}>
          {message}
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
          <button onClick={onCancel}>Cancel</button>
          <button
            onClick={onConfirm}
            className={danger ? "danger-outline" : "primary"}
            style={danger ? { borderColor: "var(--accent-red)", color: "var(--accent-red)" } : undefined}
            autoFocus
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
