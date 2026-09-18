const STATUS_STYLES = {
  pending: { color: "var(--text-secondary)", label: "Pending" },
  analyzing: { color: "var(--accent-blue)", label: "Analyzing" },
  completed: { color: "var(--accent-green)", label: "Completed" },
  failed: { color: "var(--accent-red)", label: "Failed" },
};

export default function StatusPill({ status }) {
  const style = STATUS_STYLES[status] || { color: "var(--text-faint)", label: status };
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        fontSize: 12,
        color: style.color,
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: "50%",
          background: style.color,
          display: "inline-block",
        }}
      />
      {style.label}
    </span>
  );
}
