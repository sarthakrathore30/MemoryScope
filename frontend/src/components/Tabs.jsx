export default function Tabs({ tabs, active, onChange }) {
  return (
    <div style={{ display: "flex", gap: 2, borderBottom: "1px solid var(--border)", marginBottom: 20 }}>
      {tabs.map((tab) => (
        <button
          key={tab.key}
          onClick={() => onChange(tab.key)}
          style={{
            background: "none",
            border: "none",
            borderBottom: active === tab.key ? "2px solid var(--accent-amber)" : "2px solid transparent",
            borderRadius: 0,
            padding: "10px 16px",
            color: active === tab.key ? "var(--text)" : "var(--text-secondary)",
            fontWeight: active === tab.key ? 600 : 400,
          }}
        >
          {tab.label}
          {tab.count !== undefined && (
            <span style={{ marginLeft: 6, fontSize: 11, color: "var(--text-faint)" }}>{tab.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}
