import { useState } from "react";
import { NavLink } from "react-router-dom";
import StatusPill from "./StatusPill";

export default function CaseDocket({ cases, onCreateCase, creating }) {
  const [name, setName] = useState("");

  function handleSubmit(e) {
    e.preventDefault();
    if (!name.trim()) return;
    onCreateCase(name.trim());
    setName("");
  }

  return (
    <aside
      style={{
        width: "var(--sidebar-width)",
        borderRight: "1px solid var(--border)",
        display: "flex",
        flexDirection: "column",
        height: "100vh",
      }}
    >
      <div style={{ padding: "20px 18px 14px", borderBottom: "1px solid var(--border)" }}>
        <div style={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.01em" }}>
          Memory Forensics Platform
        </div>
        <div style={{ fontSize: 12, color: "var(--text-faint)", marginTop: 2 }}>
          Case docket
        </div>
      </div>

      <form onSubmit={handleSubmit} style={{ padding: 14, borderBottom: "1px solid var(--border)" }}>
        <input
          type="text"
          placeholder="New case name..."
          value={name}
          onChange={(e) => setName(e.target.value)}
          style={{ width: "100%", marginBottom: 8 }}
        />
        <button type="submit" className="primary" disabled={creating || !name.trim()} style={{ width: "100%" }}>
          {creating ? "Creating..." : "Open new case"}
        </button>
      </form>

      <nav style={{ flex: 1, overflowY: "auto" }}>
        {cases.length === 0 && (
          <div style={{ padding: 18, color: "var(--text-faint)", fontSize: 13 }}>
            No cases yet. Open one above to begin an investigation.
          </div>
        )}
        {cases.map((c) => (
          <NavLink
            key={c.case_id}
            to={`/cases/${c.case_id}`}
            style={({ isActive }) => ({
              display: "block",
              padding: "10px 18px",
              borderBottom: "1px solid var(--border)",
              background: isActive ? "var(--surface)" : "transparent",
              borderLeft: isActive ? "2px solid var(--accent-amber)" : "2px solid transparent",
            })}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
              <span className="mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>
                CASE-{String(c.case_id).padStart(4, "0")}
              </span>
              <StatusPill status={c.status} />
            </div>
            <div style={{ fontSize: 13, marginTop: 3, color: "var(--text)" }}>{c.case_name}</div>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
