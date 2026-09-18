import { Link } from "react-router-dom";
import { useCases } from "../context/CasesContext";
import StatusPill from "../components/StatusPill";

export default function DashboardPage() {
  const { cases } = useCases();

  if (cases.length === 0) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100vh",
          color: "var(--text-faint)",
        }}
      >
        <div style={{ textAlign: "center", maxWidth: 360 }}>
          <div className="mono" style={{ fontSize: 12, marginBottom: 8, color: "var(--text-secondary)" }}>
            No case selected
          </div>
          <div style={{ fontSize: 14 }}>
            Open a new case from the docket on the left to begin an investigation.
          </div>
        </div>
      </div>
    );
  }

  const byStatus = cases.reduce((acc, c) => {
    acc[c.status] = (acc[c.status] || 0) + 1;
    return acc;
  }, {});

  const recentCases = [...cases]
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 8);

  return (
    <div style={{ flex: 1, padding: "28px 36px", overflowY: "auto", height: "100vh" }}>
      <header style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, margin: "0 0 4px" }}>Case docket overview</h1>
        <div style={{ fontSize: 13, color: "var(--text-faint)" }}>
          {cases.length} case{cases.length !== 1 ? "s" : ""} total
        </div>
      </header>

      <div style={{ display: "flex", gap: 32, marginBottom: 36 }}>
        <StatBlock label="Completed" value={byStatus.completed || 0} color="var(--accent-green)" />
        <StatBlock label="Pending" value={byStatus.pending || 0} color="var(--text-secondary)" />
        <StatBlock label="Analyzing" value={byStatus.analyzing || 0} color="var(--accent-blue)" />
        <StatBlock label="Failed" value={byStatus.failed || 0} color="var(--accent-red)" />
      </div>

      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: "var(--text-secondary)" }}>
        Recent cases
      </div>
      <table>
        <thead>
          <tr>
            <th>Case</th>
            <th>Name</th>
            <th>OS Profile</th>
            <th>Status</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {recentCases.map((c) => (
            <tr key={c.case_id}>
              <td className="mono" style={{ color: "var(--text-faint)" }}>
                CASE-{String(c.case_id).padStart(4, "0")}
              </td>
              <td>
                <Link to={`/cases/${c.case_id}`}>{c.case_name}</Link>
              </td>
              <td style={{ color: "var(--text-secondary)" }}>{c.os_profile || "—"}</td>
              <td>
                <StatusPill status={c.status} />
              </td>
              <td className="mono" style={{ color: "var(--text-faint)", fontSize: 12 }}>
                {c.created_at ? new Date(c.created_at).toLocaleString() : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StatBlock({ label, value, color }) {
  return (
    <div>
      <div className="mono" style={{ fontSize: 28, fontWeight: 600, color }}>
        {value}
      </div>
      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</div>
    </div>
  );
}
