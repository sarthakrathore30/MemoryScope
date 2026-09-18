import { useMemo, useState } from "react";
import { useSortableData, SortableTh } from "../hooks/useSortableData";

export default function ProcessTable({ processes }) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!query.trim()) return processes;
    const q = query.toLowerCase();
    return processes.filter(
      (p) =>
        p.process_name.toLowerCase().includes(q) ||
        String(p.pid).includes(q) ||
        (p.suspicion_reason || "").toLowerCase().includes(q)
    );
  }, [processes, query]);

  const { sorted, sortKey, sortDir, toggleSort } = useSortableData(filtered, "pid");

  return (
    <div>
      <input
        type="text"
        placeholder="Filter by name, PID, or reason..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        style={{ width: 320, marginBottom: 12 }}
      />
      <table>
        <thead>
          <tr>
            <SortableTh label="PID" sortKeyName="pid" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
            <SortableTh label="PPID" sortKeyName="ppid" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
            <SortableTh label="Process" sortKeyName="process_name" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
            <th>Flags</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((p) => (
            <tr key={p.process_id}>
              <td className="mono">{p.pid}</td>
              <td className="mono">{p.ppid ?? "—"}</td>
              <td>{p.process_name}</td>
              <td>
                {p.is_hidden && <Flag color="var(--accent-red)" label="HIDDEN" />}
                {p.suspicion_flag && <Flag color="var(--accent-amber)" label="SUSPICIOUS" />}
                {!p.is_hidden && !p.suspicion_flag && (
                  <span style={{ color: "var(--accent-green)", fontSize: 12 }}>clean</span>
                )}
              </td>
              <td style={{ color: "var(--text-secondary)", maxWidth: 420 }}>
                {p.suspicion_reason || "—"}
              </td>
            </tr>
          ))}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={5} style={{ color: "var(--text-faint)", textAlign: "center", padding: 24 }}>
                No processes match this filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Flag({ color, label }) {
  return (
    <span
      style={{
        display: "inline-block",
        fontSize: 10,
        fontWeight: 600,
        color,
        border: `1px solid ${color}`,
        borderRadius: 2,
        padding: "1px 5px",
        marginRight: 5,
      }}
    >
      {label}
    </span>
  );
}
