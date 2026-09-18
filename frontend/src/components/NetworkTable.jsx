import { useMemo, useState } from "react";
import { useSortableData, SortableTh } from "../hooks/useSortableData";

export default function NetworkTable({ connections, processesById }) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!query.trim()) return connections;
    const q = query.toLowerCase();
    return connections.filter(
      (c) =>
        (c.remote_ip || "").toLowerCase().includes(q) ||
        (c.local_ip || "").toLowerCase().includes(q) ||
        (c.state || "").toLowerCase().includes(q) ||
        String(c.remote_port || "").includes(q)
    );
  }, [connections, query]);

  const { sorted, sortKey, sortDir, toggleSort } = useSortableData(filtered, "remote_ip");

  return (
    <div>
      <input
        type="text"
        placeholder="Filter by IP, port, or state..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        style={{ width: 320, marginBottom: 12 }}
      />
      <table>
        <thead>
          <tr>
            <th>Process</th>
            <th>Local</th>
            <SortableTh label="Remote" sortKeyName="remote_ip" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
            <SortableTh label="Protocol" sortKeyName="protocol" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
            <SortableTh label="State" sortKeyName="state" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
          </tr>
        </thead>
        <tbody>
          {sorted.map((c) => {
            const proc = processesById.get(c.process_id);
            return (
              <tr key={c.conn_id}>
                <td className="mono">{proc ? `${proc.process_name} (${proc.pid})` : c.process_id}</td>
                <td className="mono">{c.local_ip || "—"}:{c.local_port ?? "—"}</td>
                <td className="mono">{c.remote_ip || "—"}:{c.remote_port ?? "—"}</td>
                <td>{c.protocol || "—"}</td>
                <td>{c.state || "—"}</td>
              </tr>
            );
          })}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={5} style={{ color: "var(--text-faint)", textAlign: "center", padding: 24 }}>
                No network connections match this filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
