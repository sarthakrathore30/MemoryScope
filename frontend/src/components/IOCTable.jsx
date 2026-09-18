import { useMemo, useState } from "react";
import { useSortableData, SortableTh } from "../hooks/useSortableData";

const TYPE_COLORS = {
  hidden_process: "var(--accent-red)",
  suspicious_process: "var(--accent-amber)",
  yara_rule: "var(--accent-red)",
  anomalous_memory_region: "var(--accent-red)",
  ip: "var(--accent-blue)",
};

export default function IOCTable({ iocs, processesById }) {
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");

  const types = useMemo(() => ["all", ...new Set(iocs.map((i) => i.ioc_type))], [iocs]);

  const filtered = useMemo(() => {
    return iocs.filter((i) => {
      if (typeFilter !== "all" && i.ioc_type !== typeFilter) return false;
      if (!query.trim()) return true;
      const q = query.toLowerCase();
      return (
        i.ioc_value.toLowerCase().includes(q) ||
        (i.source || "").toLowerCase().includes(q)
      );
    });
  }, [iocs, query, typeFilter]);

  const { sorted, sortKey, sortDir, toggleSort } = useSortableData(filtered, "ioc_type");

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input
          type="text"
          placeholder="Filter by value or source..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ width: 280 }}
        />
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={{
            background: "var(--bg)",
            color: "var(--text)",
            border: "1px solid var(--border-strong)",
            borderRadius: "var(--radius)",
            padding: "8px 10px",
            fontSize: 13,
          }}
        >
          {types.map((t) => (
            <option key={t} value={t}>
              {t === "all" ? "All types" : t}
            </option>
          ))}
        </select>
      </div>
      <table>
        <thead>
          <tr>
            <SortableTh label="Type" sortKeyName="ioc_type" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
            <SortableTh label="Value" sortKeyName="ioc_value" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
            <th>Source</th>
            <th>Related process</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((ioc) => {
            const proc = processesById.get(ioc.related_process_id);
            return (
              <tr key={ioc.ioc_id}>
                <td>
                  <span style={{ color: TYPE_COLORS[ioc.ioc_type] || "var(--text)", fontSize: 12 }}>
                    {ioc.ioc_type}
                  </span>
                </td>
                <td className="mono">{ioc.ioc_value}</td>
                <td style={{ color: "var(--text-secondary)" }}>{ioc.source || "—"}</td>
                <td className="mono">{proc ? `${proc.process_name} (${proc.pid})` : "—"}</td>
              </tr>
            );
          })}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={4} style={{ color: "var(--text-faint)", textAlign: "center", padding: 24 }}>
                No IOCs match this filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
