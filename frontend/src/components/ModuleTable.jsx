import { useMemo, useState } from "react";
import { useSortableData, SortableTh } from "../hooks/useSortableData";

export default function ModuleTable({ modules, processesById }) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    if (!query.trim()) return modules;
    const q = query.toLowerCase();
    return modules.filter((m) => {
      const proc = processesById.get(m.process_id);
      return (
        m.dll_name.toLowerCase().includes(q) ||
        (proc && proc.process_name.toLowerCase().includes(q))
      );
    });
  }, [modules, processesById, query]);

  const { sorted, sortKey, sortDir, toggleSort } = useSortableData(filtered, "dll_name");

  return (
    <div>
      <input
        type="text"
        placeholder="Filter by DLL name or process..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        style={{ width: 320, marginBottom: 12 }}
      />
      <table>
        <thead>
          <tr>
            <th>Process</th>
            <SortableTh label="Module" sortKeyName="dll_name" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
            <th>Base address</th>
            <SortableTh label="Size" sortKeyName="module_size" currentKey={sortKey} currentDir={sortDir} onSort={toggleSort} />
          </tr>
        </thead>
        <tbody>
          {sorted.map((m) => {
            const proc = processesById.get(m.process_id);
            return (
              <tr key={m.module_id}>
                <td className="mono">{proc ? `${proc.process_name} (${proc.pid})` : m.process_id}</td>
                <td className="mono">{m.dll_name}</td>
                <td className="mono" style={{ color: "var(--text-secondary)" }}>
                  {m.base_address || "—"}
                </td>
                <td style={{ color: "var(--text-secondary)" }}>
                  {m.module_size != null ? `${m.module_size.toLocaleString()} B` : "—"}
                </td>
              </tr>
            );
          })}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={4} style={{ color: "var(--text-faint)", textAlign: "center", padding: 24 }}>
                {modules.length === 0
                  ? "No modules were extracted for this case."
                  : "No modules match this filter."}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
