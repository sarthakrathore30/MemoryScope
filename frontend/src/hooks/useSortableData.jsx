import { useMemo, useState } from "react";

/**
 * Generic client-side sorting for small-to-medium result sets (typical
 * process/network/IOC lists in a single case). Returns the sorted array
 * plus a `sortProps` helper to spread onto <SortableTh> for each column.
 */
export function useSortableData(items, defaultKey = null, defaultDir = "asc") {
  const [sortKey, setSortKey] = useState(defaultKey);
  const [sortDir, setSortDir] = useState(defaultDir);

  const sorted = useMemo(() => {
    if (!sortKey) return items;
    const copy = [...items];
    copy.sort((a, b) => {
      let av = a[sortKey];
      let bv = b[sortKey];
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === "string") av = av.toLowerCase();
      if (typeof bv === "string") bv = bv.toLowerCase();
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }, [items, sortKey, sortDir]);

  function toggleSort(key) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  }

  return { sorted, sortKey, sortDir, toggleSort };
}

export function SortableTh({ label, sortKeyName, currentKey, currentDir, onSort }) {
  const active = currentKey === sortKeyName;
  return (
    <th
      onClick={() => onSort(sortKeyName)}
      style={{ cursor: "pointer", userSelect: "none" }}
      title={`Sort by ${label}`}
    >
      {label}
      <span style={{ marginLeft: 4, color: active ? "var(--accent-amber)" : "var(--text-faint)", fontSize: 10 }}>
        {active ? (currentDir === "asc" ? "▲" : "▼") : "↕"}
      </span>
    </th>
  );
}
