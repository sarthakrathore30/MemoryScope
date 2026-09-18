import { useMemo, useState } from "react";

function buildForest(processes) {
  const byPid = new Map(processes.map((p) => [p.pid, { ...p, children: [] }]));
  const roots = [];

  for (const proc of byPid.values()) {
    if (proc.ppid !== null && proc.ppid !== undefined && byPid.has(proc.ppid) && proc.ppid !== proc.pid) {
      byPid.get(proc.ppid).children.push(proc);
    } else {
      roots.push(proc);
    }
  }
  return roots;
}

export default function ProcessTree({ processes }) {
  const forest = useMemo(() => buildForest(processes), [processes]);

  if (processes.length === 0) {
    return <div style={{ color: "var(--text-faint)", padding: 24 }}>No process data available.</div>;
  }

  return (
    <div className="mono" style={{ fontSize: 13, lineHeight: 1.8 }}>
      {forest.map((root) => (
        <TreeNode key={root.pid} node={root} depth={0} />
      ))}
    </div>
  );
}

function TreeNode({ node, depth }) {
  const [collapsed, setCollapsed] = useState(false);
  const hasChildren = node.children.length > 0;

  const flagColor = node.is_hidden ? "var(--accent-red)" : node.suspicion_flag ? "var(--accent-amber)" : null;

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          paddingLeft: depth * 20,
          borderLeft: depth > 0 ? "1px solid var(--border)" : "none",
          marginLeft: depth > 0 ? 3 : 0,
        }}
      >
        {hasChildren ? (
          <button
            onClick={() => setCollapsed(!collapsed)}
            style={{
              width: 16,
              height: 16,
              padding: 0,
              fontSize: 10,
              lineHeight: 1,
              border: "none",
              background: "transparent",
              color: "var(--text-faint)",
            }}
            aria-label={collapsed ? "Expand" : "Collapse"}
          >
            {collapsed ? "▸" : "▾"}
          </button>
        ) : (
          <span style={{ width: 16, textAlign: "center", color: "var(--text-faint)" }}>·</span>
        )}
        <span style={{ color: "var(--text-faint)" }}>{node.pid}</span>
        <span style={{ color: flagColor || "var(--text)" }}>{node.process_name}</span>
        {node.is_hidden && (
          <span style={{ fontSize: 10, color: "var(--accent-red)", border: "1px solid var(--accent-red)", borderRadius: 2, padding: "0 4px" }}>
            HIDDEN
          </span>
        )}
        {node.suspicion_flag && (
          <span style={{ fontSize: 10, color: "var(--accent-amber)", border: "1px solid var(--accent-amber)", borderRadius: 2, padding: "0 4px" }}>
            FLAGGED
          </span>
        )}
      </div>
      {hasChildren && !collapsed && (
        <div>
          {node.children.map((child) => (
            <TreeNode key={child.pid} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}
