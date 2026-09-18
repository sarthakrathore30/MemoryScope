import { createContext, useCallback, useContext, useRef, useState } from "react";

const ToastContext = createContext(null);

let idCounter = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef({});

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    if (timers.current[id]) {
      clearTimeout(timers.current[id]);
      delete timers.current[id];
    }
  }, []);

  const showToast = useCallback(
    (message, { type = "info", duration = 4000 } = {}) => {
      const id = ++idCounter;
      setToasts((prev) => [...prev, { id, message, type }]);
      timers.current[id] = setTimeout(() => dismiss(id), duration);
      return id;
    },
    [dismiss]
  );

  return (
    <ToastContext.Provider value={{ showToast, dismiss }}>
      {children}
      <div
        style={{
          position: "fixed",
          bottom: 20,
          right: 20,
          display: "flex",
          flexDirection: "column",
          gap: 8,
          zIndex: 1000,
        }}
      >
        {toasts.map((t) => (
          <Toast key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

const TYPE_COLORS = {
  success: "var(--accent-green)",
  error: "var(--accent-red)",
  info: "var(--text-secondary)",
};

function Toast({ toast, onDismiss }) {
  const color = TYPE_COLORS[toast.type] || TYPE_COLORS.info;
  return (
    <div
      style={{
        background: "var(--surface-raised)",
        border: `1px solid ${color}`,
        borderRadius: "var(--radius)",
        padding: "10px 14px",
        minWidth: 240,
        maxWidth: 380,
        fontSize: 13,
        color: "var(--text)",
        boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        animation: "toast-in 0.15s ease-out",
      }}
    >
      <span style={{ color, flexShrink: 0, fontSize: 14, lineHeight: "18px" }}>
        {toast.type === "success" ? "✓" : toast.type === "error" ? "✕" : "·"}
      </span>
      <span style={{ flex: 1 }}>{toast.message}</span>
      <button
        onClick={onDismiss}
        style={{
          background: "none",
          border: "none",
          padding: 0,
          color: "var(--text-faint)",
          fontSize: 13,
          lineHeight: 1,
          cursor: "pointer",
        }}
        aria-label="Dismiss"
      >
        ×
      </button>
    </div>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within a ToastProvider");
  return ctx;
}
