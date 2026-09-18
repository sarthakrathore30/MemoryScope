import { useRef, useState } from "react";

export default function UploadPanel({ onUpload, uploading, progress, error }) {
  const inputRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);

  function handleFiles(files) {
    if (files && files[0]) onUpload(files[0]);
  }

  return (
    <div>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          handleFiles(e.dataTransfer.files);
        }}
        onClick={() => inputRef.current?.click()}
        style={{
          border: `1px dashed ${dragOver ? "var(--accent-amber)" : "var(--border-strong)"}`,
          borderRadius: "var(--radius)",
          padding: "40px 20px",
          textAlign: "center",
          cursor: "pointer",
          background: dragOver ? "var(--surface)" : "transparent",
        }}
      >
        <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Drop a memory image here, or click to browse
        </div>
        <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 6 }}>
          Accepted formats: .raw .mem .dmp .vmem .img .bin .lime
        </div>
        <input
          ref={inputRef}
          type="file"
          hidden
          onChange={(e) => handleFiles(e.target.files)}
        />
      </div>

      {uploading && (
        <div style={{ marginTop: 12 }}>
          <div style={{ height: 4, background: "var(--surface)", borderRadius: 2, overflow: "hidden" }}>
            <div
              style={{
                height: "100%",
                width: `${progress}%`,
                background: "var(--accent-amber)",
                transition: "width 0.2s ease",
              }}
            />
          </div>
          <div style={{ fontSize: 12, color: "var(--text-faint)", marginTop: 4 }}>
            Uploading — {progress}%
          </div>
        </div>
      )}

      {error && (
        <div
          style={{
            marginTop: 12,
            fontSize: 13,
            color: "var(--accent-red)",
            border: "1px solid var(--accent-red-dim)",
            borderRadius: "var(--radius)",
            padding: "8px 12px",
          }}
        >
          {error}
        </div>
      )}
    </div>
  );
}
