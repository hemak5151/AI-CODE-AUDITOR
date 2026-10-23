"use client";
import { useMemo, useState } from "react";
import type { CSSProperties } from "react";
import Editor from "@monaco-editor/react";
import { exportUrl, getPatch } from "../lib/api";
import type { Finding, Patch } from "../lib/api";
import DiffView from "./DiffView";

const ORDER = ["critical", "high", "medium", "low", "info"];
const COLOR: Record<string, string> = {
  critical: "#b91c1c",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#2563eb",
  info: "#6b7280",
};
const box: CSSProperties = {
  border: "1px solid #d4d4d8",
  borderRadius: 10,
  padding: 16,
  marginBottom: 16,
};

function Detail({ f }: { f: Finding }) {
  const [patch, setPatch] = useState<Patch | null | undefined>(undefined);
  const [open, setOpen] = useState(false);
  function viewPatch() {
    setOpen(true);
    getPatch(f.finding_id)
      .then(setPatch)
      .catch(() => setPatch(null));
  }
  return (
    <div style={box}>
      <h3>
        {f.message}{" "}
        <span style={{ color: COLOR[f.severity] }}>[{f.severity}]</span>
      </h3>
      <p>
        <b>{f.cwe_id || "No CWE"}</b> · confidence {f.confidence} · source{" "}
        {f.source}
      </p>
      <p>
        {f.file_path}:{f.line_number}
      </p>
      <p>{f.explanation}</p>
      {f.evidence && (
        <Editor
          height="120px"
          language="python"
          value={f.evidence}
          theme="vs-dark"
          options={{
            readOnly: true,
            minimap: { enabled: false },
            lineNumbers: "off",
            scrollBeyondLastLine: false,
          }}
        />
      )}
      {f.suggested_remediation && (
        <p>
          <b>Remediation:</b> {f.suggested_remediation}
        </p>
      )}
      <button onClick={viewPatch}>View patch</button>
      {open && patch === undefined && <p>Loading…</p>}
      {open && patch === null && (
        <p>No patch available for this finding yet.</p>
      )}
      {open && patch && <DiffView patch={patch} />}
    </div>
  );
}

export default function FindingsView({
  findings,
  jobId,
}: {
  findings: Finding[];
  jobId: string;
}) {
  const [sev, setSev] = useState("all");
  const [cwe, setCwe] = useState("all");
  const [selected, setSelected] = useState<Finding | null>(null);

  const cwes = useMemo(
    () => Array.from(new Set(findings.map((f) => f.cwe_id || "No CWE"))).sort(),
    [findings],
  );
  const shown = findings
    .filter(
      (f) =>
        (sev === "all" || f.severity === sev) &&
        (cwe === "all" || (f.cwe_id || "No CWE") === cwe),
    )
    .sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
  const max = Math.max(
    1,
    ...ORDER.map((s) => findings.filter((f) => f.severity === s).length),
  );

  return (
    <>
      <div style={box}>
        <h2>Severity chart</h2>
        {ORDER.map((s) => {
          const n = findings.filter((f) => f.severity === s).length;
          return (
            <div
              key={s}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                margin: "4px 0",
              }}
            >
              <span style={{ width: 70 }}>{s}</span>
              <div
                style={{
                  width: `${(n / max) * 300}px`,
                  minWidth: n ? 4 : 0,
                  height: 14,
                  background: COLOR[s],
                }}
              />
              <span>{n}</span>
            </div>
          );
        })}
      </div>
      <div style={box}>
        <h2>
          Findings ({shown.length}/{findings.length})
        </h2>
        <label>
          Severity{" "}
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="all">All</option>
            {ORDER.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>{" "}
        <label>
          CWE{" "}
          <select value={cwe} onChange={(e) => setCwe(e.target.value)}>
            <option value="all">All</option>
            {cwes.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <div style={{ margin: "12px 0", display: "flex", gap: 12 }}>
          <a href={exportUrl(jobId, "sarif")} style={{ color: "#60a5fa" }}>
            Export SARIF
          </a>
          <a href={exportUrl(jobId, "pdf")} style={{ color: "#60a5fa" }}>
            Export PDF report
          </a>
        </div>
        {shown.length === 0 && (
          <p>No findings match. Only Python files are scanned for now.</p>
        )}
        {shown.map((f) => (
          <div
            key={f.finding_id}
            onClick={() => setSelected(f)}
            style={{
              padding: 8,
              marginTop: 6,
              cursor: "pointer",
              borderRadius: 6,
              border:
                selected?.finding_id === f.finding_id
                  ? "2px solid #2563eb"
                  : "1px solid #e4e4e7",
            }}
          >
            <b style={{ color: COLOR[f.severity] }}>
              {f.severity.toUpperCase()}
            </b>{" "}
            · {f.cwe_id || "No CWE"} · {f.message} · {f.file_path}:
            {f.line_number}
          </div>
        ))}
      </div>
      {selected && <Detail key={selected.finding_id} f={selected} />}
    </>
  );
}
