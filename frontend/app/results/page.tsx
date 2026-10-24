"use client";
import { useEffect, useMemo, useState } from "react";
import type { CSSProperties } from "react";
import Link from "next/link";
import { getResults } from "../../lib/api";
import type { ResultsPayload } from "../../lib/api";

type Metric = "f1" | "precision" | "recall" | "fpr";
const METRICS: Metric[] = ["f1", "precision", "recall", "fpr"];
const LABEL: Record<string, string> = {
  C1: "C1 Semgrep/Bandit",
  C2: "C2 LLM only",
  C3: "C3 + AST context",
  C4: "C4 + RAG",
  C5: "C5 Full system",
};
const box: CSSProperties = {
  border: "1px solid #d4d4d8",
  borderRadius: 10,
  padding: 16,
  marginBottom: 16,
};
const fmt = (v: number | null | undefined) => (v == null ? "–" : v.toFixed(2));

export default function ResultsPage() {
  const [data, setData] = useState<ResultsPayload | null>(null);
  const [error, setError] = useState("");
  const [metric, setMetric] = useState<Metric>("f1");
  const [cwe, setCwe] = useState("ALL");

  useEffect(() => {
    getResults()
      .then(setData)
      .catch((e) =>
        setError(e instanceof Error ? e.message : "Failed to load"),
      );
  }, []);

  const cwes = useMemo(
    () => (data ? Array.from(new Set(data.rows.map((r) => r.cwe))).sort() : []),
    [data],
  );
  const rows = useMemo(
    () =>
      data
        ? data.rows
            .filter((r) => r.cwe === cwe)
            .sort((a, b) => a.config.localeCompare(b.config))
        : [],
    [data, cwe],
  );

  return (
    <div
      style={{
        maxWidth: 1100,
        margin: "0 auto",
        padding: 24,
        fontFamily: "system-ui, sans-serif",
      }}
    >
      <p>
        <Link href="/" style={{ color: "#60a5fa" }}>
          ← Back to analysis
        </Link>
      </p>
      <h1>Results dashboard</h1>
      {error && <p style={{ color: "#b91c1c" }}>{error}</p>}
      {data?.sample && (
        <div style={{ ...box, borderColor: "#ca8a04", color: "#ca8a04" }}>
          <b>Sample data, not real results.</b> No usable result files were
          found in <code>evaluation/results/</code>. Numbers below are
          placeholders to show the layout.
        </div>
      )}
      {data && !data.sample && <p>Loaded from: {data.files.join(", ")}</p>}
      {data && (
        <>
          <div style={box}>
            <label>
              Metric{" "}
              <select
                value={metric}
                onChange={(e) => setMetric(e.target.value as Metric)}
              >
                {METRICS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>{" "}
            <label>
              CWE{" "}
              <select value={cwe} onChange={(e) => setCwe(e.target.value)}>
                {cwes.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>
            {metric === "fpr" && (
              <p>
                <small>False-positive rate: lower is better.</small>
              </p>
            )}
            {rows.map((r) => {
              const v = r[metric] ?? 0;
              return (
                <div
                  key={r.config}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    margin: "6px 0",
                  }}
                >
                  <span style={{ width: 150 }}>
                    {LABEL[r.config] ?? r.config}
                  </span>
                  <div
                    style={{
                      width: `${Math.max(0, Math.min(1, v)) * 400}px`,
                      minWidth: v > 0 ? 4 : 0,
                      height: 16,
                      background: data.sample ? "#6b7280" : "#2563eb",
                    }}
                  />
                  <span>{fmt(r[metric])}</span>
                </div>
              );
            })}
          </div>
          <div style={box}>
            <h2>Table ({cwe})</h2>
            <table style={{ borderCollapse: "collapse", width: "100%" }}>
              <thead>
                <tr>
                  {["Config", "Precision", "Recall", "F1", "FPR", "n"].map(
                    (h) => (
                      <th
                        key={h}
                        style={{
                          textAlign: "left",
                          padding: 6,
                          borderBottom: "1px solid #d4d4d8",
                        }}
                      >
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.config}>
                    <td style={{ padding: 6 }}>
                      {LABEL[r.config] ?? r.config}
                    </td>
                    <td style={{ padding: 6 }}>{fmt(r.precision)}</td>
                    <td style={{ padding: 6 }}>{fmt(r.recall)}</td>
                    <td style={{ padding: 6 }}>
                      {fmt(r.f1)}
                      {r.f1_lo != null &&
                        r.f1_hi != null &&
                        ` [${fmt(r.f1_lo)}, ${fmt(r.f1_hi)}]`}
                    </td>
                    <td style={{ padding: 6 }}>{fmt(r.fpr)}</td>
                    <td style={{ padding: 6 }}>{r.n == null ? "–" : r.n}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
