"use client";
import { useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";
import {
  createGitJob,
  uploadZip,
  uploadGuideline,
  getFindings,
  eventsUrl,
} from "../lib/api";
import type { Job, Finding } from "../lib/api";
import FindingsView from "./FindingsView";
import Link from "next/link";
const box: CSSProperties = {
  border: "1px solid #d4d4d8",
  borderRadius: 10,
  padding: 16,
  marginBottom: 16,
};
const btn: CSSProperties = {
  padding: "8px 16px",
  borderRadius: 8,
  border: 0,
  background: "#2563eb",
  color: "#fff",
  cursor: "pointer",
};

export default function CodeAuditor() {
  const [mode, setMode] = useState<"zip" | "git">("zip");
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const source = useRef<EventSource | null>(null);

  useEffect(
    () => () => {
      source.current?.close();
    },
    [],
  );

  async function start() {
    setError("");
    setFindings(null);
    setJob(null);
    setBusy(true);
    try {
      if (mode === "zip" && !file) throw new Error("Choose a .zip file first");
      if (mode === "git" && !url.trim())
        throw new Error("Enter a git URL (https://...)");
      const created =
        mode === "zip"
          ? await uploadZip(file as File)
          : await createGitJob(url.trim());
      setJob(created);
      source.current?.close();
      const es = new EventSource(eventsUrl(created.job_id));
      source.current = es;
      es.onmessage = async (e) => {
        const d = JSON.parse(e.data) as Partial<Job>;
        setJob((prev) => (prev ? { ...prev, ...d } : prev));
        if (d.status === "completed" || d.status === "failed") {
          es.close();
          setBusy(false);
          if (d.status === "failed") {
            setError(d.error || "Job failed");
            return;
          }
          try {
            setFindings(await getFindings(created.job_id));
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Could not load findings",
            );
          }
        }
      };
      es.onerror = () => {
        es.close();
        setBusy(false);
      };
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
      setBusy(false);
    }
  }

  async function sendGuideline(f: File | undefined) {
    if (!f) return;
    try {
      const r = await uploadGuideline(f);
      setNote(`Uploaded ${r.filename}`);
    } catch (err) {
      setNote(err instanceof Error ? err.message : "Upload failed");
    }
  }

  return (
    <div
      style={{
        maxWidth: 1100,
        margin: "0 auto",
        padding: 24,
        fontFamily: "system-ui, sans-serif",
      }}
    >
      <h1>AI Code Auditor</h1>
      <p>
        <Link href="/results" style={{ color: "#60a5fa" }}>
          Results dashboard
        </Link>
      </p>
      <div style={box}>
        <h2>Analyze a project</h2>
        <label>
          <input
            type="radio"
            checked={mode === "zip"}
            onChange={() => setMode("zip")}
          />{" "}
          Upload .zip
        </label>{" "}
        <label>
          <input
            type="radio"
            checked={mode === "git"}
            onChange={() => setMode("git")}
          />{" "}
          Git URL
        </label>
        <div style={{ margin: "12px 0" }}>
          {mode === "zip" ? (
            <input
              type="file"
              accept=".zip"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          ) : (
            <input
              style={{ width: "100%", padding: 8 }}
              placeholder="https://github.com/user/repo.git"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          )}
        </div>
        <button
          style={{ ...btn, opacity: busy ? 0.6 : 1 }}
          disabled={busy}
          onClick={start}
        >
          {busy ? "Analyzing…" : "Start analysis"}
        </button>
        <div style={{ marginTop: 12, fontSize: 14 }}>
          Guideline files (PDF / Markdown / txt):{" "}
          <input
            type="file"
            accept=".pdf,.md,.markdown,.txt"
            onChange={(e) => sendGuideline(e.target.files?.[0])}
          />
          {note && <span> {note}</span>}
        </div>
        {job && (
          <div style={{ marginTop: 16 }}>
            <div style={{ background: "#e4e4e7", borderRadius: 6, height: 12 }}>
              <div
                style={{
                  width: `${job.progress}%`,
                  background: "#16a34a",
                  height: 12,
                  borderRadius: 6,
                }}
              />
            </div>
            <small>
              {job.progress}% · {job.status} · {job.message} ·{" "}
              {job.files_scanned} file(s)
            </small>
          </div>
        )}
        {error && <p style={{ color: "#b91c1c" }}>{error}</p>}
      </div>
      {findings && job && (
        <FindingsView findings={findings} jobId={job.job_id} />
      )}
    </div>
  );
}
