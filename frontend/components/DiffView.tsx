"use client";
import { useState } from "react";
import { DiffEditor } from "@monaco-editor/react";
import type { Patch } from "../lib/api";

function split(diff: string) {
  const original: string[] = [];
  const modified: string[] = [];
  for (const line of diff.split("\n")) {
    if (
      line.startsWith("---") ||
      line.startsWith("+++") ||
      line.startsWith("@@")
    )
      continue;
    if (line.startsWith("-")) original.push(line.slice(1));
    else if (line.startsWith("+")) modified.push(line.slice(1));
    else {
      original.push(line.replace(/^ /, ""));
      modified.push(line.replace(/^ /, ""));
    }
  }
  return { original: original.join("\n"), modified: modified.join("\n") };
}

export default function DiffView({ patch }: { patch: Patch }) {
  const [decision, setDecision] = useState<"accepted" | "rejected" | null>(
    null,
  );
  if (!patch.unified_diff) return <p>This patch has no diff.</p>;
  const { original, modified } = split(patch.unified_diff);

  function download() {
    const blob = new Blob([patch.unified_diff ?? ""], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${patch.finding_id}.patch`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div style={{ marginTop: 12 }}>
      <p>{patch.description}</p>
      <DiffEditor
        height="160px"
        language="python"
        original={original}
        modified={modified}
        theme="vs-dark"
        options={{
          readOnly: true,
          renderSideBySide: true,
          minimap: { enabled: false },
        }}
      />
      <div
        style={{ marginTop: 8, display: "flex", gap: 8, alignItems: "center" }}
      >
        <button onClick={() => setDecision("rejected")}>Reject</button>
        <button onClick={() => setDecision("accepted")}>Accept</button>
        <button onClick={download}>Download patch</button>
        {decision && <b>Patch {decision}</b>}
      </div>
    </div>
  );
}
