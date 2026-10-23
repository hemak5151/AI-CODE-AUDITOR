export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Finding = {
  finding_id: string;
  cwe_id?: string | null;
  severity: Severity;
  confidence: number;
  message: string;
  explanation: string;
  file_path: string;
  line_number: number;
  evidence?: string | null;
  source: string;
  suggested_remediation?: string | null;
};
export type Job = {
  job_id: string;
  source_type: string;
  source: string;
  status: "queued" | "running" | "completed" | "failed";
  progress: number;
  message: string;
  error?: string | null;
  files_scanned: number;
};
export type Patch = {
  finding_id: string;
  unified_diff?: string | null;
  description: string;
};

const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function parse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const d = await res.json();
      if (typeof d.detail === "string") msg = d.detail;
    } catch {
      /* keep default message */
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

export async function createGitJob(source: string): Promise<Job> {
  const res = await fetch(`${base}/api/jobs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source_type: "git", source }),
  });
  return parse<Job>(res);
}

export async function uploadZip(file: File): Promise<Job> {
  const form = new FormData();
  form.append("file", file);
  return parse<Job>(
    await fetch(`${base}/api/jobs/upload`, { method: "POST", body: form }),
  );
}

export async function uploadGuideline(
  file: File,
): Promise<{ filename: string; size_bytes: number }> {
  const form = new FormData();
  form.append("file", file);
  return parse(
    await fetch(`${base}/api/guidelines`, { method: "POST", body: form }),
  );
}

export async function getFindings(jobId: string): Promise<Finding[]> {
  return parse<Finding[]>(await fetch(`${base}/api/jobs/${jobId}/findings`));
}

export async function getPatch(findingId: string): Promise<Patch | null> {
  const res = await fetch(`${base}/api/findings/${findingId}/patch`);
  if (res.status === 404) return null;
  return parse<Patch>(res);
}

export const eventsUrl = (jobId: string) => `${base}/api/jobs/${jobId}/events`;
