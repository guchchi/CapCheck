import type { Evidence, Finding, ScanStatus, ToolDef } from "./types";

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    const envelope = body as { error?: { message?: string } } | null;
    const message =
      envelope?.error?.message ?? `Request failed (${response.status})`;
    throw new Error(message);
  }
  return body as T;
}

export function getHealth(): Promise<{
  ok: boolean;
  fixtures: string[];
  llm: string;
}> {
  return request("/healthz");
}

export function createScan(input: {
  fixture?: string;
  repo_url?: string;
}): Promise<{ scan_id: string; status: string }> {
  return request("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function getScan(scanId: string): Promise<ScanStatus> {
  return request(`/api/scans/${scanId}`);
}

export async function getFindings(scanId: string): Promise<Finding[]> {
  const body = await request<{ findings: Finding[] }>(
    `/api/scans/${scanId}/findings`,
  );
  return body.findings;
}

export async function getTools(scanId: string): Promise<ToolDef[]> {
  const body = await request<{ tools: ToolDef[] }>(
    `/api/scans/${scanId}/tools`,
  );
  return body.tools;
}

export function getEvidence(
  scanId: string,
  evidenceId: string,
): Promise<Evidence> {
  return request(`/api/scans/${scanId}/evidence/${encodeURIComponent(evidenceId)}`);
}
