import type { Evidence, Finding, ScanStatus } from "./types";

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const body = await response.json();
  if (!response.ok) {
    const message = body?.error?.message ?? `Request failed (${response.status})`;
    throw new Error(message);
  }
  return body as T;
}

export function getHealth(): Promise<{ ok: boolean; fixtures: string[]; llm: string }> {
  return request("/healthz");
}

export function createScan(fixture: string): Promise<{ scan_id: string; status: string }> {
  return request("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fixture }),
  });
}

export function getScan(scanId: string): Promise<ScanStatus> {
  return request(`/api/scans/${scanId}`);
}

export async function getFindings(scanId: string): Promise<Finding[]> {
  const body = await request<{ findings: Finding[] }>(`/api/scans/${scanId}/findings`);
  return body.findings;
}

export function getEvidence(scanId: string, evidenceId: string): Promise<Evidence> {
  return request(`/api/scans/${scanId}/evidence/${evidenceId}`);
}
