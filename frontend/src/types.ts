export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  rule_id: string;
  category: string;
  severity: Severity;
  title: string;
  summary: string;
  capabilities: string[];
  evidence_ids: string[];
  ai_claim_ids: string[];
  corroboration: string;
  confidence: number;
  reason: string;
}

export interface Evidence {
  id: string;
  kind: string;
  path: string;
  line_start: number | null;
  line_end: number | null;
  snippet: string;
  extractor: string;
  file_sha256: string;
}

export interface RiskItem {
  finding_id: string;
  severity: string;
  confidence: number;
  weight: number;
  points: number;
}

export interface Risk {
  score: number;
  band: string;
  method: string;
  breakdown: RiskItem[];
}

export interface ScanStatus {
  scan_id: string;
  source: string;
  status: string;
  stage: string;
  files_scanned: number;
  tool_count: number;
  finding_count: number;
  critical_count: number;
  risk: Risk | null;
  error: string | null;
}
