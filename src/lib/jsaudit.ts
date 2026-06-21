// JS Auditor client lib — calls /api/js-audit (static scan of the JavaScript a
// site ships) and returns the raw findings. The fix plan is folded into the
// unified Breach Detector action plan, so there's no separate report here.

import type { Severity } from "./types";

export type FindingCategory = "security" | "bug";

export interface JsFinding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  detail: string;
  file: string;
  party: 0 | 1; // 0 = first-party (your code), 1 = third-party
  line: number;
  snippet: string;
}

export interface ScannedScript {
  file: string;
  url: string;
  party: 0 | 1;
  bytes: number;
  inline: boolean;
}

export interface JsAuditResult {
  domain: string;
  scriptsScanned: ScannedScript[];
  externalFound: number;
  findings: JsFinding[];
  counts: Record<string, number>;
}

export async function auditJs(domain: string): Promise<JsAuditResult> {
  const res = await fetch("/api/js-audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  if (!res.ok) {
    const { error } = await res.json().catch(() => ({ error: "audit_failed" }));
    throw new Error(error || "audit_failed");
  }
  return res.json();
}

export function worstSeverity(a: JsAuditResult): Severity {
  if (a.counts.critical) return "critical";
  if (a.counts.high) return "high";
  if (a.counts.medium) return "medium";
  return "low";
}
