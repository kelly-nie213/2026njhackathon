// JS Auditor client lib — calls the /api/js-audit (static scan) and
// /api/js-report (AI plain-language plan) endpoints, with a deterministic
// fallback so the report still renders when no Anthropic key is configured.

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

export interface JsRecommendation {
  title: string;
  why: string;
  effort: string;
  steps: string[];
}

export interface JsReport {
  summary: string;
  recommendations: JsRecommendation[];
}

/* --------------------------- API calls --------------------------- */

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

/** AI plain-language plan with a deterministic fallback. */
export async function generateJsReport(
  audit: JsAuditResult,
  orgName: string
): Promise<{ report: JsReport; source: "ai" | "fallback" }> {
  try {
    const res = await fetch("/api/js-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        orgName,
        domain: audit.domain,
        counts: audit.counts,
        findings: audit.findings,
      }),
    });
    if (res.ok) return { report: await res.json(), source: "ai" };
  } catch {
    /* fall through */
  }
  return { report: buildJsReport(audit), source: "fallback" };
}

/* ----------------------- deterministic engine ----------------------- */

export function totalFindings(a: JsAuditResult): number {
  return a.findings.length;
}

export function worstSeverity(a: JsAuditResult): Severity {
  if (a.counts.critical) return "critical";
  if (a.counts.high) return "high";
  if (a.counts.medium) return "medium";
  return "low";
}

function buildJsReport(a: JsAuditResult): JsReport {
  const sec = a.findings.filter((f) => f.category === "security");
  const bugs = a.findings.filter((f) => f.category === "bug");
  const secrets = a.findings.filter((f) =>
    ["aws-key", "google-key", "stripe-secret", "slack-token", "private-key", "jwt", "generic-secret"].includes(f.id)
  );
  const xss = a.findings.filter((f) =>
    ["eval", "new-function", "document-write", "inner-html", "insert-html", "timer-string"].includes(f.id)
  );
  const http = a.findings.filter((f) => f.id === "insecure-http" || f.id === "ws-insecure");
  const libs = a.findings.filter((f) => ["jquery-old", "angularjs-eol", "bootstrap-old"].includes(f.id));

  const recommendations: JsRecommendation[] = [];

  if (secrets.length > 0) {
    recommendations.push({
      title: "Rotate and remove any exposed keys or secrets",
      why: "Anything shipped to the browser is public. A real key in this code can let an attacker spend your money or read your data — assume it's already leaked.",
      effort: "1 hour",
      steps: [
        `Review the ${secrets.length} flagged credential${secrets.length === 1 ? "" : "s"} and decide which are real secrets (vs. public config like Firebase).`,
        "Rotate any real secret immediately in the provider's dashboard, then delete it from the front-end code.",
        "Keep secret keys on the server only; the browser should never hold a secret API key.",
      ],
    });
  }
  if (libs.length > 0) {
    recommendations.push({
      title: "Update outdated JavaScript libraries",
      why: "Old library versions have publicly documented vulnerabilities that automated tools scan for. Updating closes known holes for free.",
      effort: "1-2 hours",
      steps: [
        `Update: ${libs.map((l) => l.title.replace("Outdated ", "")).join("; ")}.`,
        "If your site is on Wix/Squarespace/WordPress, this usually means updating a theme or plugin, or asking your host.",
        "Re-run this scan afterward to confirm the warnings clear.",
      ],
    });
  }
  if (xss.length > 0) {
    recommendations.push({
      title: "Review code that writes HTML or runs strings as code",
      why: "These patterns (innerHTML, eval, document.write) are how cross-site-scripting attacks inject malicious code. They're only dangerous with untrusted input — but worth a look.",
      effort: "varies",
      steps: [
        "Have whoever maintains your site check each flagged spot — most are in third-party widgets you can't edit.",
        "Where it's your own code, sanitize input or use textContent instead of innerHTML.",
        "Add a Content-Security-Policy header to limit the damage of any injection.",
      ],
    });
  }
  if (http.length > 0) {
    recommendations.push({
      title: "Switch insecure http:// calls to https://",
      why: "Plain-http requests on an otherwise-secure site can be read or altered by anyone on the network (mixed content).",
      effort: "30 min",
      steps: [
        "Find and update the flagged http:// (and ws://) URLs to their https:// equivalents.",
        "Most are in embedded scripts/widgets — update or replace the widget if you can't edit it.",
      ],
    });
  }
  recommendations.push({
    title: "Clean up leftover debug code",
    why: "TODO notes, debugger statements, and silently-swallowed errors are a sign code shipped unfinished and make real failures hard to catch.",
    effort: "30 min",
    steps: [
      "Ask your developer/host to remove debugger statements and resolve the flagged TODO/FIXME notes.",
      "Make sure errors are logged, not silently ignored, so problems surface early.",
    ],
  });

  const summary =
    sec.length > 0
      ? `We scanned ${a.scriptsScanned.length} script${a.scriptsScanned.length === 1 ? "" : "s"} on ${a.domain} and found ${sec.length} potential security issue${sec.length === 1 ? "" : "s"}${bugs.length ? ` and ${bugs.length} code-quality issue${bugs.length === 1 ? "" : "s"}` : ""}. Here's what matters and how to fix it — start at the top.`
      : a.findings.length > 0
        ? `We scanned ${a.scriptsScanned.length} script${a.scriptsScanned.length === 1 ? "" : "s"} on ${a.domain}. No high-risk security issues stood out, but there are ${a.findings.length} smaller items worth a look.`
        : `We scanned ${a.scriptsScanned.length} script${a.scriptsScanned.length === 1 ? "" : "s"} on ${a.domain} and didn't flag any obvious bugs or security risks. Keep your site and its plugins updated to stay clean.`;

  return { summary, recommendations };
}

export const SEVERITY_META: Record<Severity, { label: string; color: string; bg: string }> = {
  low: { label: "Low", color: "var(--color-risk-low)", bg: "rgba(52,211,153,0.12)" },
  medium: { label: "Medium", color: "var(--color-risk-med)", bg: "rgba(251,191,36,0.12)" },
  high: { label: "High", color: "var(--color-risk-high)", bg: "rgba(251,113,133,0.12)" },
  critical: { label: "Critical", color: "var(--color-risk-crit)", bg: "rgba(244,63,94,0.14)" },
};
