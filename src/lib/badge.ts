// Verifiable security-health badge — client helpers. The org issues a badge
// from its completed scan, gets a token it can embed anywhere, and anyone can
// verify that token (here, or by fetching the public key and checking offline).
// The badge proves the grade + freshness without revealing the exact score or
// any individual finding. See server/badge.mjs for the cryptography.

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface BadgeIssue {
  grade: Grade;
  score: number;
  issuedAt: number;
  expiresAt: number;
  kid: string;
  token: string;
  badge: unknown;
  credential: unknown;
}

export interface VerifyCheck {
  label: string;
  ok: boolean;
  detail: string;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  kid?: string;
  domain?: string | null;
  org?: string | null;
  grade?: Grade | null;
  issuedAt?: number | null;
  expiresAt?: number | null;
  disclosed?: Record<string, string | number>;
  hidden?: number;
  checks: VerifyCheck[];
}

/** Compact summary of a finished scan → the inputs the server scores & signs. */
export interface ScanSummary {
  webGrade?: string;
  webChecks?: { status: string; severity: string }[];
  spoofable?: boolean;
  domainWorst?: string;
  reputationFlagged?: boolean;
  breachedAccounts?: number;
  jsCounts?: Record<string, number>;
  exposedEmails?: number;
}

export async function issueBadge(
  domain: string,
  orgName: string,
  summary: ScanSummary,
  reveal?: string[]
): Promise<BadgeIssue> {
  const res = await fetch("/api/badge/issue", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, orgName, summary, reveal }),
  });
  if (!res.ok) {
    const { error } = await res.json().catch(() => ({ error: "issue_failed" }));
    throw new Error(error || "issue_failed");
  }
  return res.json();
}

export async function verifyBadge(token: string, requireGrade?: string): Promise<VerifyResult> {
  const res = await fetch("/api/badge/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, requireGrade }),
  });
  if (!res.ok) throw new Error("verify_failed");
  return res.json();
}

export const GRADE_COLOR: Record<Grade, string> = {
  A: "#30d158",
  B: "#34c759",
  C: "#ffd60a",
  D: "#ff9f0a",
  F: "#ff453a",
};

export function fmtDate(ms?: number | null): string {
  if (!ms) return "—";
  return new Date(ms).toISOString().slice(0, 10);
}

/** The HTML snippet an org pastes on its site to show a live, self-verifying badge. */
export function embedSnippet(token: string, origin: string, min: Grade = "B"): string {
  const src = `${origin}/api/badge/svg?token=${encodeURIComponent(token)}&min=${min}`;
  const link = `${origin}/verify?token=${encodeURIComponent(token)}`;
  return `<a href="${link}" target="_blank" rel="noopener">\n  <img src="${src}" alt="Aegis verified security badge" width="240" height="64">\n</a>`;
}
