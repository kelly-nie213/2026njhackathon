// BreachDetector client lib — talks to the crawl/breaches/report endpoints and
// provides a deterministic risk + action engine so the report renders even when
// no Anthropic key is configured.

import type { Severity } from "./types";
import { checkCommitmentLocally } from "./bloom";

export interface CrawlResult {
  domain: string;
  pagesScanned: string[];
  emails: string[];
  names: string[];
  phones: string[];
}

export interface BreachInfo {
  name: string;
  title: string;
  breachDate: string;
  dataClasses: string[];
  description?: string;
}

export interface EmailBreach {
  email: string;
  commitment: string; // SHA-256(email) — what the server actually saw
  status: "breached" | "clean" | "error";
  breachCount: number;
  breaches: BreachInfo[];
  error?: string;
}

export interface BreachLookup {
  source: "live" | "error";
  zkp: boolean;          // true when server response contained no plaintext emails
  bloomChecked: boolean; // true if we ran the local Bloom filter first
  results: EmailBreach[];
}

export interface RiskItem {
  title: string;
  severity: Severity;
  consequence: string;
  whoAtRisk: string[];
}

export interface ActionItem {
  title: string;
  why: string;
  effort: string;
  steps: string[];
}

export interface BreachReport {
  summary: string;
  risks: RiskItem[];
  actions: ActionItem[];
}

export interface DomainCheckItem {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail";
  severity: Severity;
  title: string;
  detail: string;
  evidence: string;
}

export interface DomainSecurity {
  domain: string;
  checks: DomainCheckItem[];
  worst: Severity;
  spoofable: boolean;
}

export interface WebCheckItem {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail";
  severity: Severity;
  title: string;
  detail: string;
  evidence: string;
}

export interface WebSecurity {
  domain: string;
  checks: WebCheckItem[];
  worst: Severity;
  grade: string;
  https: boolean;
}

export interface ReputationItem {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail";
  severity: Severity;
  title: string;
  detail: string;
  evidence: string;
}

export interface Reputation {
  domain: string;
  flagged: boolean;
  worst: Severity;
  checks: ReputationItem[];
  notChecked: { name: string; reason: string }[];
  sourcesChecked: number;
}

/** Compact code-audit summary folded into the single unified action plan. */
export interface CodeSummary {
  security: number;
  bug: number;
  top: string[];
}

/* --------------------------- API calls --------------------------- */

/** Live DNS spoofing-protection check. Returns null on failure (optional in the UI). */
export async function checkDomainSecurity(domain: string): Promise<DomainSecurity | null> {
  try {
    const res = await fetch("/api/domain-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    if (res.ok) return res.json();
  } catch {
    /* optional — don't sink the scan */
  }
  return null;
}

/** Live TLS + HTTP-security-headers check. Returns null on failure (optional in the UI). */
export async function checkWebSecurity(domain: string): Promise<WebSecurity | null> {
  try {
    const res = await fetch("/api/web-security", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    if (res.ok) return res.json();
  } catch {
    /* optional — don't sink the scan */
  }
  return null;
}

/** Live threat-intel / reputation check. Returns null on failure (optional in the UI). */
export async function checkReputation(domain: string): Promise<Reputation | null> {
  try {
    const res = await fetch("/api/reputation", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    if (res.ok) return res.json();
  } catch {
    /* optional — don't sink the scan */
  }
  return null;
}

export async function crawlDomain(domain: string): Promise<CrawlResult> {
  const res = await fetch("/api/crawl", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  if (!res.ok) {
    const { error } = await res.json().catch(() => ({ error: "crawl_failed" }));
    throw new Error(error || "crawl_failed");
  }
  return res.json();
}

/** SHA-256 of a normalized email — matches what the server computes. */
async function commitEmail(email: string): Promise<string> {
  const data = new TextEncoder().encode(email.toLowerCase().trim());
  const buf  = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function lookupBreaches(emails: string[]): Promise<BreachLookup> {
  // Phase 1 — hash every email in the browser before anything leaves.
  const commitments = await Promise.all(emails.map(commitEmail));

  // Phase 4 — check the local Bloom filter first.
  // "Definitely not breached" → skip those emails entirely (vault stays sealed).
  // "Probably breached" / "unknown" → pass to server for confirmation.
  const localResults = await Promise.all(
    commitments.map((c) => checkCommitmentLocally(c))
  );
  const bloomChecked = localResults.some((r) => r !== null);

  // Only send emails the filter didn't definitively clear.
  const toCheck        = emails.filter((_, i) => localResults[i] !== false);
  const toCheckCommits = commitments.filter((_, i) => localResults[i] !== false);

  // Emails cleared by the filter get clean results immediately — no server query.
  const filterResults: EmailBreach[] = emails
    .filter((_, i) => localResults[i] === false)
    .map((email) => ({
      email,
      commitment:   commitments[emails.indexOf(email)],
      status:       "clean" as const,
      breachCount:  0,
      breaches:     [],
      bloomCleared: true,
    }));

  if (toCheck.length === 0) {
    // Every email cleared locally — server never queried.
    return { source: "live", zkp: true, bloomChecked, results: filterResults };
  }

  const res = await fetch("/api/breaches", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ emails: toCheck, commitments: toCheckCommits }),
  });
  if (!res.ok) throw new Error("breach_lookup_failed");

  const raw = await res.json() as {
    source: "live" | "error";
    zkp: boolean;
    results: Array<{
      commitment: string;
      status: "breached" | "clean" | "error";
      breachCount: number;
      breaches: BreachInfo[];
      error?: string;
    }>;
  };

  // Reconcile commitment → email locally.
  const commitToEmail = new Map(toCheckCommits.map((c, i) => [c, toCheck[i]]));

  const serverResults: EmailBreach[] = raw.results.map((r) => ({
    email:       commitToEmail.get(r.commitment) ?? "[unknown]",
    commitment:  r.commitment,
    status:      r.status,
    breachCount: r.breachCount,
    breaches:    r.breaches,
    ...(r.error ? { error: r.error } : {}),
  }));

  return {
    source:       raw.source,
    zkp:          raw.zkp ?? false,
    bloomChecked,
    results:      [...filterResults, ...serverResults],
  };
}

/** AI report with a deterministic fallback when no key / endpoint is up. */
export async function generateReport(
  crawl: CrawlResult,
  lookup: BreachLookup,
  orgName: string,
  domainSec?: DomainSecurity | null,
  webSec?: WebSecurity | null,
  reputation?: Reputation | null,
  code?: CodeSummary | null
): Promise<{ report: BreachReport; source: "ai" | "fallback" }> {
  try {
    const res = await fetch("/api/breach-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        orgName,
        domain: crawl.domain,
        emails: crawl.emails,
        names: crawl.names,
        phones: crawl.phones,
        breaches: lookup.results.map((r) => ({
          email: r.email,
          breachCount: r.breachCount,
          breaches: r.breaches,
        })),
        domainSecurity: domainSec
          ? {
              spoofable: domainSec.spoofable,
              checks: domainSec.checks.map((c) => ({
                label: c.label,
                status: c.status,
                title: c.title,
              })),
            }
          : null,
        webSecurity: webSec
          ? {
              grade: webSec.grade,
              checks: webSec.checks
                .filter((c) => c.status !== "pass")
                .map((c) => ({ label: c.label, status: c.status, title: c.title })),
            }
          : null,
        reputation: reputation
          ? {
              flagged: reputation.flagged,
              hits: reputation.checks
                .filter((c) => c.status === "fail")
                .map((c) => ({ label: c.label, title: c.title })),
            }
          : null,
        codeSecurity: code && (code.security || code.bug)
          ? { security: code.security, bug: code.bug, top: code.top }
          : null,
      }),
    });
    if (res.ok) return { report: await res.json(), source: "ai" };
  } catch {
    /* fall through */
  }
  return { report: buildReport(crawl, lookup, domainSec, webSec, reputation, code), source: "fallback" };
}

/* ----------------------- deterministic engine ----------------------- */

export function totalBreaches(lookup: BreachLookup): number {
  return lookup.results.reduce((s, r) => s + r.breachCount, 0);
}

export function breachedAccounts(lookup: BreachLookup): number {
  return lookup.results.filter((r) => r.status === "breached").length;
}

export interface DomainBreachRollup {
  title: string;
  breachDate: string;
  emailsAffected: number;
  dataClasses: string[];
  hasPasswords: boolean;
}

/**
 * Domain-level view of the breach data: roll the per-email hits up into the
 * distinct breaches that touched this domain's public addresses, with how many
 * of those addresses each breach hit. Derived from the real per-email lookups
 * (a full "every account at the domain" enumeration needs domain verification).
 */
export function domainBreachSummary(lookup: BreachLookup): {
  breachedEmails: number;
  distinctBreaches: number;
  breaches: DomainBreachRollup[];
} {
  const map = new Map<string, DomainBreachRollup>();
  for (const r of lookup.results) {
    if (r.status !== "breached") continue;
    for (const b of r.breaches) {
      const cur =
        map.get(b.title) ||
        { title: b.title, breachDate: b.breachDate || "", emailsAffected: 0, dataClasses: [], hasPasswords: false };
      cur.emailsAffected += 1;
      for (const c of b.dataClasses || []) if (!cur.dataClasses.includes(c)) cur.dataClasses.push(c);
      if ((b.dataClasses || []).some((c) => /password/i.test(c))) cur.hasPasswords = true;
      if (!cur.breachDate && b.breachDate) cur.breachDate = b.breachDate;
      map.set(b.title, cur);
    }
  }
  const breaches = [...map.values()].sort(
    (a, b) => b.emailsAffected - a.emailsAffected || (a.title < b.title ? -1 : 1)
  );
  return { breachedEmails: breachedAccounts(lookup), distinctBreaches: breaches.length, breaches };
}

function buildReport(
  crawl: CrawlResult,
  lookup: BreachLookup,
  domainSec?: DomainSecurity | null,
  webSec?: WebSecurity | null,
  reputation?: Reputation | null,
  code?: CodeSummary | null
): BreachReport {
  const breached = lookup.results.filter((r) => r.status === "breached");
  const worst = [...breached].sort((a, b) => b.breachCount - a.breachCount)[0];
  const hasPasswords = breached.some((r) =>
    r.breaches.some((b) => b.dataClasses.some((c) => /password/i.test(c)))
  );

  const risks: RiskItem[] = [];

  if (reputation?.flagged) {
    const hits = reputation.checks.filter((c) => c.status === "fail");
    risks.push({
      title: "Your domain is flagged on threat-intelligence blocklists",
      severity: "critical",
      consequence:
        "Live threat feeds (" +
        hits.map((c) => c.label).join(", ") +
        ") report this domain is distributing malware or hosting phishing. Visitors' browsers may warn or block your site, donors will distrust you, and it often means the site is already compromised. Treat this as an active incident.",
      whoAtRisk: ["Everyone who visits your site", "Donors & supporters", "Your reputation"],
    });
  }

  if (domainSec?.spoofable) {
    risks.push({
      title: "Your domain can be spoofed in email",
      severity: "high",
      consequence:
        "Without enforced SPF/DMARC, an attacker can send email that appears to come from your real address — " +
        "fake donation appeals to supporters or 'pay this invoice' notes to staff that pass basic checks.",
      whoAtRisk: ["Donors & supporters", "Staff & volunteers", "Vendors"],
    });
  }

  if (breached.length > 0) {
    risks.push({
      title: `${breached.length} staff email${breached.length === 1 ? "" : "s"} found in known data breaches`,
      severity: breached.length >= 3 ? "critical" : "high",
      consequence:
        "Attackers can buy these addresses (and any leaked passwords) cheaply and try them against your email, " +
        "donation platform, and bank logins. Reused passwords let them walk straight in.",
      whoAtRisk: breached.map((r) => r.email).slice(0, 6),
    });
  }

  if (hasPasswords) {
    risks.push({
      title: "Leaked passwords tied to staff accounts",
      severity: "critical",
      consequence:
        "If anyone reused a breached password, an attacker can log in as them — read donor emails, redirect " +
        "payments, or send fraud from a real, trusted account. This is the single fastest way in.",
      whoAtRisk: worst ? [worst.email] : ["Anyone reusing passwords"],
    });
  }

  if (webSec) {
    const webIssues = webSec.checks.filter((c) => c.status !== "pass");
    if (webIssues.length > 0) {
      const sev = webSec.worst === "critical" ? "critical" : webSec.worst === "high" ? "high" : "medium";
      risks.push({
        title: `Website security gaps (grade ${webSec.grade})`,
        severity: sev,
        consequence:
          "Missing protections in how your site is served — " +
          webIssues.slice(0, 4).map((c) => c.label).join(", ") +
          " — leave visitors open to attacks like cross-site scripting, clickjacking, or traffic interception.",
        whoAtRisk: ["Anyone who visits your website", "Logged-in staff/admins"],
      });
    }
  }

  if (code && code.security > 0) {
    risks.push({
      title: `${code.security} security issue${code.security === 1 ? "" : "s"} in your website's code`,
      severity: code.security >= 3 ? "high" : "medium",
      consequence:
        "The JavaScript your site ships to visitors has flagged issues" +
        (code.top.length ? ` (e.g. ${code.top.slice(0, 3).join(", ")})` : "") +
        ". Depending on the type, these can expose keys, enable cross-site scripting, or send data insecurely.",
      whoAtRisk: ["Anyone who visits your website"],
    });
  }

  if (crawl.emails.length > 0) {
    risks.push({
      title: `${crawl.emails.length} email address${crawl.emails.length === 1 ? "" : "es"} are public on your site`,
      severity: crawl.emails.length >= 5 ? "high" : "medium",
      consequence:
        "Published addresses are the raw material for targeted phishing. AI can now write a flawless, personalized " +
        "scam to each one — fake invoices, donor refunds, or a 'note from the director'.",
      whoAtRisk: crawl.emails.slice(0, 6),
    });
  }

  if (crawl.names.length > 0 || crawl.phones.length > 0) {
    risks.push({
      title: "Staff names and phone numbers are exposed",
      severity: "medium",
      consequence:
        "Names + roles + phone numbers let an attacker impersonate leadership convincingly and run phone scams " +
        "(vishing) — e.g. a fake 'CEO' texting a volunteer to buy gift cards.",
      whoAtRisk: [
        ...crawl.names.slice(0, 4),
        ...crawl.phones.slice(0, 2),
      ].filter(Boolean),
    });
  }

  if (risks.length === 0) {
    risks.push({
      title: "No major exposure detected in this scan",
      severity: "low",
      consequence:
        "We didn't find public emails in breaches on this pass. Stay protected — attackers re-scan constantly, so " +
        "keep the basics (MFA, unique passwords) in place.",
      whoAtRisk: ["Whole organization"],
    });
  }

  const actions: ActionItem[] = [
    {
      title: "Turn on two-factor authentication (MFA) everywhere",
      why: "Even with a stolen password, MFA blocks the vast majority of account takeovers. This single step neutralizes most of the breach risk above.",
      effort: "30 min",
      steps: [
        "Start with email, then your donation/payment platform and bank.",
        "Use an authenticator app (Google Authenticator, Authy) rather than SMS where possible.",
        "Make sure every staff member and volunteer with an account does it too.",
      ],
    },
    {
      title: "Reset passwords for breached accounts",
      why: "Any password seen in a breach must be considered public. New, unique passwords cut off attackers who already have the old ones.",
      effort: "30 min",
      steps: [
        breached.length
          ? `Reset passwords for: ${breached.map((r) => r.email).join(", ")}.`
          : "Reset any password that's been reused across more than one site.",
        "Use a password manager (Bitwarden is free) so each login is unique.",
        "Never reuse a password between email, banking, and donation tools.",
      ],
    },
    {
      title: "Brief your team on impersonation scams",
      why: "Your public names and emails make targeted phishing easy. People who know the playbook don't fall for it.",
      effort: "30 min",
      steps: [
        "Tell staff: any request to move money, buy gift cards, or change bank details must be confirmed by phone on a known number.",
        "Treat urgency + secrecy as a red flag, even from a 'familiar' name.",
        "When unsure, forward suspicious messages to one designated person before acting.",
      ],
    },
    {
      title: "Reduce what's public on your website",
      why: "Less harvestable data means fewer, weaker attacks. Shared inboxes and contact forms are far safer than personal addresses.",
      effort: "1 hour",
      steps: [
        "Replace personal staff emails with a shared inbox (info@) or a contact form.",
        "Remove direct phone numbers that aren't strictly necessary.",
        "Avoid publishing full org charts with names, roles, and contact details together.",
      ],
    },
  ];

  if (webSec && webSec.checks.some((c) => c.status !== "pass")) {
    actions.push({
      title: "Add the missing web security headers (and keep HTTPS healthy)",
      why: "These headers are how the browser blocks XSS, clickjacking and traffic interception. They're set once at your web host/CDN and protect every visitor.",
      effort: "1 hour",
      steps: [
        "Ask your host/CDN (Cloudflare, Netlify, etc.) to add: Content-Security-Policy, Strict-Transport-Security (HSTS), X-Frame-Options, and X-Content-Type-Options: nosniff.",
        "Make sure http:// redirects to https:// and your certificate auto-renews.",
        "Re-run this scan to confirm the grade improves.",
      ],
    });
  }

  if (code && (code.security > 0 || code.bug > 0)) {
    actions.push({
      title: "Review the issues found in your website's code",
      why: "Most are in third-party widgets/plugins you can't edit directly, so the fix is usually updating or replacing them rather than rewriting code.",
      effort: "varies",
      steps: [
        "Open the Website code security section for the file and line of each finding.",
        "For your own code, rotate any exposed keys and sanitize values written into the page.",
        "For third-party scripts, update the plugin/widget or contact the vendor.",
      ],
    });
  }

  if (domainSec?.spoofable) {
    actions.unshift({
      title: "Lock down your domain so attackers can't spoof your email",
      why: "Enforced SPF + DMARC stop criminals from sending scam emails that look like they came from your real address — protecting donors, staff and vendors at once.",
      effort: "1 hour",
      steps: [
        "Ask your email provider (or a volunteer) to add a DMARC record and set the policy to 'reject'.",
        "Make sure SPF lists your real senders and ends in -all, and turn on DKIM signing.",
        "Add a line to your newsletter/site: 'We will never email you new bank details.'",
      ],
    });
  }

  const summary =
    breached.length > 0
      ? `We found ${crawl.emails.length} public email${crawl.emails.length === 1 ? "" : "s"} on ${crawl.domain}, and ${breached.length} of them appear in known data breaches. Here's what that means and exactly what to do — start at the top.`
      : `We scanned ${crawl.domain} and reviewed the public contact info we found. Here's your exposure and a short plan to stay protected.`;

  return { summary, risks, actions };
}

export const SEVERITY_META: Record<
  Severity,
  { label: string; color: string; bg: string }
> = {
  low: { label: "Low", color: "var(--color-risk-low)", bg: "rgba(52,211,153,0.12)" },
  medium: { label: "Medium", color: "var(--color-risk-med)", bg: "rgba(251,191,36,0.12)" },
  high: { label: "High", color: "var(--color-risk-high)", bg: "rgba(251,113,133,0.12)" },
  critical: { label: "Critical", color: "var(--color-risk-crit)", bg: "rgba(244,63,94,0.14)" },
};
