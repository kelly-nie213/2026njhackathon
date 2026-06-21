// BreachDetector client lib — talks to the crawl/breaches/report endpoints and
// provides a deterministic risk + action engine so the report renders even when
// no Anthropic key is configured.

import type { Severity } from "./types";

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
  status: "breached" | "clean" | "error";
  breachCount: number;
  breaches: BreachInfo[];
  error?: string;
  simulated?: boolean;
}

export interface BreachLookup {
  source: "live" | "demo";
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

/* --------------------------- API calls --------------------------- */

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

export async function lookupBreaches(emails: string[]): Promise<BreachLookup> {
  const res = await fetch("/api/breaches", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ emails }),
  });
  if (!res.ok) throw new Error("breach_lookup_failed");
  return res.json();
}

/** AI report with a deterministic fallback when no key / endpoint is up. */
export async function generateReport(
  crawl: CrawlResult,
  lookup: BreachLookup,
  orgName: string
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
      }),
    });
    if (res.ok) return { report: await res.json(), source: "ai" };
  } catch {
    /* fall through */
  }
  return { report: buildReport(crawl, lookup), source: "fallback" };
}

/* ----------------------- deterministic engine ----------------------- */

export function totalBreaches(lookup: BreachLookup): number {
  return lookup.results.reduce((s, r) => s + r.breachCount, 0);
}

export function breachedAccounts(lookup: BreachLookup): number {
  return lookup.results.filter((r) => r.status === "breached").length;
}

/** Worst severity, used to color the headline. */
export function overallSeverity(lookup: BreachLookup): Severity {
  const max = Math.max(0, ...lookup.results.map((r) => r.breachCount));
  if (max >= 4 || breachedAccounts(lookup) >= 3) return "critical";
  if (max >= 2 || breachedAccounts(lookup) >= 1) return "high";
  if (max >= 1) return "medium";
  return "low";
}

function buildReport(crawl: CrawlResult, lookup: BreachLookup): BreachReport {
  const breached = lookup.results.filter((r) => r.status === "breached");
  const worst = [...breached].sort((a, b) => b.breachCount - a.breachCount)[0];
  const hasPasswords = breached.some((r) =>
    r.breaches.some((b) => b.dataClasses.some((c) => /password/i.test(c)))
  );

  const risks: RiskItem[] = [];

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
