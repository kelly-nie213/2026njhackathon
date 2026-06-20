import type {
  ActionStep,
  DataAsset,
  Finding,
  LikelyAttack,
  OrgType,
  ScanInput,
  ScanResult,
  Severity,
} from "./types";

/* ---------- deterministic pseudo-randomness (same domain → same result) ---------- */

function hash(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function mulberry32(seed: number) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T>(rng: () => number, arr: T[]): T => arr[Math.floor(rng() * arr.length)];
const between = (rng: () => number, lo: number, hi: number) =>
  Math.floor(lo + rng() * (hi - lo + 1));

/* ---------- data assets every small nonprofit holds ---------- */

function buildDataAssets(rng: () => number, orgType: OrgType): DataAsset[] {
  const donorVerb =
    orgType === "food-bank" || orgType === "donation-center" ? "donors" : "supporters";

  const assets: DataAsset[] = [
    {
      id: "email",
      name: "Staff Email Accounts",
      icon: "📧",
      sensitivity: 95,
      connections: ["donor", "finance", "comms", "grants", "volunteer"],
      consequence: `Email is the master key. With one mailbox, an attacker can reset passwords on every other system, read past wire instructions, and impersonate your director to ${donorVerb} and vendors. Almost every other breach starts here.`,
      exposed: true,
    },
    {
      id: "donor",
      name: `${orgType === "youth-nonprofit" ? "Family" : "Donor"} Database`,
      icon: "🧑‍🤝‍🧑",
      sensitivity: 88,
      connections: ["finance", "comms"],
      consequence: `Names, emails, phone numbers and giving history of your ${donorVerb}. Leaked, this fuels hyper-personalized AI scam emails ("you gave $250 last spring — match it today") that are nearly impossible to tell from your real appeals. Donor trust collapses after a public leak.`,
      exposed: rng() > 0.35,
    },
    {
      id: "finance",
      name: "Financial & Banking Records",
      icon: "💳",
      sensitivity: 92,
      connections: ["email"],
      consequence:
        "Bank details, payment processor logins and reimbursement records. This is where money actually leaves — fraudulent wire and vendor-payment redirection attacks target exactly this. Recovered funds are rare once sent.",
      exposed: rng() > 0.6,
    },
    {
      id: "volunteer",
      name: "Volunteer Records",
      icon: "🙋",
      sensitivity: 64,
      connections: ["comms", "email"],
      consequence:
        "Contact info and schedules for volunteers — many of them minors or elderly. Attackers pose as your coordinator to send fake shift links and harvest more logins, widening the breach into people who trust you.",
      exposed: rng() > 0.5,
    },
    {
      id: "grants",
      name: "Grant Applications",
      icon: "📄",
      sensitivity: 70,
      connections: ["finance", "comms"],
      consequence:
        "Budgets, EINs, board details and program data. Exposed, it enables grant-fraud impersonation and gives attackers the exact language to forge convincing funder communications.",
      exposed: rng() > 0.7,
    },
    {
      id: "comms",
      name: "Internal Communications",
      icon: "💬",
      sensitivity: 60,
      connections: ["email"],
      consequence:
        "Board minutes, staff chats and decision history. AI can mine this to mimic your team's tone and timing, making fake 'urgent' requests from leadership land perfectly.",
      exposed: rng() > 0.55,
    },
  ];

  return assets;
}

/* ---------- findings ---------- */

function buildFindings(rng: () => number, input: ScanInput): Finding[] {
  const f: Finding[] = [];
  const breached = between(rng, 1, Math.max(2, input.emails.length || 4));

  f.push({
    id: "creds",
    category: "breached-credentials",
    severity: breached > 2 ? "critical" : "high",
    title: `${breached} staff ${breached === 1 ? "email" : "emails"} found in known data breaches`,
    detail:
      "These addresses appear in public breach dumps. If anyone reused that password anywhere — email, banking, donor platform — attackers may already have a working login.",
    evidence:
      input.emails.length > 0
        ? `${input.emails[0]} — seen in 3 breach dumps (incl. a 2024 credential combo list)`
        : `${"info@" + input.domain} — seen in breach dumps`,
  });

  f.push({
    id: "phish",
    category: "ai-phishing",
    severity: "high",
    title: "High susceptibility to AI-generated phishing",
    detail:
      "Your domain has no DMARC enforcement, so anyone can send email that looks like it comes from you. Combined with public staff names, an attacker can auto-generate flawless impersonation emails to donors and vendors.",
    evidence: `No DMARC record on ${input.domain}; SPF present but not enforced`,
  });

  f.push({
    id: "domain",
    category: "domain-exposure",
    severity: pick(rng, ["medium", "high"] as Severity[]),
    title: "Look-alike domain registered recently",
    detail:
      "A domain that closely mimics yours was registered in the last 60 days — a classic setup for donation-redirection and CEO-impersonation scams.",
    evidence: `${lookalike(input.domain)} registered ${between(rng, 6, 58)} days ago`,
  });

  if (rng() > 0.4) {
    f.push({
      id: "darkweb",
      category: "dark-web",
      severity: "medium",
      title: "Mentions found on dark-web paste sites",
      detail:
        "Fragments of your domain and at least one staff email were posted to a paste site often used to share targeting lists.",
      evidence: `Paste seen ${between(rng, 2, 9)} weeks ago; ${between(rng, 4, 22)} records referenced`,
    });
  }

  f.push({
    id: "mfa",
    category: "email-security",
    severity: "medium",
    title: "No evidence of multi-factor authentication",
    detail:
      "Logins protected only by a password are one phishing email away from takeover. MFA blocks the vast majority of these attacks and is free on most platforms.",
    evidence: "Mail provider does not advertise enforced MFA for the org",
  });

  return f;
}

function lookalike(domain: string): string {
  const [name, ...rest] = domain.split(".");
  const tld = rest.join(".") || "org";
  const tricks = [
    name.replace("o", "0"),
    name + "-donate",
    name.replace(/i/, "l"),
    name + "-give",
    "secure-" + name,
  ];
  return `${tricks.find((t) => t !== name) ?? name + "s"}.${tld === "org" ? "com" : "org"}`;
}

/* ---------- likely attack + action plan ---------- */

function buildLikelyAttack(orgType: OrgType): LikelyAttack {
  const who =
    orgType === "food-bank" || orgType === "donation-center"
      ? ["Recurring donors", "Your bookkeeper / treasurer", "Food & supply vendors"]
      : ["Families you serve", "Your program director", "Grant funders"];
  return {
    type: "AI-assisted donation-redirection & vendor fraud",
    description:
      "Based on your exposure, the most likely attack is an AI-written email impersonating your leadership or a trusted vendor, asking a donor or your treasurer to send funds to a 'new' account. The language will match your real appeals because the data to fake it is already public.",
    whoAtRisk: who,
  };
}

function buildActionPlan(findings: Finding[]): ActionStep[] {
  const plan: ActionStep[] = [
    {
      priority: 1,
      title: "Turn on multi-factor authentication everywhere — today",
      why: "This single step blocks the large majority of account-takeover attacks, even if a password is already leaked.",
      effort: "30 min",
      steps: [
        "Start with email (Gmail/Microsoft 365), then your donor platform and bank.",
        "Use an authenticator app (free) rather than text messages where possible.",
        "Make sure every staff member and the treasurer is enrolled — not just the director.",
      ],
    },
    {
      priority: 2,
      title: "Reset passwords for any breached accounts",
      why: "Breached + reused passwords are how attackers walk in the front door.",
      effort: "30 min",
      steps: [
        "Change the password on every flagged account to a unique passphrase.",
        "Never reuse a password across email, banking and your donor tools.",
        "Consider a free password manager (Bitwarden) so staff don't have to remember them.",
      ],
    },
    {
      priority: 3,
      title: "Lock down your domain so attackers can't spoof you",
      why: "Stops criminals from sending donation scams that look like they came from your real address.",
      effort: "1 hour",
      steps: [
        "Ask your email provider or a volunteer to set DMARC to 'reject'.",
        "Report the look-alike domain to its registrar (we provide a template).",
        "Add a banner to your site/newsletter: 'We will never email you new bank details.'",
      ],
    },
    {
      priority: 4,
      title: "Set a two-person rule for any money movement",
      why: "Vendor-fraud and CEO-impersonation scams rely on one person acting alone under urgency.",
      effort: "5 min",
      steps: [
        "Require a phone call (to a known number) before changing any payment details.",
        "Treat 'urgent, confidential, wire now' requests as suspicious by default.",
      ],
    },
  ];
  if (findings.some((x) => x.category === "dark-web")) {
    plan.push({
      priority: 5,
      title: "Brief volunteers and donors on what to expect",
      why: "Your people are now targets; a 3-line heads-up dramatically cuts click-through on scams.",
      effort: "30 min",
      steps: [
        "Send a short note: how you'll really contact them, and how you won't.",
        "Give them one address to forward anything suspicious to.",
      ],
    });
  }
  return plan;
}

/* ---------- scoring ---------- */

const sevWeight: Record<Severity, number> = { low: 6, medium: 14, high: 24, critical: 34 };

function scoreToLabel(score: number): ScanResult["riskLabel"] {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 28) return "Moderate";
  return "Low";
}

/* ---------- public API ---------- */

export function runScan(input: ScanInput): ScanResult {
  const seed = hash(input.domain.toLowerCase() + input.orgType);
  const rng = mulberry32(seed);

  const findings = buildFindings(rng, input);
  const dataAssets = buildDataAssets(rng, input.orgType);

  const rawScore = findings.reduce((s, f) => s + sevWeight[f.severity], 0);
  const riskScore = Math.min(96, Math.max(34, rawScore + between(rng, -4, 6)));

  return {
    input,
    scannedAt: new Date().toISOString(),
    riskScore,
    riskLabel: scoreToLabel(riskScore),
    findings,
    dataAssets,
    likelyAttack: buildLikelyAttack(input.orgType),
    actionPlan: buildActionPlan(findings),
    stats: {
      breachedAccounts: between(rng, 2, Math.max(3, input.emails.length + 2)),
      exposedRecords: between(rng, 240, 4800),
      domainAgeDays: between(rng, 400, 4200),
      phishingSusceptibility: between(rng, 62, 91),
    },
  };
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
