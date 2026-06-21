import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";
import {
  crawlDomain,
  lookupBreaches,
  generateReport,
  checkDomainSecurity,
  breachedAccounts,
  totalBreaches,
  SEVERITY_META,
  type CrawlResult,
  type BreachLookup,
  type BreachReport,
  type DomainSecurity,
  type EmailBreach,
} from "../lib/breach";
import {
  auditJs,
  generateJsReport,
  worstSeverity,
  type JsAuditResult,
  type JsReport,
  type JsFinding,
} from "../lib/jsaudit";

type Phase = "input" | "scanning" | "report";

const SCAN_STEPS = [
  "Reaching the website…",
  "Crawling public pages for contact info…",
  "Extracting emails, names & phone numbers…",
  "Checking your domain's email-spoofing protection (DNS)…",
  "Checking each email against breach databases…",
  "Scanning your site's code for bugs & security holes…",
  "Assessing risks and writing your action plan…",
];

export default function BreachDetector() {
  const [phase, setPhase] = useState<Phase>("input");
  const [domain, setDomain] = useState("");
  const [orgName, setOrgName] = useState("");
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const [crawl, setCrawl] = useState<CrawlResult | null>(null);
  const [lookup, setLookup] = useState<BreachLookup | null>(null);
  const [domainSec, setDomainSec] = useState<DomainSecurity | null>(null);
  const [report, setReport] = useState<BreachReport | null>(null);
  const [reportSource, setReportSource] = useState<"ai" | "fallback">("fallback");
  const [jsAudit, setJsAudit] = useState<JsAuditResult | null>(null);
  const [jsReport, setJsReport] = useState<JsReport | null>(null);
  const [jsReportSource, setJsReportSource] = useState<"ai" | "fallback">("fallback");

  const cleanDomain = domain.trim().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "");
  const canSubmit = cleanDomain.includes(".");

  const run = async () => {
    if (!canSubmit) return;
    setError(null);
    setPhase("scanning");
    setStep(0);
    try {
      setStep(1);
      const crawlRes = await crawlDomain(cleanDomain);
      setCrawl(crawlRes);

      // Domain spoofing (live DNS), breach lookup, and the code audit are all
      // independent of each other — run them together. The code audit is optional:
      // if it fails, it shouldn't sink the rest of the report.
      setStep(3);
      const [domainSecRes, lookupRes, auditRes] = await Promise.all([
        checkDomainSecurity(cleanDomain),
        crawlRes.emails.length
          ? lookupBreaches(crawlRes.emails)
          : Promise.resolve({ source: "live" as const, results: [] }),
        auditJs(cleanDomain).catch(() => null),
      ]);
      setDomainSec(domainSecRes);
      setLookup(lookupRes);
      setJsAudit(auditRes);
      setStep(6);

      // Breach report + code-audit report are separate AI calls — run in parallel.
      const orgLabel = orgName.trim() || crawlRes.domain;
      const [breachOut, jsOut] = await Promise.all([
        generateReport(crawlRes, lookupRes, orgLabel, domainSecRes),
        auditRes ? generateJsReport(auditRes, orgLabel) : Promise.resolve(null),
      ]);
      setReport(breachOut.report);
      setReportSource(breachOut.source);
      if (jsOut) {
        setJsReport(jsOut.report);
        setJsReportSource(jsOut.source);
      }
      setPhase("report");
    } catch (e) {
      const msg = (e as Error)?.message || "scan_failed";
      setError(
        msg === "unreachable"
          ? "We couldn't reach that website. Check the domain and try again."
          : msg === "invalid_domain"
            ? "That doesn't look like a valid domain (try something like aylus.org)."
            : "Something went wrong during the scan. Please try again."
      );
      setPhase("input");
    }
  };

  const resetAll = () => {
    setPhase("input");
    setCrawl(null);
    setLookup(null);
    setDomainSec(null);
    setReport(null);
    setJsAudit(null);
    setJsReport(null);
    setStep(0);
  };

  return (
    <div className="min-h-full pb-16">
      <Nav />

      <main className="mx-auto max-w-5xl px-6">
        <AnimatePresence mode="wait">
          {phase === "input" && (
            <InputView
              key="input"
              orgName={orgName}
              setOrgName={setOrgName}
              domain={domain}
              setDomain={setDomain}
              canSubmit={canSubmit}
              error={error}
              onSubmit={run}
              onExample={() => { setOrgName("AYLUS"); setDomain("aylus.org"); }}
            />
          )}

          {phase === "scanning" && (
            <ScanningView key="scanning" step={step} domain={cleanDomain} />
          )}

          {phase === "report" && crawl && lookup && report && (
            <ReportView
              key="report"
              orgName={orgName.trim() || crawl.domain}
              crawl={crawl}
              lookup={lookup}
              domainSec={domainSec}
              report={report}
              reportSource={reportSource}
              jsAudit={jsAudit}
              jsReport={jsReport}
              jsReportSource={jsReportSource}
              onReset={resetAll}
            />
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

/* ──────────────────────────────────────────────
   CYBER SHIELD — animated hero illustration
────────────────────────────────────────────── */

function CyberShield() {
  return (
    <div className="relative flex justify-center lg:justify-start float">
      {/* Ambient glow blob */}
      <div
        className="absolute inset-0 rounded-full"
        style={{
          background: "radial-gradient(ellipse, rgba(99,102,241,0.25) 0%, transparent 70%)",
          filter: "blur(40px)",
          transform: "scale(1.4)",
        }}
      />

      <svg
        width="260"
        height="260"
        viewBox="0 0 260 260"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        style={{ filter: "drop-shadow(0 0 22px rgba(99,102,241,0.45))" }}
      >
        <defs>
          <linearGradient id="shieldFill" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%"   stopColor="#818cf8" stopOpacity="0.95" />
            <stop offset="100%" stopColor="#a3e635" stopOpacity="0.85" />
          </linearGradient>
          <radialGradient id="shieldHighlight" cx="50%" cy="38%" r="55%">
            <stop offset="0%"   stopColor="white" stopOpacity="0.30" />
            <stop offset="100%" stopColor="white" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="outerRing" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%"   stopColor="#6366f1" stopOpacity="0.58" />
            <stop offset="50%"  stopColor="#a3e635" stopOpacity="0.38" />
            <stop offset="100%" stopColor="#6366f1" stopOpacity="0.58" />
          </linearGradient>
          <filter id="nodeglow">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* ── Outer rotating dashed ring ── */}
        <motion.g
          animate={{ rotate: 360 }}
          transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
          style={{ transformOrigin: "130px 130px" }}
        >
          <circle
            cx="130" cy="130" r="118"
            stroke="url(#outerRing)" strokeWidth="1"
            fill="none" strokeDasharray="8 14"
          />
          {/* Orbit nodes */}
          <circle cx="248" cy="130" r="5"   fill="#818cf8" filter="url(#nodeglow)" />
          <circle cx="130" cy="12"  r="4"   fill="#a3e635" filter="url(#nodeglow)" />
          <circle cx="12"  cy="130" r="4.5" fill="#818cf8" filter="url(#nodeglow)" />
          <circle cx="130" cy="248" r="4"   fill="#34d399" filter="url(#nodeglow)" />
        </motion.g>

        {/* ── Inner counter-rotating ring ── */}
        <motion.g
          animate={{ rotate: -360 }}
          transition={{ duration: 12, repeat: Infinity, ease: "linear" }}
          style={{ transformOrigin: "130px 130px" }}
        >
          <circle
            cx="130" cy="130" r="86"
            stroke="rgba(99,102,241,0.22)" strokeWidth="0.8"
            fill="none" strokeDasharray="4 9"
          />
          <circle cx="216" cy="130" r="3"   fill="#a3e635" opacity="0.85" />
          <circle cx="130" cy="44"  r="2.5" fill="#818cf8" opacity="0.85" />
          <circle cx="44"  cy="130" r="2.5" fill="#a3e635" opacity="0.85" />
        </motion.g>

        {/* ── Shield body ── */}
        <path
          d="M130 48 L185 74 L185 132 Q185 183 130 204 Q75 183 75 132 L75 74 Z"
          fill="url(#shieldFill)"
        />
        {/* Inner highlight */}
        <path
          d="M130 58 L175 82 L175 132 Q175 175 130 192 Q85 175 85 132 L85 82 Z"
          fill="url(#shieldHighlight)"
        />
        {/* Check mark */}
        <path
          d="M110 130 L124 144 L152 114"
          stroke="white" strokeWidth="4.5" fill="none"
          strokeLinecap="round" strokeLinejoin="round"
        />

        {/* ── Floating badge pills ── */}
        {/* SECURE */}
        <g opacity="0.88">
          <rect x="176" y="86" width="62" height="21" rx="10.5"
            fill="rgba(52,211,153,0.12)" stroke="rgba(52,211,153,0.35)" strokeWidth="0.8" />
          <text x="207" y="101" textAnchor="middle" fontSize="9"
            fill="#34d399" fontFamily="'SF Mono',monospace" fontWeight="700" letterSpacing="1">
            SECURE
          </text>
        </g>
        {/* SCANNING */}
        <motion.g
          animate={{ opacity: [0.65, 1, 0.65] }}
          transition={{ duration: 2.5, repeat: Infinity, ease: "easeInOut" }}
        >
          <rect x="18" y="104" width="68" height="21" rx="10.5"
            fill="rgba(251,191,36,0.12)" stroke="rgba(251,191,36,0.35)" strokeWidth="0.8" />
          <text x="52" y="119" textAnchor="middle" fontSize="9"
            fill="#fbbf24" fontFamily="'SF Mono',monospace" fontWeight="700" letterSpacing="1">
            SCANNING
          </text>
        </motion.g>
        {/* BREACH */}
        <motion.g
          animate={{ opacity: [0.55, 0.9, 0.55] }}
          transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut", delay: 0.8 }}
        >
          <rect x="178" y="158" width="58" height="21" rx="10.5"
            fill="rgba(244,63,94,0.12)" stroke="rgba(244,63,94,0.35)" strokeWidth="0.8" />
          <text x="207" y="173" textAnchor="middle" fontSize="9"
            fill="#fb7185" fontFamily="'SF Mono',monospace" fontWeight="700" letterSpacing="1">
            BREACH
          </text>
        </motion.g>

        {/* Horizontal scan line */}
        <motion.line
          x1="75" y1="132" x2="185" y2="132"
          stroke="rgba(96,165,250,0.5)" strokeWidth="1.2"
          animate={{ y1: [82, 182, 82], y2: [82, 182, 82], opacity: [0, 0.7, 0] }}
          transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
        />
      </svg>
    </div>
  );
}

/* ──────────────────────────────────────────────
   INPUT VIEW
────────────────────────────────────────────── */

function InputView(props: {
  orgName: string; setOrgName: (v: string) => void;
  domain: string;  setDomain:  (v: string) => void;
  canSubmit: boolean; error: string | null;
  onSubmit: () => void; onExample: () => void;
}) {
  const { orgName, setOrgName, domain, setDomain, canSubmit, error, onSubmit, onExample } = props;

  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="grid items-center gap-10 pt-8 lg:grid-cols-2"
    >
      {/* Left — hero copy + graphic */}
      <div>
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-risk-high/30 bg-risk-crit/10 px-3 py-1 text-xs font-medium text-risk-high">
          <span className="h-1.5 w-1.5 rounded-full bg-risk-high" />
          See your nonprofit through an attacker's eyes
        </div>

        <h1 className="text-4xl font-extrabold leading-[1.1] tracking-tight sm:text-5xl">
          What can a stranger{" "}
          <span className="bg-gradient-to-r from-risk-high to-accent-400 bg-clip-text text-transparent">
            harvest
          </span>{" "}
          from your website?
        </h1>

        <p className="mt-5 max-w-md text-[15px] leading-relaxed text-muted">
          Enter your domain once. Aegis crawls your public pages for staff emails, names and phone
          numbers, checks them against known breaches, tests whether your domain can be spoofed, and
          audits the code your site ships — then tells you, in plain English, the risks and exactly
          what to do next.
        </p>

        {/* Decorative cyber shield */}
        <CyberShield />
      </div>

      {/* Right — glass form card */}
      <div className="card card-glow p-7">
        <h2 className="text-xl font-semibold">Your project portal</h2>
        <p className="mt-1 text-sm text-muted">We only read public pages. Nothing is stored.</p>

        <div className="mt-6 space-y-4">
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-muted">Website domain</span>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onSubmit()}
              placeholder="aylus.org"
              className="bd-input"
              autoFocus
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-muted">
              Organization name <span className="text-muted/60">(optional)</span>
            </span>
            <input
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onSubmit()}
              placeholder="American Youth Leadership"
              className="bd-input"
            />
          </label>
        </div>

        {error && (
          <div className="mt-4 rounded-xl border border-risk-high/30 bg-risk-crit/10 px-3 py-2.5 text-xs text-risk-high">
            {error}
          </div>
        )}

        <button
          onClick={onSubmit}
          disabled={!canSubmit}
          className="mt-6 w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Run breach scan →
        </button>
        <button
          onClick={onExample}
          className="mt-3 w-full text-center text-xs text-muted underline-offset-4 hover:text-brand-300 hover:underline"
        >
          Try it with aylus.org
        </button>

        {/* Trust badges */}
        <div className="mt-5 flex items-center justify-center gap-4 border-t border-white/[0.06] pt-4">
          {["🔒 No data stored", "🌐 Public pages only", "⚡ AI-powered"].map((b) => (
            <span key={b} className="text-[11px] text-muted">{b}</span>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

/* ──────────────────────────────────────────────
   SCANNING VIEW
────────────────────────────────────────────── */

function ScanningView({ step, domain }: { step: number; domain: string }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="grid place-items-center py-24 text-center"
    >
      <div className="relative mx-auto mb-10 h-40 w-40">
        {[0, 1, 2].map((i) => (
          <motion.span
            key={i}
            className="absolute inset-0 rounded-full border border-brand-500/40"
            animate={{ scale: [0.4, 1.6], opacity: [0.7, 0] }}
            transition={{ duration: 2.4, repeat: Infinity, delay: i * 0.8, ease: "easeOut" }}
          />
        ))}
        <div className="absolute inset-0 grid place-items-center">
          <motion.div
            className="grid h-20 w-20 place-items-center rounded-2xl bg-gradient-to-br from-brand-500 to-accent-500 text-3xl shadow-xl shadow-brand-600/40"
            animate={{ rotate: [0, 6, -6, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            🔍
          </motion.div>
        </div>
      </div>

      <p className="text-sm text-muted">
        Scanning <span className="font-semibold text-fg">{domain}</span>
      </p>
      <div className="mt-5 h-8">
        <AnimatePresence mode="wait">
          <motion.p
            key={step}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="text-[15px] font-medium"
          >
            {SCAN_STEPS[Math.min(step, SCAN_STEPS.length - 1)]}
          </motion.p>
        </AnimatePresence>
      </div>
      <div className="mx-auto mt-4 h-1.5 w-64 overflow-hidden rounded-full bg-white/10">
        <motion.div
          className="h-full rounded-full bg-gradient-to-r from-brand-500 to-accent-500"
          animate={{ width: `${((step + 1) / SCAN_STEPS.length) * 100}%` }}
          transition={{ ease: "easeOut" }}
        />
      </div>
    </motion.div>
  );
}

/* ──────────────────────────────────────────────
   REPORT VIEW — tabbed
────────────────────────────────────────────── */

type ReportTab = "found" | "risks" | "action";

const DEMOGRAPHICS = [
  { id: "all",        label: "Everyone",        icon: "👥", color: "#818cf8" },
  { id: "leadership", label: "Leadership / ED", icon: "🏛️", color: "#f43f5e" },
  { id: "it",         label: "IT Admin",        icon: "💻", color: "#a3e635" },
  { id: "staff",      label: "Staff",           icon: "👤", color: "#fbbf24" },
  { id: "volunteers", label: "Volunteers",      icon: "🤝", color: "#34d399" },
] as const;

type DemoId = typeof DEMOGRAPHICS[number]["id"];

function getDemoCallout(title: string, steps: string[], demo: DemoId): string | null {
  if (demo === "all") return null;
  const t = title.toLowerCase();
  const body = steps.join(" ").toLowerCase();
  const has = (...kws: string[]) => kws.some((k) => t.includes(k) || body.includes(k));

  const MAP: Record<Exclude<DemoId, "all">, Record<string, string>> = {
    leadership: {
      password:  "Mandate a password manager org-wide — set a 2-week deadline for all staff to comply.",
      mfa:       "Require MFA for all admin accounts via your Google/Microsoft admin console today. No exceptions.",
      account:   "Run an offboarding audit: pull a list of all active accounts and verify everyone still works there.",
      backup:    "Approve budget for a verified backup solution and add a quarterly restore drill to your calendar.",
      train:     "Set a firm date for a 30-minute team security briefing this month — make attendance mandatory.",
      monitor:   "Assign a named point-of-contact for security alerts and add cyber incidents to your risk register.",
      default:   "At your next leadership meeting, assign a named owner with a hard deadline for this action.",
    },
    it: {
      password:  "Deploy a password manager via MDM/policy, rotate all breached credentials, and disable reuse.",
      mfa:       "Enforce MFA in the admin console — require TOTP authenticator apps, disable SMS-only fallback.",
      account:   "Pull the full user list from Google Workspace / M365. Revoke inactive accounts. Enforce least privilege.",
      backup:    "Implement the 3-2-1 rule. Verify one offline copy exists and schedule an automated monthly restore test.",
      monitor:   "Configure alerts for impossible-travel logins, bulk mailbox exports, and after-hours admin actions.",
      default:   "Implement at the infrastructure level, test first, and document the change in your runbook.",
    },
    staff: {
      password:  "Install Bitwarden (free) today — let it generate a unique password for every account you use.",
      mfa:       "Enable MFA on your work email right now — takes 3 minutes. Use an authenticator app, not SMS.",
      train:     "Hover over every link before clicking. Urgency + money + secrecy = scam. Call to verify, always.",
      phish:     "Any email asking you to act fast, pay, or share credentials — verify by phone before doing anything.",
      account:   "Report any accounts you have access to but no longer use — ask IT to remove them.",
      default:   "Do this on all your work devices today and let your manager know when it's done.",
    },
    volunteers: {
      password:  "Change your org system passwords to something unique you've never used anywhere else.",
      mfa:       "Enable MFA on the org accounts you access — ask your coordinator if you need help setting it up.",
      train:     "Because your name is on the website, you may be specifically targeted. Verify any odd requests by phone.",
      phish:     "Scammers may impersonate org leadership to request money or data. Always call to verify.",
      default:   "Ask your volunteer coordinator which of these steps apply to your level of system access.",
    },
  };

  const demoMap = MAP[demo as Exclude<DemoId, "all">];
  if (!demoMap) return null;

  if (has("password", "credential", "bitwarden", "1password")) return demoMap.password ?? demoMap.default;
  if (has("mfa", "multi-factor", "authenticator", "two-factor", "2fa")) return demoMap.mfa ?? demoMap.default;
  if (has("account", "access", "offboard", "privilege")) return demoMap.account ?? demoMap.default;
  if (has("backup", "restore", "ransomware", "3-2-1")) return demoMap.backup ?? demoMap.default;
  if (has("phish", "bec", "social engineer", "gift card")) return demoMap.phish ?? demoMap.train ?? demoMap.default;
  if (has("train", "aware", "educat")) return demoMap.train ?? demoMap.default;
  if (has("monitor", "alert", "log", "detect")) return demoMap.monitor ?? demoMap.default;
  return demoMap.default;
}

const REPORT_TABS: { id: ReportTab; label: string; icon: string }[] = [
  { id: "found",  label: "What We Found",        icon: "🔍" },
  { id: "risks",  label: "Risks & Who's at Risk", icon: "⚠️" },
  { id: "action", label: "Step-by-Step Action",   icon: "⚡" },
];

function ReportView(props: {
  orgName: string;
  crawl: CrawlResult;
  lookup: BreachLookup;
  domainSec: DomainSecurity | null;
  report: BreachReport;
  reportSource: "ai" | "fallback";
  jsAudit: JsAuditResult | null;
  jsReport: JsReport | null;
  jsReportSource: "ai" | "fallback";
  onReset: () => void;
}) {
  const { orgName, crawl, lookup, domainSec, report, reportSource, jsAudit, jsReport, jsReportSource, onReset } = props;
  const breachedCount = breachedAccounts(lookup);
  const totalB = totalBreaches(lookup);
  const [reportTab, setReportTab] = useState<ReportTab>("found");
  const [demoId, setDemoId] = useState<DemoId>("all");

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      className="space-y-5 pt-2 pb-8"
    >
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Breach exposure report</h1>
          <p className="mt-1 text-sm text-muted">
            {orgName} · <span className="font-mono text-brand-300">{crawl.domain}</span> ·{" "}
            {crawl.pagesScanned.length} page{crawl.pagesScanned.length === 1 ? "" : "s"} scanned
          </p>
        </div>
        <button
          onClick={onReset}
          className="rounded-xl border border-white/10 px-3 py-1.5 text-xs text-muted transition hover:border-white/25 hover:text-fg"
        >
          ↺ Scan another site
        </button>
      </div>

      {lookup.source === "error" && crawl.emails.length > 0 && (
        <div className="rounded-lg border border-risk-med/30 bg-risk-med/10 px-3 py-2 text-xs text-risk-med">
          ⚠ We couldn't reach the breach database, so the emails below{" "}
          <span className="font-semibold">weren't checked</span>. Check your connection and rescan.
        </div>
      )}

      {/* Stat row — always visible */}
      <div className="grid gap-4 sm:grid-cols-4">
        <Stat label="Public emails found"    value={crawl.emails.length}                       accent="high" />
        <Stat label="Emails in breaches"     value={breachedCount}                             accent="crit" />
        <Stat label="Total breach hits"      value={totalB}                                    accent="crit" />
        <Stat label="Names & phones exposed" value={crawl.names.length + crawl.phones.length} accent="med"  />
      </div>

      {/* ── Tab bar ── */}
      <div className="card flex gap-1.5 p-1.5">
        {REPORT_TABS.map((t) => {
          const active = reportTab === t.id;
          const isAction = t.id === "action";
          return (
            <button
              key={t.id}
              onClick={() => setReportTab(t.id)}
              className="relative flex flex-1 items-center justify-center gap-1.5 rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200"
              style={
                active
                  ? isAction
                    ? { background: "linear-gradient(135deg, #e11d48, #f97316)", color: "#fff", boxShadow: "0 2px 18px rgba(225,29,72,0.45)" }
                    : { background: "linear-gradient(135deg, #4f46e5, #65a30d)", color: "#fff", boxShadow: "0 2px 12px rgba(99,102,241,0.35)" }
                  : isAction
                    ? { color: "#fb7185", border: "1px solid rgba(244,63,94,0.40)", background: "rgba(244,63,94,0.10)" }
                    : { color: "var(--color-muted)" }
              }
            >
              <span className="text-base leading-none">{t.icon}</span>
              <span className="hidden sm:inline">{t.label}</span>
              <span className="sm:hidden text-xs">{t.label.split(" ")[0]}</span>
              {/* Pulsing dot on inactive action tab */}
              {isAction && !active && (
                <motion.span
                  animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
                  transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
                  className="flex-none h-2 w-2 rounded-full bg-risk-crit"
                />
              )}
            </button>
          );
        })}
      </div>

      {/* domain spoofing protection (live DNS) */}
      {domainSec && <DomainSecurityCard sec={domainSec} />}

      {/* ── Tab panels ── */}
      <AnimatePresence mode="wait">

        {/* ─ What We Found ─ */}
        {reportTab === "found" && (
          <motion.div
            key="found"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
            className="card p-6 space-y-5"
          >
            <div>
              <h2 className="text-lg font-bold">What we harvested from your site</h2>
              <p className="mt-1 text-sm text-muted">Public data an attacker could scrape in seconds.</p>
            </div>

            {lookup.results.length > 0 ? (
              <div className="space-y-2.5">
                {lookup.results
                  .slice()
                  .sort((a, b) => b.breachCount - a.breachCount)
                  .map((r) => <EmailRow key={r.email} r={r} />)}
              </div>
            ) : (
              <p className="rounded-xl bg-white/[0.03] px-3 py-3 text-sm text-muted">
                No public email addresses found — good for your attack surface.
              </p>
            )}

            {(crawl.names.length > 0 || crawl.phones.length > 0) && (
              <div className="grid gap-4 sm:grid-cols-2">
                {crawl.names.length  > 0 && <Chips title="Names found"         items={crawl.names}  icon="👤" />}
                {crawl.phones.length > 0 && <Chips title="Phone numbers found" items={crawl.phones} icon="📞" />}
              </div>
            )}
          </motion.div>
        )}

        {/* ─ Risks ─ */}
        {reportTab === "risks" && (
          <motion.div
            key="risks"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
            className="card p-6 space-y-5"
          >
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold">Potential risks & who's at risk</h2>
              {reportSource === "ai" && (
                <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
                  ✦ AI-assessed
                </span>
              )}
            </div>
            <p className="text-sm leading-relaxed text-fg/85">{report.summary}</p>
            <div className="space-y-3">
              {report.risks.map((risk, i) => {
                const m = SEVERITY_META[risk.severity];
                return (
                  <div key={i} className="rounded-xl border border-white/8 bg-white/[0.025] p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="font-semibold">{risk.title}</div>
                      <span
                        className="flex-none rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
                        style={{ color: m.color, background: m.bg }}
                      >
                        {m.label}
                      </span>
                    </div>
                    <p className="mt-1.5 text-sm text-muted">{risk.consequence}</p>
                    {risk.whoAtRisk.length > 0 && (
                      <div className="mt-3">
                        <div className="text-[11px] font-medium uppercase tracking-wide text-risk-high">
                          Who's at risk
                        </div>
                        <div className="mt-1.5 flex flex-wrap gap-1.5">
                          {risk.whoAtRisk.map((w) => (
                            <span key={w} className="rounded-lg border border-white/10 bg-white/5 px-2 py-0.5 text-[11px]">
                              {w}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}

        {/* ─ Step-by-Step Action ─ */}
        {reportTab === "action" && (
          <motion.div
            key="action"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
            className="space-y-4"
          >
            {/* Demographic selector */}
            <div className="card p-4">
              <p className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted">
                Select your role — steps are tailored to you
              </p>
              <div className="flex flex-wrap gap-2">
                {DEMOGRAPHICS.map((d) => {
                  const active = demoId === d.id;
                  return (
                    <button
                      key={d.id}
                      onClick={() => setDemoId(d.id)}
                      className="flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-sm font-medium transition-all duration-150"
                      style={
                        active
                          ? { background: d.color + "28", color: d.color, border: `1px solid ${d.color}55`, boxShadow: `0 0 12px ${d.color}30` }
                          : { color: "var(--color-muted)", border: "1px solid rgba(255,255,255,0.08)" }
                      }
                    >
                      <span>{d.icon}</span>
                      <span>{d.label}</span>
                    </button>
                  );
                })}
              </div>
              {demoId !== "all" && (
                <p className="mt-3 text-xs text-muted">
                  Showing <span className="text-fg">{DEMOGRAPHICS.find(d => d.id === demoId)?.label}</span> callouts inside each step.
                </p>
              )}
            </div>

            {/* Action steps */}
            <div className="card card-glow p-6 space-y-3">
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <h2 className="text-lg font-bold">Your step-by-step action plan</h2>
                <span className="rounded-full bg-risk-low/15 px-2 py-0.5 text-[11px] font-medium text-risk-low">
                  start at the top
                </span>
                {reportSource === "ai" && (
                  <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
                    ✦ AI-generated for {orgName}
                  </span>
                )}
              </div>
              <p className="text-sm text-muted">
                Priority order — the first two steps stop the majority of attacks on their own.
              </p>

              <div className="space-y-3 pt-1">
                {report.actions.map((action, i) => {
                  const callout = getDemoCallout(action.title, action.steps, demoId);
                  const demo = DEMOGRAPHICS.find((d) => d.id === demoId)!;
                  return (
                    <details
                      key={i}
                      className="group rounded-xl border border-white/8 bg-white/[0.025] p-4 open:border-risk-high/30"
                      open={i === 0}
                    >
                      <summary className="flex cursor-pointer list-none items-center gap-3">
                        <span
                          className="grid h-7 w-7 flex-none place-items-center rounded-full text-sm font-bold text-white"
                          style={{ background: "linear-gradient(135deg, #e11d48, #f97316)" }}
                        >
                          {i + 1}
                        </span>
                        <span className="flex-1 font-semibold">{action.title}</span>
                        <span className="rounded-full border border-white/10 px-2 py-0.5 text-[11px] text-muted">
                          {action.effort}
                        </span>
                        <span className="text-muted transition group-open:rotate-180">▾</span>
                      </summary>

                      <div className="mt-3 pl-10 space-y-3">
                        <div className="text-xs italic text-brand-300">Why: {action.why}</div>

                        {/* Demographic callout */}
                        {callout && (
                          <div
                            className="flex items-start gap-2.5 rounded-xl px-3 py-2.5"
                            style={{ background: demo.color + "1a", border: `1px solid ${demo.color}45` }}
                          >
                            <span className="mt-0.5 text-base">{demo.icon}</span>
                            <div>
                              <div
                                className="text-[11px] font-bold uppercase tracking-widest mb-0.5"
                                style={{ color: demo.color }}
                              >
                                {demo.label}
                              </div>
                              <p className="text-sm text-fg/90">{callout}</p>
                            </div>
                          </div>
                        )}

                        <ul className="space-y-1.5">
                          {action.steps.map((s, j) => (
                            <li key={j} className="flex gap-2 text-sm text-fg/85">
                              <span className="text-risk-med">›</span>
                              {s}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </details>
                  );
                })}
              </div>

              {reportSource === "fallback" && (
                <div className="rounded-xl bg-white/[0.03] px-3 py-2 text-[11px] text-muted">
                  Showing the built-in plan — add an <span className="text-fg">ANTHROPIC_API_KEY</span> to
                  generate one tailored to your exact findings.
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* website code security (combined JS audit) */}
      {jsAudit && (
        <CodeSecuritySection audit={jsAudit} report={jsReport} reportSource={jsReportSource} />
      )}
    </motion.div>
  );
}

function CodeSecuritySection({
  audit,
  report,
  reportSource,
}: {
  audit: JsAuditResult;
  report: JsReport | null;
  reportSource: "ai" | "fallback";
}) {
  const top = worstSeverity(audit);
  const topMeta = SEVERITY_META[top];
  const hasFindings = audit.findings.length > 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 pt-2">
        <h2 className="text-xl font-bold tracking-tight">Website code security</h2>
        <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
          {audit.scriptsScanned.length} script{audit.scriptsScanned.length === 1 ? "" : "s"} scanned
        </span>
      </div>

      {/* code stat row */}
      <div className="grid gap-4 sm:grid-cols-4">
        <Stat label="Security issues" value={audit.counts.security || 0} accent="crit" />
        <Stat label="Code-quality issues" value={audit.counts.bug || 0} accent="med" />
        <Stat label="Critical / high" value={(audit.counts.critical || 0) + (audit.counts.high || 0)} accent="high" />
        <div className="card p-5">
          <div className="text-xs text-muted">Highest severity</div>
          <div className="mt-2 text-2xl font-extrabold" style={{ color: topMeta.color }}>
            {hasFindings ? topMeta.label : "Clean"}
          </div>
        </div>
      </div>

      {/* summary + fix plan */}
      {report && (
        <div className="card card-glow p-6">
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <h3 className="text-lg font-bold">Summary & fix plan</h3>
            {reportSource === "ai" && (
              <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
                ✦ AI-assessed
              </span>
            )}
          </div>
          <p className="mb-5 text-sm leading-relaxed text-fg/85">{report.summary}</p>
          <div className="space-y-3">
            {report.recommendations.map((rec, i) => (
              <details
                key={i}
                className="group rounded-xl border border-white/8 bg-white/[0.02] p-4 open:border-brand-400/40"
                open={i === 0}
              >
                <summary className="flex cursor-pointer list-none items-center gap-3">
                  <span className="grid h-7 w-7 flex-none place-items-center rounded-full bg-gradient-to-br from-brand-500 to-accent-500 text-sm font-bold text-white">
                    {i + 1}
                  </span>
                  <span className="flex-1 font-semibold">{rec.title}</span>
                  <span className="rounded-full border border-white/10 px-2 py-0.5 text-[11px] text-muted">
                    {rec.effort}
                  </span>
                  <span className="text-muted transition group-open:rotate-180">▾</span>
                </summary>
                <div className="mt-3 pl-10">
                  <div className="mb-2 text-xs italic text-brand-300">Why: {rec.why}</div>
                  <ul className="space-y-1.5">
                    {rec.steps.map((s, j) => (
                      <li key={j} className="flex gap-2 text-sm text-fg/85">
                        <span className="text-brand-400">›</span>
                        {s}
                      </li>
                    ))}
                  </ul>
                </div>
              </details>
            ))}
          </div>
          {reportSource === "fallback" && (
            <div className="mt-4 rounded-lg bg-white/[0.03] px-3 py-2 text-[11px] text-muted">
              Showing the built-in plan — add an <span className="text-fg">ANTHROPIC_API_KEY</span> to
              generate one tailored to your exact findings.
            </div>
          )}
        </div>
      )}

      {/* findings */}
      <div className="card p-6">
        <h3 className="mb-1 text-lg font-bold">What we found in your code</h3>
        <p className="mb-4 text-sm text-muted">
          Each item shows the file and line. Items marked{" "}
          <span className="rounded border border-white/10 px-1 py-0.5 text-[10px]">3rd-party</span> come
          from widgets/libraries you likely can't edit directly — update or replace them instead.
        </p>
        {hasFindings ? (
          <div className="space-y-2.5">
            {audit.findings.map((f, i) => (
              <JsFindingRow key={i} f={f} />
            ))}
          </div>
        ) : (
          <p className="rounded-lg bg-white/[0.03] px-3 py-3 text-sm text-muted">
            No bugs or security risks were flagged in the scripts we scanned — nice. Keep your site
            and its plugins up to date to stay that way.
          </p>
        )}
      </div>
    </div>
  );
}

function JsFindingRow({ f }: { f: JsFinding }) {
  const m = SEVERITY_META[f.severity];
  return (
    <details className="group rounded-xl border border-white/8 bg-white/[0.02] px-4 py-3">
      <summary className="flex cursor-pointer list-none items-center gap-3">
        <span
          className="flex-none rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
          style={{ color: m.color, background: m.bg }}
        >
          {m.label}
        </span>
        <span className="flex-1 font-semibold">{f.title}</span>
        <span className="hidden truncate font-mono text-[11px] text-muted sm:block">
          {f.file}:{f.line}
        </span>
        {f.party === 1 && (
          <span className="flex-none rounded border border-white/10 px-1 py-0.5 text-[10px] text-muted">
            3rd-party
          </span>
        )}
        <span className="text-muted transition group-open:rotate-180">▾</span>
      </summary>
      <div className="mt-3 space-y-2 pl-1">
        <p className="text-sm text-muted">{f.detail}</p>
        <div className="text-[11px] text-muted">
          <span className="font-mono">{f.file}</span> · line {f.line}
        </div>
        <pre className="overflow-x-auto rounded-lg bg-ink-900/60 px-3 py-2 font-mono text-[11px] leading-relaxed text-fg/80">
          {f.snippet}
        </pre>
      </div>
    </details>
  );
}

const DSEC_META = {
  pass: { icon: "🟢", color: "var(--color-risk-low)", bg: "rgba(52,211,153,0.12)", label: "OK" },
  warn: { icon: "🟡", color: "var(--color-risk-med)", bg: "rgba(251,191,36,0.12)", label: "Weak" },
  fail: { icon: "🔴", color: "var(--color-risk-crit)", bg: "rgba(244,63,94,0.14)", label: "Missing" },
} as const;

function DomainSecurityCard({ sec }: { sec: DomainSecurity }) {
  return (
    <div className="card p-6">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-bold">Email-spoofing protection</h2>
        <span
          className="rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
          style={{
            color: sec.spoofable ? "var(--color-risk-crit)" : "var(--color-risk-low)",
            background: sec.spoofable ? "rgba(244,63,94,0.14)" : "rgba(52,211,153,0.12)",
          }}
        >
          {sec.spoofable ? "Spoofable" : "Protected"}
        </span>
        <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
          live DNS check
        </span>
      </div>
      <p className="mb-4 text-sm leading-relaxed text-fg/85">
        {sec.spoofable
          ? `Right now an attacker can send email that looks like it comes from ${sec.domain} — the records that stop that aren't fully in place.`
          : `${sec.domain} has the DNS records that make it hard to forge email from your address. Keep them in place.`}
      </p>
      <div className="space-y-2.5">
        {sec.checks.map((c) => {
          const m = DSEC_META[c.status];
          return (
            <div key={c.id} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span>{m.icon}</span>
                  <span className="font-semibold">{c.label}</span>
                  <span className="text-sm text-fg/85">— {c.title}</span>
                </div>
                <span
                  className="flex-none rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
                  style={{ color: m.color, background: m.bg }}
                >
                  {m.label}
                </span>
              </div>
              <p className="mt-1.5 text-sm text-muted">{c.detail}</p>
              <div className="mt-2 font-mono text-[11px] text-muted/80">{c.evidence}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function EmailRow({ r }: { r: EmailBreach }) {
  const breached = r.status === "breached";
  const err      = r.status === "error";
  return (
    <details className="group rounded-xl border border-white/8 bg-white/[0.025] px-4 py-3">
      <summary className="flex cursor-pointer list-none items-center gap-3">
        <span className="text-base">{breached ? "🔴" : err ? "⚪" : "🟢"}</span>
        <span className="flex-1 truncate font-mono text-sm">{r.email}</span>
        <span
          className="flex-none rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
          style={{
            color:      breached ? "var(--color-risk-crit)" : err ? "var(--color-muted)" : "var(--color-risk-low)",
            background: breached ? "rgba(244,63,94,0.14)" : err ? "rgba(255,255,255,0.05)" : "rgba(52,211,153,0.12)",
          }}
        >
          {breached ? `${r.breachCount} breach${r.breachCount === 1 ? "" : "es"}` : err ? "lookup failed" : "no breaches"}
        </span>
        {breached && <span className="text-muted transition group-open:rotate-180">▾</span>}
      </summary>
      {breached && (
        <div className="mt-3 space-y-2 pl-9">
          {r.breaches.map((b, i) => (
            <div key={i} className="rounded-xl bg-ink-900/60 px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold">{b.title}</span>
                <span className="text-[11px] text-muted">{b.breachDate?.slice(0, 4)}</span>
              </div>
              {b.dataClasses.length > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {b.dataClasses.slice(0, 6).map((c) => (
                    <span key={c} className="rounded border border-white/10 px-1.5 py-0.5 text-[10px] text-muted">
                      {c}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </details>
  );
}

function Chips({ title, items, icon }: { title: string; items: string[]; icon: string }) {
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4">
      <div className="mb-2 text-xs font-medium text-muted">
        {icon} {title} ({items.length})
      </div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((it) => (
          <span key={it} className="rounded-lg border border-white/10 bg-white/5 px-2 py-0.5 text-xs">
            {it}
          </span>
        ))}
      </div>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string | number; accent: "crit" | "high" | "med" }) {
  const color =
    accent === "crit" ? "var(--color-risk-crit)"
    : accent === "high" ? "var(--color-risk-high)"
    : "var(--color-risk-med)";
  return (
    <div className="card p-5">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-2 text-3xl font-extrabold tabular-nums" style={{ color }}>
        {value}
      </div>
    </div>
  );
}
