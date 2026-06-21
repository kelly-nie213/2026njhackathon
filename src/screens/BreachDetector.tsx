import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";
import {
  crawlDomain,
  lookupBreaches,
  generateReport,
  checkDomainSecurity,
  checkWebSecurity,
  checkReputation,
  breachedAccounts,
  totalBreaches,
  SEVERITY_META,
  type CrawlResult,
  type BreachLookup,
  type BreachReport,
  type DomainSecurity,
  type WebSecurity,
  type Reputation,
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
  "Checking HTTPS, TLS & web security headers…",
  "Checking threat-intel blocklists for malware/phishing…",
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
  const [webSec, setWebSec] = useState<WebSecurity | null>(null);
  const [reputation, setReputation] = useState<Reputation | null>(null);
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
      const [domainSecRes, webSecRes, repRes, lookupRes, auditRes] = await Promise.all([
        checkDomainSecurity(cleanDomain),
        checkWebSecurity(cleanDomain),
        checkReputation(cleanDomain),
        crawlRes.emails.length
          ? lookupBreaches(crawlRes.emails)
          : Promise.resolve({ source: "live" as const, results: [] }),
        auditJs(cleanDomain).catch(() => null),
      ]);
      setDomainSec(domainSecRes);
      setWebSec(webSecRes);
      setReputation(repRes);
      setLookup(lookupRes);
      setJsAudit(auditRes);
      setStep(8);

      // Breach report + code-audit report are separate AI calls — run in parallel.
      const orgLabel = orgName.trim() || crawlRes.domain;
      const [breachOut, jsOut] = await Promise.all([
        generateReport(crawlRes, lookupRes, orgLabel, domainSecRes, webSecRes, repRes),
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
    setWebSec(null);
    setReputation(null);
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
              webSec={webSec}
              reputation={reputation}
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
   SHIELD HERO — stroke-only shield + orbiting Liquid Glass badges
────────────────────────────────────────────── */

function StatusBadge({ label, color, className }: { label: string; color: string; className: string }) {
  return (
    <span className={`lg-pill absolute ${className}`} style={{ color: "rgba(255,255,255,0.85)" }}>
      <span className="pulse-dot inline-block h-1.5 w-1.5 flex-none rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}

function ShieldHero() {
  return (
    <div className="relative mb-9 grid place-items-center" style={{ width: 240, height: 170 }}>
      {/* stroke-only shield with checkmark that draws on load */}
      <svg width="104" height="120" viewBox="0 0 64 74" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path
          d="M32 5 L56 14 L56 36 C56 52 45 64 32 69 C19 64 8 52 8 36 L8 14 Z"
          stroke="#ffffff" strokeWidth="2" strokeLinejoin="round" fill="none"
        />
        <path
          className="draw-check"
          d="M21 37 L29 45 L44 28"
          stroke="#ffffff" strokeWidth="2.5" fill="none"
          strokeLinecap="round" strokeLinejoin="round"
        />
      </svg>

      <StatusBadge label="SCANNING" color="#0a84ff" className="top-1 right-0" />
      <StatusBadge label="SECURE"   color="#30d158" className="top-1/2 -left-2 -translate-y-1/2" />
      <StatusBadge label="BREACH"   color="#ff453a" className="bottom-2 right-2" />
    </div>
  );
}

/* ──────────────────────────────────────────────
   INPUT VIEW
────────────────────────────────────────────── */

/* SF-Symbols-style stroke icons (no emoji) for the trust row. */
function TrustIcon({ name }: { name: "lock" | "globe" | "bolt" }) {
  const common = { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  if (name === "lock")
    return (<svg {...common}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></svg>);
  if (name === "globe")
    return (<svg {...common}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></svg>);
  return (<svg {...common}><path d="M13 2 4 14h7l-1 8 9-12h-7z" /></svg>);
}

function InputView(props: {
  orgName: string; setOrgName: (v: string) => void;
  domain: string;  setDomain:  (v: string) => void;
  canSubmit: boolean; error: string | null;
  onSubmit: () => void; onExample: () => void;
}) {
  const { orgName, setOrgName, domain, setDomain, canSubmit, error, onSubmit, onExample } = props;
  const labelClass = "mb-2 block text-[13px] font-medium uppercase tracking-[0.06em] text-white/40";

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] }}
      className="flex flex-col items-center pt-12"
    >
      {/* ── Hero ── */}
      <ShieldHero />

      <h1
        className="text-center"
        style={{ fontSize: "clamp(38px, 7vw, 56px)", fontWeight: 700, letterSpacing: "-0.025em", lineHeight: 1.05 }}
      >
        Protect what matters.
      </h1>
      <p
        className="mt-4 max-w-[34rem] text-center"
        style={{ fontSize: 21, fontWeight: 400, letterSpacing: "-0.01em", color: "rgba(255,255,255,0.55)" }}
      >
        Scan any domain for breaches, leaks, and active threats in seconds.
      </p>

      {/* ── Liquid Glass form card ── */}
      <div className="card card-glow mt-12 w-full p-7" style={{ maxWidth: 520 }}>
        <h2 style={{ fontSize: 28, fontWeight: 700, letterSpacing: "-0.02em" }}>Your project portal</h2>
        <p className="mt-1" style={{ fontSize: 15, color: "rgba(255,255,255,0.55)" }}>
          We only read public pages. Nothing is stored.
        </p>

        <div className="mt-7 space-y-5">
          <label className="block">
            <span className={labelClass}>Website domain</span>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onSubmit()}
              placeholder="aylus.org"
              className="p-form-text"
              style={{ width: "100%" }}
              autoFocus
            />
          </label>
          <label className="block">
            <span className={labelClass}>
              Organization name <span className="normal-case tracking-normal text-white/25">(optional)</span>
            </span>
            <input
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onSubmit()}
              placeholder="American Youth Leadership"
              className="p-form-text"
              style={{ width: "100%" }}
            />
          </label>
        </div>

        {error && (
          <div
            className="mt-4 rounded-xl px-3 py-2.5 text-[13px]"
            style={{ background: "rgba(255,69,58,0.12)", border: "1px solid rgba(255,69,58,0.3)", color: "#ff453a" }}
          >
            {error}
          </div>
        )}

        <button
          onClick={onSubmit}
          disabled={!canSubmit}
          className={`p-btn p-prim-col p-btn-block ${!canSubmit ? "p-btn-disabled" : ""}`}
          style={{ width: "100%", margin: "1.75rem 0 0", fontSize: 17, fontWeight: 600 }}
        >
          Run breach scan →
        </button>
        <button
          onClick={onExample}
          className="mt-3 w-full text-center"
          style={{ fontSize: 13, color: "rgba(255,255,255,0.35)" }}
        >
          Try it with aylus.org
        </button>

        {/* Trust row */}
        <div
          className="mt-6 flex items-center justify-center gap-3 pt-5"
          style={{ borderTop: "0.5px solid rgba(255,255,255,0.1)", fontSize: 13, color: "rgba(255,255,255,0.55)" }}
        >
          <span className="inline-flex items-center gap-1.5"><TrustIcon name="lock" /> No data stored</span>
          <span className="text-white/20">·</span>
          <span className="inline-flex items-center gap-1.5"><TrustIcon name="globe" /> Public pages only</span>
          <span className="text-white/20">·</span>
          <span className="inline-flex items-center gap-1.5"><TrustIcon name="bolt" /> AI-powered</span>
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
            className="grid h-20 w-20 place-items-center rounded-2xl bg-gradient-to-br from-brand-500 to-accent-500 shadow-xl shadow-brand-600/40"
            animate={{ rotate: [0, 6, -6, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="7" />
              <path d="m21 21-4.3-4.3" />
            </svg>
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
  { id: "all",        label: "Everyone",        color: "#0a84ff" },
  { id: "leadership", label: "Leadership / ED", color: "#ff453a" },
  { id: "it",         label: "IT Admin",        color: "#64d2ff" },
  { id: "staff",      label: "Staff",           color: "#ffd60a" },
  { id: "volunteers", label: "Volunteers",      color: "#30d158" },
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

const REPORT_TABS: { id: ReportTab; label: string }[] = [
  { id: "found",  label: "What We Found" },
  { id: "risks",  label: "Risks & Who's at Risk" },
  { id: "action", label: "Step-by-Step Action" },
];

function ReportView(props: {
  orgName: string;
  crawl: CrawlResult;
  lookup: BreachLookup;
  domainSec: DomainSecurity | null;
  webSec: WebSecurity | null;
  reputation: Reputation | null;
  report: BreachReport;
  reportSource: "ai" | "fallback";
  jsAudit: JsAuditResult | null;
  jsReport: JsReport | null;
  jsReportSource: "ai" | "fallback";
  onReset: () => void;
}) {
  const { orgName, crawl, lookup, domainSec, webSec, reputation, report, reportSource, jsAudit, jsReport, jsReportSource, onReset } = props;
  const breachedCount = breachedAccounts(lookup);
  const totalB = totalBreaches(lookup);
  const [reportTab, setReportTab] = useState<ReportTab>("found");
  const [demoId, setDemoId] = useState<DemoId>("all");

  // When the tab changes, bring the tab bar (and the panel right under it) into
  // view so the switch is always visible, even from far down a long panel.
  const tabsRef = useRef<HTMLDivElement>(null);
  const firstTab = useRef(true);
  useEffect(() => {
    if (firstTab.current) { firstTab.current = false; return; }
    tabsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [reportTab]);

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
          We couldn't reach the breach database, so the emails below{" "}
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

      {/* ── Tab bar (sticky so switching is always reachable & visible) ── */}
      <div ref={tabsRef} className="card sticky top-3 z-20 flex gap-1.5 p-1.5 scroll-mt-3">
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
                    ? { background: "linear-gradient(135deg, #ff453a, #ff9f0a)", color: "#fff", boxShadow: "0 2px 18px rgba(225,29,72,0.45)" }
                    : { background: "linear-gradient(135deg, #0a84ff, #32ade6)", color: "#fff", boxShadow: "0 2px 12px rgba(99,102,241,0.35)" }
                  : isAction
                    ? { color: "#fb7185", border: "1px solid rgba(244,63,94,0.40)", background: "rgba(244,63,94,0.10)" }
                    : { color: "var(--color-muted)" }
              }
            >
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
            className="space-y-5"
          >
            {/* threat-intel reputation (live blocklists) */}
            {reputation && <ReputationCard rep={reputation} />}

            <div className="card p-6 space-y-5">
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
                  {crawl.names.length  > 0 && <Chips title="Names found"         items={crawl.names} />}
                  {crawl.phones.length > 0 && <Chips title="Phone numbers found" items={crawl.phones} />}
                </div>
              )}
            </div>

            {/* domain spoofing protection (live DNS) */}
            {domainSec && <DomainSecurityCard sec={domainSec} />}

            {/* web security: TLS + HTTP headers (live) */}
            {webSec && <WebSecurityCard sec={webSec} />}

            {/* website code security (combined JS audit) */}
            {jsAudit && (
              <CodeSecuritySection audit={jsAudit} report={jsReport} reportSource={jsReportSource} />
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
                      <span
                        className="inline-block h-2 w-2 flex-none rounded-full"
                        style={{ background: d.color }}
                      />
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
                          style={{ background: "linear-gradient(135deg, #ff453a, #ff9f0a)" }}
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
                            <span
                              className="mt-1.5 inline-block h-2 w-2 flex-none rounded-full"
                              style={{ background: demo.color }}
                            />
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
  pass: { color: "var(--color-risk-low)", bg: "rgba(52,211,153,0.12)", label: "OK" },
  warn: { color: "var(--color-risk-med)", bg: "rgba(251,191,36,0.12)", label: "Weak" },
  fail: { color: "var(--color-risk-crit)", bg: "rgba(244,63,94,0.14)", label: "Missing" },
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
                  <span className="inline-block h-2.5 w-2.5 flex-none rounded-full" style={{ background: m.color }} />
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

function WebSecurityCard({ sec }: { sec: WebSecurity }) {
  const gradeColor =
    sec.grade === "A" ? "var(--color-risk-low)"
    : sec.grade === "B" ? "var(--color-risk-low)"
    : sec.grade === "C" ? "var(--color-risk-med)"
    : "var(--color-risk-crit)";
  return (
    <div className="card p-6">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-bold">Web security: HTTPS &amp; headers</h2>
        <span
          className="rounded-full px-2.5 py-0.5 text-[11px] font-bold"
          style={{ color: gradeColor, background: "rgba(255,255,255,0.06)" }}
        >
          Grade {sec.grade}
        </span>
        <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
          live check
        </span>
      </div>
      <p className="mb-4 text-sm leading-relaxed text-fg/85">
        How your site is <span className="italic">served</span> — its certificate and the HTTP
        headers a browser relies on to block XSS, clickjacking and network attacks.
      </p>
      <div className="space-y-2.5">
        {sec.checks.map((c) => {
          const m = DSEC_META[c.status];
          return (
            <div key={c.id} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="inline-block h-2.5 w-2.5 flex-none rounded-full" style={{ background: m.color }} />
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

function ReputationCard({ rep }: { rep: Reputation }) {
  return (
    <div className="card p-6">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-bold">Domain reputation</h2>
        <span
          className="rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
          style={{
            color: rep.flagged ? "var(--color-risk-crit)" : "var(--color-risk-low)",
            background: rep.flagged ? "rgba(244,63,94,0.14)" : "rgba(52,211,153,0.12)",
          }}
        >
          {rep.flagged ? "Flagged" : "Clean"}
        </span>
        <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
          live threat intel
        </span>
      </div>
      <p className="mb-4 text-sm leading-relaxed text-fg/85">
        {rep.flagged
          ? `${rep.domain} is currently flagged by a threat-intelligence source for malware or phishing — treat this as an active incident.`
          : `${rep.domain} isn't flagged on the ${rep.sourcesChecked} live source${rep.sourcesChecked === 1 ? "" : "s"} we could check.`}
      </p>
      <div className="space-y-2.5">
        {rep.checks.map((c) => {
          const m = DSEC_META[c.status];
          return (
            <div key={c.id} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="inline-block h-2.5 w-2.5 flex-none rounded-full" style={{ background: m.color }} />
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
      {rep.notChecked.length > 0 && (
        <p className="mt-3 text-[11px] text-muted">
          Not checked:{" "}
          {rep.notChecked.map((n) => `${n.name} (${n.reason})`).join(" · ")}
        </p>
      )}
    </div>
  );
}

function EmailRow({ r }: { r: EmailBreach }) {
  const breached = r.status === "breached";
  const err      = r.status === "error";
  return (
    <details className="group rounded-xl border border-white/8 bg-white/[0.025] px-4 py-3">
      <summary className="flex cursor-pointer list-none items-center gap-3">
        <span
          className="inline-block h-2.5 w-2.5 flex-none rounded-full"
          style={{ background: breached ? "var(--color-risk-crit)" : err ? "rgba(255,255,255,0.3)" : "var(--color-risk-low)" }}
        />
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

function Chips({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4">
      <div className="mb-2 text-xs font-medium text-muted">
        {title} ({items.length})
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
