import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Brand } from "../components/Brand";
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

type Phase = "input" | "scanning" | "report";

const SCAN_STEPS = [
  "Reaching the website…",
  "Crawling public pages for contact info…",
  "Extracting emails, names & phone numbers…",
  "Checking your domain's email-spoofing protection (DNS)…",
  "Checking each email against breach databases…",
  "Assessing risks and writing your action plan…",
];

export default function BreachDetector() {
  const nav = useNavigate();
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

      // Domain spoofing check (live DNS) and breach lookup are independent — run together.
      setStep(3);
      const [domainSecRes, lookupRes] = await Promise.all([
        checkDomainSecurity(cleanDomain),
        crawlRes.emails.length
          ? lookupBreaches(crawlRes.emails)
          : Promise.resolve({ source: "demo" as const, results: [] }),
      ]);
      setDomainSec(domainSecRes);
      setLookup(lookupRes);
      setStep(5);

      const { report: rep, source } = await generateReport(
        crawlRes,
        lookupRes,
        orgName.trim() || crawlRes.domain,
        domainSecRes
      );
      setReport(rep);
      setReportSource(source);
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
    setStep(0);
  };

  return (
    <div className="bg-aurora min-h-full pb-16">
      <header className="mx-auto flex max-w-5xl items-center justify-between px-6 py-6">
        <Brand />
        <div className="flex items-center gap-2">
          <button
            onClick={() => nav("/code-audit")}
            className="rounded-full border border-brand-400/40 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-200 transition hover:bg-brand-500/20"
          >
            {"</>"} Code auditor
          </button>
          <button
            onClick={() => nav("/phishing")}
            className="rounded-full border border-brand-400/40 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-200 transition hover:bg-brand-500/20"
          >
            ✉️ Phishing checker
          </button>
          <button
            onClick={() => nav("/triage")}
            className="rounded-full border border-risk-high/40 bg-risk-crit/10 px-3 py-1 text-xs font-medium text-risk-high transition hover:bg-risk-crit/20"
          >
            ⚑ Something already happened?
          </button>
        </div>
      </header>

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
              onExample={() => {
                setOrgName("AYLUS");
                setDomain("aylus.org");
              }}
            />
          )}

          {phase === "scanning" && <ScanningView key="scanning" step={step} domain={cleanDomain} />}

          {phase === "report" && crawl && lookup && report && (
            <ReportView
              key="report"
              orgName={orgName.trim() || crawl.domain}
              crawl={crawl}
              lookup={lookup}
              domainSec={domainSec}
              report={report}
              reportSource={reportSource}
              onReset={resetAll}
            />
          )}
        </AnimatePresence>
      </main>

      <style>{`
        .bd-input {
          width: 100%; border-radius: 0.75rem;
          background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1);
          padding: 0.7rem 0.9rem; font-size: 0.95rem; color: var(--color-fg);
          outline: none; transition: border-color .15s, box-shadow .15s;
        }
        .bd-input:focus { border-color: var(--color-brand-400); box-shadow: 0 0 0 3px rgba(139,92,246,0.18); }
        .bd-input::placeholder { color: #6b6b85; }
      `}</style>
    </div>
  );
}

/* ----------------------------- Input ----------------------------- */

function InputView(props: {
  orgName: string;
  setOrgName: (v: string) => void;
  domain: string;
  setDomain: (v: string) => void;
  canSubmit: boolean;
  error: string | null;
  onSubmit: () => void;
  onExample: () => void;
}) {
  const { orgName, setOrgName, domain, setDomain, canSubmit, error, onSubmit, onExample } = props;
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="grid items-center gap-10 pt-6 lg:grid-cols-2"
    >
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
          Enter your domain. BreachDetector crawls your public pages for staff emails, names and
          phone numbers — then checks each email against known data breaches and tells you, in plain
          English, the risks and exactly what to do next.
        </p>
        <ul className="mt-7 space-y-3 text-sm">
          {[
            "Finds the emails & contact info an attacker would scrape first",
            "Checks each address against known breaches (XposedOrNot)",
            "Tests whether your domain can be spoofed in email (SPF/DMARC/DKIM)",
            "Turns it into risks, consequences, and a step-by-step plan",
          ].map((t) => (
            <li key={t} className="flex items-start gap-3 text-fg/90">
              <span className="mt-0.5 grid h-5 w-5 flex-none place-items-center rounded-full bg-brand-500/20 text-brand-300">
                ✓
              </span>
              {t}
            </li>
          ))}
        </ul>
      </div>

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
              Organization name (optional)
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
          <div className="mt-4 rounded-lg border border-risk-high/30 bg-risk-crit/10 px-3 py-2 text-xs text-risk-high">
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
      </div>
    </motion.div>
  );
}

/* ---------------------------- Scanning ---------------------------- */

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

/* ----------------------------- Report ----------------------------- */

function ReportView(props: {
  orgName: string;
  crawl: CrawlResult;
  lookup: BreachLookup;
  domainSec: DomainSecurity | null;
  report: BreachReport;
  reportSource: "ai" | "fallback";
  onReset: () => void;
}) {
  const { orgName, crawl, lookup, domainSec, report, reportSource, onReset } = props;
  const breachedCount = breachedAccounts(lookup);
  const totalB = totalBreaches(lookup);

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      className="space-y-6 pt-2"
    >
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
          className="rounded-lg border border-white/12 px-3 py-1.5 text-xs text-muted transition hover:border-white/30 hover:text-fg"
        >
          ↺ Scan another site
        </button>
      </div>

      {lookup.source === "demo" && crawl.emails.length > 0 && (
        <div className="rounded-lg border border-risk-med/30 bg-risk-med/10 px-3 py-2 text-xs text-risk-med">
          ⚠ Couldn't reach the breach database, so results below are{" "}
          <span className="font-semibold">simulated</span>. Check your connection and rescan for live
          data.
        </div>
      )}

      {/* stat row */}
      <div className="grid gap-4 sm:grid-cols-4">
        <Stat label="Public emails found" value={crawl.emails.length} accent="high" />
        <Stat label="Emails in breaches" value={breachedCount} accent="crit" />
        <Stat label="Total breach hits" value={totalB} accent="crit" />
        <Stat label="Names & phones exposed" value={crawl.names.length + crawl.phones.length} accent="med" />
      </div>

      {/* what we harvested */}
      <div className="card p-6">
        <h2 className="mb-1 text-lg font-bold">What we harvested from your site</h2>
        <p className="mb-4 text-sm text-muted">
          This is public data an attacker could scrape in seconds. Each email is checked below.
        </p>

        {lookup.results.length > 0 ? (
          <div className="space-y-2.5">
            {lookup.results
              .slice()
              .sort((a, b) => b.breachCount - a.breachCount)
              .map((r) => (
                <EmailRow key={r.email} r={r} />
              ))}
          </div>
        ) : (
          <p className="rounded-lg bg-white/[0.03] px-3 py-3 text-sm text-muted">
            No public email addresses were found on the pages we scanned — that's good for your
            attack surface.
          </p>
        )}

        {(crawl.names.length > 0 || crawl.phones.length > 0) && (
          <div className="mt-5 grid gap-4 sm:grid-cols-2">
            {crawl.names.length > 0 && (
              <Chips title="Names found" items={crawl.names} icon="👤" />
            )}
            {crawl.phones.length > 0 && (
              <Chips title="Phone numbers found" items={crawl.phones} icon="📞" />
            )}
          </div>
        )}
      </div>

      {/* domain spoofing protection (live DNS) */}
      {domainSec && <DomainSecurityCard sec={domainSec} />}

      {/* risks */}
      <div className="card p-6">
        <div className="mb-1 flex items-center gap-2">
          <h2 className="text-lg font-bold">Potential risks & who's at risk</h2>
          {reportSource === "ai" && (
            <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
              ✦ AI-assessed
            </span>
          )}
        </div>
        <p className="mb-4 text-sm leading-relaxed text-fg/85">{report.summary}</p>
        <div className="space-y-3">
          {report.risks.map((risk, i) => {
            const m = SEVERITY_META[risk.severity];
            return (
              <div key={i} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
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
                        <span
                          key={w}
                          className="rounded-lg border border-white/10 bg-white/5 px-2 py-0.5 text-[11px]"
                        >
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
      </div>

      {/* action plan */}
      <div className="card card-glow p-6">
        <div className="mb-1 flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-bold">Your step-by-step action plan</h2>
          <span className="rounded-full bg-risk-low/15 px-2 py-0.5 text-[11px] font-medium text-risk-low">
            start at the top
          </span>
        </div>
        <p className="mb-5 text-sm text-muted">
          Plain English, in priority order. The first two steps stop most attacks on their own.
        </p>
        <div className="space-y-3">
          {report.actions.map((step, i) => (
            <details
              key={i}
              className="group rounded-xl border border-white/8 bg-white/[0.02] p-4 open:border-brand-400/40"
              open={i === 0}
            >
              <summary className="flex cursor-pointer list-none items-center gap-3">
                <span className="grid h-7 w-7 flex-none place-items-center rounded-full bg-gradient-to-br from-brand-500 to-accent-500 text-sm font-bold text-white">
                  {i + 1}
                </span>
                <span className="flex-1 font-semibold">{step.title}</span>
                <span className="rounded-full border border-white/10 px-2 py-0.5 text-[11px] text-muted">
                  {step.effort}
                </span>
                <span className="text-muted transition group-open:rotate-180">▾</span>
              </summary>
              <div className="mt-3 pl-10">
                <div className="mb-2 text-xs italic text-brand-300">Why: {step.why}</div>
                <ul className="space-y-1.5">
                  {step.steps.map((s, j) => (
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
    </motion.div>
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
  const err = r.status === "error";
  return (
    <details className="group rounded-xl border border-white/8 bg-white/[0.02] px-4 py-3">
      <summary className="flex cursor-pointer list-none items-center gap-3">
        <span className="text-base">{breached ? "🔴" : err ? "⚪" : "🟢"}</span>
        <span className="flex-1 truncate font-mono text-sm">{r.email}</span>
        <span
          className="flex-none rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
          style={{
            color: breached ? "var(--color-risk-crit)" : err ? "var(--color-muted)" : "var(--color-risk-low)",
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
            <div key={i} className="rounded-lg bg-ink-900/60 px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold">{b.title}</span>
                <span className="text-[11px] text-muted">{b.breachDate?.slice(0, 4)}</span>
              </div>
              {b.dataClasses.length > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {b.dataClasses.slice(0, 6).map((c) => (
                    <span
                      key={c}
                      className="rounded border border-white/10 px-1.5 py-0.5 text-[10px] text-muted"
                    >
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
    <div className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
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

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent: "crit" | "high" | "med";
}) {
  const color =
    accent === "crit"
      ? "var(--color-risk-crit)"
      : accent === "high"
        ? "var(--color-risk-high)"
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
