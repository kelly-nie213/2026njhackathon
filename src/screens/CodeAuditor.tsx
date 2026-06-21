import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";
import {
  auditJs,
  generateJsReport,
  worstSeverity,
  SEVERITY_META,
  type JsAuditResult,
  type JsReport,
  type JsFinding,
} from "../lib/jsaudit";

type Phase = "input" | "scanning" | "report";

const SCAN_STEPS = [
  "Reaching the website…",
  "Finding the JavaScript it loads…",
  "Downloading external & inline scripts…",
  "Scanning code for bugs & security risks…",
  "Writing your plain-language fix plan…",
];

/* ── Decorative code-shield SVG ── */
function CodeShieldGraphic() {
  return (
    <div className="relative flex justify-center lg:justify-start float">
      <div
        className="absolute inset-0 rounded-full"
        style={{
          background: "radial-gradient(ellipse, rgba(99,102,241,0.24) 0%, transparent 70%)",
          filter: "blur(40px)",
          transform: "scale(1.4)",
        }}
      />

      <svg
        width="240"
        height="240"
        viewBox="0 0 240 240"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        style={{ filter: "drop-shadow(0 0 22px rgba(99,102,241,0.45))" }}
      >
        <defs>
          <linearGradient id="csg" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%"   stopColor="#818cf8" stopOpacity="0.92" />
            <stop offset="100%" stopColor="#a3e635" stopOpacity="0.80" />
          </linearGradient>
          <radialGradient id="csh" cx="50%" cy="38%" r="55%">
            <stop offset="0%"   stopColor="white" stopOpacity="0.26" />
            <stop offset="100%" stopColor="white" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="crg" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%"   stopColor="#6366f1" stopOpacity="0.52" />
            <stop offset="50%"  stopColor="#a3e635" stopOpacity="0.32" />
            <stop offset="100%" stopColor="#6366f1" stopOpacity="0.52" />
          </linearGradient>
        </defs>

        {/* Outer ring */}
        <motion.g
          animate={{ rotate: 360 }}
          transition={{ duration: 22, repeat: Infinity, ease: "linear" }}
          style={{ transformOrigin: "120px 120px" }}
        >
          <circle cx="120" cy="120" r="108" stroke="url(#crg)" strokeWidth="1" fill="none" strokeDasharray="6 12"/>
          <circle cx="228" cy="120" r="4.5" fill="#818cf8"/>
          <circle cx="120" cy="12"  r="3.5" fill="#a3e635"/>
          <circle cx="12"  cy="120" r="4"   fill="#818cf8"/>
          <circle cx="120" cy="228" r="3.5" fill="#34d399"/>
        </motion.g>

        {/* Inner ring */}
        <motion.g
          animate={{ rotate: -360 }}
          transition={{ duration: 14, repeat: Infinity, ease: "linear" }}
          style={{ transformOrigin: "120px 120px" }}
        >
          <circle cx="120" cy="120" r="78" stroke="rgba(6,182,212,0.20)" strokeWidth="0.8" fill="none" strokeDasharray="3 8"/>
          <circle cx="198" cy="120" r="2.5" fill="#a3e635" opacity="0.75"/>
          <circle cx="120" cy="42"  r="2"   fill="#818cf8" opacity="0.75"/>
        </motion.g>

        {/* Shield */}
        <path d="M120 44 L170 68 L170 122 Q170 170 120 190 Q70 170 70 122 L70 68 Z" fill="url(#csg)"/>
        <path d="M120 54 L160 76 L160 122 Q160 162 120 178 Q80 162 80 122 L80 76 Z" fill="url(#csh)"/>

        {/* Code brackets inside shield */}
        <text x="120" y="133" textAnchor="middle" fontSize="28" fontFamily="'SF Mono',monospace"
          fontWeight="800" fill="white" opacity="0.9">
          {"</>"}
        </text>

        {/* Status badges */}
        <motion.g animate={{ opacity: [0.7, 1, 0.7] }} transition={{ duration: 2.8, repeat: Infinity }}>
          <rect x="164" y="80" width="58" height="20" rx="10" fill="rgba(34,211,238,0.12)" stroke="rgba(34,211,238,0.35)" strokeWidth="0.8"/>
          <text x="193" y="94" textAnchor="middle" fontSize="8.5" fill="#22d3ee" fontFamily="'SF Mono',monospace" fontWeight="700" letterSpacing="0.5">
            AUDITING
          </text>
        </motion.g>
        <g opacity="0.85">
          <rect x="18" y="96" width="52" height="20" rx="10" fill="rgba(52,211,153,0.12)" stroke="rgba(52,211,153,0.35)" strokeWidth="0.8"/>
          <text x="44" y="110" textAnchor="middle" fontSize="8.5" fill="#34d399" fontFamily="'SF Mono',monospace" fontWeight="700" letterSpacing="0.5">
            SECURE
          </text>
        </g>
        <motion.g animate={{ opacity: [0.5, 0.85, 0.5] }} transition={{ duration: 3.5, repeat: Infinity, delay: 0.6 }}>
          <rect x="166" y="152" width="54" height="20" rx="10" fill="rgba(251,191,36,0.12)" stroke="rgba(251,191,36,0.35)" strokeWidth="0.8"/>
          <text x="193" y="166" textAnchor="middle" fontSize="8.5" fill="#fbbf24" fontFamily="'SF Mono',monospace" fontWeight="700" letterSpacing="0.5">
            PATCHING
          </text>
        </motion.g>

        {/* Scan line */}
        <motion.line
          x1="70" y1="122" x2="170" y2="122"
          stroke="rgba(34,211,238,0.45)" strokeWidth="1"
          animate={{ y1: [68, 172, 68], y2: [68, 172, 68], opacity: [0, 0.6, 0] }}
          transition={{ duration: 3.2, repeat: Infinity, ease: "easeInOut" }}
        />
      </svg>
    </div>
  );
}

export default function CodeAuditor() {
  const [phase, setPhase] = useState<Phase>("input");
  const [domain, setDomain] = useState("");
  const [orgName, setOrgName] = useState("");
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const [audit, setAudit] = useState<JsAuditResult | null>(null);
  const [report, setReport] = useState<JsReport | null>(null);
  const [reportSource, setReportSource] = useState<"ai" | "fallback">("fallback");

  const cleanDomain = domain.trim().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "");
  const canSubmit = cleanDomain.includes(".");

  const run = async () => {
    if (!canSubmit) return;
    setError(null);
    setPhase("scanning");
    setStep(0);
    try {
      setStep(2);
      const auditRes = await auditJs(cleanDomain);
      setAudit(auditRes);
      setStep(4);

      const { report: rep, source } = await generateJsReport(
        auditRes,
        orgName.trim() || auditRes.domain
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
    setAudit(null);
    setReport(null);
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
              orgName={orgName} setOrgName={setOrgName}
              domain={domain}   setDomain={setDomain}
              canSubmit={canSubmit} error={error}
              onSubmit={run}
              onExample={() => { setOrgName("AYLUS"); setDomain("aylus.org"); }}
            />
          )}

          {phase === "scanning" && (
            <ScanningView key="scanning" step={step} domain={cleanDomain} />
          )}

          {phase === "report" && audit && report && (
            <ReportView
              key="report"
              orgName={orgName.trim() || audit.domain}
              audit={audit} report={report}
              reportSource={reportSource} onReset={resetAll}
            />
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

/* ──────────── Input ──────────── */

function InputView(props: {
  orgName: string; setOrgName: (v: string) => void;
  domain: string;  setDomain:  (v: string) => void;
  canSubmit: boolean; error: string | null;
  onSubmit: () => void; onExample: () => void;
}) {
  const { orgName, setOrgName, domain, setDomain, canSubmit, error, onSubmit, onExample } = props;
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      className="grid items-center gap-10 pt-8 lg:grid-cols-2"
    >
      <div>
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
          <span className="h-1.5 w-1.5 rounded-full bg-brand-400" />
          Static analysis of your live site's code
        </div>
        <h1 className="text-4xl font-extrabold leading-[1.1] tracking-tight sm:text-5xl">
          Is there a{" "}
          <span className="bg-gradient-to-r from-brand-300 to-accent-400 bg-clip-text text-transparent">
            bug or security hole
          </span>{" "}
          in your website's code?
        </h1>
        <p className="mt-5 max-w-md text-[15px] leading-relaxed text-muted">
          Enter your domain. The Code Auditor reads the JavaScript your site ships to visitors and
          scans it for leaked keys, XSS holes, insecure requests, outdated libraries and leftover debug
          code — then explains which ones matter and how to fix them.
        </p>

        <CodeShieldGraphic />
      </div>

      <div className="card card-glow p-7">
        <h2 className="text-xl font-semibold">Scan your site's code</h2>
        <p className="mt-1 text-sm text-muted">We only read public scripts. Nothing is executed or stored.</p>

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
          Audit my code →
        </button>
        <button
          onClick={onExample}
          className="mt-3 w-full text-center text-xs text-muted underline-offset-4 hover:text-brand-300 hover:underline"
        >
          Try it with aylus.org
        </button>

        <div className="mt-5 flex items-center justify-center gap-4 border-t border-white/[0.06] pt-4">
          {["🔒 Read-only", "🧬 Deep analysis", "⚡ AI-powered"].map((b) => (
            <span key={b} className="text-[11px] text-muted">{b}</span>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

/* ──────────── Scanning ──────────── */

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
            {"</>"}
          </motion.div>
        </div>
      </div>
      <p className="text-sm text-muted">
        Auditing <span className="font-semibold text-fg">{domain}</span>
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

/* ──────────── Report ──────────── */

function ReportView(props: {
  orgName: string; audit: JsAuditResult; report: JsReport;
  reportSource: "ai" | "fallback"; onReset: () => void;
}) {
  const { orgName, audit, report, reportSource, onReset } = props;
  const top = worstSeverity(audit);
  const topMeta = SEVERITY_META[top];
  const hasFindings = audit.findings.length > 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      className="space-y-6 pt-6"
    >
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Code security audit</h1>
          <p className="mt-1 text-sm text-muted">
            {orgName} · <span className="font-mono text-brand-300">{audit.domain}</span> ·{" "}
            {audit.scriptsScanned.length} script{audit.scriptsScanned.length === 1 ? "" : "s"} scanned
          </p>
        </div>
        <button
          onClick={onReset}
          className="rounded-xl border border-white/10 px-3 py-1.5 text-xs text-muted transition hover:border-white/25 hover:text-fg"
        >
          ↺ Scan another site
        </button>
      </div>

      {/* Stat row */}
      <div className="grid gap-4 sm:grid-cols-4">
        <Stat label="Security issues"     value={audit.counts.security || 0}     accent="crit" />
        <Stat label="Code-quality issues" value={audit.counts.bug || 0}          accent="med"  />
        <Stat label="Critical / high"     value={(audit.counts.critical || 0) + (audit.counts.high || 0)} accent="high" />
        <div className="card p-5">
          <div className="text-xs text-muted">Highest severity</div>
          <div className="mt-2 text-2xl font-extrabold" style={{ color: topMeta.color }}>
            {hasFindings ? topMeta.label : "Clean"}
          </div>
        </div>
      </div>

      {/* Summary */}
      <div className="card card-glow p-6">
        <div className="mb-1 flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-bold">Summary & fix plan</h2>
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
              className="group rounded-xl border border-white/8 bg-white/[0.025] p-4 open:border-brand-400/40"
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
          <div className="mt-4 rounded-xl bg-white/[0.03] px-3 py-2 text-[11px] text-muted">
            Showing the built-in plan — add an <span className="text-fg">ANTHROPIC_API_KEY</span> to
            generate one tailored to your exact findings.
          </div>
        )}
      </div>

      {/* Findings */}
      <div className="card p-6">
        <h2 className="mb-1 text-lg font-bold">What we found in your code</h2>
        <p className="mb-4 text-sm text-muted">
          Items marked{" "}
          <span className="rounded border border-white/10 px-1 py-0.5 text-[10px]">3rd-party</span>
          {" "}come from libraries — update or replace them instead of editing directly.
        </p>

        {hasFindings ? (
          <div className="space-y-2.5">
            {audit.findings.map((f, i) => <FindingRow key={i} f={f} />)}
          </div>
        ) : (
          <p className="rounded-xl bg-white/[0.03] px-3 py-3 text-sm text-muted">
            No bugs or security risks were flagged — nice. Keep your site and plugins up to date.
          </p>
        )}
      </div>

      {/* Scripts scanned */}
      <div className="card p-6">
        <h2 className="mb-3 text-lg font-bold">
          Scripts scanned ({audit.scriptsScanned.length}
          {audit.externalFound > audit.scriptsScanned.length
            ? ` of ${audit.externalFound} found` : ""})
        </h2>
        <div className="flex flex-wrap gap-1.5">
          {audit.scriptsScanned.map((s) => (
            <span
              key={s.url + s.file}
              className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/5 px-2 py-0.5 font-mono text-[11px]"
              title={s.url}
            >
              {s.party === 0 ? "🏠" : "🌐"} {s.file}
              <span className="text-muted">{(s.bytes / 1024).toFixed(0)}kb</span>
            </span>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

/* ──────────── Sub-components ──────────── */

function FindingRow({ f }: { f: JsFinding }) {
  const m = SEVERITY_META[f.severity];
  return (
    <details className="group rounded-xl border border-white/8 bg-white/[0.025] px-4 py-3">
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
        <pre className="overflow-x-auto rounded-xl bg-ink-900/60 px-3 py-2 font-mono text-[11px] leading-relaxed text-fg/80">
          {f.snippet}
        </pre>
      </div>
    </details>
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
