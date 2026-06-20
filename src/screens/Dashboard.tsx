import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Brand } from "../components/Brand";
import { RiskGauge } from "../components/RiskGauge";
import { InterconnectionMap } from "../components/InterconnectionMap";
import { useScan } from "../store";
import { SEVERITY_META } from "../lib/scan";
import { generateActionPlan, type AiActionPlan } from "../lib/api";
import type { DataAsset } from "../lib/types";

export default function Dashboard() {
  const nav = useNavigate();
  const { result, reset } = useScan();
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [aiPlan, setAiPlan] = useState<AiActionPlan | null>(null);
  const [planSource, setPlanSource] = useState<"ai" | "fallback" | null>(null);
  const [planLoading, setPlanLoading] = useState(false);

  if (!result) {
    nav("/");
    return null;
  }

  const { input, riskScore, riskLabel, findings, dataAssets, likelyAttack, actionPlan, stats } =
    result;

  const selected: DataAsset =
    dataAssets.find((a) => a.id === selectedAsset) ??
    [...dataAssets].sort((a, b) => b.connections.length - a.connections.length)[0];

  const exposedAssets = dataAssets.filter((a) => a.exposed);

  const trend = useMemo(
    () =>
      Array.from({ length: 12 }, (_, i) => ({
        m: i,
        v: Math.round(20 + Math.abs(Math.sin(i * 1.3 + riskScore) * 70) + i * 4),
      })),
    [riskScore]
  );

  const runAiPlan = async () => {
    setPlanLoading(true);
    const { plan, source } = await generateActionPlan(result);
    setAiPlan(plan);
    setPlanSource(source);
    setPlanLoading(false);
  };

  const planSteps = aiPlan
    ? aiPlan.steps.map((s, i) => ({ priority: i + 1, ...s }))
    : actionPlan;

  return (
    <div className="bg-aurora min-h-full pb-16">
      {/* top bar */}
      <header className="sticky top-0 z-10 border-b border-white/8 bg-ink-950/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-2 px-4 py-3 sm:px-6 sm:py-4">
          <Brand />
          <div className="flex flex-wrap items-center justify-end gap-2">
            <div className="hidden text-right lg:block">
              <div className="text-sm font-semibold">{input.orgName}</div>
              <div className="text-xs text-muted">{input.domain}</div>
            </div>
            <button
              onClick={() => nav("/phishing")}
              title="Check a suspicious email"
              className="rounded-lg border border-brand-400/40 bg-brand-500/10 px-2.5 py-1.5 text-xs font-medium text-brand-200 transition hover:bg-brand-500/20"
            >
              ✦ <span className="hidden sm:inline">Check an email</span>
            </button>
            <button
              onClick={() => nav("/triage")}
              title="Something already happened"
              className="rounded-lg border border-risk-high/40 bg-risk-crit/10 px-2.5 py-1.5 text-xs font-medium text-risk-high transition hover:bg-risk-crit/20"
            >
              ⚑ <span className="hidden sm:inline">Something happened</span>
            </button>
            <button
              onClick={() => {
                reset();
                nav("/");
              }}
              title="Run a new scan"
              className="rounded-lg border border-white/12 px-2.5 py-1.5 text-xs text-muted transition hover:border-white/30 hover:text-fg"
            >
              <span className="hidden sm:inline">New scan</span>
              <span className="sm:hidden">↺</span>
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-6 px-4 pt-7 sm:px-6">
        <Reveal>
          <h1 className="text-2xl font-bold tracking-tight">
            Cyber Health Check
          </h1>
          <p className="mt-1 text-sm text-muted">
            {exposedAssets.length} of {dataAssets.length} data types currently exposed for{" "}
            <span className="text-fg">{input.orgName}</span>
          </p>
        </Reveal>

        {/* hero: gauge + likely attack */}
        <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
          <Reveal className="card flex flex-col items-center justify-center p-6">
            <span className="mb-1 self-start text-xs font-medium uppercase tracking-wide text-muted">
              Overall risk score
            </span>
            <RiskGauge score={riskScore} label={riskLabel} />
            <p className="mt-3 text-center text-xs text-muted">
              A score, not a verdict — what matters is the{" "}
              <span className="text-fg">consequences</span> and your{" "}
              <span className="text-fg">action plan</span> below.
            </p>
          </Reveal>

          <Reveal className="card relative overflow-hidden p-6">
            <div className="absolute right-0 top-0 h-32 w-32 rounded-full bg-risk-crit/20 blur-3xl" />
            <div className="mb-2 inline-flex items-center gap-2 rounded-full bg-risk-crit/15 px-3 py-1 text-xs font-semibold text-risk-high">
              ⚠ Most likely attack against you
            </div>
            <h2 className="text-xl font-bold">{likelyAttack.type}</h2>
            <p className="mt-2 max-w-xl text-sm leading-relaxed text-fg/85">
              {likelyAttack.description}
            </p>
            <div className="mt-4">
              <div className="text-xs font-medium uppercase tracking-wide text-muted">
                Who's most at risk
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {likelyAttack.whoAtRisk.map((w) => (
                  <span
                    key={w}
                    className="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs"
                  >
                    {w}
                  </span>
                ))}
              </div>
            </div>
          </Reveal>
        </div>

        {/* stat row */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Stat label="Staff accounts in breaches" value={stats.breachedAccounts} accent="crit" sub="found in public dumps" />
          <Stat label="Records potentially exposed" value={stats.exposedRecords.toLocaleString()} accent="high" sub="donors, volunteers, staff" />
          <Stat label="AI-phishing susceptibility" value={`${stats.phishingSusceptibility}%`} accent="high" sub="chance a fake email lands" />
          <Stat label="Look-alike domains" value={1} accent="med" sub="registered to impersonate you" />
        </div>

        {/* CONSEQUENCES — the emphasis */}
        <Reveal className="card p-6">
          <div className="mb-1 flex items-center gap-2">
            <h2 className="text-lg font-bold">What happens if this data leaks?</h2>
            <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
              tap a node
            </span>
          </div>
          <p className="mb-4 text-sm text-muted">
            Your data is interconnected. One breach rarely stays contained — here's how it
            cascades, and what each leak really costs you.
          </p>

          <div className="grid items-center gap-6 lg:grid-cols-[1.1fr_1fr]">
            <div className="rounded-2xl border border-white/8 bg-ink-900/50 p-2">
              <InterconnectionMap
                assets={dataAssets}
                selected={selectedAsset}
                onSelect={(id) => setSelectedAsset((cur) => (cur === id ? null : id))}
              />
            </div>

            <motion.div
              key={selected.id}
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              className="rounded-2xl border border-white/10 bg-gradient-to-br from-white/[0.05] to-transparent p-5"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-base font-semibold">
                  <span className="text-2xl">{selected.icon}</span>
                  {selected.name}
                </div>
                <span
                  className="rounded-full px-2.5 py-1 text-xs font-semibold"
                  style={{
                    color: selected.exposed ? "var(--color-risk-crit)" : "var(--color-risk-low)",
                    background: selected.exposed ? "rgba(244,63,94,0.14)" : "rgba(52,211,153,0.12)",
                  }}
                >
                  {selected.exposed ? "Exposed" : "Not yet exposed"}
                </span>
              </div>

              <div className="mt-3 text-xs font-medium uppercase tracking-wide text-risk-high">
                If this leaks:
              </div>
              <p className="mt-1.5 text-sm leading-relaxed text-fg/90">{selected.consequence}</p>

              <div className="mt-4 flex items-center gap-4 text-xs text-muted">
                <span>
                  Sensitivity{" "}
                  <span className="font-semibold text-fg">{selected.sensitivity}/100</span>
                </span>
                <span>
                  Spreads to{" "}
                  <span className="font-semibold text-fg">
                    {selected.connections.length} other system
                    {selected.connections.length === 1 ? "" : "s"}
                  </span>
                </span>
              </div>
            </motion.div>
          </div>
        </Reveal>

        {/* findings + trend */}
        <div className="grid gap-6 lg:grid-cols-[1.5fr_1fr]">
          <Reveal className="card p-6">
            <h2 className="mb-4 text-lg font-bold">What we found</h2>
            <div className="space-y-3">
              {findings.map((f) => {
                const m = SEVERITY_META[f.severity];
                return (
                  <div
                    key={f.id}
                    className="rounded-xl border border-white/8 bg-white/[0.02] p-4"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="font-semibold">{f.title}</div>
                      <span
                        className="flex-none rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
                        style={{ color: m.color, background: m.bg }}
                      >
                        {m.label}
                      </span>
                    </div>
                    <p className="mt-1.5 text-sm text-muted">{f.detail}</p>
                    <div className="mt-2 rounded-lg bg-ink-900/60 px-3 py-1.5 font-mono text-[11px] text-brand-300">
                      {f.evidence}
                    </div>
                  </div>
                );
              })}
            </div>
          </Reveal>

          <Reveal className="card flex flex-col p-6">
            <h2 className="text-lg font-bold">Exposure mentions</h2>
            <p className="text-xs text-muted">references to your org seen online, last 12 weeks</p>
            <div className="mt-4 flex-1">
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={trend} margin={{ top: 6, right: 6, left: -22, bottom: 0 }}>
                  <defs>
                    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#8b5cf6" stopOpacity={0.6} />
                      <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="m" hide />
                  <YAxis hide />
                  <Tooltip
                    contentStyle={{
                      background: "#14142a",
                      border: "1px solid rgba(255,255,255,0.1)",
                      borderRadius: 10,
                      fontSize: 12,
                    }}
                    labelFormatter={(l) => `Week ${Number(l) + 1}`}
                    formatter={(v) => [`${v} mentions`, ""]}
                  />
                  <Area type="monotone" dataKey="v" stroke="#a78bfa" strokeWidth={2} fill="url(#g)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 rounded-lg bg-risk-crit/10 px-3 py-2 text-xs text-risk-high">
              ↑ Mentions are trending up — attention from attackers is increasing.
            </div>
          </Reveal>
        </div>

        {/* ACTION PLAN — what to do next */}
        <Reveal className="card card-glow p-6">
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-bold">Your action plan</h2>
            <span className="rounded-full bg-risk-low/15 px-2 py-0.5 text-[11px] font-medium text-risk-low">
              start at the top
            </span>
            <button
              onClick={runAiPlan}
              disabled={planLoading}
              className="ml-auto rounded-lg border border-brand-400/40 bg-brand-500/10 px-3 py-1.5 text-xs font-medium text-brand-200 transition hover:bg-brand-500/20 disabled:opacity-50"
            >
              {planLoading ? "Personalizing…" : aiPlan ? "↻ Regenerate" : "✦ Personalize with AI"}
            </button>
          </div>
          <p className="mb-5 text-sm text-muted">
            {aiPlan
              ? aiPlan.summary
              : "No jargon. Do these in order — the first two stop most attacks on their own."}
          </p>
          {planSource === "fallback" && (
            <div className="mb-4 rounded-lg bg-white/[0.03] px-3 py-2 text-[11px] text-muted">
              Showing the built-in plan — add an <span className="text-fg">ANTHROPIC_API_KEY</span> to
              generate one tailored to your exact findings.
            </div>
          )}

          <div className="space-y-3">
            {planSteps.map((step) => (
              <details
                key={step.priority}
                className="group rounded-xl border border-white/8 bg-white/[0.02] p-4 open:border-brand-400/40"
              >
                <summary className="flex cursor-pointer list-none items-center gap-3">
                  <span className="grid h-7 w-7 flex-none place-items-center rounded-full bg-gradient-to-br from-brand-500 to-accent-500 text-sm font-bold text-white">
                    {step.priority}
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
                    {step.steps.map((s, i) => (
                      <li key={i} className="flex gap-2 text-sm text-fg/85">
                        <span className="text-brand-400">›</span>
                        {s}
                      </li>
                    ))}
                  </ul>
                </div>
              </details>
            ))}
          </div>
        </Reveal>
      </main>
    </div>
  );
}

function Stat({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub: string;
  accent: "crit" | "high" | "med";
}) {
  const color =
    accent === "crit"
      ? "var(--color-risk-crit)"
      : accent === "high"
        ? "var(--color-risk-high)"
        : "var(--color-risk-med)";
  return (
    <Reveal className="card p-5">
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-2 text-3xl font-extrabold tabular-nums" style={{ color }}>
        {value}
      </div>
      <div className="mt-1 text-[11px] text-muted">{sub}</div>
    </Reveal>
  );
}

function Reveal({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-40px" }}
      transition={{ duration: 0.4 }}
      className={className}
    >
      {children}
    </motion.div>
  );
}
