import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";
import {
  QUESTIONS,
  triage,
  SEVERITY_STYLE,
  type Answers,
  type TriageResult,
} from "../lib/triage";
import { generateRecovery, type RecoveryGuidance } from "../lib/api";

function describe(answers: Answers): string {
  return QUESTIONS.map((q) => {
    const picked = (answers[q.id] ?? [])
      .map((v) => q.options.find((o) => o.value === v)?.label ?? v)
      .join(", ");
    return picked ? `- ${q.prompt} ${picked}` : null;
  })
    .filter(Boolean)
    .join("\n");
}

/* ── Decorative alert icon ── */
function AlertIcon() {
  return (
    <div className="relative">
      <div className="absolute inset-0 rounded-full bg-risk-crit/20 blur-lg scale-150" />
      <svg width="44" height="44" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="ag" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%"   stopColor="#fb7185" />
            <stop offset="100%" stopColor="#f43f5e" />
          </linearGradient>
        </defs>
        {/* Triangle warning */}
        <path d="M22 6 L40 36 L4 36 Z" fill="url(#ag)" opacity="0.2" stroke="url(#ag)" strokeWidth="1.5" strokeLinejoin="round"/>
        <line x1="22" y1="17" x2="22" y2="27" stroke="#fb7185" strokeWidth="2.5" strokeLinecap="round"/>
        <circle cx="22" cy="31.5" r="1.5" fill="#fb7185"/>
      </svg>
    </div>
  );
}

export default function IncidentTriage() {
  const nav = useNavigate();
  const [step, setStep] = useState(0);
  const [answers, setAnswers] = useState<Answers>({});
  const [result, setResult] = useState<TriageResult | null>(null);
  const [recovery, setRecovery] = useState<RecoveryGuidance | null>(null);
  const [loading, setLoading] = useState(false);

  const q = QUESTIONS[step];
  const done = result !== null;

  const goNext = (next: Answers) => {
    if (step < QUESTIONS.length - 1) setStep((s) => s + 1);
    else setResult(triage(next));
  };

  const select = (value: string) => {
    const cur = answers[q.id] ?? [];
    let next: Answers;
    if (q.multi) {
      const picks = cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value];
      next = { ...answers, [q.id]: picks };
      setAnswers(next);
    } else {
      next = { ...answers, [q.id]: [value] };
      setAnswers(next);
      setTimeout(() => goNext(next), 180);
    }
  };

  const advance = () => goNext(answers);

  const restart = () => {
    setStep(0);
    setAnswers({});
    setResult(null);
    setRecovery(null);
  };

  const runAi = async () => {
    if (!result) return;
    setLoading(true);
    const guide = await generateRecovery(describe(answers), result, "a small nonprofit");
    setRecovery(guide);
    setLoading(false);
  };

  const selected = answers[q?.id] ?? [];
  const steps = recovery ? recovery.steps : result?.steps ?? [];

  return (
    <div className="min-h-full pb-16">
      <Nav />

      <main className="mx-auto max-w-3xl px-6 pt-8">
        {/* Page header */}
        <div className="mb-6">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
            <span className="h-1.5 w-1.5 rounded-full bg-brand-400" /> Incident triage
          </div>
          <div className="flex items-center gap-3">
            <AlertIcon />
            <div>
              <h1 className="text-2xl font-bold tracking-tight">
                {done ? "Here's what to do" : "Something happened? Let's sort it out."}
              </h1>
              {!done && (
                <p className="mt-0.5 text-sm text-muted">
                  Answer a few quick questions. We'll tell you severity, what's reversible, and who to call.
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Progress bar */}
        {!done && (
          <div className="mb-6 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-brand-500 to-accent-500"
              animate={{ width: `${((step + (selected.length ? 1 : 0)) / QUESTIONS.length) * 100}%` }}
            />
          </div>
        )}

        <AnimatePresence mode="wait">
          {!done && (
            <motion.div
              key={q.id}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="card p-6"
            >
              <div className="mb-1 text-xs text-muted">
                Question {step + 1} of {QUESTIONS.length}
              </div>
              <h2 className="text-lg font-semibold">{q.prompt}</h2>
              {q.help && <p className="mt-1 text-xs text-muted">{q.help}</p>}

              <div className="mt-4 space-y-2">
                {q.options.map((o) => {
                  const on = selected.includes(o.value);
                  return (
                    <button
                      key={o.value}
                      onClick={() => select(o.value)}
                      className={`flex w-full items-center gap-3 rounded-xl border px-4 py-3 text-left text-sm transition ${
                        on
                          ? "border-brand-400 bg-brand-500/15"
                          : "border-white/10 bg-white/[0.02] hover:border-white/25"
                      }`}
                    >
                      <span
                        className={`grid h-5 w-5 flex-none place-items-center border text-[11px] ${
                          q.multi ? "rounded-md" : "rounded-full"
                        } ${on ? "border-brand-400 bg-brand-500 text-white" : "border-white/25"}`}
                      >
                        {on ? "✓" : ""}
                      </span>
                      <span className="flex-1">
                        {o.label}
                        {o.hint && <span className="ml-1 text-xs text-muted">— {o.hint}</span>}
                      </span>
                    </button>
                  );
                })}
              </div>

              <div className="mt-5 flex items-center justify-between">
                <button
                  onClick={() => setStep((s) => Math.max(0, s - 1))}
                  disabled={step === 0}
                  className="text-sm text-muted disabled:opacity-30"
                >
                  ← Previous
                </button>
                {q.multi && (
                  <button
                    onClick={advance}
                    disabled={selected.length === 0}
                    className="p-btn p-prim-col"
                    style={{ margin: 0 }}
                  >
                    Continue →
                  </button>
                )}
              </div>
            </motion.div>
          )}

          {done && result && (
            <motion.div
              key="result"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-5"
            >
              {/* Severity + reversibility */}
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="card p-5">
                  <div className="text-xs font-medium uppercase tracking-wide text-muted">Severity</div>
                  <div
                    className="mt-2 inline-block rounded-full px-3 py-1 text-lg font-bold"
                    style={{
                      color: SEVERITY_STYLE[result.severity].color,
                      background: SEVERITY_STYLE[result.severity].bg,
                    }}
                  >
                    {SEVERITY_STYLE[result.severity].label}
                  </div>
                  <p className="mt-2 text-sm text-fg/85">{result.severityNote}</p>
                </div>
                <div className="card p-5">
                  <div className="text-xs font-medium uppercase tracking-wide text-muted">
                    Can the damage be undone?
                  </div>
                  <div
                    className="mt-2 text-sm font-semibold"
                    style={{
                      color:
                        result.reversible === "hard"    ? "var(--color-risk-crit)"
                        : result.reversible === "partial" ? "var(--color-risk-med)"
                        : "var(--color-risk-low)",
                    }}
                  >
                    {result.reversible === "hard"
                      ? "Hard to reverse — act now"
                      : result.reversible === "partial"
                        ? "Partly — if you move fast"
                        : "Likely, with quick action"}
                  </div>
                  <p className="mt-2 text-sm text-fg/85">{result.reversibility}</p>
                </div>
              </div>

              {/* Who to notify */}
              <div className="card p-5">
                <h3 className="mb-3 text-base font-bold">Who to notify</h3>
                <div className="space-y-2.5">
                  {result.notify.map((n, i) => (
                    <div key={i} className="flex items-start gap-3 rounded-xl border border-white/8 bg-white/[0.02] p-3">
                      <span
                        className={`mt-0.5 flex-none rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                          n.urgent ? "bg-risk-crit/15 text-risk-high" : "bg-white/10 text-muted"
                        }`}
                      >
                        {n.urgent ? "NOW" : "SOON"}
                      </span>
                      <div>
                        <div className="text-sm font-semibold">{n.who}</div>
                        <div className="text-xs text-muted">{n.why}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recovery steps */}
              <div className="card card-glow p-5">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <h3 className="text-base font-bold">Do this now</h3>
                  <button
                    onClick={runAi}
                    disabled={loading}
                    className="ml-auto rounded-xl border border-brand-400/40 bg-brand-500/10 px-3 py-1.5 text-xs font-medium text-brand-200 transition hover:bg-brand-500/20 disabled:opacity-50"
                  >
                    {loading ? "Thinking…" : recovery ? "↻ Regenerate" : "✦ AI recovery guidance"}
                  </button>
                </div>
                {recovery && <p className="mb-3 text-sm text-muted">{recovery.summary}</p>}
                {recovery?.source === "fallback" && (
                  <div className="mb-3 rounded-xl bg-white/[0.03] px-3 py-2 text-[11px] text-muted">
                    Built-in guidance — add an <span className="text-fg">ANTHROPIC_API_KEY</span> for
                    advice tailored to your exact situation.
                  </div>
                )}
                <ol className="space-y-2.5">
                  {steps.map((s, i) => (
                    <li key={i} className="flex gap-3 text-sm text-fg/90">
                      <span className="grid h-6 w-6 flex-none place-items-center rounded-full bg-gradient-to-br from-brand-500 to-accent-500 text-xs font-bold text-white">
                        {i + 1}
                      </span>
                      <span className="pt-0.5">{s}</span>
                    </li>
                  ))}
                </ol>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={restart}
                  className="rounded-xl border border-white/10 px-4 py-2 text-sm text-muted transition hover:border-white/25 hover:text-fg"
                >
                  Start over
                </button>
                <button
                  onClick={() => nav("/phishing")}
                  className="rounded-xl border border-brand-400/40 bg-brand-500/10 px-4 py-2 text-sm font-medium text-brand-200 transition hover:bg-brand-500/20"
                >
                  Check the message that caused this →
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
