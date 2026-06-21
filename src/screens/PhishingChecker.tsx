import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";
import { analyzePhishing, type PhishingVerdict } from "../lib/api";

const SAMPLE = `From: Pastor David Reyes <d.reyes@grace-foodbank.com>
Subject: Urgent - quick favor

Hi, are you at your desk? I'm in a board meeting and can't talk.
We need to send a payment to a new vendor today before 3pm. I'll
send the new bank account details shortly. Please keep this between
us until I announce it. Thanks - David`;

const VERDICT_META: Record<
  PhishingVerdict["verdict"],
  { label: string; color: string; bg: string }
> = {
  likely_phishing: { label: "Likely phishing", color: "var(--color-risk-crit)", bg: "rgba(244,63,94,0.14)" },
  suspicious:      { label: "Suspicious",      color: "var(--color-risk-med)",  bg: "rgba(251,191,36,0.14)" },
  likely_safe:     { label: "Likely safe",     color: "var(--color-risk-low)",  bg: "rgba(52,211,153,0.14)" },
};

/* ── Decorative mail-shield SVG ── */
function MailShieldIcon() {
  return (
    <svg width="44" height="44" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="mg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stopColor="#818cf8" />
          <stop offset="100%" stopColor="#a3e635" />
        </linearGradient>
      </defs>
      {/* Envelope */}
      <rect x="5" y="12" width="28" height="20" rx="3" fill="url(#mg)" opacity="0.22" stroke="url(#mg)" strokeWidth="1.5"/>
      <path d="M5 15 L19 23 L33 15" stroke="#818cf8" strokeWidth="1.5" strokeLinecap="round"/>
      {/* Shield badge */}
      <path d="M34 24 L28 27 L28 33 Q28 37 34 39 Q40 37 40 33 L40 27 Z"
        fill="#6366f1" opacity="0.9"/>
      <path d="M31.5 32 L33 33.5 L36.5 30" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

export default function PhishingChecker() {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PhishingVerdict | null>(null);

  const run = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setResult(null);
    const verdict = await analyzePhishing(text, "a small nonprofit");
    setResult(verdict);
    setLoading(false);
  };

  return (
    <div className="min-h-full pb-16">
      <Nav />

      <main className="mx-auto max-w-4xl px-6 pt-8">
        {/* Page header */}
        <div className="mb-6">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
            <span className="h-1.5 w-1.5 rounded-full bg-brand-400" /> AI phishing analyzer
          </div>
          <div className="flex items-center gap-3">
            <MailShieldIcon />
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Is this message a scam?</h1>
              <p className="mt-0.5 text-sm text-muted">
                Paste a suspicious email or text. AI checks it for hallmarks of social-engineering attacks.
              </p>
            </div>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          {/* Input card */}
          <div className="card p-5">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-medium text-muted">Paste the message</span>
              <button
                onClick={() => setText(SAMPLE)}
                className="text-xs text-brand-300 underline-offset-4 hover:underline"
              >
                Use a sample
              </button>
            </div>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={12}
              placeholder={"From: ...\nSubject: ...\n\nPaste the full message here"}
              className="w-full resize-none rounded-xl border border-white/10 bg-white/[0.04] p-3 font-mono text-[13px] leading-relaxed text-fg outline-none focus:border-brand-400 transition"
            />
            <button
              onClick={run}
              disabled={loading || !text.trim()}
              className="p-btn p-prim-col p-btn-block"
              style={{ width: "100%", margin: "0.75rem 0 0" }}
            >
              {loading ? "Analyzing…" : "Analyze message"}
            </button>
          </div>

          {/* Result card */}
          <div className="card p-5">
            <span className="text-xs font-medium text-muted">Analysis</span>

            <AnimatePresence mode="wait">
              {loading && (
                <motion.div
                  key="loading"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="mt-8 flex flex-col items-center gap-3 text-sm text-muted"
                >
                  <div className="relative h-10 w-10">
                    <div className="absolute inset-0 animate-spin rounded-full border-2 border-white/10 border-t-brand-400" />
                    <div className="absolute inset-1 animate-spin rounded-full border border-white/5 border-b-accent-400"
                      style={{ animationDirection: "reverse", animationDuration: "0.6s" }} />
                  </div>
                  Reading it the way an attacker would…
                </motion.div>
              )}

              {!loading && !result && (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="mt-10 flex flex-col items-center gap-4 text-center"
                >
                  {/* Placeholder graphic */}
                  <svg width="64" height="64" viewBox="0 0 64 64" fill="none" opacity="0.25">
                    <circle cx="32" cy="32" r="30" stroke="#8b5cf6" strokeWidth="1.5" strokeDasharray="6 8"/>
                    <path d="M32 18 L44 26 L44 38 Q44 50 32 54 Q20 50 20 38 L20 26 Z"
                      fill="#8b5cf6" opacity="0.5"/>
                    <path d="M26 34 L30 38 L38 28" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                  <p className="text-sm text-muted">Your verdict, red flags, and next step will appear here.</p>
                </motion.div>
              )}

              {!loading && result && (
                <motion.div
                  key="result"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-4 space-y-4"
                >
                  <div
                    className="flex items-center justify-between rounded-xl px-4 py-3"
                    style={{ background: VERDICT_META[result.verdict].bg }}
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className="inline-block h-3 w-3 flex-none rounded-full"
                        style={{ background: VERDICT_META[result.verdict].color }}
                      />
                      <span className="text-lg font-bold" style={{ color: VERDICT_META[result.verdict].color }}>
                        {VERDICT_META[result.verdict].label}
                      </span>
                    </div>
                    <span className="text-xs text-muted">{result.confidence}% confidence</span>
                  </div>

                  <div>
                    <div className="text-xs font-medium uppercase tracking-wide text-muted">Likely attack type</div>
                    <div className="mt-1 text-sm font-medium">{result.attackType}</div>
                  </div>

                  <div>
                    <div className="text-xs font-medium uppercase tracking-wide text-muted">Red flags</div>
                    <ul className="mt-1.5 space-y-1.5">
                      {result.redFlags.map((f, i) => (
                        <li key={i} className="flex gap-2 text-sm text-fg/90">
                          <span className="text-risk-high">›</span>
                          {f}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <p className="text-sm leading-relaxed text-muted">{result.explanation}</p>

                  <div className="rounded-xl border border-brand-400/30 bg-brand-500/10 p-3">
                    <div className="text-xs font-semibold uppercase tracking-wide text-brand-300">Do this now</div>
                    <p className="mt-1 text-sm text-fg">{result.recommendedAction}</p>
                  </div>

                  <div className="text-right text-[11px] text-muted">
                    {result.source === "ai"
                      ? "✦ Analyzed by Claude"
                      : "Offline heuristic (add an API key for full AI analysis)"}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </main>
    </div>
  );
}
