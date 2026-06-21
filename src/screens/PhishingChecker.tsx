import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Brand } from "../components/Brand";
import { analyzePhishing, type PhishingVerdict } from "../lib/api";

const SAMPLE = `From: Pastor David Reyes <d.reyes@grace-foodbank.com>
Subject: Urgent - quick favor

Hi, are you at your desk? I'm in a board meeting and can't talk.
We need to send a payment to a new vendor today before 3pm. I'll
send the new bank account details shortly. Please keep this between
us until I announce it. Thanks - David`;

const VERDICT_META: Record<
  PhishingVerdict["verdict"],
  { label: string; color: string; bg: string; icon: string }
> = {
  likely_phishing: { label: "Likely phishing", color: "var(--color-risk-crit)", bg: "rgba(244,63,94,0.14)", icon: "🚨" },
  suspicious: { label: "Suspicious", color: "var(--color-risk-med)", bg: "rgba(251,191,36,0.14)", icon: "⚠️" },
  likely_safe: { label: "Likely safe", color: "var(--color-risk-low)", bg: "rgba(52,211,153,0.14)", icon: "✓" },
};

export default function PhishingChecker() {
  const nav = useNavigate();
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
    <div className="bg-aurora min-h-full pb-16">
      <header className="border-b border-white/8">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <Brand />
          <button
            onClick={() => nav("/")}
            className="rounded-lg border border-white/12 px-3 py-1.5 text-xs text-muted transition hover:border-white/30 hover:text-fg"
          >
            ← Back
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-6 pt-8">
        <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
          <span className="h-1.5 w-1.5 rounded-full bg-brand-400" /> AI phishing analyzer
        </div>
        <h1 className="text-2xl font-bold tracking-tight">Is this message a scam?</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted">
          Paste a suspicious email or text — a donation request, a vendor invoice, a message
          that looks like it's from your director. AI checks it for the hallmarks of an
          AI-generated attack and tells you, in plain English, what to do.
        </p>

        <div className="mt-6 grid gap-6 lg:grid-cols-2">
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
              placeholder="From: ...&#10;Subject: ...&#10;&#10;Paste the full message here"
              className="w-full resize-none rounded-xl border border-white/10 bg-white/[0.04] p-3 font-mono text-[13px] leading-relaxed text-fg outline-none focus:border-brand-400"
            />
            <button
              onClick={run}
              disabled={loading || !text.trim()}
              className="mt-3 w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {loading ? "Analyzing…" : "Analyze message"}
            </button>
          </div>

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
                  <div className="h-8 w-8 animate-spin rounded-full border-2 border-white/15 border-t-brand-400" />
                  Reading it the way an attacker would…
                </motion.div>
              )}

              {!loading && !result && (
                <motion.p
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="mt-8 text-center text-sm text-muted"
                >
                  Your verdict, red flags, and next step will appear here.
                </motion.p>
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
                      <span className="text-xl">{VERDICT_META[result.verdict].icon}</span>
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
                    {result.source === "ai" ? "Analyzed by Claude" : "Offline heuristic (add an API key for full AI analysis)"}
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
