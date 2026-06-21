import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  issueBadge,
  embedSnippet,
  GRADE_COLOR,
  fmtDate,
  type BadgeIssue,
  type Grade,
  type ScanSummary,
} from "../lib/badge";

/**
 * Verifiable-badge card shown on the scan report. The org issues a signed badge
 * that proves its grade + freshness WITHOUT publishing the report (which would
 * be an attacker's roadmap). The badge cryptographically hides the exact score
 * and every individual finding — only the grade, domain and dates are revealed.
 */
export function BadgeCard({
  domain,
  orgName,
  summary,
}: {
  domain: string;
  orgName: string;
  summary: ScanSummary;
}) {
  const [issued, setIssued] = useState<BadgeIssue | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<"embed" | "link" | null>(null);

  const origin = typeof window !== "undefined" ? window.location.origin : "";

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      setIssued(await issueBadge(domain, orgName, summary));
    } catch {
      setError("Couldn't issue the badge. Make sure the API server is running.");
    } finally {
      setLoading(false);
    }
  };

  const copy = async (text: string, which: "embed" | "link") => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(which);
      setTimeout(() => setCopied(null), 1600);
    } catch {
      /* clipboard blocked — ignore */
    }
  };

  return (
    <div className="card card-glow p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="mb-1 flex items-center gap-2">
            <h2 className="text-lg font-bold">Verifiable security badge</h2>
            <span className="rounded-full bg-brand-500/15 px-2 py-0.5 text-[11px] font-medium text-brand-300">
              zero-knowledge
            </span>
          </div>
          <p className="max-w-xl text-sm text-muted">
            Prove this scan graded you{" "}
            <span className="font-semibold text-fg">{issued ? issued.grade : "—"}</span> to donors and
            partners — <span className="font-semibold text-fg">without</span> publishing your report.
            The badge cryptographically reveals only your grade and the dates; your exact score and
            every individual finding stay sealed.
          </p>
        </div>
      </div>

      <AnimatePresence mode="wait">
        {!issued ? (
          <motion.div key="cta" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="mt-5">
            <button
              onClick={run}
              disabled={loading}
              className="rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Signing your badge…" : "Issue my verifiable badge →"}
            </button>
            {error && <p className="mt-3 text-xs text-risk-high">{error}</p>}
          </motion.div>
        ) : (
          <motion.div
            key="result"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-5 grid gap-5 lg:grid-cols-[auto,1fr]"
          >
            {/* Live preview of the embeddable SVG, straight from the verify endpoint */}
            <div className="flex flex-col items-start gap-3">
              <img
                src={`${origin}/api/badge/svg?token=${encodeURIComponent(issued.token)}&min=B`}
                alt="Aegis verified security badge"
                width={240}
                height={64}
              />
              <div className="flex items-center gap-3 text-xs text-muted">
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: GRADE_COLOR[issued.grade as Grade] }} />
                  Grade {issued.grade}
                </span>
                <span>·</span>
                <span>valid to {fmtDate(issued.expiresAt)}</span>
              </div>
              <a
                href={`/verify?token=${encodeURIComponent(issued.token)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-brand-300 underline-offset-4 hover:underline"
              >
                Open the public verification page ↗
              </a>
            </div>

            {/* Embed snippet */}
            <div className="min-w-0">
              <div className="mb-1.5 flex items-center justify-between">
                <span className="text-xs font-medium text-muted">Paste this on your website</span>
                <button
                  onClick={() => copy(embedSnippet(issued.token, origin), "embed")}
                  className="rounded-lg border border-white/12 px-2.5 py-1 text-[11px] text-muted transition hover:border-white/30 hover:text-fg"
                >
                  {copied === "embed" ? "Copied ✓" : "Copy embed code"}
                </button>
              </div>
              <pre className="max-h-40 overflow-auto rounded-xl border border-white/10 bg-ink-900/60 p-3 font-mono text-[11px] leading-relaxed text-fg/80">
{embedSnippet(issued.token, origin)}
              </pre>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button
                  onClick={() => copy(issued.token, "link")}
                  className="rounded-lg border border-white/12 px-2.5 py-1 text-[11px] text-muted transition hover:border-white/30 hover:text-fg"
                >
                  {copied === "link" ? "Copied ✓" : "Copy raw token"}
                </button>
                <span className="text-[11px] text-muted">
                  Signed by Aegis key <span className="font-mono">{issued.kid.slice(0, 10)}…</span> · anyone can verify it
                  offline against <span className="font-mono">/api/badge/pubkey</span>.
                </span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
