import { useState, useEffect, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Nav } from "../components/Nav";
import { verifyBadge, GRADE_COLOR, fmtDate, type VerifyResult, type Grade } from "../lib/badge";

// Public verification page. Anyone can paste an Aegis badge token (or land here
// from a badge link) and confirm it's genuine — the page proves the grade and
// freshness while showing that the detailed findings stay sealed.
export default function VerifyBadge() {
  const [params] = useSearchParams();
  const [token, setToken] = useState("");
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async (t: string) => {
    if (!t.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await verifyBadge(t.trim()));
    } catch {
      setError("Couldn't reach the verifier. Is the API server running?");
    } finally {
      setLoading(false);
    }
  }, []);

  // Auto-verify when arriving via a ?token= link (e.g. from a badge click).
  useEffect(() => {
    const t = params.get("token");
    if (t) {
      setToken(t);
      run(t);
    }
  }, [params, run]);

  return (
    <div className="min-h-full pb-16">
      <Nav />
      <main className="mx-auto max-w-3xl px-6 pt-8">
        <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
          <span className="h-1.5 w-1.5 rounded-full bg-brand-400" /> Badge verifier
        </div>
        <h1 className="text-2xl font-bold tracking-tight">Verify an Aegis security badge</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted">
          Paste a badge token to confirm it was genuinely issued by Aegis and hasn't expired or been
          altered. The badge proves the organization's grade and dates — it never reveals the
          underlying findings.
        </p>

        <div className="card mt-6 p-5">
          <span className="text-xs font-medium text-muted">Badge token</span>
          <textarea
            value={token}
            onChange={(e) => setToken(e.target.value)}
            rows={4}
            placeholder="Paste the Aegis badge token here…"
            className="mt-2 w-full resize-none rounded-xl border border-white/10 bg-white/[0.04] p-3 font-mono text-[12px] leading-relaxed text-fg outline-none focus:border-brand-400"
          />
          <button
            onClick={() => run(token)}
            disabled={loading || !token.trim()}
            className="mt-3 w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? "Verifying…" : "Verify badge"}
          </button>
          {error && <p className="mt-3 text-xs text-risk-high">{error}</p>}
        </div>

        {result && <ResultPanel result={result} />}
      </main>
    </div>
  );
}

function ResultPanel({ result }: { result: VerifyResult }) {
  const valid = result.valid;
  const grade = (result.grade || "F") as Grade;
  const color = valid ? GRADE_COLOR[grade] : "var(--color-risk-crit)";

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="card mt-5 p-6"
    >
      <div className="flex items-center gap-4">
        <div
          className="grid h-16 w-16 flex-none place-items-center rounded-2xl border-2 text-2xl font-extrabold"
          style={{ borderColor: color, color }}
        >
          {valid ? grade : "✕"}
        </div>
        <div>
          <div className="text-lg font-bold" style={{ color }}>
            {valid ? "Genuine Aegis badge" : "Not verified"}
          </div>
          <p className="text-sm text-muted">
            {valid ? (
              <>
                <span className="font-mono text-fg">{result.domain}</span>
                {result.org && result.org !== result.domain ? ` · ${result.org}` : ""} · grade{" "}
                <span className="font-semibold text-fg">{result.grade}</span>
              </>
            ) : (
              <>This badge could not be verified — {reasonText(result.reason)}.</>
            )}
          </p>
        </div>
      </div>

      {valid && (
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="Issued" value={fmtDate(result.issuedAt)} />
          <Field label="Valid until" value={fmtDate(result.expiresAt)} />
          <Field label="Issuer key" value={result.kid ? `${result.kid.slice(0, 12)}…` : "—"} mono />
          <Field label="Sealed (hidden) checks" value={`${result.hidden ?? 0} not disclosed`} />
        </div>
      )}

      <div className="mt-5">
        <div className="mb-2 text-xs font-medium uppercase tracking-wide text-muted">
          Cryptographic checks
        </div>
        <ul className="space-y-1.5">
          {result.checks.map((c, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <span className={c.ok ? "text-risk-low" : "text-risk-high"}>{c.ok ? "✓" : "✕"}</span>
              <span className="text-fg/90">
                {c.label}
                <span className="text-muted"> — {c.detail}</span>
              </span>
            </li>
          ))}
        </ul>
      </div>

      <p className="mt-5 rounded-lg bg-white/[0.03] px-3 py-2 text-[11px] text-muted">
        The signature is over a Merkle root that commits to every claim; each disclosed claim carries
        an inclusion proof, so it can't be swapped or forged. The exact score and individual findings
        were sealed at issue time and are never exposed by the badge.
      </p>
    </motion.div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.02] px-3 py-2">
      <div className="text-[11px] text-muted">{label}</div>
      <div className={`mt-0.5 text-sm text-fg ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}

function reasonText(reason?: string): string {
  switch (reason) {
    case "malformed_badge": return "the token isn't a valid badge";
    case "unknown_issuer": return "it wasn't signed by this Aegis instance";
    case "bad_signature": return "the signature is invalid";
    case "tampered_claim": return "a disclosed value was altered";
    case "expired": return "it has expired";
    case "grade_below_threshold": return "the grade is below the required threshold";
    default: return "the token is invalid";
  }
}
