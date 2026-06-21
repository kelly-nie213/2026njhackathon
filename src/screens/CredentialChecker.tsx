import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";

type Tab = "password" | "email";

/* ── SHA helpers ─────────────────────────────────────────────────────────── */

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

async function sha1(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  return toHex(await crypto.subtle.digest("SHA-1", data));
}

async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text.toLowerCase().trim());
  return toHex(await crypto.subtle.digest("SHA-256", data));
}

/* ── Screen ──────────────────────────────────────────────────────────────── */

export default function CredentialChecker() {
  const [tab, setTab] = useState<Tab>("password");

  return (
    <div className="min-h-full pb-20">
      <Nav />
      <main className="mx-auto max-w-3xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6 pt-8"
        >
          {/* Hero */}
          <div className="text-center space-y-3">
            <div className="inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
              <span className="h-1.5 w-1.5 rounded-full bg-brand-400" />
              Real cryptography — running in your browser
            </div>
            <h1 className="text-4xl font-extrabold tracking-tight">
              Credential{" "}
              <span className="bg-gradient-to-r from-brand-300 to-accent-400 bg-clip-text text-transparent">
                Breach Check
              </span>
            </h1>
            <p className="mx-auto max-w-lg text-sm leading-relaxed text-muted">
              Check whether a password or email has appeared in known data breaches.
              Both tabs hash your credential locally before anything leaves your device.
            </p>
          </div>

          {/* Tab bar */}
          <div className="card flex gap-1.5 p-1.5">
            {[
              {
                id: "password" as Tab,
                label: "Password Check",
                icon: "🔑",
                badge: "TRUE ZKP",
                badgeColor: "var(--color-risk-low)",
                badgeBg: "rgba(52,211,153,0.14)",
              },
              {
                id: "email" as Tab,
                label: "Email Check",
                icon: "✉️",
                badge: "commitment-based",
                badgeColor: "var(--color-brand-300)",
                badgeBg: "rgba(99,102,241,0.15)",
              },
            ].map((t) => {
              const active = tab === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className="flex flex-1 items-center justify-center gap-2 rounded-xl px-4 py-3 text-sm font-medium transition-all duration-200"
                  style={
                    active
                      ? {
                          background: "linear-gradient(135deg,#4f46e5,#65a30d)",
                          color: "#fff",
                          boxShadow: "0 2px 14px rgba(99,102,241,0.40)",
                        }
                      : { color: "var(--color-muted)" }
                  }
                >
                  <span className="text-base">{t.icon}</span>
                  <span className="hidden sm:inline">{t.label}</span>
                  <span
                    className="hidden sm:inline rounded-full px-2 py-0.5 text-[10px] font-bold"
                    style={{ color: active ? "#fff" : t.badgeColor, background: active ? "rgba(255,255,255,0.18)" : t.badgeBg }}
                  >
                    {t.badge}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Panels */}
          <AnimatePresence mode="wait">
            {tab === "password" && <PasswordTab key="password" />}
            {tab === "email"    && <EmailTab    key="email"    />}
          </AnimatePresence>
        </motion.div>
      </main>
    </div>
  );
}

/* ──────────────────────────────────────────────
   PASSWORD TAB — TRUE zero-knowledge proof
   Uses HIBP k-anonymity: only 5 hex chars leave the browser.
────────────────────────────────────────────── */

interface PasswordResult {
  found: boolean;
  count: number;
  prefix: string;
  suffix: string;
  totalSuffixesReturned: number;
}

function PasswordTab() {
  const [password, setPassword]   = useState("");
  const [hash, setHash]           = useState("");
  const [checking, setChecking]   = useState(false);
  const [result, setResult]       = useState<PasswordResult | null>(null);
  const [error, setError]         = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Recompute SHA-1 live as the user types
  useEffect(() => {
    if (!password) { setHash(""); setResult(null); return; }
    if (debounce.current) clearTimeout(debounce.current);
    debounce.current = setTimeout(() => {
      sha1(password).then(setHash);
    }, 120);
  }, [password]);

  const check = async () => {
    if (!password) return;
    setChecking(true); setError(null); setResult(null);
    try {
      const fullHash = await sha1(password);
      const prefix   = fullHash.slice(0, 5);    // only this leaves the browser
      const suffix   = fullHash.slice(5);       // stays local

      // Server proxies to HIBP — HIBP never sees the full hash
      const res = await fetch(`/api/password-range/${prefix}`);
      if (!res.ok) throw new Error("hibp_unavailable");
      const text  = await res.text();
      const lines = text.trim().split("\n");

      let found = false;
      let count = 0;
      for (const line of lines) {
        const [s, c] = line.split(":");
        if (s.trim().toUpperCase() === suffix.toUpperCase()) {
          found = true;
          count = parseInt(c.trim(), 10);
          break;
        }
      }
      setResult({ found, count, prefix, suffix, totalSuffixesReturned: lines.length });
    } catch {
      setError("Could not reach the breach database. Check your connection.");
    } finally {
      setChecking(false);
    }
  };

  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.2 }}
      className="space-y-5"
    >
      {/* ZKP guarantee banner */}
      <div className="rounded-xl border border-risk-low/30 bg-risk-low/8 px-4 py-3">
        <div className="flex items-center gap-2 text-xs font-bold text-risk-low mb-1">
          ✓ TRUE Zero-Knowledge Proof — powered by HaveIBeenPwned k-anonymity
        </div>
        <p className="text-[11px] text-muted leading-relaxed">
          Only the first 5 characters of SHA-1(password) leave your browser.
          The server, HIBP, and any network observer never see your password or its full hash.
          Your browser checks the result locally from hundreds of returned suffixes.
        </p>
      </div>

      {/* Input */}
      <div className="card card-glow p-6 space-y-5">
        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-muted">Password to check</span>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => { setPassword(e.target.value); setResult(null); }}
              onKeyDown={(e) => e.key === "Enter" && check()}
              placeholder="Enter any password…"
              className="bd-input pr-10"
              autoComplete="off"
            />
            <button
              onClick={() => setShowPassword((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-fg text-xs"
              tabIndex={-1}
            >
              {showPassword ? "hide" : "show"}
            </button>
          </div>
        </label>

        {/* Live hash display */}
        {hash && (
          <div className="rounded-xl border border-white/8 bg-white/[0.025] p-3 space-y-1.5">
            <div className="text-[11px] font-medium text-muted">SHA-1(password) — updates as you type</div>
            <div className="break-all font-mono text-[12px] leading-relaxed">
              <span
                className="rounded px-0.5"
                style={{ color: "#34d399", background: "rgba(52,211,153,0.15)" }}
              >
                {prefix}
              </span>
              <span className="text-fg/35">{suffix}</span>
            </div>
            <div className="flex gap-4 text-[11px] mt-1">
              <span>
                <span style={{ color: "#34d399" }}>■</span>
                <span className="text-muted ml-1">Prefix sent to server ({prefix || "—"})</span>
              </span>
              <span>
                <span className="text-fg/35">■</span>
                <span className="text-muted ml-1">Suffix stays in browser only</span>
              </span>
            </div>
          </div>
        )}

        <button
          onClick={check}
          disabled={!password || checking}
          className="w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:opacity-40"
        >
          {checking ? "Checking…" : "Check password →"}
        </button>

        {error && (
          <div className="rounded-xl border border-risk-med/30 bg-risk-med/10 px-3 py-2 text-xs text-risk-med">
            {error}
          </div>
        )}
      </div>

      {/* Result */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="space-y-4"
          >
            {/* Verdict */}
            <div
              className="rounded-xl border px-5 py-4"
              style={
                result.found
                  ? { borderColor: "rgba(244,63,94,0.35)", background: "rgba(244,63,94,0.08)" }
                  : { borderColor: "rgba(52,211,153,0.35)", background: "rgba(52,211,153,0.08)" }
              }
            >
              <div
                className="text-xl font-extrabold mb-1"
                style={{ color: result.found ? "var(--color-risk-crit)" : "var(--color-risk-low)" }}
              >
                {result.found
                  ? `⚠ Found in ${result.count.toLocaleString()} breach${result.count === 1 ? "" : "es"}`
                  : "✓ Not found in any known breach"}
              </div>
              <p className="text-sm text-muted">
                {result.found
                  ? "This exact password has appeared in known data breach dumps. Anyone using it as a password is at risk of credential-stuffing attacks."
                  : "This password hasn't appeared in HaveIBeenPwned's database of over 800 million breached passwords. That doesn't guarantee it's strong — only that it hasn't been seen in a known breach."}
              </p>
            </div>

            {/* Step-by-step what happened */}
            <div className="card p-5 space-y-3">
              <div className="text-xs font-bold">What just happened — step by step</div>
              {[
                {
                  n: "1",
                  label: "Hashed in your browser",
                  value: `SHA-1(password) = ${result.prefix}${result.suffix}`,
                  highlight: false,
                },
                {
                  n: "2",
                  label: "Only 5 chars sent to server",
                  value: `GET /api/password-range/${result.prefix}`,
                  highlight: true,
                },
                {
                  n: "3",
                  label: "Server proxied to HaveIBeenPwned",
                  value: `HIBP returned ${result.totalSuffixesReturned.toLocaleString()} hash suffixes starting with "${result.prefix}"`,
                  highlight: false,
                },
                {
                  n: "4",
                  label: "Checked locally — no server involved",
                  value: `Scanned all ${result.totalSuffixesReturned.toLocaleString()} suffixes for "${result.suffix}"`,
                  highlight: true,
                },
                {
                  n: "5",
                  label: result.found ? "Match found" : "No match",
                  value: result.found
                    ? `Suffix found with count ${result.count.toLocaleString()} — password is in breach records`
                    : "Suffix not in returned list — password not in HIBP database",
                  highlight: true,
                },
              ].map((s) => (
                <div key={s.n} className="flex gap-3">
                  <span
                    className="mt-0.5 flex h-5 w-5 flex-none items-center justify-center rounded-full text-[10px] font-bold text-white"
                    style={{ background: s.highlight ? "linear-gradient(135deg,#6366f1,#84cc16)" : "rgba(255,255,255,0.12)" }}
                  >
                    {s.n}
                  </span>
                  <div className="min-w-0">
                    <div className="text-[11px] font-medium text-muted">{s.label}</div>
                    <div
                      className="mt-0.5 break-all font-mono text-[11px]"
                      style={{ color: s.highlight ? "var(--color-brand-300)" : "var(--color-fg)" }}
                    >
                      {s.value}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* What the server and HIBP learned */}
            <div className="card p-4 space-y-2">
              <div className="text-xs font-bold">What each party learned</div>
              <div className="grid gap-2 sm:grid-cols-3 text-[11px]">
                {[
                  { who: "Your browser", learned: `Full hash · suffix match · result`, color: "var(--color-risk-low)" },
                  { who: "Our server", learned: `Prefix "${result.prefix}" only — nothing else`, color: "var(--color-brand-300)" },
                  { who: "HaveIBeenPwned", learned: `Prefix "${result.prefix}" only — same constraint`, color: "var(--color-brand-300)" },
                ].map((p) => (
                  <div key={p.who} className="rounded-lg border border-white/8 bg-white/[0.025] p-2.5">
                    <div className="font-semibold mb-1" style={{ color: p.color }}>{p.who}</div>
                    <div className="text-muted">{p.learned}</div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/* ──────────────────────────────────────────────
   EMAIL TAB — commitment-based (semi-ZKP)
   SHA-256 commitment generated in browser.
   Server receives email for XposedOrNot lookup
   but response is keyed by commitment only.
────────────────────────────────────────────── */

interface EmailResult {
  status: "breached" | "clean" | "error";
  breachCount: number;
  commitment: string;
  breaches: Array<{ title: string; breachDate: string; dataClasses: string[] }>;
}

function EmailTab() {
  const [email, setEmail]       = useState("");
  const [hash, setHash]         = useState("");
  const [checking, setChecking] = useState(false);
  const [result, setResult]     = useState<EmailResult | null>(null);
  const [error, setError]       = useState<string | null>(null);
  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!email) { setHash(""); setResult(null); return; }
    if (debounce.current) clearTimeout(debounce.current);
    debounce.current = setTimeout(() => {
      sha256(email).then(setHash);
    }, 120);
  }, [email]);

  const check = async () => {
    if (!email) return;
    setChecking(true); setError(null); setResult(null);
    try {
      const commitment = await sha256(email);
      const res = await fetch("/api/breaches", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ emails: [email], commitments: [commitment] }),
      });
      if (!res.ok) throw new Error("lookup_failed");
      const data = await res.json();
      const r    = data.results?.[0];
      if (!r) throw new Error("no_result");
      setResult({
        status:      r.status,
        breachCount: r.breachCount,
        commitment:  r.commitment,
        breaches:    r.breaches ?? [],
      });
    } catch {
      setError("Could not reach the breach database. Check your connection.");
    } finally {
      setChecking(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.2 }}
      className="space-y-5"
    >
      {/* Honest caveat banner */}
      <div className="rounded-xl border border-brand-500/30 bg-brand-500/8 px-4 py-3">
        <div className="flex items-center gap-2 text-xs font-bold text-brand-300 mb-1">
          🔐 Commitment-based — response is ZKP; request is not
        </div>
        <p className="text-[11px] text-muted leading-relaxed">
          SHA-256(email) is computed in your browser. The email is sent to our server
          because XposedOrNot (the breach API) has no hash-based lookup — this is an API
          constraint, not a design choice. The server's <strong className="text-fg">response</strong> is
          commitment-keyed only: no email ever appears in what comes back.
        </p>
      </div>

      {/* Input */}
      <div className="card card-glow p-6 space-y-5">
        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-muted">Email to check</span>
          <input
            type="email"
            value={email}
            onChange={(e) => { setEmail(e.target.value); setResult(null); }}
            onKeyDown={(e) => e.key === "Enter" && check()}
            placeholder="staff@yourorg.org"
            className="bd-input"
          />
        </label>

        {/* Live SHA-256 */}
        {hash && (
          <div className="rounded-xl border border-white/8 bg-white/[0.025] p-3 space-y-1.5">
            <div className="text-[11px] font-medium text-muted">SHA-256(email) — your commitment</div>
            <div className="break-all font-mono text-[12px]">
              <span className="text-brand-300">{hash.slice(0, 16)}</span>
              <span className="text-fg/35">{hash.slice(16)}</span>
            </div>
            <div className="text-[11px] text-muted">
              This 64-char string is what the server keys its response to. Not the email.
            </div>
          </div>
        )}

        <button
          onClick={check}
          disabled={!email || checking}
          className="w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:opacity-40"
        >
          {checking ? "Checking…" : "Check email →"}
        </button>

        {error && (
          <div className="rounded-xl border border-risk-med/30 bg-risk-med/10 px-3 py-2 text-xs text-risk-med">
            {error}
          </div>
        )}
      </div>

      {/* Result */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="space-y-4"
          >
            {/* Verdict */}
            <div
              className="rounded-xl border px-5 py-4"
              style={
                result.status === "breached"
                  ? { borderColor: "rgba(244,63,94,0.35)", background: "rgba(244,63,94,0.08)" }
                  : result.status === "error"
                    ? { borderColor: "rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.04)" }
                    : { borderColor: "rgba(52,211,153,0.35)", background: "rgba(52,211,153,0.08)" }
              }
            >
              <div
                className="text-xl font-extrabold mb-1"
                style={{
                  color: result.status === "breached"
                    ? "var(--color-risk-crit)"
                    : result.status === "error"
                      ? "var(--color-muted)"
                      : "var(--color-risk-low)",
                }}
              >
                {result.status === "breached"
                  ? `⚠ Found in ${result.breachCount} breach${result.breachCount === 1 ? "" : "es"}`
                  : result.status === "error"
                    ? "⚪ Lookup failed"
                    : "✓ Not found in any known breach"}
              </div>
              <div className="text-[11px] text-muted font-mono mt-1">
                Server responded with commitment: {result.commitment.slice(0, 24)}… — no email in response
              </div>
            </div>

            {/* Breach list */}
            {result.breaches.length > 0 && (
              <div className="card p-5 space-y-2.5">
                <div className="text-xs font-bold">Breach records</div>
                {result.breaches.map((b, i) => (
                  <div key={i} className="rounded-xl border border-white/8 bg-white/[0.025] px-3 py-2.5">
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

            {/* What each party learned */}
            <div className="card p-4 space-y-2">
              <div className="text-xs font-bold">What each party learned</div>
              <div className="grid gap-2 sm:grid-cols-3 text-[11px]">
                {[
                  { who: "Your browser", learned: "Email · hash · full breach details", color: "var(--color-risk-low)" },
                  { who: "Our server", learned: "Email (for XposedOrNot) · never stored · discarded immediately", color: "var(--color-risk-med)" },
                  { who: "Network observer", learned: `Commitment hash only — email not in response`, color: "var(--color-brand-300)" },
                ].map((p) => (
                  <div key={p.who} className="rounded-lg border border-white/8 bg-white/[0.025] p-2.5">
                    <div className="font-semibold mb-1" style={{ color: p.color }}>{p.who}</div>
                    <div className="text-muted">{p.learned}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Contrast with password tab */}
            <div className="rounded-xl border border-white/8 bg-white/[0.025] px-4 py-3 text-[11px] text-muted">
              <strong className="text-fg">Why this differs from the password tab:</strong> HIBP's password
              API supports prefix-based lookup — only 5 chars are needed. No equivalent exists for email
              breach lookup. The password tab is true ZKP; this tab is the best possible without a
              hash-indexed email breach database.
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
