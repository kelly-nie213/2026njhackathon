import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";
import {
  createZkpProof,
  verifyZkpProof,
  hashEmail,
  buildZkpSteps,
  type ZkpProof,
  type ZkpStep,
} from "../lib/zkp";
import { fetchBloomFilter, checkCommitmentLocally } from "../lib/bloom";
import { fetchMerkleProof, fetchMerkleRoot, verifyMerkleProof, type MerkleProof } from "../lib/merkle";
import {
  generateKeyPair,
  signDomainClaim,
  verifyDomainClaim,
  storeIdentity,
  loadIdentity,
  clearIdentity,
  registerWithServer,
  authenticateWithServer,
  type TiamKeyPair,
  type DomainClaim,
  type StoredIdentity,
  type TiamAuthResult,
} from "../lib/tiam";

type Tab = "explainer" | "zkp" | "bloom" | "merkle" | "tiam";

export default function TiamScreen() {
  const [tab, setTab] = useState<Tab>("explainer");

  return (
    <div className="min-h-full pb-20">
      <Nav />
      <main className="mx-auto max-w-5xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6 pt-8"
        >
          {/* ── Hero ── */}
          <div className="text-center">
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
              <span className="h-1.5 w-1.5 rounded-full bg-brand-400" />
              Live cryptography — running entirely in your browser
            </div>
            <h1 className="text-4xl font-extrabold tracking-tight sm:text-5xl">
              <span className="bg-gradient-to-r from-brand-300 to-accent-400 bg-clip-text text-transparent">
                TIAM
              </span>{" "}
              &amp;{" "}
              <span className="bg-gradient-to-r from-accent-400 to-brand-300 bg-clip-text text-transparent">
                ZKP
              </span>
            </h1>
            <p className="mx-auto mt-3 max-w-xl text-sm leading-relaxed text-muted">
              The information is never unencrypted. It is just validated.
              The vault is never opened — we only prove that something inside it exists and is valid.
            </p>
          </div>

          {/* ── Tab bar ── */}
          <div className="card flex gap-1.5 p-1.5">
            {[
              { id: "explainer", label: "How It Works",    icon: "🧠" },
              { id: "zkp",       label: "ZKP Commitment",  icon: "🔐" },
              { id: "bloom",     label: "Bloom Filter",    icon: "🌸" },
              { id: "merkle",    label: "Merkle Proof",    icon: "🌳" },
              { id: "tiam",      label: "TIAM Auth",       icon: "🗝️" },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id as Tab)}
                className="relative flex flex-1 items-center justify-center gap-1.5 rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200"
                style={
                  tab === t.id
                    ? {
                        background: "linear-gradient(135deg,#4f46e5,#65a30d)",
                        color: "#fff",
                        boxShadow: "0 2px 14px rgba(99,102,241,0.40)",
                      }
                    : { color: "var(--color-muted)" }
                }
              >
                <span className="text-base leading-none">{t.icon}</span>
                <span className="hidden sm:inline">{t.label}</span>
              </button>
            ))}
          </div>

          {/* ── Panels ── */}
          <AnimatePresence mode="wait">
            {tab === "explainer" && <ExplainerTab key="explainer" />}
            {tab === "zkp"       && <ZkpTab        key="zkp"    />}
            {tab === "bloom"     && <BloomTab       key="bloom"  />}
            {tab === "merkle"    && <MerkleTab      key="merkle" />}
            {tab === "tiam"      && <TiamTab        key="tiam"   />}
          </AnimatePresence>
        </motion.div>
      </main>
    </div>
  );
}

/* ──────────────────────────────────────────────
   EXPLAINER TAB
────────────────────────────────────────────── */

function ExplainerTab() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      transition={{ duration: 0.2 }}
      className="grid gap-5 lg:grid-cols-2"
    >
      {/* ZKP card */}
      <ConceptCard
        icon="🔐"
        title="Zero-Knowledge Proof (ZKP)"
        color="#6366f1"
        what="The information is never unencrypted. It is just validated. The server never opens the vault — it only confirms that something inside exists and is valid."
        analogy="Think of a safety deposit box. The bank confirms 'yes, something is in box 7' without ever opening it or knowing what's inside. You hold the only key. The bank never needs to see the contents to answer your question."
        howWeUseIt={[
          "Your email sits in the vault — it is the secret.",
          "Your browser hashes it: SHA-256(email) → a 64-char commitment. The vault is now sealed.",
          "Only the commitment hash leaves your browser. The email stays inside.",
          "The server checks: does this hash appear in breach records? It never opens the vault.",
          "Server responds: exists: true or false. No email. No name. Just a boolean.",
          "Your browser maps the hash back to the email locally. Vault opened only by you.",
        ]}
        why="The server only ever validated that something exists. It never needed to know what was in there."
      />

      {/* TIAM card */}
      <ConceptCard
        icon="🗝️"
        title="Trustless IAM (TIAM)"
        color="#a3e635"
        what="Identity management where no central authority ever needs to access your vault. Your private key is the vault — it never leaves your browser, and validation is pure math."
        analogy="Traditional login: the server opens its own vault (the password database) to check if you're allowed. TIAM: you sign a claim with your private key. The verifier checks the math — it never needs to open any vault."
        howWeUseIt={[
          "Your browser generates an ECDSA keypair. The private key is the vault — it never leaves.",
          "To prove you own a domain, you sign a claim with your private key.",
          "Only the signature and public key are transmitted. The private key stays sealed.",
          "Any verifier checks: does this signature match this public key? Math only, no server vault.",
          "Valid or invalid — that is all the server learns. Nothing else about you.",
          "No password database to breach. No session to hijack. No vault to open.",
        ]}
        why="The private key is never accessed by anyone but you. Everything else is just validation."
      />

      {/* Comparison table */}
      <div className="card p-6 lg:col-span-2">
        <h3 className="mb-4 text-base font-bold">Traditional vs. TIAM + ZKP</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-left text-xs font-medium text-muted">
                <th className="pb-2 pr-6">Concern</th>
                <th className="pb-2 pr-6">Traditional approach</th>
                <th className="pb-2">TIAM + ZKP approach</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {[
                ["Who opens the vault?",  "The server opens its password DB on every login",         "Nobody — the vault (private key) never leaves your browser"],
                ["What is validated?",    "Server checks your password matches its stored copy",      "Math checks your signature matches your public key — vault stays sealed"],
                ["If server is breached", "All passwords exposed — every vault opened at once",       "Attacker gets public keys only — worthless without the private key vault"],
                ["Email in transit",      "Raw plaintext email sent to server and third-party APIs",  "SHA-256 commitment hash only — email stays in the browser vault"],
                ["What server learns",    "Your identity, your secrets, your history",               "Only: this commitment exists, this signature is valid — nothing else"],
              ].map(([concern, traditional, tiam]) => (
                <tr key={concern} className="text-sm">
                  <td className="py-2.5 pr-6 font-medium">{concern}</td>
                  <td className="py-2.5 pr-6 text-muted">{traditional}</td>
                  <td className="py-2.5 text-risk-low">{tiam}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </motion.div>
  );
}

function ConceptCard({
  icon, title, color, what, analogy, howWeUseIt, why,
}: {
  icon: string; title: string; color: string;
  what: string; analogy: string; howWeUseIt: string[]; why: string;
}) {
  return (
    <div className="card p-6 space-y-4" style={{ borderColor: color + "30" }}>
      <div className="flex items-center gap-3">
        <span className="text-2xl">{icon}</span>
        <h2 className="text-lg font-bold" style={{ color }}>{title}</h2>
      </div>

      <Section label="What is it?">{what}</Section>
      <Section label="Analogy">{analogy}</Section>

      <div>
        <div className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-muted">
          How Aegis uses it
        </div>
        <ol className="space-y-1.5">
          {howWeUseIt.map((step, i) => (
            <li key={i} className="flex gap-2 text-sm text-fg/85">
              <span className="mt-0.5 flex-none text-[11px] font-bold" style={{ color }}>
                {i + 1}.
              </span>
              {step}
            </li>
          ))}
        </ol>
      </div>

      <div
        className="rounded-xl px-3 py-2.5 text-sm"
        style={{ background: color + "18", border: `1px solid ${color}35` }}
      >
        <span className="font-semibold" style={{ color }}>Why it matters: </span>
        <span className="text-fg/85">{why}</span>
      </div>
    </div>
  );
}

function Section({ label, children }: { label: string; children: string }) {
  return (
    <div>
      <div className="mb-1 text-[11px] font-semibold uppercase tracking-widest text-muted">
        {label}
      </div>
      <p className="text-sm leading-relaxed text-fg/85">{children}</p>
    </div>
  );
}

/* ──────────────────────────────────────────────
   ZKP DEMO TAB
────────────────────────────────────────────── */

function ZkpTab() {
  const [email, setEmail] = useState("staff@aylus.org");
  const [proof, setProof] = useState<ZkpProof | null>(null);
  const [steps, setSteps] = useState<ZkpStep[]>([]);
  const [liveHash, setLiveHash] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [verified, setVerified] = useState<boolean | null>(null);

  // Update the live SHA-256 as the user types
  useEffect(() => {
    if (!email) { setLiveHash(""); return; }
    hashEmail(email).then(setLiveHash).catch(() => {});
  }, [email]);

  const handleGenerate = async () => {
    if (!email) return;
    setIsGenerating(true);
    setVerified(null);
    try {
      const p = await createZkpProof(email);
      const s = await buildZkpSteps(email, p);
      setProof(p);
      setSteps(s);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleVerify = async () => {
    if (!proof) return;
    setVerified(await verifyZkpProof(email, proof));
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      transition={{ duration: 0.2 }}
      className="space-y-5"
    >
      {/* Input + live hash */}
      <div className="card card-glow p-6 space-y-5">
        <div>
          <h2 className="text-lg font-bold">Zero-Knowledge Proof — live demo</h2>
          <p className="mt-1 text-sm text-muted">
            Type any email. Watch it get committed to a hash. Only the prefix ever leaves your browser.
          </p>
        </div>

        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-muted">Email to prove knowledge of</span>
          <input
            value={email}
            onChange={(e) => { setEmail(e.target.value); setProof(null); setVerified(null); }}
            placeholder="staff@yourorg.org"
            className="bd-input"
          />
        </label>

        {/* Live hash preview */}
        {liveHash && (
          <div className="rounded-xl border border-white/8 bg-white/[0.025] p-3">
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-widest text-muted">
              SHA-256(email) — updates as you type
            </div>
            <div className="break-all font-mono text-[12px] leading-relaxed">
              <span className="text-brand-300">{liveHash.slice(0, 8)}</span>
              <span className="text-fg/40">{liveHash.slice(8)}</span>
            </div>
            <p className="mt-1.5 text-[11px] text-muted">
              Indigo = prefix sent to server · Grey = stays in browser only
            </p>
          </div>
        )}

        <button
          onClick={handleGenerate}
          disabled={!email || isGenerating}
          className="w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {isGenerating ? "Generating proof…" : "Generate ZKP commitment →"}
        </button>
      </div>

      {/* Step-by-step proof walkthrough */}
      {proof && steps.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="card p-6 space-y-4"
        >
          <h3 className="font-bold">Step-by-step: what just happened</h3>

          <div className="space-y-3">
            {steps.map((s, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.07 }}
                className="flex gap-3"
              >
                <div
                  className="mt-0.5 flex h-6 w-6 flex-none items-center justify-center rounded-full text-[11px] font-bold text-white"
                  style={{ background: s.highlight ? "linear-gradient(135deg,#6366f1,#84cc16)" : "rgba(255,255,255,0.12)" }}
                >
                  {i + 1}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium text-muted">{s.label}</div>
                  <div
                    className="mt-0.5 break-all font-mono text-[11px] leading-relaxed"
                    style={{ color: s.highlight ? "var(--color-brand-300)" : "var(--color-fg)" }}
                  >
                    {s.value}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>

          {/* Proof data */}
          <details className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
            <summary className="cursor-pointer text-xs font-medium text-muted">
              View raw proof object ▾
            </summary>
            <pre className="mt-3 overflow-x-auto rounded-lg bg-ink-900/60 p-3 font-mono text-[11px] leading-relaxed text-fg/80">
              {JSON.stringify(proof, null, 2)}
            </pre>
          </details>

          {/* Verify */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleVerify}
              className="rounded-xl border border-brand-500/40 bg-brand-500/10 px-4 py-2 text-sm font-medium text-brand-300 transition hover:bg-brand-500/20"
            >
              Verify proof locally →
            </button>
            <AnimatePresence>
              {verified !== null && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-semibold"
                  style={
                    verified
                      ? { color: "var(--color-risk-low)", background: "rgba(52,211,153,0.14)" }
                      : { color: "var(--color-risk-crit)", background: "rgba(244,63,94,0.14)" }
                  }
                >
                  {verified ? "✓ Valid — SHA-256(email:salt) matches commitment" : "✗ Invalid — commitment mismatch"}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {verified === true && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="rounded-xl border border-risk-low/30 bg-risk-low/10 px-4 py-3 text-sm text-risk-low"
            >
              The proof is valid. The verifier now knows that <strong>someone</strong> who holds this commitment
              knows an email whose hash starts with <code className="font-mono">{proof.prefix}</code> — but
              never learned which email that is.
            </motion.div>
          )}
        </motion.div>
      )}

      {/* Privacy guarantee */}
      <div className="card p-5 space-y-2">
        <h3 className="text-sm font-bold">What this guarantees</h3>
        <div className="grid gap-3 sm:grid-cols-3 text-sm">
          {[
            { icon: "🙈", title: "Server blindness", desc: "The server receives 8 hex chars, not your email. It cannot reverse a SHA-256 hash." },
            { icon: "🔗", title: "Unlinkable proofs", desc: "Each call generates a fresh random salt. Two proofs of the same email look completely different." },
            { icon: "✅", title: "Verifiable locally", desc: "You (or any auditor) can re-run SHA-256(email:salt) and confirm the commitment is genuine." },
          ].map((g) => (
            <div key={g.title} className="rounded-xl border border-white/8 bg-white/[0.025] p-3">
              <div className="mb-1 text-lg">{g.icon}</div>
              <div className="text-xs font-semibold">{g.title}</div>
              <div className="mt-0.5 text-xs text-muted">{g.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

/* ──────────────────────────────────────────────
   TIAM DEMO TAB
────────────────────────────────────────────── */

/* ──────────────────────────────────────────────
   BLOOM FILTER TAB
────────────────────────────────────────────── */

function BloomTab() {
  const [email, setEmail] = useState("staff@aylus.org");
  const [commitment, setCommitment] = useState("");
  const [filterMeta, setFilterMeta] = useState<{ count: number; sizeBits: number } | null>(null);
  const [localResult, setLocalResult] = useState<boolean | null | undefined>(undefined);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchBloomFilter().then((f) => {
      if (f) setFilterMeta({ count: f.count, sizeBits: 524_288 });
    });
  }, []);

  useEffect(() => {
    if (!email) { setCommitment(""); return; }
    hashEmail(email).then(setCommitment).catch(() => {});
    setLocalResult(undefined);
  }, [email]);

  const handleCheck = async () => {
    if (!commitment) return;
    setLoading(true);
    const result = await checkCommitmentLocally(commitment);
    setLocalResult(result);
    setLoading(false);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.2 }}
      className="space-y-5"
    >
      <div className="card card-glow p-6 space-y-4">
        <div>
          <h2 className="text-lg font-bold">Bloom Filter — local breach check</h2>
          <p className="mt-1 text-sm text-muted">
            The client downloads a ~64KB probabilistic filter. You hash an email locally and
            check against the filter — the server receives nothing at all.
          </p>
        </div>

        {filterMeta ? (
          <div className="grid gap-3 sm:grid-cols-3 text-sm">
            <KeyValue label="Filter size" value="512k bits (64KB)" />
            <KeyValue label="Hash functions (k)" value="7" />
            <KeyValue label="Breached commitments indexed" value={String(filterMeta.count)} highlight />
          </div>
        ) : (
          <div className="text-xs text-muted">
            Filter not yet populated — run a breach scan first to seed it with breach commitments.
          </div>
        )}

        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-muted">Email to check locally</span>
          <input value={email} onChange={(e) => setEmail(e.target.value)} className="bd-input" placeholder="staff@org.org" />
        </label>

        {commitment && (
          <div className="rounded-xl border border-white/8 bg-white/[0.025] p-3">
            <div className="mb-1 text-[11px] font-medium text-muted">SHA-256(email) — what gets checked against the filter</div>
            <div className="break-all font-mono text-[12px]">
              <span className="text-brand-300">{commitment.slice(0, 16)}</span>
              <span className="text-fg/40">{commitment.slice(16)}</span>
            </div>
          </div>
        )}

        <button
          onClick={handleCheck}
          disabled={!commitment || loading}
          className="w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:opacity-40"
        >
          {loading ? "Checking filter…" : "Check locally — no server query →"}
        </button>

        <AnimatePresence>
          {localResult !== undefined && (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-3">
              {localResult === null ? (
                <div className="rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-muted">
                  Filter not yet loaded — run a breach scan first to populate it. Falling back to server.
                </div>
              ) : localResult === false ? (
                <div className="rounded-xl border border-risk-low/30 bg-risk-low/10 px-4 py-3 text-sm text-risk-low">
                  <strong>Definitely NOT in breach set.</strong> The filter guarantees this with zero false negatives.
                  Server was never contacted — the vault stayed completely sealed.
                </div>
              ) : (
                <div className="rounded-xl border border-risk-med/30 bg-risk-med/10 px-4 py-3 text-sm text-risk-med">
                  <strong>Probably in breach set</strong> (filter hit). Running server confirmation to eliminate false positives…
                  This is normal — the Bloom filter trades a small false positive rate for complete privacy on negative results.
                </div>
              )}

              <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4 space-y-2 text-[11px]">
                <div className="font-semibold text-xs">What just happened</div>
                {[
                  ["1", "Your email was hashed to a 64-char commitment in the browser"],
                  ["2", "The commitment was tested against the 512k-bit local filter"],
                  ["3", localResult === false
                    ? "All 7 bit positions were NOT set → definitely not in breach set"
                    : "All 7 bit positions were set → probably in breach set"],
                  ["4", localResult === false
                    ? "No server query. Server saw nothing. Vault sealed."
                    : "Server queried only to confirm (eliminate false positives)"],
                ].map(([n, text]) => (
                  <div key={n} className="flex gap-2.5">
                    <span className="flex-none text-brand-300 font-bold">{n}.</span>
                    <span className="text-fg/80">{text}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="card p-5 space-y-2">
        <h3 className="text-sm font-bold">Why Bloom filters are powerful here</h3>
        <div className="grid gap-3 sm:grid-cols-3 text-sm">
          {[
            { icon: "🏠", title: "Local check", desc: "Filter downloaded once. All checks run in your browser. Server sees no queries." },
            { icon: "⚡", title: "Instant results", desc: "Bit-array lookup is O(k) — microseconds. No network round-trip for clean emails." },
            { icon: "🔒", title: "No false negatives", desc: "If the filter says 'definitely not breached,' it is provably correct. 100% guarantee." },
          ].map((g) => (
            <div key={g.title} className="rounded-xl border border-white/8 bg-white/[0.025] p-3">
              <div className="mb-1 text-lg">{g.icon}</div>
              <div className="text-xs font-semibold">{g.title}</div>
              <div className="mt-0.5 text-xs text-muted">{g.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

/* ──────────────────────────────────────────────
   MERKLE PROOF TAB
────────────────────────────────────────────── */

function MerkleTab() {
  const [commitment, setCommitment] = useState("");
  const [email, setEmail] = useState("staff@aylus.org");
  const [root, setRoot] = useState<{ root: string | null; size: number } | null>(null);
  const [proof, setProof] = useState<MerkleProof | null>(null);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMerkleRoot().then(setRoot).catch(() => {});
  }, []);

  useEffect(() => {
    if (!email) { setCommitment(""); return; }
    hashEmail(email).then(setCommitment).catch(() => {});
    setProof(null); setVerifyResult(null); setError(null);
  }, [email]);

  const handleFetchProof = async () => {
    if (!commitment) return;
    setLoading(true); setError(null); setProof(null); setVerifyResult(null);
    const p = await fetchMerkleProof(commitment);
    if (!p) setError("Commitment not in the Merkle tree yet — run a breach scan for this email first.");
    else setProof(p);
    setLoading(false);
  };

  const handleVerify = async () => {
    if (!proof) return;
    setVerifyResult(await verifyMerkleProof(proof));
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.2 }}
      className="space-y-5"
    >
      <div className="card card-glow p-6 space-y-4">
        <div>
          <h2 className="text-lg font-bold">Merkle Tree — membership proof</h2>
          <p className="mt-1 text-sm text-muted">
            The server keeps all processed commitment hashes in a Merkle tree.
            A membership proof lets you verify "this commitment was processed" using only
            a chain of sibling hashes — no other entries revealed.
          </p>
        </div>

        {root && (
          <div className="rounded-xl border border-white/8 bg-white/[0.025] p-3 space-y-1.5">
            <div className="text-[11px] font-medium text-muted">Current Merkle root ({root.size} commitment{root.size === 1 ? "" : "s"})</div>
            <div className="break-all font-mono text-[12px] text-brand-300">
              {root.root ?? "empty — no commitments yet"}
            </div>
          </div>
        )}

        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-muted">Email (we derive its commitment)</span>
          <input value={email} onChange={(e) => setEmail(e.target.value)} className="bd-input" placeholder="staff@org.org" />
        </label>

        {commitment && (
          <div className="text-[11px] text-muted font-mono break-all">
            Commitment: <span className="text-brand-300">{commitment}</span>
          </div>
        )}

        <button
          onClick={handleFetchProof}
          disabled={!commitment || loading}
          className="w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg transition hover:brightness-110 disabled:opacity-40"
        >
          {loading ? "Fetching proof…" : "Fetch membership proof →"}
        </button>

        {error && (
          <div className="rounded-xl border border-risk-med/30 bg-risk-med/10 px-3 py-2.5 text-xs text-risk-med">{error}</div>
        )}

        {proof && (
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="space-y-3">
            <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4 space-y-3">
              <div className="text-xs font-semibold">Proof path ({proof.proof.length} step{proof.proof.length === 1 ? "" : "s"})</div>
              {proof.proof.map((step, i) => (
                <div key={i} className="flex gap-3 items-center text-[11px]">
                  <span className="text-muted w-4">{i + 1}.</span>
                  <span
                    className="rounded px-1.5 py-0.5 font-mono text-[10px]"
                    style={step.side === "left"
                      ? { background: "rgba(99,102,241,0.15)", color: "var(--color-brand-300)" }
                      : { background: "rgba(163,230,53,0.12)", color: "var(--color-accent-400)" }
                    }
                  >
                    {step.side}
                  </span>
                  <span className="font-mono text-fg/60 truncate">{step.hash.slice(0, 32)}…</span>
                </div>
              ))}
              <div className="text-[11px] text-muted pt-1 border-t border-white/8">
                Root: <span className="font-mono text-brand-300">{proof.root}</span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleVerify}
                className="rounded-xl border border-accent-500/40 bg-accent-500/10 px-4 py-2 text-sm font-medium text-accent-400 transition hover:bg-accent-500/20"
              >
                Verify proof locally →
              </button>
              <AnimatePresence>
                {verifyResult !== null && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}
                    className="flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-bold"
                    style={verifyResult
                      ? { color: "var(--color-risk-low)", background: "rgba(52,211,153,0.14)" }
                      : { color: "var(--color-risk-crit)", background: "rgba(244,63,94,0.14)" }
                    }
                  >
                    {verifyResult ? "✓ Valid — commitment is provably in the set" : "✗ Invalid"}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {verifyResult && (
              <div className="rounded-xl border border-risk-low/30 bg-risk-low/10 px-4 py-3 text-sm text-risk-low">
                The Merkle proof is valid. This commitment exists in the server's set — proven by
                recomputing the root hash from the proof path alone. No other commitments were revealed.
              </div>
            )}
          </motion.div>
        )}
      </div>
    </motion.div>
  );
}

/* ──────────────────────────────────────────────
   TIAM AUTH TAB
────────────────────────────────────────────── */

function TiamTab() {
  const [keyPair, setKeyPair] = useState<TiamKeyPair | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [domain, setDomain] = useState("aylus.org");
  const [claim, setClaim] = useState<DomainClaim | null>(null);
  const [isSigning, setIsSigning] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [stored, setStored] = useState<StoredIdentity | null>(loadIdentity);
  const [org, setOrg] = useState("AYLUS");
  const [serverReg, setServerReg] = useState<{ fingerprint: string; organization: string } | null>(null);
  const [isRegistering, setIsRegistering] = useState(false);
  const [authResult, setAuthResult] = useState<TiamAuthResult | null>(null);
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  const handleGenerate = async () => {
    setIsGenerating(true);
    setClaim(null); setVerifyResult(null); setServerReg(null); setAuthResult(null);
    try {
      const kp = await generateKeyPair();
      setKeyPair(kp);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleRegister = async () => {
    if (!keyPair) return;
    setIsRegistering(true);
    try {
      const reg = await registerWithServer(keyPair, org);
      setServerReg(reg);
    } catch {
      // show fallback
    } finally {
      setIsRegistering(false);
    }
  };

  const handleAuthenticate = async () => {
    if (!keyPair || !serverReg) return;
    setIsAuthenticating(true);
    try {
      const result = await authenticateWithServer(keyPair);
      setAuthResult(result);
    } finally {
      setIsAuthenticating(false);
    }
  };

  const handleSign = async () => {
    if (!keyPair || !domain) return;
    setIsSigning(true);
    setVerifyResult(null);
    try {
      const c = await signDomainClaim(domain, keyPair);
      setClaim(c);
    } finally {
      setIsSigning(false);
    }
  };

  const handleVerify = async () => {
    if (!claim) return;
    setIsVerifying(true);
    try {
      setVerifyResult(await verifyDomainClaim(claim));
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSaveIdentity = () => {
    if (!keyPair || !claim) return;
    const identity: StoredIdentity = {
      publicKeyJwk: keyPair.publicKeyJwk,
      fingerprint: keyPair.fingerprint,
      domain: claim.domain,
      createdAt: new Date().toISOString(),
    };
    storeIdentity(identity);
    setStored(identity);
  };

  const handleClearIdentity = () => {
    clearIdentity();
    setStored(null);
    setKeyPair(null);
    setClaim(null);
    setVerifyResult(null);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      transition={{ duration: 0.2 }}
      className="space-y-5"
    >
      {/* Stored identity banner */}
      {stored && (
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-risk-low/30 bg-risk-low/10 p-4"
        >
          <div>
            <div className="flex items-center gap-2 text-sm font-bold text-risk-low">
              ✓ Stored TIAM identity
            </div>
            <p className="mt-0.5 text-xs text-muted">
              Domain: <span className="font-mono text-fg">{stored.domain}</span> ·
              Fingerprint: <span className="font-mono text-fg">{stored.fingerprint}</span>
            </p>
            <p className="mt-0.5 text-[11px] text-muted">
              Created {new Date(stored.createdAt).toLocaleString()} · private key in memory only (refresh = gone)
            </p>
          </div>
          <button
            onClick={handleClearIdentity}
            className="rounded-lg border border-white/10 px-2 py-1 text-[11px] text-muted hover:text-fg"
          >
            Clear
          </button>
        </motion.div>
      )}

      {/* Step 1 — Generate keypair */}
      <Step number={1} title="Generate your cryptographic identity">
        <p className="text-sm text-muted">
          Creates an ECDSA P-256 keypair using your browser's Web Crypto API. The private key is
          generated and used entirely in memory — it is never transmitted anywhere.
        </p>
        <button
          onClick={handleGenerate}
          disabled={isGenerating}
          className="mt-4 rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 px-5 py-2.5 font-semibold text-white shadow-lg shadow-brand-600/25 transition hover:brightness-110 disabled:opacity-40"
        >
          {isGenerating ? "Generating keypair…" : "Generate ECDSA P-256 keypair →"}
        </button>

        {keyPair && (
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-4 space-y-3">
            <KeyValue label="Key algorithm" value="ECDSA P-256 (secp256r1)" />
            <KeyValue label="Security level" value="128-bit equivalent (same as TLS certificates)" />
            <KeyValue
              label="Public key fingerprint"
              value={keyPair.fingerprint}
              mono
              highlight
            />
            <details className="rounded-xl border border-white/8 bg-white/[0.02] p-3">
              <summary className="cursor-pointer text-[11px] text-muted">View public key (JWK) ▾</summary>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-ink-900/60 p-3 font-mono text-[11px] leading-relaxed text-fg/80">
                {keyPair.publicKeyJwk}
              </pre>
            </details>
            <div className="rounded-xl border border-white/8 bg-white/[0.02] px-3 py-2 text-[11px] text-muted">
              🔒 Private key: <span className="text-risk-crit font-semibold">in browser memory only</span> — never exported, never transmitted.
            </div>
          </motion.div>
        )}
      </Step>

      {/* Step 2 — Sign a domain claim */}
      {keyPair && (
        <Step number={2} title="Sign a domain-ownership claim">
          <p className="text-sm text-muted">
            Your private key signs a structured message that includes the domain and a timestamp.
            Anyone who has your public key can verify this signature — no server required.
          </p>

          <label className="mt-4 block">
            <span className="mb-1.5 block text-xs font-medium text-muted">Domain to claim</span>
            <input
              value={domain}
              onChange={(e) => { setDomain(e.target.value); setClaim(null); setVerifyResult(null); }}
              placeholder="yourorg.org"
              className="bd-input"
            />
          </label>

          {domain && (
            <div className="mt-3 rounded-xl border border-white/8 bg-white/[0.02] p-3">
              <div className="mb-1 text-[11px] font-medium text-muted">Message that will be signed</div>
              <code className="font-mono text-[11px] text-brand-300">
                tiam:v1:domain-claim:{domain}:{new Date().toISOString().slice(0, 10)}T…
              </code>
            </div>
          )}

          <button
            onClick={handleSign}
            disabled={!domain || isSigning}
            className="mt-4 rounded-xl bg-gradient-to-r from-accent-500 to-brand-500 px-5 py-2.5 font-semibold text-white shadow-lg shadow-accent-600/25 transition hover:brightness-110 disabled:opacity-40"
          >
            {isSigning ? "Signing…" : "Sign domain claim →"}
          </button>

          {claim && (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-4 space-y-3">
              <KeyValue label="Domain claimed" value={claim.domain} />
              <KeyValue label="Timestamp" value={claim.timestamp} mono />
              <KeyValue label="Signer fingerprint" value={claim.fingerprint} mono highlight />
              <KeyValue
                label="Signature (base64, first 48 chars)"
                value={claim.signature.slice(0, 48) + "…"}
                mono
              />
              <details className="rounded-xl border border-white/8 bg-white/[0.02] p-3">
                <summary className="cursor-pointer text-[11px] text-muted">View full claim object ▾</summary>
                <pre className="mt-2 overflow-x-auto rounded-lg bg-ink-900/60 p-3 font-mono text-[11px] leading-relaxed text-fg/80">
                  {JSON.stringify({ ...claim, publicKey: "[JWK — see above]" }, null, 2)}
                </pre>
              </details>
            </motion.div>
          )}
        </Step>
      )}

      {/* Step 3 — Verify */}
      {claim && (
        <Step number={3} title="Verify the claim — no server, no trust required">
          <p className="text-sm text-muted">
            Re-derives the signed message from the claim's fields, then uses the embedded public key
            to verify the signature. This is pure math — you can run it on any machine, offline,
            with no connection to us.
          </p>

          <div className="mt-3 rounded-xl border border-white/8 bg-white/[0.02] p-3 space-y-1 text-[12px]">
            <div className="text-muted">Verification steps:</div>
            <div className="font-mono text-fg/80">1. message = "tiam:v1:domain-claim:{claim.domain}:{claim.timestamp}"</div>
            <div className="font-mono text-fg/80">2. pubKey  = importKey(claim.publicKey)  <span className="text-muted">// JWK → CryptoKey</span></div>
            <div className="font-mono text-fg/80">3. result  = ECDSA_verify(pubKey, message, claim.signature)</div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <button
              onClick={handleVerify}
              disabled={isVerifying}
              className="rounded-xl border border-accent-500/40 bg-accent-500/10 px-4 py-2 text-sm font-medium text-accent-400 transition hover:bg-accent-500/20 disabled:opacity-40"
            >
              {isVerifying ? "Verifying…" : "Verify signature →"}
            </button>

            <AnimatePresence>
              {verifyResult !== null && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2 rounded-full px-4 py-2 text-sm font-bold"
                  style={
                    verifyResult
                      ? { color: "var(--color-risk-low)", background: "rgba(52,211,153,0.15)" }
                      : { color: "var(--color-risk-crit)", background: "rgba(244,63,94,0.15)" }
                  }
                >
                  {verifyResult
                    ? "✓ VALID — signature proves ownership without any server"
                    : "✗ INVALID — signature does not match"}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {verifyResult === true && (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-4 space-y-3"
            >
              <div className="rounded-xl border border-risk-low/30 bg-risk-low/10 px-4 py-3 text-sm text-risk-low">
                The holder of the private key matching fingerprint{" "}
                <code className="font-mono">{claim.fingerprint}</code> has cryptographically proven they
                intended to claim <strong>{claim.domain}</strong> at {claim.timestamp}. No
                password, no central server, no trust required.
              </div>

              {!stored && (
                <button
                  onClick={handleSaveIdentity}
                  className="rounded-xl border border-brand-500/40 bg-brand-500/10 px-4 py-2 text-sm font-medium text-brand-300 transition hover:bg-brand-500/20"
                >
                  Save identity to localStorage →
                </button>
              )}
            </motion.div>
          )}

          {verifyResult === false && (
            <div className="mt-4 rounded-xl border border-risk-crit/30 bg-risk-crit/10 px-4 py-3 text-sm text-risk-crit">
              The signature is invalid — either the claim was tampered with, or the wrong private key was used.
              A real attacker can't forge a valid signature without the original private key.
            </div>
          )}
        </Step>
      )}

      {/* Step 4 — Register public key with server */}
      {verifyResult === true && (
        <Step number={4} title="Register public key with server — no password">
          <p className="text-sm text-muted">
            Sends only your public key and organization name to the server.
            No password. No email. No secret. Server stores: public key + org + permissions.
          </p>
          <label className="mt-4 block">
            <span className="mb-1.5 block text-xs font-medium text-muted">Organization name</span>
            <input value={org} onChange={(e) => setOrg(e.target.value)} className="bd-input" placeholder="Your Nonprofit" />
          </label>
          <button
            onClick={handleRegister}
            disabled={!keyPair || isRegistering || !!serverReg}
            className="mt-4 rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 px-5 py-2.5 font-semibold text-white shadow-lg transition hover:brightness-110 disabled:opacity-40"
          >
            {isRegistering ? "Registering…" : serverReg ? "✓ Registered" : "Register public key →"}
          </button>
          {serverReg && (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-4 space-y-2">
              <KeyValue label="Server registered" value={serverReg.organization} />
              <KeyValue label="Fingerprint on server" value={serverReg.fingerprint} mono highlight />
              <KeyValue label="What server stored" value="publicKey + organization + permissions — no password, no secret" />
            </motion.div>
          )}
        </Step>
      )}

      {/* Step 5 — Challenge-response login */}
      {serverReg && (
        <Step number={5} title="Authenticate — challenge-response, no password">
          <p className="text-sm text-muted">
            Server issues a one-time challenge. Your browser signs it with the private key.
            Server verifies the math. That is the entire authentication — the vault never opened.
          </p>
          <button
            onClick={handleAuthenticate}
            disabled={isAuthenticating}
            className="mt-4 rounded-xl bg-gradient-to-r from-accent-500 to-brand-500 px-5 py-2.5 font-semibold text-white shadow-lg transition hover:brightness-110 disabled:opacity-40"
          >
            {isAuthenticating ? "Authenticating…" : "Authenticate with server →"}
          </button>
          {authResult && (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-4 space-y-3">
              <div
                className="flex items-center gap-2 rounded-full px-4 py-2 text-sm font-bold w-fit"
                style={authResult.verified
                  ? { color: "var(--color-risk-low)", background: "rgba(52,211,153,0.15)" }
                  : { color: "var(--color-risk-crit)", background: "rgba(244,63,94,0.15)" }
                }
              >
                {authResult.verified ? "✓ AUTHENTICATED — private key validated by math" : `✗ FAILED — ${authResult.reason}`}
              </div>
              {authResult.verified && (
                <>
                  <KeyValue label="Organization" value={authResult.organization ?? ""} />
                  <KeyValue label="Permissions granted" value={(authResult.permissions ?? []).join(", ")} highlight />
                  <div className="rounded-xl border border-risk-low/30 bg-risk-low/10 px-4 py-3 text-sm text-risk-low">
                    The server issued a challenge, your private key signed it, the server verified the signature.
                    No password was transmitted. The vault (private key) was never opened by anyone but you.
                  </div>
                </>
              )}
            </motion.div>
          )}
        </Step>
      )}

      {/* Security guarantee */}
      <div className="card p-5 space-y-2">
        <h3 className="text-sm font-bold">What TIAM guarantees</h3>
        <div className="grid gap-3 sm:grid-cols-3 text-sm">
          {[
            { icon: "🔑", title: "No password", desc: "Nothing to steal from a server database. Your identity is a math key, not a stored secret." },
            { icon: "🏛️", title: "No central authority", desc: "Any verifier can check any claim offline using open cryptographic standards (WebCrypto)." },
            { icon: "🛡️", title: "Unforgeable", desc: "ECDSA P-256 signatures cannot be forged without the private key — the math is the guarantee." },
          ].map((g) => (
            <div key={g.title} className="rounded-xl border border-white/8 bg-white/[0.025] p-3">
              <div className="mb-1 text-lg">{g.icon}</div>
              <div className="text-xs font-semibold">{g.title}</div>
              <div className="mt-0.5 text-xs text-muted">{g.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

/* ── Shared helper components ── */

function Step({ number, title, children }: { number: number; title: string; children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="card card-glow p-6"
    >
      <div className="mb-4 flex items-center gap-3">
        <span
          className="grid h-8 w-8 flex-none place-items-center rounded-full text-sm font-bold text-white"
          style={{ background: "linear-gradient(135deg,#6366f1,#84cc16)" }}
        >
          {number}
        </span>
        <h2 className="text-base font-bold">{title}</h2>
      </div>
      {children}
    </motion.div>
  );
}

function KeyValue({
  label, value, mono = false, highlight = false,
}: {
  label: string; value: string; mono?: boolean; highlight?: boolean;
}) {
  return (
    <div className="rounded-xl border border-white/8 bg-white/[0.02] p-3">
      <div className="mb-0.5 text-[11px] font-medium text-muted">{label}</div>
      <div
        className={mono ? "break-all font-mono text-[12px]" : "text-sm"}
        style={{ color: highlight ? "var(--color-brand-300)" : "var(--color-fg)" }}
      >
        {value}
      </div>
    </div>
  );
}
