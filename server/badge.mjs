// Verifiable security-health badge — lets a nonprofit PROVE an independent Aegis
// scan graded their site (e.g. "B or better, issued in the last 90 days")
// WITHOUT publishing the underlying report, which is itself an attacker's
// roadmap. This is a salted-Merkle selective-disclosure credential (the same
// idea behind SD-JWT) signed by Aegis with Ed25519:
//
//   • Every claim about the scan (domain, grade, exact score, per-component
//     results, dates) is salted and hashed into a Merkle leaf.
//   • Aegis signs ONLY the Merkle root — so the signature commits to all claims
//     at once, but the signed bytes reveal nothing.
//   • The public badge discloses a chosen SUBSET of claims (by default just
//     domain + grade + dates), each with its salt and a Merkle inclusion proof.
//   • Anyone can verify, offline, against Aegis's public key: the signature is
//     valid AND each disclosed claim provably belongs to the signed root. The
//     exact score and every individual finding stay hidden.
//
// This gives genuine zero-knowledge-STYLE minimal disclosure. The natural
// upgrade for "prove grade ≥ B without revealing even the grade bucket" is a
// BBS+ credential or a Bulletproofs/Noir range proof; the claim model here is
// designed to swap into one without changing the API.

import {
  generateKeyPairSync, createPrivateKey, createPublicKey,
  sign as edSign, verify as edVerify, createHash, randomBytes,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const KEY_FILE = join(HERE, ".badge-keys.json"); // gitignored; stable across restarts
const SIG_PREFIX = "aegis-badge-v1\n"; // domain-separates the signed message
const VALID_DAYS = 90;
const GRADE_ORDER = ["F", "D", "C", "B", "A"]; // worst → best

/* ───────────────────────── issuer key management ───────────────────────── */

function loadIssuer() {
  // 1) Explicit key from the environment wins (production).
  const envPem = process.env.AEGIS_BADGE_PRIVATE_KEY;
  if (envPem) {
    const privateKey = createPrivateKey(envPem.includes("BEGIN") ? envPem : Buffer.from(envPem, "base64").toString());
    const publicKey = createPublicKey(privateKey);
    return finalizeIssuer(privateKey, publicKey, "env");
  }
  // 2) Reuse a persisted dev key so previously-issued badges keep verifying.
  if (existsSync(KEY_FILE)) {
    try {
      const { priv } = JSON.parse(readFileSync(KEY_FILE, "utf8"));
      const privateKey = createPrivateKey(priv);
      return finalizeIssuer(privateKey, createPublicKey(privateKey), "file");
    } catch {
      /* fall through and regenerate */
    }
  }
  // 3) First run: generate, then try to persist (best-effort).
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ type: "pkcs8", format: "pem" });
  try {
    writeFileSync(KEY_FILE, JSON.stringify({ priv }), { mode: 0o600 });
  } catch {
    console.warn("[badge] could not persist issuer key — badges won't survive a restart");
  }
  return finalizeIssuer(privateKey, publicKey, "generated");
}

function finalizeIssuer(privateKey, publicKey, origin) {
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  const kid = createHash("sha256").update(spkiDer).digest("hex").slice(0, 16);
  return {
    kid,
    origin,
    alg: "Ed25519",
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    sign: (msg) => edSign(null, Buffer.from(msg), privateKey),
    verify: (msg, sig) => edVerify(null, Buffer.from(msg), publicKey, sig),
  };
}

let _issuer = null;
export function issuer() {
  if (!_issuer) _issuer = loadIssuer();
  return _issuer;
}

/* ────────────────────────────── primitives ────────────────────────────── */

const sha = (s) => createHash("sha256").update(s).digest("hex");
const b64u = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s) => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");

export function encodeToken(badge) { return b64u(JSON.stringify(badge)); }
export function decodeToken(token) {
  try { return JSON.parse(fromB64u(token).toString("utf8")); } catch { return null; }
}

// Leaf = SHA256(salt | canonical(key, value)). The salt stops a verifier from
// brute-forcing a hidden claim's value from its hash.
const leafHash = (salt, k, v) => sha(`${salt}|${JSON.stringify([k, v])}`);
const hashPair = (a, b) => sha(a + b);

function buildLevels(leaves) {
  const levels = [leaves.slice()];
  let cur = leaves.slice();
  while (cur.length > 1) {
    const next = [];
    for (let i = 0; i < cur.length; i += 2) {
      const left = cur[i];
      const right = i + 1 < cur.length ? cur[i + 1] : cur[i]; // duplicate odd tail
      next.push(hashPair(left, right));
    }
    levels.push(next);
    cur = next;
  }
  return levels;
}

function proofFor(levels, index) {
  const proof = [];
  let idx = index;
  for (let l = 0; l < levels.length - 1; l++) {
    const level = levels[l];
    const isRight = idx % 2 === 1;
    const sibIdx = isRight ? idx - 1 : idx + 1;
    const sibling = sibIdx < level.length ? level[sibIdx] : level[idx]; // duplicated node
    proof.push({ h: sibling, left: isRight }); // sibling sits on the LEFT iff we're the right child
    idx = Math.floor(idx / 2);
  }
  return proof;
}

function rootFromProof(leaf, proof) {
  let h = leaf;
  for (const p of proof) h = p.left ? hashPair(p.h, h) : hashPair(h, p.h);
  return h;
}

/* ───────────────────────────── scan scoring ───────────────────────────── */

// Deterministic composite score from the live scan signals. The server scores
// it (never the client) so a badge can't be self-awarded a passing grade.
export function scoreScan(s = {}) {
  let score = 100;
  if (s.reputationFlagged) score -= 50;

  const pen = { critical: 30, high: 20, medium: 10, low: 3 };
  if (Array.isArray(s.webChecks)) {
    for (const c of s.webChecks) if (c?.status && c.status !== "pass") score -= pen[c.severity] ?? 0;
  }
  if (s.spoofable) score -= 15;
  else if (s.domainWorst === "medium") score -= 6;

  score -= Math.min(30, (s.breachedAccounts || 0) * 8);

  const jc = s.jsCounts || {};
  score -= Math.min(40, (jc.critical || 0) * 20 + (jc.high || 0) * 10 + (jc.medium || 0) * 3);

  score -= Math.min(8, s.exposedEmails || 0);

  score = Math.max(0, Math.min(100, Math.round(score)));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade };
}

export function gradeAtLeast(have, min) {
  return GRADE_ORDER.indexOf(have) >= GRADE_ORDER.indexOf(min) && GRADE_ORDER.includes(have);
}

/* ─────────────────────────── issue / disclose ─────────────────────────── */

// Claims that are safe to show on a public badge by default. Everything else
// (exact score, per-component results) is committed-to but hidden.
const DEFAULT_DISCLOSE = ["domain", "grade", "issuedAt", "expiresAt"];

/**
 * Build the FULL credential (kept privately by the org / returned to the
 * issuer's client). It contains every claim + salt so the org can later choose
 * what to disclose. Use deriveBadge() to produce the public, minimal token.
 */
export function issueCredential({ domain, orgName, summary }) {
  const iss = issuer();
  const { score, grade } = scoreScan(summary);
  const now = Date.now();
  const issuedAt = now;
  const expiresAt = now + VALID_DAYS * 86400000;

  // Ordered claim set. Order is fixed so inclusion-proof indices are stable.
  const jc = summary?.jsCounts || {};
  const claims = [
    { k: "domain", v: domain },
    { k: "org", v: orgName || domain },
    { k: "grade", v: grade },
    { k: "score", v: score },                 // hidden by default
    { k: "issuedAt", v: issuedAt },
    { k: "expiresAt", v: expiresAt },
    { k: "emailSpoofing", v: summary?.spoofable ? "spoofable" : "protected" },
    { k: "reputation", v: summary?.reputationFlagged ? "flagged" : "clean" },
    { k: "webGrade", v: summary?.webGrade || "n/a" },
    { k: "breachedAccounts", v: summary?.breachedAccounts || 0 },
    { k: "codeSecurityIssues", v: (jc.security ?? jc.critical ?? 0) || 0 },
    { k: "nonce", v: b64u(randomBytes(12)) },  // makes each credential unique
  ];

  const salts = claims.map(() => b64u(randomBytes(16)));
  const leaves = claims.map((c, i) => leafHash(salts[i], c.k, c.v));
  const levels = buildLevels(leaves);
  const root = levels[levels.length - 1][0];
  const sig = b64u(iss.sign(SIG_PREFIX + root));

  return {
    v: 1, kid: iss.kid, alg: iss.alg,
    root, sig, score, grade, issuedAt, expiresAt,
    // private material the org keeps to re-derive badges later:
    claims: claims.map((c, i) => ({ ...c, salt: salts[i], index: i, proof: proofFor(levels, i) })),
  };
}

/** Produce the PUBLIC badge token, revealing only the requested claim keys. */
export function deriveBadge(credential, reveal = DEFAULT_DISCLOSE) {
  const want = new Set(reveal);
  const disclosed = credential.claims
    .filter((c) => want.has(c.k))
    .map((c) => ({ k: c.k, v: c.v, salt: c.salt, index: c.index, proof: c.proof }));
  const badge = {
    v: 1, kid: credential.kid, alg: credential.alg,
    root: credential.root, sig: credential.sig,
    disclosed,
    // count of committed-but-hidden claims, so a verifier sees the badge isn't
    // hiding a tiny tree — without revealing what those claims are.
    hidden: credential.claims.length - disclosed.length,
  };
  return { badge, token: encodeToken(badge) };
}

/* ───────────────────────────────── verify ─────────────────────────────── */

/**
 * Verify a badge token against Aegis's public key. Checks the Ed25519 signature
 * over the Merkle root, every disclosed claim's inclusion proof, and freshness.
 * Returns a structured result; never throws on bad input.
 */
export function verifyBadge(token, opts = {}) {
  const badge = typeof token === "string" ? decodeToken(token) : token;
  const checks = [];
  const fail = (reason) => ({ valid: false, reason, checks, badge: badge || null });

  if (!badge || badge.v !== 1 || !badge.root || !badge.sig || !Array.isArray(badge.disclosed)) {
    return fail("malformed_badge");
  }
  const iss = issuer();
  if (badge.kid !== iss.kid) {
    checks.push({ label: "Issuer key", ok: false, detail: `unknown key id ${badge.kid}` });
    return fail("unknown_issuer");
  }
  checks.push({ label: "Issuer key", ok: true, detail: `Aegis key ${iss.kid}` });

  // 1) Signature over the Merkle root.
  let sigOk = false;
  try { sigOk = iss.verify(SIG_PREFIX + badge.root, fromB64u(badge.sig)); } catch { sigOk = false; }
  checks.push({ label: "Signature", ok: sigOk, detail: sigOk ? "valid Ed25519 over root" : "invalid" });
  if (!sigOk) return fail("bad_signature");

  // 2) Each disclosed claim provably belongs to the signed root.
  const fields = {};
  for (const d of badge.disclosed) {
    const recomputed = rootFromProof(leafHash(d.salt, d.k, d.v), d.proof || []);
    if (recomputed !== badge.root) {
      checks.push({ label: `Claim "${d.k}"`, ok: false, detail: "inclusion proof failed" });
      return fail("tampered_claim");
    }
    fields[d.k] = d.v;
  }
  checks.push({ label: "Disclosed claims", ok: true, detail: `${badge.disclosed.length} proven, ${badge.hidden ?? 0} hidden` });

  // 3) Freshness.
  const now = Date.now();
  const expiresAt = Number(fields.expiresAt) || 0;
  const fresh = expiresAt === 0 ? true : now <= expiresAt;
  checks.push({
    label: "Freshness",
    ok: fresh,
    detail: expiresAt ? (fresh ? `valid until ${new Date(expiresAt).toISOString().slice(0, 10)}` : "expired") : "no expiry set",
  });
  if (!fresh) return fail("expired");

  // 4) Optional grade threshold requested by the verifier.
  if (opts.requireGrade) {
    const meets = fields.grade && gradeAtLeast(fields.grade, opts.requireGrade);
    checks.push({ label: `Grade ≥ ${opts.requireGrade}`, ok: Boolean(meets), detail: `disclosed grade ${fields.grade ?? "—"}` });
    if (!meets) return fail("grade_below_threshold");
  }

  return {
    valid: true,
    kid: badge.kid,
    domain: fields.domain || null,
    grade: fields.grade || null,
    org: fields.org || null,
    issuedAt: Number(fields.issuedAt) || null,
    expiresAt: expiresAt || null,
    disclosed: fields,
    hidden: badge.hidden ?? 0,
    checks,
  };
}

/* ──────────────────────────── SVG badge image ─────────────────────────── */

const GRADE_COLOR = { A: "#30d158", B: "#34c759", C: "#ffd60a", D: "#ff9f0a", F: "#ff453a" };

/** Render an embeddable SVG for a verified badge (or a "could not verify" pill). */
export function renderSvg(token, opts = {}) {
  const r = verifyBadge(token, opts);
  const esc = (s) => String(s).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
  if (!r.valid) {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="56" role="img" aria-label="Aegis: not verified">
  <rect width="220" height="56" rx="10" fill="#1c1c22"/>
  <rect x="0" y="0" width="6" height="56" rx="3" fill="#ff453a"/>
  <text x="20" y="24" fill="#fff" font-family="system-ui,Segoe UI,Arial" font-size="13" font-weight="700">Aegis security badge</text>
  <text x="20" y="42" fill="#ff8a80" font-family="system-ui,Segoe UI,Arial" font-size="11">Not verified · ${esc(r.reason || "invalid")}</text>
</svg>`;
  }
  const color = GRADE_COLOR[r.grade] || "#8b5cf6";
  const until = r.expiresAt ? new Date(r.expiresAt).toISOString().slice(0, 10) : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="240" height="64" role="img" aria-label="Aegis verified, grade ${esc(r.grade)}">
  <rect width="240" height="64" rx="12" fill="#15151b"/>
  <rect x="0" y="0" width="6" height="64" rx="3" fill="${color}"/>
  <circle cx="40" cy="32" r="18" fill="none" stroke="${color}" stroke-width="2.5"/>
  <text x="40" y="38" text-anchor="middle" fill="${color}" font-family="system-ui,Segoe UI,Arial" font-size="18" font-weight="800">${esc(r.grade)}</text>
  <text x="68" y="26" fill="#fff" font-family="system-ui,Segoe UI,Arial" font-size="13" font-weight="700">Aegis verified</text>
  <text x="68" y="43" fill="#9aa0ad" font-family="system-ui,Segoe UI,Arial" font-size="11">${esc(r.domain || "")}</text>
  <text x="68" y="57" fill="#6b7280" font-family="system-ui,Segoe UI,Arial" font-size="9">valid to ${esc(until)} · ${r.hidden} checks sealed</text>
</svg>`;
}
