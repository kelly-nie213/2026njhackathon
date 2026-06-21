// Aegis API proxy — AI endpoints degrade gracefully:
// Uses Anthropic (claude-opus-4-8) when ANTHROPIC_API_KEY is set,
// falls back to Gemini (gemini-2.0-flash) when GEMINI_API_KEY is set,
// returns 503 when neither is configured and the client's deterministic fallback takes over.
import express from "express";
import Anthropic from "@anthropic-ai/sdk";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { crawlDomain } from "./crawl.mjs";
import { checkEmails } from "./breachlookup.mjs";
import { auditDomainJs } from "./jsaudit.mjs";
import { checkDomainSecurity } from "./domaincheck.mjs";
import { breachBloomFilter } from "./bloomfilter.mjs";
import { breachMerkleTree, verifyProof } from "./merkle.mjs";
import { registerIdentity, issueChallenge, verifyChallenge, getIdentity } from "./tiamstore.mjs";
import { checkWebSecurity } from "./webheaders.mjs";
import { checkReputation } from "./reputation.mjs";

const PORT = process.env.PORT || 8787;

const app = express();
app.use(express.json({ limit: "1mb" }));

// ── AI provider setup ─────────────────────────────────────────────────────────
const anthropicKey = process.env.ANTHROPIC_API_KEY;
const geminiKey    = process.env.GEMINI_API_KEY;

const anthropic = anthropicKey ? new Anthropic({ apiKey: anthropicKey }) : null;
const geminiAI  = geminiKey    ? new GoogleGenerativeAI(geminiKey)       : null;

const hasAi = Boolean(anthropic || geminiAI);
const aiProvider = anthropic ? "anthropic" : geminiAI ? "gemini" : "none";

/**
 * Unified AI call — tries Anthropic first, then Gemini.
 * Both are prompted to return strict JSON; we parse and return the object.
 * @param {string} system  System/instruction prompt
 * @param {string} user    User message
 * @param {object} schema  JSON schema (used for Anthropic structured output; Gemini uses prompt only)
 * @returns {Promise<object>}
 */
async function callAi(system, user, schema) {
  if (anthropic) {
    const result = await anthropic.messages.create({
      model:        "claude-opus-4-8",
      max_tokens:   16000,
      thinking:     { type: "adaptive" },
      output_config: { effort: "medium", format: { type: "json_schema", schema } },
      system,
      messages: [{ role: "user", content: user }],
    });
    const text = result.content
      .filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("");
    return JSON.parse(text);
  }

  if (geminiAI) {
    const model = geminiAI.getGenerativeModel({
      model: "gemini-2.0-flash",
      generationConfig: { responseMimeType: "application/json" },
      systemInstruction: system,
    });
    const result = await model.generateContent(user);
    return JSON.parse(result.response.text());
  }

  throw new Error("no_ai_provider");
}

/** Legacy: pull the first text block out of a raw Anthropic Messages response. */
function parseJsonContent(message) {
  const text = message.content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");
  return JSON.parse(text);
}

/**
 * Multi-turn AI call returning plain text — used for the conversational advisor.
 * @param {string} system  System/instruction prompt
 * @param {Array<{role:string,content:string}>} messages  Conversation history
 * @returns {Promise<string>}
 */
async function callAiConversation(system, messages) {
  if (anthropic) {
    const result = await anthropic.messages.create({
      model:        "claude-opus-4-8",
      max_tokens:   2000,
      thinking:     { type: "adaptive" },
      output_config: { effort: "low" },
      system,
      messages,
    });
    return result.content.filter((b) => b.type === "text").map((b) => b.text).join("").trim();
  }
  if (geminiAI) {
    const model = geminiAI.getGenerativeModel({ model: "gemini-2.0-flash", systemInstruction: system });
    const history = messages.slice(0, -1).map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));
    const lastContent = messages[messages.length - 1].content;
    const chat = model.startChat({ history });
    const result = await chat.sendMessage(lastContent);
    return result.response.text().trim();
  }
  throw new Error("no_ai_provider");
}

const PHISHING_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    verdict: { type: "string", enum: ["likely_phishing", "suspicious", "likely_safe"] },
    confidence: { type: "integer" },
    attackType: { type: "string" },
    redFlags: { type: "array", items: { type: "string" } },
    explanation: { type: "string" },
    recommendedAction: { type: "string" },
  },
  required: ["verdict", "confidence", "attackType", "redFlags", "explanation", "recommendedAction"],
};

const TRIAGE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    summary: { type: "string" },
    steps: { type: "array", items: { type: "string" } },
  },
  required: ["summary", "steps"],
};

const BREACH_REPORT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    summary: { type: "string" },
    risks: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          title: { type: "string" },
          severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
          consequence: { type: "string" },
          whoAtRisk: { type: "array", items: { type: "string" } },
        },
        required: ["title", "severity", "consequence", "whoAtRisk"],
      },
    },
    actions: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          title: { type: "string" },
          why: { type: "string" },
          effort: { type: "string" },
          steps: { type: "array", items: { type: "string" } },
        },
        required: ["title", "why", "effort", "steps"],
      },
    },
  },
  required: ["summary", "risks", "actions"],
};

const JS_REPORT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    summary: { type: "string" },
    recommendations: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          title: { type: "string" },
          why: { type: "string" },
          effort: { type: "string" },
          steps: { type: "array", items: { type: "string" } },
        },
        required: ["title", "why", "effort", "steps"],
      },
    },
  },
  required: ["summary", "recommendations"],
};

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, ai: hasAi, aiProvider, breaches: "xposedornot" });
});

// BreachDetector: crawl a domain for public emails/names/phone numbers.
app.post("/api/crawl", async (req, res) => {
  const { domain } = req.body ?? {};
  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "domain_required" });
  }
  try {
    const result = await crawlDomain(domain);
    res.json(result);
  } catch (err) {
    const msg = err?.message || "crawl_error";
    const code = msg === "invalid_domain" ? 400 : msg === "unreachable" ? 502 : 500;
    console.error("crawl error:", msg);
    res.status(code).json({ error: msg });
  }
});

// BreachDetector: ZKP-compliant breach lookup.
// Accepts { emails, commitments } — commitment[i] is SHA-256(emails[i]) from the client.
// Response contains commitment hashes only — the email is NEVER echoed back.
app.post("/api/breaches", async (req, res) => {
  const { emails, commitments } = req.body ?? {};
  if (!Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({ error: "emails_required" });
  }
  try {
    const out = await checkEmails(emails.slice(0, 100), (commitments || []).slice(0, 100));
    for (const r of out.results) {
      // ZKP oracle cache — keyed by commitment, no email stored.
      commitmentCache.set(r.commitment, { status: r.status, breachCount: r.breachCount });
      // Add ALL commitments to the Merkle tree (proves we processed this one).
      breachMerkleTree.add(r.commitment);
      // Add ONLY breached commitments to the Bloom filter.
      if (r.status === "breached") breachBloomFilter.add(r.commitment);
    }
    res.json(out);
  } catch (err) {
    console.error("breaches error:", err?.message || err);
    res.status(502).json({ error: "breach_lookup_error" });
  }
});

// ZKP oracle: given a commitment hash, return whether a breach exists for it.
// The server re-derives the commitment from its internal breach records and
// answers only "valid/invalid" — the vault is never opened.
// NOTE: this endpoint requires the server to already hold the commitment→email
// mapping from a prior /api/breaches call (stored in the request cache below).
const commitmentCache = new Map(); // commitment → { status, breachCount } — no email stored

app.post("/api/zkp-verify", (req, res) => {
  const { commitment } = req.body ?? {};
  if (!commitment || typeof commitment !== "string") {
    return res.status(400).json({ error: "commitment_required" });
  }
  const record = commitmentCache.get(commitment);
  if (!record) {
    // Unknown commitment — we haven't seen this email before.
    return res.json({ commitment, valid: false, reason: "not_in_vault" });
  }
  res.json({
    commitment,
    valid: true,
    exists: record.status === "breached",
    breachCount: record.breachCount,
    // No email field — the vault stays sealed.
  });
});

// ── Phase 4: Bloom filter ────────────────────────────────────────────────────
// Client downloads the filter (~64KB) and checks SHA-256(email) locally.
// "Definitely not breached" = no server query at all. Vault stays sealed.
app.get("/api/bloom-filter", (_req, res) => {
  res.json(breachBloomFilter.serialize());
});

// ── Phase 5: Merkle tree ─────────────────────────────────────────────────────
// Returns the current Merkle root — a single hash representing all processed commitments.
app.get("/api/merkle-root", (_req, res) => {
  res.json({ root: breachMerkleTree.root, size: breachMerkleTree.size });
});

// Returns a membership proof for a commitment — proves it was processed without
// revealing any other entries.
app.post("/api/merkle-proof", (req, res) => {
  const { commitment } = req.body ?? {};
  if (!commitment) return res.status(400).json({ error: "commitment_required" });
  const proof = breachMerkleTree.getProof(commitment);
  if (!proof) return res.status(404).json({ error: "commitment_not_in_tree" });
  res.json(proof);
});

// Client-side proof verification (server echoes the result — the math is the same
// either way; clients can also run verifyProof() locally with the proof payload).
app.post("/api/merkle-verify", (req, res) => {
  const { leaf, proof, root } = req.body ?? {};
  if (!leaf || !proof || !root) return res.status(400).json({ error: "leaf_proof_root_required" });
  const valid = verifyProof(leaf, proof, root);
  res.json({ valid, leaf, root });
});

// ── Phase 3: TIAM authentication ─────────────────────────────────────────────
// Register a public key — no password, no email, no secret.
app.post("/api/tiam/register", (req, res) => {
  const { publicKeyJwk, organization } = req.body ?? {};
  if (!publicKeyJwk) return res.status(400).json({ error: "publicKeyJwk_required" });
  try {
    const result = registerIdentity(publicKeyJwk, organization);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Issue a one-time challenge for a fingerprint — client signs this with their private key.
app.post("/api/tiam/challenge", (req, res) => {
  const { fingerprint } = req.body ?? {};
  if (!fingerprint) return res.status(400).json({ error: "fingerprint_required" });
  try {
    res.json(issueChallenge(fingerprint));
  } catch (err) {
    const status = err.status || 400;
    res.status(status).json({ error: err.message });
  }
});

// Verify a signed challenge — server checks math only, never sees the private key.
app.post("/api/tiam/verify", async (req, res) => {
  const { fingerprint, signature } = req.body ?? {};
  if (!fingerprint || !signature) return res.status(400).json({ error: "fingerprint_and_signature_required" });
  const result = await verifyChallenge(fingerprint, signature);
  res.json(result);
});

// Look up a registered identity by fingerprint (public info only).
app.get("/api/tiam/identity/:fingerprint", (req, res) => {
  const id = getIdentity(req.params.fingerprint);
  if (!id) return res.status(404).json({ error: "not_found" });
  res.json(id);
});

// ── HIBP Passwords k-anonymity proxy ─────────────────────────────────────────
// TRUE zero-knowledge proof: client sends only the first 5 hex chars of SHA-1(password).
// We proxy to api.pwnedpasswords.com/range/{prefix} and return the suffix list.
// HIBP never learns the full hash; we never learn the full hash; only the client knows.
// Add-Padding header makes all responses the same size → prevents traffic analysis.
app.get("/api/password-range/:prefix", async (req, res) => {
  const { prefix } = req.params;
  if (!/^[0-9A-Fa-f]{5}$/.test(prefix)) {
    return res.status(400).json({ error: "prefix must be exactly 5 hex characters" });
  }
  try {
    const upstream = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix.toUpperCase()}`,
      {
        headers: {
          "User-Agent":   "Aegis-BreachDetector-Hackathon",
          "Add-Padding":  "true", // pads response so all sizes are equal — prevents size-based traffic analysis
        },
        signal: AbortSignal.timeout(10_000),
      }
    );
    if (!upstream.ok) throw new Error("hibp_error");
    const text = await upstream.text();
    res.set("Content-Type", "text/plain").send(text);
  } catch {
    res.status(502).json({ error: "hibp_unavailable" });
  }
});

// ── Phase 2: ZKP oracle ──────────────────────────────────────────────────────
// BreachDetector: live DNS check of email-spoofing protection (SPF/DMARC/DKIM/MX).
app.post("/api/domain-check", async (req, res) => {
  const { domain } = req.body ?? {};
  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "domain_required" });
  }
  try {
    const result = await checkDomainSecurity(domain);
    res.json(result);
  } catch (err) {
    const msg = err?.message || "domain_check_error";
    const code = msg === "invalid_domain" ? 400 : 500;
    console.error("domain-check error:", msg);
    res.status(code).json({ error: msg });
  }
});

// BreachDetector: live check of TLS + HTTP security headers (how the site is served).
app.post("/api/web-security", async (req, res) => {
  const { domain } = req.body ?? {};
  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "domain_required" });
  }
  try {
    const result = await checkWebSecurity(domain);
    res.json(result);
  } catch (err) {
    const msg = err?.message || "web_security_error";
    const code = msg === "invalid_domain" ? 400 : 500;
    console.error("web-security error:", msg);
    res.status(code).json({ error: msg });
  }
});

// BreachDetector: live threat-intel / reputation lookup (URLhaus, OpenPhish, +keys).
app.post("/api/reputation", async (req, res) => {
  const { domain } = req.body ?? {};
  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "domain_required" });
  }
  try {
    const result = await checkReputation(domain);
    res.json(result);
  } catch (err) {
    const msg = err?.message || "reputation_error";
    const code = msg === "invalid_domain" ? 400 : 500;
    console.error("reputation error:", msg);
    res.status(code).json({ error: msg });
  }
});

// BreachDetector: turn raw exposure findings into risks + a plain-language plan.
app.post("/api/breach-report", async (req, res) => {
  if (!hasAi) return res.status(503).json({ error: "no_api_key" });
  const { orgName, domain, emails, names, phones, breaches, domainSecurity, webSecurity, reputation, codeSecurity } = req.body ?? {};
  try {
    const breachLines = (breaches || [])
      .map((b) => `- ${b.email}: ${b.breachCount} breach(es)${b.breaches?.length ? ` (${b.breaches.map((x) => x.title).join(", ")})` : ""}`)
      .join("\n");
    const domainLines = domainSecurity
      ? `Email-spoofing protection (live DNS check) — domain ${domainSecurity.spoofable ? "CAN be spoofed" : "is reasonably protected"}:\n` +
        (domainSecurity.checks || [])
          .map((c) => `- ${c.label} [${c.status}]: ${c.title}`)
          .join("\n")
      : "Email-spoofing protection: not checked";
    const webLines = webSecurity
      ? `Web security headers / TLS (live check) — grade ${webSecurity.grade}; issues found:\n` +
        ((webSecurity.checks || []).length
          ? webSecurity.checks.map((c) => `- ${c.label} [${c.status}]: ${c.title}`).join("\n")
          : "- none (all good)")
      : "Web security headers: not checked";
    const repLines = reputation
      ? reputation.flagged
        ? `Threat-intelligence reputation (live): FLAGGED — ${(reputation.hits || []).map((c) => `${c.label}: ${c.title}`).join("; ")}`
        : "Threat-intelligence reputation (live): not flagged on the sources checked"
      : "Threat-intelligence reputation: not checked";
    const codeLines = codeSecurity
      ? `Website code audit (the JavaScript the site ships): ${codeSecurity.security || 0} security + ${codeSecurity.bug || 0} code-quality issue(s)` +
        (codeSecurity.top?.length ? `. Examples: ${codeSecurity.top.join("; ")}` : "") +
        ". Note many findings are in third-party widgets the nonprofit can't edit directly."
      : "Website code audit: no issues (or not run)";
    const report = await callAi(
      "You advise small nonprofits with no IT staff. A scan of their public website found staff emails, " +
      "names and phone numbers, checked those emails against known data breaches, checked via live DNS " +
      "whether the domain can be spoofed in email (SPF/DMARC/DKIM), checked the site's TLS certificate and " +
      "HTTP security headers (CSP/HSTS/X-Frame-Options, etc.), and statically scanned the JavaScript the site ships. " +
      "Explain, in plain language a volunteer can act on, the concrete RISKS this exposure creates " +
      "(who an attacker could impersonate, what a breached password lets them do, how harvested names/phones enable " +
      "phishing and vishing, and what an unprotected domain lets attackers send), the real-world CONSEQUENCES, and WHO is at risk. " +
      "Then give a prioritized, jargon-free action plan — highest-impact, easiest wins first. " +
      "Be specific to what was actually found; never invent findings. Respond with JSON only.",
      `Organization: ${orgName || domain} (domain ${domain}).\n` +
      `Public emails found: ${(emails || []).join(", ") || "none"}\n` +
      `Public names found: ${(names || []).join(", ") || "none"}\n` +
      `Public phone numbers found: ${(phones || []).join(", ") || "none"}\n\n` +
      `Breach exposure per email:\n${breachLines || "none checked"}\n\n` +
      `${domainLines}\n\n` +
      `${webLines}\n\n` +
      `${repLines}\n\n` +
      `${codeLines}\n\n` +
      `Write a 2-3 sentence summary, 3-5 risks, and 4-6 ordered action steps. ` +
      `Return JSON matching: { summary: string, risks: [{ title, severity, consequence, whoAtRisk }], actions: [{ title, why, effort, steps }] }`,
      BREACH_REPORT_SCHEMA,
    );
    res.json(report);
  } catch (err) {
    console.error("breach-report error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});

// JS Auditor: statically scan the JavaScript a site ships for bugs & risks.
app.post("/api/js-audit", async (req, res) => {
  const { domain } = req.body ?? {};
  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "domain_required" });
  }
  try {
    const result = await auditDomainJs(domain);
    res.json(result);
  } catch (err) {
    const msg = err?.message || "audit_error";
    const code = msg === "invalid_domain" ? 400 : msg === "unreachable" ? 502 : 500;
    console.error("js-audit error:", msg);
    res.status(code).json({ error: msg });
  }
});

// JS Auditor: turn raw static findings into a plain-language summary + plan.
app.post("/api/js-report", async (req, res) => {
  if (!hasAi) return res.status(503).json({ error: "no_api_key" });
  const { orgName, domain, counts, findings } = req.body ?? {};
  try {
    const byTitle = new Map();
    for (const f of (findings || []).slice(0, 120)) {
      const k = `${f.severity}|${f.title}`;
      const g = byTitle.get(k) || { severity: f.severity, title: f.title, detail: f.detail, files: new Set() };
      g.files.add(f.file);
      byTitle.set(k, g);
    }
    const findingLines = [...byTitle.values()]
      .map((g) => `- [${g.severity}] ${g.title} — ${g.files.size} file(s): ${[...g.files].slice(0, 4).join(", ")}. ${g.detail}`)
      .join("\n");
    const report = await callAi(
      "You advise small nonprofits with no IT staff or developers. An automated scanner read the JavaScript " +
      "their public website ships to visitors and flagged potential bugs and security risks (hardcoded secrets, " +
      "cross-site-scripting sinks, insecure http requests, leftover debug code, outdated/vulnerable libraries). " +
      "Explain in plain language what these findings mean, which ones genuinely matter and why, and what the real-world " +
      "consequence would be (site defacement, stolen donor data, drained API/cloud accounts). Then give a prioritized, " +
      "jargon-free fix plan they can hand to a volunteer or their web host — highest-impact, easiest wins first. Many " +
      "findings come from third-party widgets the nonprofit can't edit; say so and tell them what to do instead (update " +
      "the plugin, contact the vendor, restrict the key). Be specific to what was actually found; never invent findings. Respond with JSON only.",
      `Organization: ${orgName || domain} (domain ${domain}).\n` +
      `Severity counts: ${JSON.stringify(counts || {})}.\n\n` +
      `Findings (grouped):\n${findingLines || "none"}\n\n` +
      `Write a 2-3 sentence summary and 3-6 ordered recommendations. ` +
      `Return JSON matching: { summary: string, recommendations: [{ title, why, effort, steps }] }`,
      JS_REPORT_SCHEMA,
    );
    res.json(report);
  } catch (err) {
    console.error("js-report error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});


// Turn a described security incident into calm, ordered recovery guidance.
app.post("/api/triage", async (req, res) => {
  if (!hasAi) return res.status(503).json({ error: "no_api_key" });
  const { situation, severity, reversibility, orgName } = req.body ?? {};
  if (!situation) return res.status(400).json({ error: "situation_required" });
  try {
    const report = await callAi(
      "You are a calm incident responder helping a panicking volunteer at a small nonprofit that has no IT staff. " +
      "Someone may have just fallen for a scam. Give clear, ordered, plain-language recovery steps they can do right now — " +
      "most urgent and time-sensitive first (stopping money movement and locking accounts before anything else). " +
      "Be reassuring but honest about what's reversible. No jargon, no blame. Respond with JSON only.",
      `Organization: ${orgName || "a small nonprofit"}.\n` +
      `Assessed severity: ${severity}. ${reversibility}\n\n` +
      `What happened:\n${situation}\n\n` +
      `Return JSON matching: { summary: string (2-3 calming sentences), steps: string[] (4-7 concrete steps, most urgent first) }`,
      TRIAGE_SCHEMA,
    );
    res.json(report);
  } catch (err) {
    console.error("triage error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});

// Analyze a pasted suspicious message for AI-generated phishing.
app.post("/api/phishing", async (req, res) => {
  if (!hasAi) return res.status(503).json({ error: "no_api_key" });
  const { message, orgName } = req.body ?? {};
  if (!message || typeof message !== "string") {
    return res.status(400).json({ error: "message_required" });
  }
  try {
    const report = await callAi(
      "You are a cybersecurity analyst protecting a small nonprofit that has no IT staff. " +
      "You assess whether a message is an AI-generated phishing / social-engineering attempt " +
      "(fake donation requests, vendor-payment redirection, CEO/board impersonation, fake volunteer messages). " +
      "Be decisive but fair. Write every field in plain language a non-technical volunteer can act on. " +
      "redFlags should be concrete and quote/point to specifics. recommendedAction is the single most important next step. Respond with JSON only.",
      `Organization: ${orgName || "a small nonprofit"}\n\n` +
      `Analyze this message they received:\n\n"""\n${message.slice(0, 8000)}\n"""\n\n` +
      `Return JSON matching: { verdict: "likely_phishing"|"suspicious"|"likely_safe", confidence: 0-100, attackType: string, redFlags: string[], explanation: string, recommendedAction: string }`,
      PHISHING_SCHEMA,
    );
    res.json(report);
  } catch (err) {
    console.error("phishing error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});

// Personalized advisor: a grounded chat over the user's actual scan results.
// Guided plan + free-form follow-ups, tailored to the person's role/comfort/budget.
function formatScanContext(ctx = {}, profile = {}) {
  const lines = [];
  lines.push(`Organization: ${ctx.orgName || ctx.domain || "a small nonprofit"} (domain ${ctx.domain || "unknown"}).`);
  if (profile.role || profile.comfort || profile.budget) {
    lines.push(
      `About the person asking: role = ${profile.role || "unspecified"}; ` +
        `tech comfort = ${profile.comfort || "unspecified"}; budget = ${profile.budget || "unspecified"}.`
    );
  }
  lines.push("");
  lines.push("SCAN RESULTS:");
  lines.push(`- Public emails found: ${ctx.emails ?? 0}; names: ${ctx.names ?? 0}; phones: ${ctx.phones ?? 0}`);
  if (Array.isArray(ctx.breachedEmails) && ctx.breachedEmails.length) {
    lines.push(`- Emails in known breaches:`);
    for (const b of ctx.breachedEmails.slice(0, 12)) {
      lines.push(`    • ${b.email}: ${b.count} breach(es)${b.breaches?.length ? ` (${b.breaches.slice(0, 5).join(", ")})` : ""}`);
    }
  } else {
    lines.push(`- No emails found in known breaches.`);
  }
  if (ctx.domainSecurity) {
    lines.push(`- Email spoofing (DNS): domain is ${ctx.domainSecurity.spoofable ? "SPOOFABLE" : "reasonably protected"}.` +
      (ctx.domainSecurity.issues?.length ? ` Issues: ${ctx.domainSecurity.issues.join("; ")}` : ""));
  }
  if (ctx.webSecurity) {
    lines.push(`- Web security headers / TLS: grade ${ctx.webSecurity.grade}.` +
      (ctx.webSecurity.issues?.length ? ` Issues: ${ctx.webSecurity.issues.join("; ")}` : ""));
  }
  if (ctx.reputation) {
    lines.push(`- Threat-intel reputation: ${ctx.reputation.flagged ? `FLAGGED — ${(ctx.reputation.hits || []).join("; ")}` : "not flagged on the sources checked"}.`);
  }
  if (ctx.code) {
    lines.push(`- Website code audit: ${ctx.code.security || 0} security + ${ctx.code.bug || 0} quality findings.` +
      (ctx.code.top?.length ? ` Top: ${ctx.code.top.slice(0, 6).join("; ")}` : ""));
  }
  if (Array.isArray(ctx.topRisks) && ctx.topRisks.length) {
    lines.push(`- Assessed top risks: ${ctx.topRisks.slice(0, 6).join("; ")}`);
  }
  return lines.join("\n");
}

app.post("/api/advisor", async (req, res) => {
  if (!hasAi) return res.status(503).json({ error: "no_api_key" });
  const { context, profile, messages } = req.body ?? {};
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: "messages_required" });
  }
  try {
    const convo = messages
      .slice(-12)
      .filter((m) => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string")
      .map((m) => ({ role: m.role, content: m.content.slice(0, 4000) }));
    if (convo.length === 0 || convo[0].role !== "user") {
      return res.status(400).json({ error: "messages_required" });
    }
    const systemPrompt =
      "You are Aegis, a calm, encouraging cybersecurity advisor for a small nonprofit that has no IT staff. " +
      "You are given the real results of a security scan of their website plus some context about the person asking. " +
      "Give specific, prioritized, plain-language advice tailored to THEIR actual findings and THEIR situation " +
      "(role, tech comfort, budget). Always ground answers in the scan results below — reference the specific findings. " +
      "When they ask how to do something, give short numbered steps. Recommend free/low-cost tools when budget is tight. " +
      "Be concise and concrete; no jargon, no blame, never invent findings that aren't in the results.\n\n" +
      formatScanContext(context, profile);
    const reply = await callAiConversation(systemPrompt, convo);
    res.json({ reply });
  } catch (err) {
    console.error("advisor error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});

app.listen(PORT, () => {
  console.log(
    `[aegis-api] listening on http://localhost:${PORT}  ` +
      `(AI ${hasAi ? `enabled via ${aiProvider}` : "disabled — set ANTHROPIC_API_KEY or GEMINI_API_KEY"}; ` +
      `breach lookups via XposedOrNot — no key needed)`
  );
});
