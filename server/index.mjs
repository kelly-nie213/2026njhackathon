// Aegis API proxy — keeps the Anthropic API key server-side.
// Two endpoints power the live-AI features; both degrade gracefully:
// if no ANTHROPIC_API_KEY is set, they return 503 and the client falls back.
import express from "express";
import Anthropic from "@anthropic-ai/sdk";
import { crawlDomain } from "./crawl.mjs";
import { checkEmails } from "./breachlookup.mjs";
import { auditDomainJs } from "./jsaudit.mjs";
import { checkDomainSecurity } from "./domaincheck.mjs";
import { checkWebSecurity } from "./webheaders.mjs";
import { checkReputation } from "./reputation.mjs";
import { issueCredential, deriveBadge, verifyBadge, renderSvg, issuer } from "./badge.mjs";

const PORT = process.env.PORT || 8787;
const MODEL = "claude-opus-4-8";

const app = express();
app.use(express.json({ limit: "1mb" }));

const hasKey = Boolean(process.env.ANTHROPIC_API_KEY);
const client = hasKey ? new Anthropic() : null;

/** Pull the first text block out of a Messages response and JSON.parse it. */
function parseJsonContent(message) {
  const text = message.content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("");
  return JSON.parse(text);
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

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, ai: hasKey, breaches: "xposedornot" });
});

/* ───────────────────── verifiable security-health badge ─────────────────── */

// Issue a signed, selectively-disclosable badge from a completed scan summary.
// The server scores the scan itself so a badge can't be self-awarded.
app.post("/api/badge/issue", (req, res) => {
  const { domain, orgName, summary, reveal } = req.body ?? {};
  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "domain_required" });
  }
  try {
    const credential = issueCredential({ domain, orgName, summary: summary || {} });
    const { badge, token } = deriveBadge(credential, Array.isArray(reveal) && reveal.length ? reveal : undefined);
    res.json({
      grade: credential.grade,
      score: credential.score,
      issuedAt: credential.issuedAt,
      expiresAt: credential.expiresAt,
      kid: credential.kid,
      token,
      badge,
      credential, // full private credential — the org keeps this to re-derive badges
    });
  } catch (err) {
    console.error("badge issue error:", err?.message || err);
    res.status(500).json({ error: "issue_error" });
  }
});

// Verify a badge token against Aegis's public key. Offline-equivalent: callers
// can also fetch /api/badge/pubkey and run the same checks themselves.
app.post("/api/badge/verify", (req, res) => {
  const { token, requireGrade } = req.body ?? {};
  if (!token || typeof token !== "string") {
    return res.status(400).json({ error: "token_required" });
  }
  res.json(verifyBadge(token, requireGrade ? { requireGrade } : {}));
});

// Public issuer key, so any third party can verify badges independently.
app.get("/api/badge/pubkey", (_req, res) => {
  const iss = issuer();
  res.json({ kid: iss.kid, alg: iss.alg, publicKeyPem: iss.publicKeyPem });
});

// Embeddable badge image: <img src="/api/badge/svg?token=..."> on the org's site.
app.get("/api/badge/svg", (req, res) => {
  const token = String(req.query.token || "");
  const requireGrade = req.query.min ? String(req.query.min) : undefined;
  res.setHeader("content-type", "image/svg+xml; charset=utf-8");
  res.setHeader("cache-control", "no-cache");
  res.send(renderSvg(token, requireGrade ? { requireGrade } : {}));
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

// BreachDetector: look each email up against Have I Been Pwned.
app.post("/api/breaches", async (req, res) => {
  const { emails } = req.body ?? {};
  if (!Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({ error: "emails_required" });
  }
  try {
    // Cap high enough to cover a full crawl, low enough to bound run time.
    const out = await checkEmails(emails.slice(0, 100));
    res.json(out);
  } catch (err) {
    console.error("breaches error:", err?.message || err);
    res.status(502).json({ error: "breach_lookup_error" });
  }
});

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
  if (!client) return res.status(503).json({ error: "no_api_key" });
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
        ". Note many findings are in third-party widgets the organization can't edit directly."
      : "Website code audit: no issues (or not run)";
    const result = await client.messages.create({
      model: MODEL,
      max_tokens: 16000,
      thinking: { type: "adaptive" },
      output_config: { effort: "medium", format: { type: "json_schema", schema: BREACH_REPORT_SCHEMA } },
      system:
        "You advise small nonprofits and businesses with no IT staff. A scan of their public website found staff emails, " +
        "names and phone numbers, checked those emails against known data breaches, checked via live DNS " +
        "whether the domain can be spoofed in email (SPF/DMARC/DKIM), checked the site's TLS certificate and " +
        "HTTP security headers (CSP/HSTS/X-Frame-Options, etc.), and statically scanned the JavaScript the site ships. " +
        "Explain, in plain language a volunteer can act on, the concrete RISKS this exposure creates " +
        "(who an attacker could impersonate, what a breached password lets them do, how harvested names/phones enable " +
        "phishing and vishing, and what an unprotected domain lets attackers send), the real-world CONSEQUENCES, and WHO is at risk. " +
        "Then give a prioritized, jargon-free action plan — highest-impact, easiest wins first. " +
        "Be specific to what was actually found; never invent findings.",
      messages: [
        {
          role: "user",
          content:
            `Organization: ${orgName || domain} (domain ${domain}).\n` +
            `Public emails found: ${(emails || []).join(", ") || "none"}\n` +
            `Public names found: ${(names || []).join(", ") || "none"}\n` +
            `Public phone numbers found: ${(phones || []).join(", ") || "none"}\n\n` +
            `Breach exposure per email:\n${breachLines || "none checked"}\n\n` +
            `${domainLines}\n\n` +
            `${webLines}\n\n` +
            `${repLines}\n\n` +
            `${codeLines}\n\n` +
            `Write a 2-3 sentence summary, 3-5 risks, and 4-6 ordered action steps.`,
        },
      ],
    });
    res.json(parseJsonContent(result));
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

// Turn a described security incident into calm, ordered recovery guidance.
app.post("/api/triage", async (req, res) => {
  if (!client) return res.status(503).json({ error: "no_api_key" });
  const { situation, severity, reversibility, orgName } = req.body ?? {};
  if (!situation) return res.status(400).json({ error: "situation_required" });
  try {
    const result = await client.messages.create({
      model: MODEL,
      max_tokens: 16000,
      thinking: { type: "adaptive" },
      output_config: { effort: "medium", format: { type: "json_schema", schema: TRIAGE_SCHEMA } },
      system:
        "You are a calm incident responder helping a panicking volunteer at a small nonprofit or business that has no IT staff. " +
        "Someone may have just fallen for a scam. Give clear, ordered, plain-language recovery steps they can do right now — " +
        "most urgent and time-sensitive first (stopping money movement and locking accounts before anything else). " +
        "Be reassuring but honest about what's reversible. No jargon, no blame. Write a short calming summary (2-3 sentences) and 4-7 concrete steps.",
      messages: [
        {
          role: "user",
          content:
            `Organization: ${orgName || "a small nonprofit or business"}.\n` +
            `Assessed severity: ${severity}. ${reversibility}\n\n` +
            `What happened:\n${situation}`,
        },
      ],
    });
    res.json(parseJsonContent(result));
  } catch (err) {
    console.error("triage error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});

// Analyze a pasted suspicious message for AI-generated phishing.
app.post("/api/phishing", async (req, res) => {
  if (!client) return res.status(503).json({ error: "no_api_key" });
  const { message, orgName } = req.body ?? {};
  if (!message || typeof message !== "string") {
    return res.status(400).json({ error: "message_required" });
  }
  try {
    const result = await client.messages.create({
      model: MODEL,
      max_tokens: 16000,
      thinking: { type: "adaptive" },
      output_config: { effort: "medium", format: { type: "json_schema", schema: PHISHING_SCHEMA } },
      system:
        "You are a cybersecurity analyst protecting a small nonprofit or business that has no IT staff. " +
        "You assess whether a message is an AI-generated phishing / social-engineering attempt " +
        "(fake donation requests, vendor-payment redirection, CEO/board impersonation, fake volunteer messages). " +
        "Be decisive but fair. Write every field in plain language a non-technical volunteer can act on. " +
        "redFlags should be concrete and quote/point to specifics. recommendedAction is the single most important next step.",
      messages: [
        {
          role: "user",
          content:
            `Organization: ${orgName || "a small nonprofit or business"}\n\n` +
            `Analyze this message they received:\n\n"""\n${message.slice(0, 8000)}\n"""`,
        },
      ],
    });
    res.json(parseJsonContent(result));
  } catch (err) {
    console.error("phishing error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});

// Personalized advisor: a grounded chat over the user's actual scan results.
// Guided plan + free-form follow-ups, tailored to the person's role/comfort/budget.
function formatScanContext(ctx = {}, profile = {}) {
  const lines = [];
  lines.push(`Organization: ${ctx.orgName || ctx.domain || "a small nonprofit or business"} (domain ${ctx.domain || "unknown"}).`);
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
  if (!client) return res.status(503).json({ error: "no_api_key" });
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
    const result = await client.messages.create({
      model: MODEL,
      max_tokens: 2000,
      thinking: { type: "adaptive" },
      output_config: { effort: "low" },
      system:
        "You are Aegis, a calm, encouraging cybersecurity advisor for a small nonprofit or business that has no IT staff. " +
        "You are given the real results of a security scan of their website plus some context about the person asking. " +
        "Give specific, prioritized, plain-language advice tailored to THEIR actual findings and THEIR situation " +
        "(role, tech comfort, budget). Always ground answers in the scan results below — reference the specific findings. " +
        "When they ask how to do something, give short numbered steps. Recommend free/low-cost tools when budget is tight. " +
        "Be concise and concrete; no jargon, no blame, never invent findings that aren't in the results.\n\n" +
        formatScanContext(context, profile),
      messages: convo,
    });
    const reply = result.content.filter((b) => b.type === "text").map((b) => b.text).join("").trim();
    res.json({ reply });
  } catch (err) {
    console.error("advisor error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});

app.listen(PORT, () => {
  console.log(
    `[aegis-api] listening on http://localhost:${PORT}  ` +
      `(AI ${hasKey ? "enabled" : "disabled — set ANTHROPIC_API_KEY"}; ` +
      `breach lookups via XposedOrNot — no key needed)`
  );
});
