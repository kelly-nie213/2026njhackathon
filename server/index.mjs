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
  res.json({ ok: true, ai: hasKey, breaches: "xposedornot" });
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
  const { orgName, domain, emails, names, phones, breaches, domainSecurity, webSecurity, reputation } = req.body ?? {};
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
    const result = await client.messages.create({
      model: MODEL,
      max_tokens: 16000,
      thinking: { type: "adaptive" },
      output_config: { effort: "medium", format: { type: "json_schema", schema: BREACH_REPORT_SCHEMA } },
      system:
        "You advise small nonprofits with no IT staff. A scan of their public website found staff emails, " +
        "names and phone numbers, checked those emails against known data breaches, checked via live DNS " +
        "whether the domain can be spoofed in email (SPF/DMARC/DKIM), and checked the site's TLS certificate and " +
        "HTTP security headers (CSP/HSTS/X-Frame-Options, etc.). " +
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

// JS Auditor: turn raw static findings into a plain-language summary + plan.
app.post("/api/js-report", async (req, res) => {
  if (!client) return res.status(503).json({ error: "no_api_key" });
  const { orgName, domain, counts, findings } = req.body ?? {};
  try {
    // Group findings by title so the model sees patterns, not 200 raw rows.
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
    const result = await client.messages.create({
      model: MODEL,
      max_tokens: 16000,
      thinking: { type: "adaptive" },
      output_config: { effort: "medium", format: { type: "json_schema", schema: JS_REPORT_SCHEMA } },
      system:
        "You advise small nonprofits with no IT staff or developers. An automated scanner read the JavaScript " +
        "their public website ships to visitors and flagged potential bugs and security risks (hardcoded secrets, " +
        "cross-site-scripting sinks, insecure http requests, leftover debug code, outdated/vulnerable libraries). " +
        "Explain in plain language what these findings mean, which ones genuinely matter and why, and what the real-world " +
        "consequence would be (site defacement, stolen donor data, drained API/cloud accounts). Then give a prioritized, " +
        "jargon-free fix plan they can hand to a volunteer or their web host — highest-impact, easiest wins first. Many " +
        "findings come from third-party widgets the nonprofit can't edit; say so and tell them what to do instead (update " +
        "the plugin, contact the vendor, restrict the key). Be specific to what was actually found; never invent findings.",
      messages: [
        {
          role: "user",
          content:
            `Organization: ${orgName || domain} (domain ${domain}).\n` +
            `Severity counts: ${JSON.stringify(counts || {})}.\n\n` +
            `Findings (grouped):\n${findingLines || "none"}\n\n` +
            `Write a 2-3 sentence summary and 3-6 ordered recommendations.`,
        },
      ],
    });
    res.json(parseJsonContent(result));
  } catch (err) {
    console.error("js-report error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
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
        "You are a calm incident responder helping a panicking volunteer at a small nonprofit that has no IT staff. " +
        "Someone may have just fallen for a scam. Give clear, ordered, plain-language recovery steps they can do right now — " +
        "most urgent and time-sensitive first (stopping money movement and locking accounts before anything else). " +
        "Be reassuring but honest about what's reversible. No jargon, no blame. Write a short calming summary (2-3 sentences) and 4-7 concrete steps.",
      messages: [
        {
          role: "user",
          content:
            `Organization: ${orgName || "a small nonprofit"}.\n` +
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
        "You are a cybersecurity analyst protecting a small nonprofit that has no IT staff. " +
        "You assess whether a message is an AI-generated phishing / social-engineering attempt " +
        "(fake donation requests, vendor-payment redirection, CEO/board impersonation, fake volunteer messages). " +
        "Be decisive but fair. Write every field in plain language a non-technical volunteer can act on. " +
        "redFlags should be concrete and quote/point to specifics. recommendedAction is the single most important next step.",
      messages: [
        {
          role: "user",
          content:
            `Organization: ${orgName || "a small nonprofit"}\n\n` +
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

app.listen(PORT, () => {
  console.log(
    `[aegis-api] listening on http://localhost:${PORT}  ` +
      `(AI ${hasKey ? "enabled" : "disabled — set ANTHROPIC_API_KEY"}; ` +
      `breach lookups via XposedOrNot — no key needed)`
  );
});
