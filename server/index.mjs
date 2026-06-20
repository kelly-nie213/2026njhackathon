// Aegis API proxy — keeps the Anthropic API key server-side.
// Two endpoints power the live-AI features; both degrade gracefully:
// if no ANTHROPIC_API_KEY is set, they return 503 and the client falls back.
import express from "express";
import Anthropic from "@anthropic-ai/sdk";

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

const PLAN_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    summary: { type: "string" },
    steps: {
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
  required: ["summary", "steps"],
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

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, ai: hasKey });
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

// Turn raw scan findings into a personalized, plain-language action plan.
app.post("/api/action-plan", async (req, res) => {
  if (!client) return res.status(503).json({ error: "no_api_key" });
  const { orgName, orgType, domain, findings, topConsequence } = req.body ?? {};
  try {
    const result = await client.messages.create({
      model: MODEL,
      max_tokens: 16000,
      thinking: { type: "adaptive" },
      output_config: { effort: "medium", format: { type: "json_schema", schema: PLAN_SCHEMA } },
      system:
        "You advise small nonprofits with no IT staff or security budget. " +
        "Given the results of a cyber health check, produce a prioritized, jargon-free action plan a volunteer can follow. " +
        "Order steps so the highest-impact, easiest wins come first. " +
        "Each step's 'why' must make the stakes concrete for this organization. Keep 'effort' to a short time estimate like '5 min' or '1 hour'.",
      messages: [
        {
          role: "user",
          content:
            `Organization: ${orgName} (${orgType}), domain ${domain}.\n` +
            `Most damaging exposure if leaked: ${topConsequence}\n\n` +
            `Findings:\n` +
            (findings || [])
              .map((f) => `- [${f.severity}] ${f.title}: ${f.detail}`)
              .join("\n") +
            `\n\nWrite a short summary (2-3 sentences) and 4-6 ordered action steps.`,
        },
      ],
    });
    res.json(parseJsonContent(result));
  } catch (err) {
    console.error("action-plan error:", err?.message || err);
    res.status(502).json({ error: "ai_error" });
  }
});

app.listen(PORT, () => {
  console.log(`[aegis-api] listening on http://localhost:${PORT}  (AI ${hasKey ? "enabled" : "disabled — set ANTHROPIC_API_KEY"})`);
});
