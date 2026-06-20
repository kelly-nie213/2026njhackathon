# 🛡️ Aegis — Cyber Health Check for Nonprofits

A 2-minute cyber health check that tells a small nonprofit — in plain English — what an
AI attacker could do to them, and exactly what to do about it.

Built for the Cybersecurity Innovation Hackathon. Target users: small nonprofits with no
dedicated IT staff (food banks, donation centers, community orgs) who hold sensitive donor,
volunteer, and financial data but have no one watching for breaches.

## What it does

1. **Onboarding** — enter org name, domain, and a few staff emails.
2. **Scan** — checks domain spoofing protection, breached credentials, dark-web mentions, and
   AI-phishing susceptibility.
3. **Health Check Dashboard**
   - **Risk score** (deliberately de-emphasized — a number, not a verdict)
   - **Consequence map** ⭐ — an interactive "blast radius" graph showing how one leak cascades
     into others, with plain-language "what happens if this leaks" for every data type
   - **Most likely attack** + who's at risk
   - **Findings** with evidence
   - **Plain-language action plan** — prioritized, jargon-free, "do these in order"
     (one click to **personalize it with Claude** for your exact findings)
4. **AI Phishing Checker** — paste a suspicious email/text; Claude returns a verdict,
   the red flags it spotted, and the single most important next step.
5. **Incident Triage Wizard** — for when something already happened. A few plain questions
   ("did someone click? was money sent?") → severity, what's still reversible, exactly who to
   notify (with urgency), and ordered recovery steps — with optional AI-personalized guidance.

The novel angle: fighting **AI-fueled attacks** *with* AI — translating technical exposure into
consequences and a do-this-next plan a volunteer can follow, not another breach-lookup tool.

## Run it

```bash
npm install
npm run dev      # web → http://localhost:5173, API proxy → :8787
```

Try the **"sample food bank"** link on the landing page for an instant demo.

### Enable the live AI features (optional)

```bash
cp .env.example .env       # then add your ANTHROPIC_API_KEY
```

Without a key, the app still works end to end: the phishing checker falls back to a built-in
heuristic and the action plan uses the deterministic one — so a demo never breaks on stage.

## Stack

- Vite + React + TypeScript · Tailwind CSS v4 · Recharts · Framer Motion
- **Claude** (`claude-opus-4-8`, adaptive thinking, structured outputs) via a tiny Express proxy
  in [server/index.mjs](server/index.mjs) that keeps the API key server-side
- Deterministic mock scan engine in [src/lib/scan.ts](src/lib/scan.ts) — same domain always
  produces the same result, so the demo is repeatable
- Graceful AI fallbacks in [src/lib/api.ts](src/lib/api.ts)

## Status / roadmap

- ✅ **Phase 1:** end-to-end onboarding → scan → dashboard with mock data
- ✅ **Phase 2:** live Claude integration — AI action-plan generation + paste-an-email phishing
  analyzer, with graceful fallback so the demo works without a key
- ✅ **Phase 3:** incident triage wizard (deterministic severity/reversibility/notify + ordered
  steps, plus optional AI-personalized recovery guidance)
