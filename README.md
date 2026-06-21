# 🛡️ Aegis — Cyber Health Check for Nonprofits

Plain-English cybersecurity tools for small nonprofits — built to tell a volunteer, with no IT
staff, what an attacker could actually do to them and exactly what to do about it.

Built for the Cybersecurity Innovation Hackathon. Target users: small nonprofits (food banks,
donation centers, community orgs) who hold sensitive donor, volunteer, and financial data but
have no one watching for breaches.

## What it does

Three tools, all powered by **real data and analysis**:

1. **Breach Detector** (home) — enter your domain. Aegis crawls your public pages for the staff
   emails, names and phone numbers an attacker would scrape first, then checks each email against
   known data breaches and turns the findings into risks, consequences, and a plain-language
   action plan.
2. **AI Phishing Checker** — paste a suspicious email/text; Claude returns a verdict, the red
   flags it spotted, and the single most important next step.
3. **Incident Triage Wizard** — for when something already happened. A few plain questions
   ("did someone click? was money sent?") → severity, what's still reversible, exactly who to
   notify (with urgency), and ordered recovery steps — with optional AI-personalized guidance.

The angle: fighting **AI-fueled attacks** *with* AI — translating real, public exposure into
consequences and a do-this-next plan a volunteer can follow, not another breach-lookup tool.

## Run it

```bash
npm install
npm run dev      # web → http://localhost:5173, API proxy → :8787
```

Try the **"aylus.org"** link on the Breach Detector for a live demo against a real site.

### Enable the live AI features (optional)

```bash
cp .env.example .env       # then add your ANTHROPIC_API_KEY
```

The breach lookup and crawl need **no key** (they use XposedOrNot's free public API). Without an
Anthropic key the AI features still work: the phishing checker falls back to a built-in heuristic,
and the breach/triage reports use deterministic plain-language plans — so a demo never breaks.

## Stack

- Vite + React + TypeScript · Tailwind CSS v4 · Framer Motion
- **Claude** (`claude-opus-4-8`, adaptive thinking, structured outputs) via a tiny Express proxy
  in [server/index.mjs](server/index.mjs) that keeps the API key server-side
- Live website crawl in [server/crawl.mjs](server/crawl.mjs) (read-only, public pages only) and
  breach lookups via **XposedOrNot** in [server/breachlookup.mjs](server/breachlookup.mjs) — no key needed
- Graceful AI fallbacks in [src/lib/api.ts](src/lib/api.ts) and [src/lib/breach.ts](src/lib/breach.ts)
