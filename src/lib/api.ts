import type { TriageResult } from "./triage";

export interface PhishingVerdict {
  verdict: "likely_phishing" | "suspicious" | "likely_safe";
  confidence: number;
  attackType: string;
  redFlags: string[];
  explanation: string;
  recommendedAction: string;
  source: "ai" | "heuristic";
}

/* ---------- Phishing checker (AI with heuristic fallback) ---------- */

export async function analyzePhishing(
  message: string,
  orgName: string
): Promise<PhishingVerdict> {
  try {
    const res = await fetch("/api/phishing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, orgName }),
    });
    if (res.ok) {
      const data = await res.json();
      return { ...data, source: "ai" as const };
    }
  } catch {
    /* fall through to heuristic */
  }
  return heuristicPhishing(message);
}

const SUSPICIOUS_PATTERNS: { re: RegExp; flag: string; weight: number }[] = [
  { re: /\b(urgent|immediately|right away|asap|act now|expires? (today|soon))\b/i, flag: "Manufactured urgency ('urgent', 'act now') — a classic pressure tactic.", weight: 2 },
  { re: /\b(wire|transfer|gift ?cards?|bitcoin|crypto|payment|invoice|bank details)\b/i, flag: "Asks about money movement (wire, gift cards, bank details).", weight: 3 },
  { re: /\b(new (bank )?account|updated? (our )?(bank|payment|account) (details|info))\b/i, flag: "Requests a change to payment/banking details — the core of vendor-fraud scams.", weight: 3 },
  { re: /\b(confidential|keep this between us|don'?t tell|do not discuss)\b/i, flag: "Demands secrecy — attackers isolate the target so no one double-checks.", weight: 2 },
  { re: /(https?:\/\/[^\s]*(bit\.ly|tinyurl|\.ru|\.top|login|verify|secure-)[^\s]*)/i, flag: "Contains a shortened or look-alike link.", weight: 2 },
  { re: /\b(verify your account|confirm your (password|login|identity)|reset your password)\b/i, flag: "Asks you to verify credentials via a link — credential-harvesting.", weight: 3 },
  { re: /\b(ceo|director|board|treasurer|president)\b/i, flag: "Invokes leadership authority — common in impersonation scams.", weight: 1 },
  { re: /\b(are you (at your desk|available)|quick (favor|task)|need your help)\b/i, flag: "Vague 'quick favor' opener used to start a scam thread.", weight: 2 },
];

function heuristicPhishing(message: string): PhishingVerdict {
  const flags: string[] = [];
  let score = 0;
  for (const p of SUSPICIOUS_PATTERNS) {
    if (p.re.test(message)) {
      flags.push(p.flag);
      score += p.weight;
    }
  }
  const verdict: PhishingVerdict["verdict"] =
    score >= 5 ? "likely_phishing" : score >= 2 ? "suspicious" : "likely_safe";
  const confidence = Math.min(92, 50 + score * 8);

  return {
    verdict,
    confidence,
    attackType:
      score >= 5
        ? "Payment-redirection / impersonation attempt"
        : score >= 2
          ? "Possible social-engineering attempt"
          : "No strong phishing signals detected",
    redFlags: flags.length ? flags : ["No obvious red flags found in the text."],
    explanation:
      flags.length > 0
        ? "This message shows hallmarks of a social-engineering attack. Treat any request involving money, credentials, or secrecy as suspicious until verified through a separate, trusted channel."
        : "Nothing in the text strongly matches common scam patterns — but a clean-looking message can still be fake. When in doubt, verify the sender directly.",
    recommendedAction:
      score >= 2
        ? "Do NOT click links or send anything. Call the supposed sender on a number you already have (not one from this message) to confirm."
        : "If anything feels off, confirm with the sender through a channel you already trust before acting.",
    source: "heuristic",
  };
}

/* ---------- Incident recovery guidance (AI with deterministic fallback) ---------- */

export interface RecoveryGuidance {
  summary: string;
  steps: string[];
  source: "ai" | "fallback";
}

export async function generateRecovery(
  situation: string,
  res: TriageResult,
  orgName: string
): Promise<RecoveryGuidance> {
  try {
    const r = await fetch("/api/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        situation,
        severity: res.severity,
        reversibility: res.reversibility,
        orgName,
      }),
    });
    if (r.ok) {
      const data = await r.json();
      return { ...data, source: "ai" as const };
    }
  } catch {
    /* fall through */
  }
  return {
    source: "fallback",
    summary:
      "Take a breath — here's exactly what to do, in order. Start at the top; the first steps are the time-sensitive ones.",
    steps: res.steps,
  };
}
