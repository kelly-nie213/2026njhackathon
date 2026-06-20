/* Incident triage — guided Q&A → severity, reversibility, who to notify, next steps.
   Fully deterministic so it always works; the screen can optionally enrich the
   recovery steps with AI. */

export type Severity = "low" | "medium" | "high" | "critical";

export interface TriageQuestion {
  id: string;
  prompt: string;
  help?: string;
  multi?: boolean;
  options: { value: string; label: string; hint?: string }[];
}

export type Answers = Record<string, string[]>;

export const QUESTIONS: TriageQuestion[] = [
  {
    id: "what",
    prompt: "What happened? Select everything that applies.",
    help: "Best guess is fine — you can pick more than one.",
    multi: true,
    options: [
      { value: "clicked", label: "Clicked a link in a suspicious message" },
      { value: "credentials", label: "Typed a password, login, or 2FA code after clicking" },
      { value: "money-sent", label: "Sent money or made a payment" },
      { value: "details-changed", label: "Changed bank / payment details on someone's request" },
      { value: "attachment", label: "Opened an attachment" },
      { value: "replied", label: "Replied with personal or organization info" },
      { value: "unsure", label: "Not sure — something just feels off" },
    ],
  },
  {
    id: "account",
    prompt: "Which account or system was involved?",
    multi: false,
    options: [
      { value: "email", label: "Staff email", hint: "the master key to everything else" },
      { value: "bank", label: "Bank / payment processor" },
      { value: "donor", label: "Donor or fundraising platform" },
      { value: "social", label: "Social media" },
      { value: "website", label: "Website / admin login" },
      { value: "other", label: "Something else" },
      { value: "unsure", label: "Not sure" },
    ],
  },
  {
    id: "credentials",
    prompt: "Did you type a password, login, or verification code?",
    multi: false,
    options: [
      { value: "yes", label: "Yes" },
      { value: "no", label: "No" },
      { value: "unsure", label: "Not sure" },
    ],
  },
  {
    id: "money",
    prompt: "Was any money sent, or were payment details changed?",
    multi: false,
    options: [
      { value: "sent", label: "Yes — money was sent" },
      { value: "details", label: "Yes — bank / payment details were changed" },
      { value: "no", label: "No money or details involved" },
    ],
  },
  {
    id: "timing",
    prompt: "When did this happen?",
    multi: false,
    options: [
      { value: "hour", label: "Within the last hour" },
      { value: "today", label: "Earlier today" },
      { value: "week", label: "This week" },
      { value: "older", label: "Longer ago" },
    ],
  },
  {
    id: "mfa",
    prompt: "Is two-factor authentication (MFA) turned on for that account?",
    help: "MFA is the extra code/app prompt after your password.",
    multi: false,
    options: [
      { value: "yes", label: "Yes" },
      { value: "no", label: "No" },
      { value: "unsure", label: "Not sure" },
    ],
  },
];

export interface Notify {
  who: string;
  why: string;
  urgent: boolean;
}

export interface TriageResult {
  severity: Severity;
  severityNote: string;
  reversibility: string;
  reversible: "likely" | "partial" | "hard";
  notify: Notify[];
  steps: string[];
}

const has = (a: Answers, id: string, v: string) => (a[id] ?? []).includes(v);
const val = (a: Answers, id: string) => (a[id] ?? [])[0];

export function triage(a: Answers): TriageResult {
  let score = 0;
  const account = val(a, "account");

  if (has(a, "money", "sent") || has(a, "what", "money-sent")) score += 42;
  if (has(a, "money", "details") || has(a, "what", "details-changed")) score += 30;
  if (has(a, "what", "credentials") || val(a, "credentials") === "yes") {
    score += 24;
    if (account === "bank") score += 16;
    if (account === "email") score += 16; // email resets every other password
    if (account === "donor") score += 8;
  }
  if (val(a, "credentials") === "unsure") score += 8;
  if (has(a, "what", "attachment")) score += 16;
  if (has(a, "what", "replied")) score += 10;
  if (has(a, "what", "clicked")) score += 8;
  if (val(a, "mfa") === "no") score += 10;
  if (val(a, "mfa") === "unsure") score += 5;
  if (val(a, "timing") === "older" || val(a, "timing") === "week") score += 5;

  const severity: Severity =
    score >= 55 ? "critical" : score >= 34 ? "high" : score >= 15 ? "medium" : "low";

  const severityNote =
    severity === "critical"
      ? "This needs action in the next few minutes, not later today."
      : severity === "high"
        ? "Treat this as time-sensitive — act today, ideally now."
        : severity === "medium"
          ? "Not an emergency, but don't let it sit — lock things down today."
          : "Low risk based on your answers — a few quick checks and you're likely fine.";

  // Reversibility
  let reversible: TriageResult["reversible"] = "likely";
  let reversibility =
    "Likely contained. Changing the password and turning on MFA now should close the door.";
  if (has(a, "money", "sent") || has(a, "what", "money-sent")) {
    reversible = "hard";
    reversibility =
      "Time-critical. Sent funds are often only recoverable if your bank acts within hours — call them immediately. After that, recovery is unlikely.";
  } else if (has(a, "money", "details") || has(a, "what", "details-changed")) {
    reversible = "partial";
    reversibility =
      "Reversible if caught before the next payment runs. Revert the details and warn anyone who might pay the fake account.";
  } else if (has(a, "what", "credentials") || val(a, "credentials") === "yes") {
    reversible = "partial";
    reversibility =
      "Reversible if you act before the attacker logs in: change the password and enable MFA now, then check for changes they may have already made.";
  }

  // Who to notify
  const notify: Notify[] = [];
  if (has(a, "money", "sent") || has(a, "what", "money-sent")) {
    notify.push({ who: "Your bank / payment processor", why: "Only they can attempt to stop or claw back the transfer — minutes matter.", urgent: true });
    notify.push({ who: "FBI IC3 (ic3.gov)", why: "Report the fraud; for wires there's a recovery process that works best within 72 hours.", urgent: true });
  }
  if (has(a, "money", "details") || has(a, "what", "details-changed")) {
    notify.push({ who: "Anyone who pays you (donors, funders, vendors)", why: "Warn them not to use new bank details until you confirm them by phone.", urgent: true });
  }
  if (account === "email" && (has(a, "what", "credentials") || val(a, "credentials") === "yes")) {
    notify.push({ who: "Your email provider (Google / Microsoft) admin", why: "Force a sign-out, reset the password, and check for forwarding rules the attacker may have added.", urgent: true });
  }
  if (account === "bank" && (has(a, "what", "credentials") || val(a, "credentials") === "yes")) {
    notify.push({ who: "Your bank's fraud line", why: "Lock the account and watch for unauthorized transactions.", urgent: true });
  }
  if (account === "donor") {
    notify.push({ who: "Your donor-platform support", why: "They can secure the account and tell you what donor data was accessible.", urgent: severity !== "low" });
  }
  if (severity === "high" || severity === "critical") {
    notify.push({ who: "Your board / leadership", why: "They need to know early — and may have a duty to act on donor-data exposure.", urgent: false });
  }
  if (notify.length === 0) {
    notify.push({ who: "A second staff member or trusted volunteer", why: "A second set of eyes helps confirm whether anything actually happened.", urgent: false });
  }

  // Steps (ordered, plain language)
  const steps: string[] = [];
  if (has(a, "money", "sent") || has(a, "what", "money-sent")) {
    steps.push("Call your bank's fraud line right now and ask them to recall/stop the payment.");
    steps.push("Do not wait for email replies — phone is faster and the window is short.");
  }
  if (has(a, "money", "details") || has(a, "what", "details-changed")) {
    steps.push("Revert the payment details to the known-good ones and confirm the real ones by phone.");
  }
  if (has(a, "what", "credentials") || val(a, "credentials") === "yes") {
    steps.push("Change the password on that account immediately — and anywhere you reused it.");
    steps.push("Turn on two-factor authentication (MFA) so a stolen password isn't enough.");
    if (account === "email") {
      steps.push("Check your email settings for new forwarding rules or filters and delete any you didn't create.");
    }
  }
  if (has(a, "what", "attachment")) {
    steps.push("Disconnect that device from the internet and run a full antivirus scan before using it again.");
  }
  steps.push("Write down what happened, when, and what you clicked — a short timeline helps anyone you call.");
  steps.push("Tell the rest of your team so no one else falls for the same message.");

  return { severity, severityNote, reversibility, reversible, notify, steps };
}

export const SEVERITY_STYLE: Record<Severity, { label: string; color: string; bg: string }> = {
  low: { label: "Low", color: "var(--color-risk-low)", bg: "rgba(52,211,153,0.14)" },
  medium: { label: "Medium", color: "var(--color-risk-med)", bg: "rgba(251,191,36,0.14)" },
  high: { label: "High", color: "var(--color-risk-high)", bg: "rgba(251,113,133,0.14)" },
  critical: { label: "Critical", color: "var(--color-risk-crit)", bg: "rgba(244,63,94,0.16)" },
};
