import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";

/* ════════════════════════════════════════
   DATA
════════════════════════════════════════ */

const STATS = [
  { num: 68,   decimals: 0, prefix: "",  suffix: "%",  label: "of nonprofits and small businesses experienced a cyberattack or breach" },
  { num: 1.54, decimals: 2, prefix: "$", suffix: "M",  label: "average ransomware payment in 2023" },
  { num: 277,  decimals: 0, prefix: "",  suffix: "",   label: "days average time to detect a breach" },
  { num: 88,   decimals: 0, prefix: "",  suffix: "%",  label: "of all breaches start with human error" },
];

type Severity = "critical" | "high" | "medium";

interface Pillar {
  id: number;
  title: string;
  severity: Severity;
  stat: string;
  statLabel: string;
  what: string;
  scenario: string;
  connectedTo: number[];
  tips: string[];
  quickWin: string;
  deepDive: string;
}

const PILLARS: Pillar[] = [
  {
    id: 1,
    title: "Weak Password Hygiene",
    severity: "critical",
    stat: "81%",
    statLabel: "of breaches involve stolen or weak passwords",
    what: "Reusing the same password across accounts, using simple guessable phrases, or storing credentials in a shared spreadsheet means one single compromise cascades into total exposure across every platform you use.",
    scenario: "A volunteer signs up for a food bank newsletter with the same password they use for the organization's donor CRM. That newsletter service is breached. Attackers try the leaked credentials on your CRM — and walk right in.",
    connectedTo: [2, 6, 7],
    tips: [
      "Use a password manager (Bitwarden is free and open source)",
      "Every single account must have a unique, randomly generated password",
      "Check haveibeenpwned.com right now — your email may already be in a breach",
    ],
    quickWin: "Install Bitwarden (free) this afternoon. Import your existing passwords and let it generate new unique ones for each account over the next week.",
    deepDive: "Credential stuffing attacks are fully automated. After any large breach, attackers run software that tests stolen username/password combos against thousands of other sites simultaneously. If you've reused a password anywhere, it will eventually be tried everywhere. A password manager solves this completely — one strong master password protects everything else.",
  },
  {
    id: 2,
    title: "No Multi-Factor Authentication",
    severity: "critical",
    stat: "99.9%",
    statLabel: "of automated account attacks are stopped by MFA",
    what: "A password alone is a single lock on your door. Multi-factor authentication (MFA) adds a second lock that requires physical proof — a code from your phone, an authenticator app, or a hardware key. Without it, a stolen password gives instant, total access.",
    scenario: "Your executive director's email password is leaked in a LinkedIn breach. That same night, attackers log in, read months of donor correspondence, then send convincing wire-transfer requests to your board members — all before anyone notices.",
    connectedTo: [1, 6, 7],
    tips: [
      "Enable MFA on email first — it controls everything else (password resets, etc.)",
      "Use an authenticator app (Google Authenticator, Authy) rather than SMS codes",
      "Require MFA for anyone with access to donor data, finances, or administrative accounts",
    ],
    quickWin: "Right now, enable MFA on your primary email. It takes under 5 minutes and immediately blocks 99.9% of automated attacks.",
    deepDive: "SMS-based MFA is better than nothing, but SIM-swapping attacks let sophisticated attackers intercept text codes. Authenticator apps (TOTP) generate codes locally on your phone and can't be intercepted over the network. Hardware keys (like a YubiKey) are the gold standard but any MFA is dramatically better than none.",
  },
  {
    id: 3,
    title: "Outdated Computers & Unpatched Software",
    severity: "high",
    stat: "60%",
    statLabel: "of breaches exploit vulnerabilities with patches already available",
    what: "Every unpatched system is a known-vulnerability advertisement. Attackers use automated scanners to find computers running old operating systems, unupdated WordPress plugins, or legacy donor databases — then exploit published security holes that were fixed months ago.",
    scenario: "Your website runs a WordPress plugin that hasn't been updated in 18 months. A critical security vulnerability in that plugin was published publicly three months ago. Automated bots find and exploit it, installing a backdoor that quietly harvests visitor data for weeks.",
    connectedTo: [5, 6],
    tips: [
      "Enable automatic updates on all computers, phones, tablets, and routers",
      "Build an asset inventory — list every device and software version so nothing gets overlooked",
      "Replace any device running Windows 10 or earlier that can no longer receive security updates",
    ],
    quickWin: "Go to Settings → Windows Update (or System Preferences → Software Update on Mac) on every staff computer today and make sure automatic updates are on.",
    deepDive: "The WannaCry ransomware attack of 2017 infected 200,000 machines in 150 countries — but it exploited a vulnerability that Microsoft had patched two months earlier. Every unpatched machine is vulnerable to attacks that were already solved. Patching is the single highest-ROI security action you can take.",
  },
  {
    id: 4,
    title: "Lack of Robust Backups",
    severity: "critical",
    stat: "3-2-1",
    statLabel: "the backup rule almost no nonprofit or small business actually follows",
    what: "Ransomware encrypts everything it can reach — including cloud folders synced to an infected computer. Without an offline or air-gapped backup, you pay the ransom or lose everything permanently. The 3-2-1 rule: 3 copies of data, on 2 different media types, with 1 stored offsite or offline.",
    scenario: "Ransomware executes at 11pm on a Friday. By Saturday morning, your donor list, grant history, financial records, and program files are encrypted. Your cloud backup synced automatically — and is also encrypted. Without a clean offline backup, you face paying $50,000–$500,000 or rebuilding from scratch.",
    connectedTo: [5, 6],
    tips: [
      "Follow the 3-2-1 rule: 3 copies, 2 types of media, 1 offsite/offline",
      "Test your backups quarterly by actually restoring a file — untested backups don't count",
      "Ensure at least one backup copy cannot be reached from a compromised computer (offline or versioned cloud with immutability)",
    ],
    quickWin: "Set up Backblaze Personal Backup ($9/month per computer). It keeps 30 days of file versions and stores data offsite — a real backup, not just a cloud sync.",
    deepDive: "Cloud sync (Dropbox, OneDrive, Google Drive) is NOT a backup. When ransomware encrypts your local files, the encrypted versions sync to the cloud within minutes, overwriting your good copies. True backups are versioned (you can restore from before the infection), and at least one copy is stored where ransomware cannot reach it.",
  },
  {
    id: 5,
    title: "No Modern Security Protections",
    severity: "high",
    stat: "94%",
    statLabel: "of malware is delivered by email — basic filtering stops most of it",
    what: "Running with no endpoint protection, no email filtering, no DNS firewall, and no web filtering is the digital equivalent of leaving every door, window, and fire exit unlocked. Modern security tools are cheap or free and block the vast majority of automated attacks before they reach a human.",
    scenario: "A staff member receives an invoice PDF attachment that looks legitimate. They open it. A macro executes, installing keylogger malware that silently records all passwords typed over the next two weeks — including the bank login used for payroll.",
    connectedTo: [3, 7],
    tips: [
      "Enable Microsoft Defender (free, already on Windows 10/11) or install Malwarebytes Free",
      "Use Google Workspace or Microsoft 365 for email — their built-in filtering catches the majority of malicious attachments",
      "Enable Cloudflare Gateway (free) as a DNS firewall to block known malicious domains",
    ],
    quickWin: "Enable Microsoft Defender on every Windows machine right now via Windows Security settings. It's already installed and just needs to be turned on.",
    deepDive: "Endpoint Detection & Response (EDR) tools go beyond traditional antivirus by watching for suspicious behavior rather than just known malware signatures. Products like Microsoft Defender for Business ($3/user/month) are affordable for nonprofits and small businesses and provide enterprise-grade protection. The Cybersecurity and Infrastructure Security Agency (CISA) offers free cybersecurity resources specifically for nonprofits and small businesses.",
  },
  {
    id: 6,
    title: "Poor IT Procedures & Governance",
    severity: "high",
    stat: "277 days",
    statLabel: "average time to detect a breach — poor procedures extend this dramatically",
    what: "No formal offboarding process means departed staff retain access indefinitely. Shared logins make it impossible to audit who did what. No incident response plan means chaotic, expensive decision-making during a crisis rather than calm, practiced execution.",
    scenario: "A program coordinator leaves for a competing organization. Six months later, they still have admin access to your Salesforce CRM, your email list, and your Google Drive — because no one ran an offboarding checklist. They export your full donor list before you notice.",
    connectedTo: [1, 2, 3, 4],
    tips: [
      "Create and follow a 30-minute offboarding checklist: revoke all account access the day someone leaves",
      "Centralize identity through Google Workspace or Microsoft 365 — one place to provision and deprovision access",
      "Write a one-page incident response plan: who to call, what to do in the first hour of a suspected breach",
    ],
    quickWin: "Right now, list every person with login access to your critical systems. For anyone who left in the last 12 months, check if their access is still active and revoke it.",
    deepDive: "The Principle of Least Privilege means users should only have access to what they strictly need for their role. Your volunteer who manages social media shouldn't have access to your donor database. Role-based access control (RBAC) sounds complex but is built into every major platform and takes an afternoon to configure correctly.",
  },
  {
    id: 7,
    title: "No Security Awareness Training",
    severity: "critical",
    stat: "88%",
    statLabel: "of all data breaches are caused by human error — training is the highest-ROI defense",
    what: "Staff who can't recognize phishing emails, social engineering phone calls, or Business Email Compromise (BEC) attacks are the most exploited vulnerability in any organization — regardless of how good the technology protections are. One click undoes everything else.",
    scenario: "A new volunteer receives an email that appears to be from the Executive Director: 'I'm in a meeting and need you to buy $1,500 in Amazon gift cards for a donor event. Keep it quiet until I announce it.' Wanting to help and not wanting to bother a busy leader, they comply. The money is gone.",
    connectedTo: [1, 2, 5],
    tips: [
      "Run a free simulated phishing test with your team (KnowBe4 offers a free phishing security test)",
      "Establish a hard 'call to verify' rule: any financial request received via email must be confirmed by phone before action",
      "Run a 30-minute security awareness session quarterly — real examples from recent nonprofit and small business attacks are more memorable than abstract theory",
    ],
    quickWin: "Send your team one real-world phishing example this week (search 'small business BEC phishing example') with an explanation of what makes it suspicious. Then establish the 'call to verify' rule for all financial requests.",
    deepDive: "Business Email Compromise (BEC) attacks cost $2.7 billion in 2022 alone — more than ransomware. They require zero technical sophistication: an attacker registers a look-alike domain or hacks a real email account and simply asks for money or data. The only defense is a trained human who pauses, questions, and verifies by phone before acting.",
  },
];

const PERSONAL_TIPS = [
  { tip: "Use a password manager", detail: "Bitwarden (free) or 1Password — never reuse a password", icon: "key" },
  { tip: "Enable MFA on everything", detail: "Start with email, then banking, then everything else", icon: "shield" },
  { tip: "Update immediately", detail: "When your phone or computer says 'update available', do it today, not next week", icon: "refresh" },
  { tip: "Pause before you click", detail: "Urgency + unusual request = almost certainly a scam. Call to verify.", icon: "cursor" },
  { tip: "Use a VPN on public Wi-Fi", detail: "Coffee shops, airports, hotels — always use a VPN (Mullvad, ProtonVPN)", icon: "wifi" },
  { tip: "Back up your personal data", detail: "Photos, documents — use an external drive AND cloud backup", icon: "cloud" },
  { tip: "Lock your screens", detail: "Auto-lock after 2 minutes on all devices, every time, everywhere", icon: "lock" },
  { tip: "Check your accounts", detail: "Review bank and credit card statements weekly — catch fraud fast", icon: "eye" },
] as const;

const ORG_TIPS = [
  { tip: "Write an offboarding checklist", detail: "Revoke all access the day someone leaves — email, CRM, Slack, everything", icon: "list" },
  { tip: "Map your data", detail: "Know where donor PII lives: which databases, cloud drives, spreadsheets", icon: "map" },
  { tip: "Upgrade to Microsoft 365 or Google Workspace", detail: "Built-in email filtering, MFA, device management — worth every dollar", icon: "building" },
  { tip: "Write a one-page incident response plan", detail: "Who to call, what to do first, who has authority to act — before you need it", icon: "doc" },
  { tip: "Get cyber insurance", detail: "Many nonprofits and small businesses qualify for affordable policies that cover breach response costs", icon: "shield" },
  { tip: "Quarterly security check-in", detail: "30-minute team meeting: review recent phishing examples and remind of procedures", icon: "calendar" },
  { tip: "Enforce MFA org-wide", detail: "Require it in your Google/Microsoft admin console — not optional", icon: "key" },
  { tip: "Test your backups", detail: "Quarterly fire drill: restore a file from backup to prove it actually works", icon: "refresh" },
] as const;

/* ════════════════════════════════════════
   QUIZ DATA
════════════════════════════════════════ */

interface QuizQ {
  id: number;
  scenario: string;
  pillarId: number;
  options: { label: string; text: string }[];
  correct: string;
  explanation: string;
}

const QUIZ: QuizQ[] = [
  {
    id: 1,
    scenario: "Your ED sends an email from their real address asking you to urgently wire $3,500 to a new vendor. What do you do?",
    pillarId: 7,
    options: [
      { label: "A", text: "Wire the money — it's from their real address" },
      { label: "B", text: "Reply to the email asking for written confirmation" },
      { label: "C", text: "Call the ED on their personal number to verify before doing anything" },
      { label: "D", text: "Google the vendor to check if they exist, then send" },
    ],
    correct: "C",
    explanation: "Email can be hacked or spoofed. Always verify financial requests by phone on a number you already have — never one from the email. This is Business Email Compromise (BEC), the #1 fraud targeting nonprofits and small businesses.",
  },
  {
    id: 2,
    scenario: "You're onboarding five new volunteers who need access to your donor CRM. What's the safest approach?",
    pillarId: 1,
    options: [
      { label: "A", text: "Create one shared login everyone uses — simpler to manage" },
      { label: "B", text: "Each volunteer gets their own login with MFA enabled" },
      { label: "C", text: "Email each volunteer the password so they have it handy" },
      { label: "D", text: "Use the same password as your main email for convenience" },
    ],
    correct: "B",
    explanation: "Shared logins can't be audited and one breach exposes everyone. Individual logins + MFA means a stolen password alone can't grant access, and you can revoke exactly one person when needed.",
  },
  {
    id: 3,
    scenario: "Ransomware encrypts all your files at 3am. Which backup strategy actually saves your data?",
    pillarId: 4,
    options: [
      { label: "A", text: "Google Drive synced live from your computer" },
      { label: "B", text: "External hard drive always plugged into the computer" },
      { label: "C", text: "Automated daily backup to a versioned cloud service + one offline copy" },
      { label: "D", text: "Monthly USB backup kept in your desk drawer" },
    ],
    correct: "C",
    explanation: "Live-synced cloud mirrors the encrypted files within minutes — overwriting your good copies. Always-plugged-in drives get encrypted too. Monthly USB means losing 30 days of data. Only versioned, offsite backups survive ransomware.",
  },
  {
    id: 4,
    scenario: "A program coordinator left your org last month. What should have happened on their last day?",
    pillarId: 6,
    options: [
      { label: "A", text: "Nothing — they left on good terms and signed an NDA" },
      { label: "B", text: "Changed the office Wi-Fi password" },
      { label: "C", text: "Revoked all access: email, CRM, Slack, cloud drives — everything" },
      { label: "D", text: "Asked them to delete work files from their personal device" },
    ],
    correct: "C",
    explanation: "Former staff are among the top sources of data incidents — not always malicious, but always a risk. An offboarding checklist that revokes all system access on the last day is the only reliable protection.",
  },
  {
    id: 5,
    scenario: "Which MFA method provides the strongest protection for your staff email accounts?",
    pillarId: 2,
    options: [
      { label: "A", text: "SMS text code sent to a phone number" },
      { label: "B", text: "One-time code sent to your email inbox" },
      { label: "C", text: "Authenticator app (Google Authenticator / Authy) generating a 6-digit code" },
      { label: "D", text: "Security questions — mother's maiden name, first pet, etc." },
    ],
    correct: "C",
    explanation: "SMS can be intercepted via SIM-swapping. Email codes are useless if email is what's being hacked. Security questions are easily guessed. Authenticator apps generate codes locally — no network interception possible.",
  },
];

/* ════════════════════════════════════════
   ANIMATED COUNTER
════════════════════════════════════════ */

function useCountUp(end: number, decimals = 0, duration = 1400) {
  const [count, setCount] = useState(0);
  const started = useRef(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started.current) {
          started.current = true;
          const startTime = performance.now();
          const tick = (now: number) => {
            const t = Math.min((now - startTime) / duration, 1);
            const eased = 1 - Math.pow(1 - t, 3);
            setCount(parseFloat((eased * end).toFixed(decimals)));
            if (t < 1) requestAnimationFrame(tick);
          };
          requestAnimationFrame(tick);
        }
      },
      { threshold: 0.5 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [end, decimals, duration]);

  return { count, ref };
}

function AnimatedStat({ stat }: { stat: typeof STATS[0] }) {
  const { count, ref } = useCountUp(stat.num, stat.decimals);
  return (
    <div ref={ref} className="text-center">
      <div className="text-3xl font-extrabold bg-gradient-to-r from-brand-300 to-accent-400 bg-clip-text text-transparent tabular-nums">
        {stat.prefix}{count.toFixed(stat.decimals)}{stat.suffix}
      </div>
      <div className="mt-1 text-[11px] leading-snug text-muted">{stat.label}</div>
    </div>
  );
}

/* ════════════════════════════════════════
   TIP ICONS
════════════════════════════════════════ */

function TipIcon({ name }: { name: string }) {
  const c = { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  switch (name) {
    case "key":      return <svg {...c}><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3"/></svg>;
    case "shield":   return <svg {...c}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
    case "refresh":  return <svg {...c}><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/></svg>;
    case "cursor":   return <svg {...c}><path d="m4 4 7.07 17 2.51-7.39L21 11.07z"/></svg>;
    case "wifi":     return <svg {...c}><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><circle cx="12" cy="20" r="1" fill="currentColor"/></svg>;
    case "cloud":    return <svg {...c}><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>;
    case "lock":     return <svg {...c}><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>;
    case "eye":      return <svg {...c}><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>;
    case "list":     return <svg {...c}><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>;
    case "map":      return <svg {...c}><polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/></svg>;
    case "building": return <svg {...c}><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>;
    case "doc":      return <svg {...c}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>;
    case "calendar": return <svg {...c}><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>;
    default:         return <svg {...c}><circle cx="12" cy="12" r="10"/></svg>;
  }
}

/* ════════════════════════════════════════
   SEVERITY META
════════════════════════════════════════ */

const SEV: Record<Severity, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "CRITICAL", color: "#ff453a", bg: "rgba(255,69,58,0.12)",  border: "rgba(255,69,58,0.30)" },
  high:     { label: "HIGH",     color: "#ff9f0a", bg: "rgba(255,159,10,0.10)", border: "rgba(255,159,10,0.28)" },
  medium:   { label: "MEDIUM",   color: "#ffd60a", bg: "rgba(255,214,10,0.10)", border: "rgba(255,214,10,0.28)" },
};

/* ════════════════════════════════════════
   PILLAR CARD
════════════════════════════════════════ */

function PillarCard({ p }: { p: Pillar }) {
  const [open, setOpen] = useState(false);
  const [deepOpen, setDeepOpen] = useState(false);
  const s = SEV[p.severity];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-60px" }}
      transition={{ duration: 0.45 }}
      className="card overflow-hidden"
    >
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-4 p-6 text-left transition hover:bg-white/[0.02]"
      >
        <div className="flex-none">
          <div
            className="flex h-12 w-12 items-center justify-center rounded-2xl text-lg font-bold tabular-nums"
            style={{ background: s.bg, border: `1px solid ${s.border}`, color: s.color }}
          >
            {String(p.id).padStart(2, "0")}
          </div>
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-base font-bold">{p.title}</h3>
            <span
              className="rounded-full px-2 py-0.5 text-[10px] font-bold tracking-widest"
              style={{ color: s.color, background: s.bg }}
            >
              {s.label}
            </span>
          </div>
          <div className="mt-1.5 flex items-baseline gap-1.5">
            <span className="text-2xl font-extrabold" style={{ color: s.color }}>{p.stat}</span>
            <span className="text-xs text-muted leading-tight">{p.statLabel}</span>
          </div>
          <p className="mt-2 text-sm leading-relaxed text-muted line-clamp-2">{p.what}</p>
        </div>
        <div
          className="flex-none text-muted transition-transform duration-200"
          style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
        >
          ▾
        </div>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div className="space-y-5 border-t border-white/[0.06] px-6 pb-6 pt-5">
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-widest text-brand-400">
                  What this means
                </div>
                <p className="text-sm leading-relaxed text-fg/88">{p.what}</p>
              </div>

              <div
                className="rounded-xl border-l-4 px-4 py-3"
                style={{ borderColor: s.color, background: s.bg }}
              >
                <div className="mb-1 text-[11px] font-semibold uppercase tracking-widest" style={{ color: s.color }}>
                  Real-world scenario
                </div>
                <p className="text-sm italic leading-relaxed text-fg/90">{p.scenario}</p>
              </div>

              {p.connectedTo.length > 0 && (
                <div>
                  <div className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-muted">
                    Directly connected to
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {p.connectedTo.map((id) => {
                      const other = PILLARS.find((x) => x.id === id)!;
                      return (
                        <span
                          key={id}
                          className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs"
                        >
                          <span className="text-brand-300">#{String(id).padStart(2, "0")}</span>
                          <span className="text-muted">{other.title}</span>
                        </span>
                      );
                    })}
                  </div>
                  <p className="mt-2 text-[12px] text-muted">
                    Fixing this pillar also reduces risk in the connected pillars above — they compound each other.
                  </p>
                </div>
              )}

              <div>
                <div className="mb-2.5 text-[11px] font-semibold uppercase tracking-widest text-accent-400">
                  Quick actions
                </div>
                <ul className="space-y-2">
                  {p.tips.map((t, i) => (
                    <li key={i} className="flex items-start gap-2.5 text-sm text-fg/88">
                      <span className="mt-0.5 grid h-5 w-5 flex-none place-items-center rounded-full bg-accent-500/20 text-[10px] font-bold text-accent-400">
                        {i + 1}
                      </span>
                      {t}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="card-glow-lime rounded-xl border border-accent-500/25 bg-accent-500/8 px-4 py-3">
                <div className="mb-1 text-[11px] font-bold uppercase tracking-widest text-accent-400">
                  Quick win — do this today
                </div>
                <p className="text-sm leading-relaxed text-fg">{p.quickWin}</p>
              </div>

              <button
                onClick={() => setDeepOpen((v) => !v)}
                className="flex items-center gap-2 text-xs text-brand-400 hover:text-brand-300 transition"
              >
                <span>{deepOpen ? "▾ Hide" : "▸ Read"} deeper explanation</span>
              </button>
              <AnimatePresence initial={false}>
                {deepOpen && (
                  <motion.div
                    key="deep"
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <div className="rounded-xl border border-brand-500/15 bg-brand-500/[0.06] px-4 py-3">
                      <p className="text-sm leading-relaxed text-fg/85">{p.deepDive}</p>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/* ════════════════════════════════════════
   CHECKLIST TAB (Personal / Org)
════════════════════════════════════════ */

function ChecklistTab({
  tips,
  accentColor,
  badgeLabel,
  badgeBg,
  badgeBorder,
  title,
  subtitle,
}: {
  tips: readonly { tip: string; detail: string; icon: string }[];
  accentColor: string;
  badgeLabel: string;
  badgeBg: string;
  badgeBorder: string;
  title: string;
  subtitle: string;
}) {
  const [checked, setChecked] = useState<Set<number>>(new Set());
  const pct = Math.round((checked.size / tips.length) * 100);

  const toggle = (i: number) =>
    setChecked((prev) => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });

  return (
    <div className="pb-6">
      <div className="mb-5">
        <div
          className="mb-2 inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium"
          style={{ color: accentColor, background: badgeBg, border: `1px solid ${badgeBorder}` }}
        >
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: accentColor }} />
          {badgeLabel}
        </div>
        <h2 className="mb-1 text-2xl font-bold tracking-tight">{title}</h2>
        <p className="text-sm text-muted">{subtitle}</p>
      </div>

      {/* Progress bar */}
      <div className="card mb-5 p-4">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-sm font-semibold">
            {checked.size === 0
              ? "Start checking items off as you complete them"
              : checked.size === tips.length
              ? "All done — great work! 🎉"
              : `${checked.size} of ${tips.length} complete`}
          </span>
          <span className="text-sm font-bold tabular-nums" style={{ color: accentColor }}>
            {pct}%
          </span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-white/10">
          <motion.div
            className="h-full rounded-full"
            style={{ background: accentColor }}
            animate={{ width: `${pct}%` }}
            transition={{ type: "spring", stiffness: 120, damping: 20 }}
          />
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {tips.map((t, i) => {
          const done = checked.has(i);
          return (
            <motion.button
              key={i}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: i * 0.04 }}
              onClick={() => toggle(i)}
              className="card flex items-start gap-3.5 p-4 text-left transition-all duration-200"
              style={done ? { background: "rgba(255,255,255,0.06)", borderColor: accentColor + "55" } : {}}
            >
              {/* Checkbox */}
              <div
                className="mt-0.5 grid h-5 w-5 flex-none place-items-center rounded-full border-2 transition-all duration-200"
                style={
                  done
                    ? { background: accentColor, borderColor: accentColor }
                    : { borderColor: "rgba(255,255,255,0.2)" }
                }
              >
                {done && (
                  <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                    <path d="M1 4l3 3 5-6" stroke="#000" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                )}
              </div>

              {/* Icon */}
              <div className="mt-0.5 flex-none" style={{ color: done ? accentColor : "rgba(255,255,255,0.35)" }}>
                <TipIcon name={t.icon} />
              </div>

              <div className="min-w-0">
                <div className={`text-sm font-semibold transition-colors ${done ? "line-through opacity-60" : ""}`}>
                  {t.tip}
                </div>
                <div className="mt-0.5 text-xs leading-relaxed text-muted">{t.detail}</div>
              </div>
            </motion.button>
          );
        })}
      </div>
    </div>
  );
}

/* ════════════════════════════════════════
   QUIZ TAB
════════════════════════════════════════ */

function QuizTab() {
  const [current, setCurrent] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [answers, setAnswers] = useState<Record<number, string>>({});
  const [done, setDone] = useState(false);

  const q = QUIZ[current];
  const answered = selected !== null;
  const isCorrect = selected === q.correct;

  const pick = (label: string) => {
    if (answered) return;
    setSelected(label);
  };

  const next = () => {
    if (!selected) return;
    const next = { ...answers, [q.id]: selected };
    setAnswers(next);
    if (current < QUIZ.length - 1) {
      setCurrent((c) => c + 1);
      setSelected(null);
    } else {
      setDone(true);
    }
  };

  const restart = () => {
    setCurrent(0);
    setSelected(null);
    setAnswers({});
    setDone(false);
  };

  if (done) {
    const score = QUIZ.filter((q) => answers[q.id] === q.correct).length;
    const missed = QUIZ.filter((q) => answers[q.id] !== q.correct);
    const pct = Math.round((score / QUIZ.length) * 100);
    const grade =
      score === 5 ? { label: "Perfect score", color: "#30d158", msg: "Your team is well-prepared. Share this quiz with your volunteers." }
      : score >= 4 ? { label: "Strong", color: "#30d158", msg: "Nearly perfect — review the missed scenario below and you're set." }
      : score >= 3 ? { label: "Good foundation", color: "#ffd60a", msg: "You know the basics. Focus on the pillar(s) below where you missed." }
      : score >= 2 ? { label: "Needs attention", color: "#ff9f0a", msg: "A few critical gaps — read the pillar cards for the missed topics." }
      : { label: "High risk", color: "#ff453a", msg: "Start with the 7 Pillars tab and share this quiz with your leadership team." };

    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        className="pb-6 space-y-5"
      >
        <div className="card p-7 text-center">
          <div
            className="mx-auto mb-3 flex h-20 w-20 items-center justify-center rounded-full text-3xl font-extrabold"
            style={{ background: grade.color + "22", color: grade.color, border: `2px solid ${grade.color}55` }}
          >
            {pct}%
          </div>
          <div className="text-2xl font-bold">{grade.label}</div>
          <div className="mt-1 text-sm text-muted">{score} / {QUIZ.length} correct</div>
          <p className="mx-auto mt-4 max-w-sm text-sm leading-relaxed text-fg/80">{grade.msg}</p>
        </div>

        {missed.length > 0 && (
          <div className="card p-5 space-y-4">
            <h3 className="text-base font-bold">Review: what to focus on</h3>
            {missed.map((mq) => {
              const pillar = PILLARS.find((p) => p.id === mq.pillarId)!;
              const s = SEV[pillar.severity];
              return (
                <div key={mq.id} className="rounded-xl border border-white/8 bg-white/[0.02] p-4">
                  <div className="mb-1 flex items-center gap-2">
                    <span className="text-xs font-bold" style={{ color: s.color }}>
                      Pillar #{pillar.id} — {pillar.title}
                    </span>
                  </div>
                  <p className="mb-2 text-xs italic text-muted">"{mq.scenario}"</p>
                  <div className="rounded-lg bg-risk-crit/10 border border-risk-crit/25 px-3 py-2 text-xs text-fg/85">
                    <span className="font-semibold text-risk-high">Correct answer ({mq.correct}): </span>
                    {mq.options.find((o) => o.label === mq.correct)?.text}
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-muted">{mq.explanation}</p>
                </div>
              );
            })}
          </div>
        )}

        <div className="flex justify-center">
          <button
            onClick={restart}
            className="rounded-xl border border-white/12 px-5 py-2.5 text-sm font-medium text-muted transition hover:border-white/25 hover:text-fg"
          >
            ↺ Retake quiz
          </button>
        </div>
      </motion.div>
    );
  }

  return (
    <div className="pb-6 space-y-5">
      {/* Progress */}
      <div className="flex items-center gap-3">
        <div className="flex gap-1.5">
          {QUIZ.map((_, i) => (
            <div
              key={i}
              className="h-1.5 rounded-full transition-all duration-300"
              style={{
                width: i === current ? 24 : 8,
                background: i < current ? "#30d158" : i === current ? "#0a84ff" : "rgba(255,255,255,0.15)",
              }}
            />
          ))}
        </div>
        <span className="text-xs text-muted">{current + 1} / {QUIZ.length}</span>
      </div>

      {/* Question */}
      <AnimatePresence mode="wait">
        <motion.div
          key={q.id}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.2 }}
          className="space-y-4"
        >
          <div className="card p-5">
            <div className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-brand-400">
              Scenario {current + 1}
            </div>
            <p className="text-base font-semibold leading-snug">{q.scenario}</p>
          </div>

          <div className="space-y-2.5">
            {q.options.map((opt) => {
              const isSelected = selected === opt.label;
              const isRight = answered && opt.label === q.correct;
              const isWrong = answered && isSelected && !isRight;
              return (
                <motion.button
                  key={opt.label}
                  onClick={() => pick(opt.label)}
                  disabled={answered}
                  whileHover={!answered ? { scale: 1.01 } : {}}
                  whileTap={!answered ? { scale: 0.99 } : {}}
                  className="flex w-full items-start gap-3.5 rounded-xl border p-4 text-left transition-all duration-200"
                  style={{
                    borderColor: isRight
                      ? "#30d158"
                      : isWrong
                      ? "#ff453a"
                      : isSelected
                      ? "#0a84ff"
                      : "rgba(255,255,255,0.08)",
                    background: isRight
                      ? "rgba(48,209,88,0.10)"
                      : isWrong
                      ? "rgba(255,69,58,0.10)"
                      : isSelected
                      ? "rgba(10,132,255,0.10)"
                      : "rgba(255,255,255,0.02)",
                    cursor: answered ? "default" : "pointer",
                  }}
                >
                  <span
                    className="grid h-7 w-7 flex-none place-items-center rounded-full text-[11px] font-bold transition-colors"
                    style={{
                      background: isRight
                        ? "#30d158"
                        : isWrong
                        ? "#ff453a"
                        : isSelected
                        ? "#0a84ff"
                        : "rgba(255,255,255,0.08)",
                      color: isRight || isWrong || isSelected ? "#fff" : "rgba(255,255,255,0.5)",
                    }}
                  >
                    {isRight ? "✓" : isWrong ? "✗" : opt.label}
                  </span>
                  <span className="text-sm leading-snug pt-1">{opt.text}</span>
                </motion.button>
              );
            })}
          </div>

          {/* Explanation */}
          <AnimatePresence>
            {answered && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl border px-4 py-3"
                style={
                  isCorrect
                    ? { borderColor: "rgba(48,209,88,0.35)", background: "rgba(48,209,88,0.08)" }
                    : { borderColor: "rgba(255,159,10,0.35)", background: "rgba(255,159,10,0.08)" }
                }
              >
                <div
                  className="mb-1 text-[11px] font-bold uppercase tracking-widest"
                  style={{ color: isCorrect ? "#30d158" : "#ff9f0a" }}
                >
                  {isCorrect ? "Correct!" : "Not quite"}
                </div>
                <p className="text-sm leading-relaxed text-fg/88">{q.explanation}</p>
              </motion.div>
            )}
          </AnimatePresence>

          {answered && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex justify-end">
              <button
                onClick={next}
                className="rounded-xl px-5 py-2.5 text-sm font-semibold text-white transition"
                style={{ background: "linear-gradient(135deg, #0a84ff, #32ade6)" }}
              >
                {current < QUIZ.length - 1 ? "Next question →" : "See my results →"}
              </button>
            </motion.div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

/* ════════════════════════════════════════
   TABS CONFIG
════════════════════════════════════════ */

const TABS = [
  { id: "overview",  label: "Overview" },
  { id: "pillars",   label: "7 Pillars" },
  { id: "personal",  label: "Protect Yourself" },
  { id: "org",       label: "For Organizations" },
  { id: "quiz",      label: "Test Yourself" },
] as const;

type TabId = typeof TABS[number]["id"];

/* ════════════════════════════════════════
   MAIN PAGE
════════════════════════════════════════ */

export default function LearnMore() {
  const nav = useNavigate();
  const [activeTab, setActiveTab] = useState<TabId>("overview");

  return (
    <div className="min-h-full pb-20">
      <Nav />

      <main className="mx-auto max-w-4xl px-6">

        {/* ── Hero ── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="pt-10 pb-6 text-center"
        >
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-accent-500/30 bg-accent-500/10 px-3 py-1 text-xs font-medium text-accent-400">
            <span className="h-1.5 w-1.5 rounded-full bg-accent-400" />
            Nonprofit & Small Business Cyber Defense
          </div>

          <h1 className="text-4xl font-extrabold leading-tight tracking-tight sm:text-5xl">
            Learn &amp;{" "}
            <span className="bg-gradient-to-r from-brand-300 via-brand-400 to-accent-400 bg-clip-text text-transparent">
              Protect
            </span>
          </h1>

          <p className="mx-auto mt-3 max-w-xl text-[14px] leading-relaxed text-muted">
            Understand the most common cyber vulnerabilities, take our quiz to test your readiness, and check off actions as you complete them.
          </p>
        </motion.div>

        {/* ── Tab bar ── */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="mb-8 overflow-x-auto"
        >
          <div className="card inline-flex min-w-full gap-1 p-1.5 sm:min-w-0 sm:w-full">
            {TABS.map((t) => {
              const active = activeTab === t.id;
              const isQuiz = t.id === "quiz";
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id)}
                  className="relative flex flex-1 items-center justify-center gap-1.5 whitespace-nowrap rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200"
                  style={
                    active
                      ? isQuiz
                        ? { background: "linear-gradient(135deg, #30d158, #0a84ff)", color: "#fff", boxShadow: "0 2px 12px rgba(48,209,88,0.35)" }
                        : { background: "linear-gradient(135deg, #0a84ff, #32ade6)", color: "#fff", boxShadow: "0 2px 12px rgba(99,102,241,0.35)" }
                      : isQuiz
                        ? { color: "#30d158", border: "1px solid rgba(48,209,88,0.3)", background: "rgba(48,209,88,0.08)" }
                        : { color: "var(--color-muted)" }
                  }
                >
                  <span className="hidden sm:inline">{t.label}</span>
                  <span className="sm:hidden text-xs">{t.label.split(" ")[0]}</span>
                  {isQuiz && !active && (
                    <motion.span
                      animate={{ scale: [1, 1.4, 1], opacity: [1, 0.5, 1] }}
                      transition={{ duration: 1.6, repeat: Infinity }}
                      className="h-1.5 w-1.5 rounded-full bg-accent-500"
                    />
                  )}
                </button>
              );
            })}
          </div>
        </motion.div>

        {/* ── Tab panels ── */}
        <AnimatePresence mode="wait">

          {/* ─ Overview ─ */}
          {activeTab === "overview" && (
            <motion.div
              key="overview"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.25 }}
              className="space-y-6 pb-6"
            >
              <div className="card grid gap-6 p-6 sm:grid-cols-4">
                {STATS.map((s, i) => <AnimatedStat key={i} stat={s} />)}
              </div>

              <div className="card p-6 space-y-4">
                <h2 className="text-lg font-bold">What you'll find here</h2>
                <div className="grid gap-3 sm:grid-cols-2">
                  {TABS.filter(t => t.id !== "overview").map((t) => (
                    <button
                      key={t.id}
                      onClick={() => setActiveTab(t.id)}
                      className="flex items-start gap-3 rounded-xl border border-white/8 bg-white/[0.03] p-4 text-left transition hover:border-brand-500/30 hover:bg-brand-500/[0.05]"
                    >
                      <div>
                        <div className="text-sm font-semibold text-fg">{t.label}</div>
                        <div className="mt-0.5 text-xs text-muted">
                          {t.id === "pillars"  && "The 7 most exploited nonprofit and small business vulnerabilities — click any to expand"}
                          {t.id === "personal" && "8 actions every individual should take — check them off as you go"}
                          {t.id === "org"      && "Process & policy improvements with an interactive checklist"}
                          {t.id === "quiz"     && "5 scenario-based questions — see how your team would handle a real attack"}
                        </div>
                      </div>
                      <span className="ml-auto text-muted opacity-50">›</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="rounded-xl border border-brand-500/20 bg-brand-500/[0.06] px-5 py-4">
                <p className="text-sm leading-relaxed text-fg/88">
                  <span className="font-semibold text-brand-300">These pillars are interconnected.</span>{" "}
                  Weak passwords become catastrophic without MFA. Ransomware is permanent without backups.
                  Phishing works because of missing training. Each pillar card shows which others it amplifies —
                  so you can see the full chain of risk.
                </p>
              </div>

              <div className="card card-glow rounded-2xl p-6 text-center">
                <h2 className="mb-2 text-lg font-bold">Ready to check your actual exposure?</h2>
                <p className="mb-5 text-sm text-muted">Use Aegis's tools to see which risks apply to you right now.</p>
                <div className="flex flex-wrap justify-center gap-3">
                  <button onClick={() => nav("/")} className="p-btn p-prim-col" style={{ margin: 0 }}>
                    Scan for breach exposure
                  </button>
                  <button
                    onClick={() => nav("/phishing")}
                    className="rounded-xl border border-white/12 px-5 py-2.5 text-sm font-medium text-muted transition hover:border-white/25 hover:text-fg"
                  >
                    Check a suspicious message
                  </button>
                  <button
                    onClick={() => nav("/triage")}
                    className="rounded-xl border border-risk-high/30 bg-risk-crit/8 px-5 py-2.5 text-sm font-medium text-risk-high transition hover:bg-risk-crit/15"
                  >
                    Something already happened
                  </button>
                </div>
                <div className="mt-6 border-t border-white/[0.06] pt-5">
                  <p className="text-[12px] text-muted">
                    Free resources:{" "}
                    <a href="https://www.cisa.gov/resources-tools/resources/free-cybersecurity-services-and-tools" target="_blank" rel="noopener noreferrer" className="text-brand-300 hover:underline">CISA Free Tools</a>
                    {" · "}
                    <a href="https://www.techsoup.org/cybersecurity" target="_blank" rel="noopener noreferrer" className="text-brand-300 hover:underline">TechSoup Nonprofit Cybersecurity</a>
                    {" · "}
                    <a href="https://haveibeenpwned.com" target="_blank" rel="noopener noreferrer" className="text-brand-300 hover:underline">Have I Been Pwned</a>
                  </p>
                </div>
              </div>
            </motion.div>
          )}

          {/* ─ 7 Pillars ─ */}
          {activeTab === "pillars" && (
            <motion.div
              key="pillars"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.25 }}
              className="space-y-4 pb-6"
            >
              <p className="text-sm text-muted">
                Click any card to expand — each shows a real-world scenario, connections to other pillars, and a quick win you can do today.
              </p>
              {PILLARS.map((p) => (
                <PillarCard key={p.id} p={p} />
              ))}
            </motion.div>
          )}

          {/* ─ Personal ─ */}
          {activeTab === "personal" && (
            <motion.div
              key="personal"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.25 }}
            >
              <ChecklistTab
                tips={PERSONAL_TIPS}
                accentColor="#0a84ff"
                badgeLabel="For individuals"
                badgeBg="rgba(10,132,255,0.10)"
                badgeBorder="rgba(10,132,255,0.25)"
                title="Personal Protection Checklist"
                subtitle="Things every person — staff, volunteer, or board member — should do regardless of their role."
              />
            </motion.div>
          )}

          {/* ─ Organizations ─ */}
          {activeTab === "org" && (
            <motion.div
              key="org"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.25 }}
            >
              <ChecklistTab
                tips={ORG_TIPS}
                accentColor="#30d158"
                badgeLabel="For organizations"
                badgeBg="rgba(48,209,88,0.08)"
                badgeBorder="rgba(48,209,88,0.25)"
                title="Organizational Security Checklist"
                subtitle="Process and policy improvements that protect the whole organization, not just individual accounts."
              />

              <div className="card card-glow-lime mt-5 rounded-2xl border border-accent-500/20 p-6 text-center">
                <h3 className="mb-1 text-base font-bold">Need help getting started?</h3>
                <p className="mb-4 text-sm text-muted">Use Aegis's tools to assess your organization's current exposure.</p>
                <div className="flex flex-wrap justify-center gap-3">
                  <button onClick={() => nav("/")} className="p-btn p-prim-col" style={{ margin: 0 }}>
                    Breach Detector
                  </button>
                  <button
                    onClick={() => nav("/triage")}
                    className="rounded-xl border border-white/12 px-4 py-2 text-sm font-medium text-muted transition hover:border-white/25 hover:text-fg"
                  >
                    Incident Triage
                  </button>
                  <button
                    onClick={() => nav("/phishing")}
                    className="rounded-xl border border-white/12 px-4 py-2 text-sm font-medium text-muted transition hover:border-white/25 hover:text-fg"
                  >
                    Phishing Checker
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {/* ─ Quiz ─ */}
          {activeTab === "quiz" && (
            <motion.div
              key="quiz"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.25 }}
            >
              <div className="mb-5">
                <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-accent-500/25 bg-accent-500/8 px-3 py-1 text-xs font-medium text-accent-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-accent-400" /> 5 questions
                </div>
                <h2 className="mb-1 text-2xl font-bold tracking-tight">How would your team respond?</h2>
                <p className="text-sm text-muted">
                  Real scenarios nonprofit and small business staff actually face. No trick questions — just practical judgment calls.
                </p>
              </div>
              <QuizTab />
            </motion.div>
          )}

        </AnimatePresence>
      </main>
    </div>
  );
}
