import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Nav } from "../components/Nav";

/* ════════════════════════════════════════
   DATA
════════════════════════════════════════ */

const STATS = [
  { value: "68%",   label: "of nonprofits experienced a cyberattack or breach" },
  { value: "$1.54M", label: "average ransomware payment in 2023" },
  { value: "277",   label: "days average time to detect a breach" },
  { value: "88%",   label: "of all breaches start with human error" },
];

type Severity = "critical" | "high" | "medium";

interface Pillar {
  id: number;
  icon: string;
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
    icon: "🔑",
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
    icon: "🔐",
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
    icon: "💻",
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
    icon: "💾",
    title: "Lack of Robust Backups",
    severity: "critical",
    stat: "3-2-1",
    statLabel: "the backup rule almost no nonprofit actually follows",
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
    icon: "🛡️",
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
    deepDive: "Endpoint Detection & Response (EDR) tools go beyond traditional antivirus by watching for suspicious behavior rather than just known malware signatures. Products like Microsoft Defender for Business ($3/user/month) are affordable for nonprofits and provide enterprise-grade protection. The Cybersecurity and Infrastructure Security Agency (CISA) offers free cybersecurity resources specifically for nonprofits.",
  },
  {
    id: 6,
    icon: "📋",
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
    icon: "🎣",
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
      "Run a 30-minute security awareness session quarterly — real examples from recent nonprofit attacks are more memorable than abstract theory",
    ],
    quickWin: "Send your team one real-world phishing example this week (search 'nonprofit BEC phishing example') with an explanation of what makes it suspicious. Then establish the 'call to verify' rule for all financial requests.",
    deepDive: "Business Email Compromise (BEC) attacks cost $2.7 billion in 2022 alone — more than ransomware. They require zero technical sophistication: an attacker registers a look-alike domain or hacks a real email account and simply asks for money or data. The only defense is a trained human who pauses, questions, and verifies by phone before acting.",
  },
];

const PERSONAL_TIPS = [
  { icon: "🔑", tip: "Use a password manager", detail: "Bitwarden (free) or 1Password — never reuse a password" },
  { icon: "📱", tip: "Enable MFA on everything", detail: "Start with email, then banking, then everything else" },
  { icon: "🔄", tip: "Update immediately", detail: "When your phone or computer says 'update available', do it today, not next week" },
  { icon: "🎣", tip: "Pause before you click", detail: "Urgency + unusual request = almost certainly a scam. Call to verify." },
  { icon: "📶", tip: "Use a VPN on public Wi-Fi", detail: "Coffee shops, airports, hotels — always use a VPN (Mullvad, ProtonVPN)" },
  { icon: "💾", tip: "Back up your personal data", detail: "Photos, documents — use an external drive AND cloud backup" },
  { icon: "🔒", tip: "Lock your screens", detail: "Auto-lock after 2 minutes on all devices, every time, everywhere" },
  { icon: "👁️", tip: "Check your accounts", detail: "Review bank and credit card statements weekly — catch fraud fast" },
];

const ORG_TIPS = [
  { icon: "📝", tip: "Write an offboarding checklist", detail: "Revoke all access the day someone leaves — email, CRM, Slack, everything" },
  { icon: "🗺️", tip: "Map your data", detail: "Know where donor PII lives: which databases, cloud drives, spreadsheets" },
  { icon: "📧", tip: "Upgrade to Microsoft 365 or Google Workspace", detail: "Built-in email filtering, MFA, device management — worth every dollar" },
  { icon: "🚨", tip: "Write a one-page incident response plan", detail: "Who to call, what to do first, who has authority to act — before you need it" },
  { icon: "💰", tip: "Cyber insurance", detail: "Many nonprofits qualify for affordable policies that cover breach response costs" },
  { icon: "📚", tip: "Quarterly security check-in", detail: "30-minute team meeting: review recent phishing examples and remind of procedures" },
  { icon: "🔑", tip: "Enforce MFA org-wide", detail: "Require it in your Google/Microsoft admin console — not optional" },
  { icon: "📦", tip: "Test your backups", detail: "Quarterly fire drill: restore a file from backup to prove it actually works" },
];

/* ════════════════════════════════════════
   SEVERITY META
════════════════════════════════════════ */

const SEV: Record<Severity, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "CRITICAL", color: "#f43f5e", bg: "rgba(244,63,94,0.12)",  border: "rgba(244,63,94,0.30)" },
  high:     { label: "HIGH",     color: "#fb7185", bg: "rgba(251,113,133,0.10)", border: "rgba(251,113,133,0.28)" },
  medium:   { label: "MEDIUM",   color: "#fbbf24", bg: "rgba(251,191,36,0.10)",  border: "rgba(251,191,36,0.28)" },
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
      {/* Header row */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-4 p-6 text-left transition hover:bg-white/[0.02]"
      >
        {/* Number + icon */}
        <div className="flex-none text-center">
          <div
            className="flex h-12 w-12 items-center justify-center rounded-2xl text-2xl"
            style={{ background: s.bg, border: `1px solid ${s.border}` }}
          >
            {p.icon}
          </div>
          <div className="mt-1 text-[10px] font-bold tabular-nums text-muted">
            #{String(p.id).padStart(2, "0")}
          </div>
        </div>

        {/* Title + meta */}
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

          {/* Key stat */}
          <div className="mt-1.5 flex items-baseline gap-1.5">
            <span className="text-2xl font-extrabold" style={{ color: s.color }}>{p.stat}</span>
            <span className="text-xs text-muted leading-tight">{p.statLabel}</span>
          </div>

          {/* What it is — always visible preview */}
          <p className="mt-2 text-sm leading-relaxed text-muted line-clamp-2">{p.what}</p>
        </div>

        {/* Expand toggle */}
        <div
          className="flex-none text-muted transition-transform duration-200"
          style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
        >
          ▾
        </div>
      </button>

      {/* Expandable body */}
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

              {/* Full "what" paragraph */}
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-widest text-brand-400">
                  What this means
                </div>
                <p className="text-sm leading-relaxed text-fg/88">{p.what}</p>
              </div>

              {/* Scenario */}
              <div
                className="rounded-xl border-l-4 px-4 py-3"
                style={{ borderColor: s.color, background: s.bg }}
              >
                <div className="mb-1 text-[11px] font-semibold uppercase tracking-widest" style={{ color: s.color }}>
                  Real-world scenario
                </div>
                <p className="text-sm italic leading-relaxed text-fg/90">{p.scenario}</p>
              </div>

              {/* Connected pillars */}
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
                          <span>{other.icon}</span>
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

              {/* Quick tips */}
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

              {/* Quick win highlight */}
              <div className="card-glow-lime rounded-xl border border-accent-500/25 bg-accent-500/8 px-4 py-3">
                <div className="mb-1 text-[11px] font-bold uppercase tracking-widest text-accent-400">
                  ⚡ Quick win — do this today
                </div>
                <p className="text-sm leading-relaxed text-fg">{p.quickWin}</p>
              </div>

              {/* Deep dive toggle */}
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
   TABS CONFIG
════════════════════════════════════════ */

const TABS = [
  { id: "overview",  label: "Overview",        icon: "📊" },
  { id: "pillars",   label: "7 Pillars",        icon: "🏛️" },
  { id: "personal",  label: "Protect Yourself", icon: "👤" },
  { id: "org",       label: "For Organizations",icon: "🏢" },
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

        {/* ── Hero (always visible) ── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="pt-10 pb-6 text-center"
        >
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-accent-500/30 bg-accent-500/10 px-3 py-1 text-xs font-medium text-accent-400">
            <span className="h-1.5 w-1.5 rounded-full bg-accent-400" />
            Nonprofit Cyber Defense Education
          </div>

          <h1 className="text-4xl font-extrabold leading-tight tracking-tight sm:text-5xl">
            Learn &amp;{" "}
            <span className="bg-gradient-to-r from-brand-300 via-brand-400 to-accent-400 bg-clip-text text-transparent">
              Protect
            </span>
          </h1>

          <p className="mx-auto mt-3 max-w-xl text-[14px] leading-relaxed text-muted">
            Understand the most common cyber vulnerabilities and how to close them — for individuals and organizations.
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
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id)}
                  className="relative flex flex-1 items-center justify-center gap-1.5 whitespace-nowrap rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200"
                  style={
                    active
                      ? { background: "linear-gradient(135deg, #4f46e5, #65a30d)", color: "#fff", boxShadow: "0 2px 12px rgba(99,102,241,0.35)" }
                      : { color: "var(--color-muted)" }
                  }
                >
                  <span className="text-base leading-none">{t.icon}</span>
                  <span className="hidden sm:inline">{t.label}</span>
                  <span className="sm:hidden text-xs">{t.label.split(" ")[0]}</span>
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
              {/* Stats */}
              <div className="card grid gap-6 p-6 sm:grid-cols-4">
                {STATS.map((s) => (
                  <div key={s.value} className="text-center">
                    <div className="text-3xl font-extrabold bg-gradient-to-r from-brand-300 to-accent-400 bg-clip-text text-transparent">
                      {s.value}
                    </div>
                    <div className="mt-1 text-[11px] leading-snug text-muted">{s.label}</div>
                  </div>
                ))}
              </div>

              {/* What this page covers */}
              <div className="card p-6 space-y-4">
                <h2 className="text-lg font-bold">What you'll find here</h2>
                <div className="grid gap-3 sm:grid-cols-2">
                  {TABS.filter(t => t.id !== "overview").map((t) => (
                    <button
                      key={t.id}
                      onClick={() => setActiveTab(t.id)}
                      className="flex items-start gap-3 rounded-xl border border-white/8 bg-white/[0.03] p-4 text-left transition hover:border-brand-500/30 hover:bg-brand-500/[0.05]"
                    >
                      <span className="text-2xl">{t.icon}</span>
                      <div>
                        <div className="text-sm font-semibold text-fg">{t.label}</div>
                        <div className="mt-0.5 text-xs text-muted">
                          {t.id === "pillars"  && "The 7 most exploited nonprofit vulnerabilities — click any to expand"}
                          {t.id === "personal" && "8 actions every individual should take to stay safe"}
                          {t.id === "org"      && "Process & policy improvements that protect your whole organization"}
                        </div>
                      </div>
                      <span className="ml-auto text-muted opacity-50">›</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Connection note */}
              <div className="rounded-xl border border-brand-500/20 bg-brand-500/[0.06] px-5 py-4">
                <p className="text-sm leading-relaxed text-fg/88">
                  <span className="font-semibold text-brand-300">These pillars are interconnected.</span>{" "}
                  Weak passwords become catastrophic without MFA. Ransomware is permanent without backups.
                  Phishing works because of missing training. Each pillar card shows which others it amplifies —
                  so you can see the full chain of risk.
                </p>
              </div>

              {/* CTA */}
              <div className="card card-glow rounded-2xl p-6 text-center">
                <div className="mb-1 text-2xl">🛡️</div>
                <h2 className="mb-2 text-lg font-bold">Ready to check your actual exposure?</h2>
                <p className="mb-5 text-sm text-muted">Use Aegis's tools to see which risks apply to you right now.</p>
                <div className="flex flex-wrap justify-center gap-3">
                  <button
                    onClick={() => nav("/")}
                    className="rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110"
                  >
                    🔍 Scan for breach exposure
                  </button>
                  <button
                    onClick={() => nav("/phishing")}
                    className="rounded-xl border border-white/12 px-5 py-2.5 text-sm font-medium text-muted transition hover:border-white/25 hover:text-fg"
                  >
                    ✉️ Check a suspicious message
                  </button>
                  <button
                    onClick={() => nav("/triage")}
                    className="rounded-xl border border-risk-high/30 bg-risk-crit/8 px-5 py-2.5 text-sm font-medium text-risk-high transition hover:bg-risk-crit/15"
                  >
                    ⚡ Something already happened
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
              <div className="mb-2 flex items-center justify-between">
                <p className="text-sm text-muted">Click any card to expand — each shows a real-world scenario, connections to other pillars, and a quick win you can do today.</p>
              </div>
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
              className="pb-6"
            >
              <div className="mb-6">
                <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-brand-500/25 bg-brand-500/8 px-3 py-1 text-xs font-medium text-brand-300">
                  <span className="h-1.5 w-1.5 rounded-full bg-brand-400" /> For individuals
                </div>
                <h2 className="mb-1 text-2xl font-bold tracking-tight">Personal Protection Checklist</h2>
                <p className="text-sm text-muted">
                  Things every person — staff, volunteer, or board member — should do regardless of their role.
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                {PERSONAL_TIPS.map((t, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, delay: i * 0.05 }}
                    className="card flex items-start gap-3.5 p-4"
                  >
                    <span className="flex-none text-xl">{t.icon}</span>
                    <div>
                      <div className="text-sm font-semibold">{t.tip}</div>
                      <div className="mt-0.5 text-xs leading-relaxed text-muted">{t.detail}</div>
                    </div>
                  </motion.div>
                ))}
              </div>
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
              className="pb-6"
            >
              <div className="mb-6">
                <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-accent-500/25 bg-accent-500/8 px-3 py-1 text-xs font-medium text-accent-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-accent-400" /> For organizations
                </div>
                <h2 className="mb-1 text-2xl font-bold tracking-tight">Organizational Security Checklist</h2>
                <p className="text-sm text-muted">
                  Process and policy improvements that protect the whole organization, not just individual accounts.
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 mb-8">
                {ORG_TIPS.map((t, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, delay: i * 0.05 }}
                    className="card flex items-start gap-3.5 p-4"
                  >
                    <span className="flex-none text-xl">{t.icon}</span>
                    <div>
                      <div className="text-sm font-semibold">{t.tip}</div>
                      <div className="mt-0.5 text-xs leading-relaxed text-muted">{t.detail}</div>
                    </div>
                  </motion.div>
                ))}
              </div>

              {/* Inline CTA at bottom of org tab */}
              <div className="card card-glow-lime rounded-2xl border border-accent-500/20 p-6 text-center">
                <h3 className="mb-1 text-base font-bold">Need help getting started?</h3>
                <p className="mb-4 text-sm text-muted">Use Aegis's tools to assess your organization's current exposure.</p>
                <div className="flex flex-wrap justify-center gap-3">
                  <button
                    onClick={() => nav("/")}
                    className="rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 px-4 py-2 text-sm font-semibold text-white transition hover:brightness-110"
                  >
                    🔍 Breach Detector
                  </button>
                  <button
                    onClick={() => nav("/triage")}
                    className="rounded-xl border border-white/12 px-4 py-2 text-sm font-medium text-muted transition hover:border-white/25 hover:text-fg"
                  >
                    ⚡ Incident Triage
                  </button>
                  <button
                    onClick={() => nav("/code-audit")}
                    className="rounded-xl border border-white/12 px-4 py-2 text-sm font-medium text-muted transition hover:border-white/25 hover:text-fg"
                  >
                    &lt;/&gt; Code Auditor
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
