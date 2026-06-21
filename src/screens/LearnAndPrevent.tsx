import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Brand } from "../components/Brand";

/* ─── DATA ─────────────────────────────────────────────── */

const PILLARS = [
  {
    id: 1,
    icon: "🛡️",
    title: "No Modern Security Protections",
    colorHex: "#f43f5e",
    stat: "204 days",
    statLabel: "avg attacker dwell time before detection",
    description:
      "Running without antivirus, endpoint detection, or a properly configured firewall leaves every device on your network fully exposed to automated malware, ransomware, and remote exploitation — with no alert when something goes wrong.",
    risks: [
      "Malware runs undetected for months (average dwell time: 204 days)",
      "Ransomware can encrypt every file across your network in under an hour",
      "No visibility means you don't know you're breached until donors call",
    ],
    actions: [
      {
        term: "This Week",
        emoji: "⚡",
        items: [
          "Enable Windows Defender or install Malwarebytes Free on every device",
          "Turn on your router's built-in firewall",
        ],
      },
      {
        term: "This Month",
        emoji: "📆",
        items: [
          "Enable DNS-layer filtering (Cloudflare Gateway is free)",
          "Schedule weekly automated scans on all computers",
        ],
      },
      {
        term: "Long-Term",
        emoji: "🏗️",
        items: [
          "Apply for Cisco's nonprofit license for Umbrella DNS protection",
          "Look into Microsoft Defender for Business (discounted for nonprofits)",
        ],
      },
    ],
  },
  {
    id: 2,
    icon: "💻",
    title: "Outdated Computers & Software",
    colorHex: "#f43f5e",
    stat: "60%",
    statLabel: "of breaches exploit known, patchable vulnerabilities",
    description:
      "Every unpatched OS and application is a published vulnerability list. Attackers actively scan for organizations running Windows 7, Office 2013, or un-updated plugins — these have known, public exploits that require zero technical skill to run.",
    risks: [
      "EternalBlue (the WannaCry exploit) still works against unpatched Windows machines",
      "Old browsers can be silently compromised just by visiting a malicious website",
      "Unsupported software won't receive patches when new flaws are discovered",
    ],
    actions: [
      {
        term: "This Week",
        emoji: "⚡",
        items: [
          "Enable automatic updates on all computers (Windows Update, macOS Software Update)",
          "Update every browser to its latest version",
        ],
      },
      {
        term: "This Month",
        emoji: "📆",
        items: [
          "Audit every device — create a spreadsheet of OS version and last patch date",
          "Uninstall software that is no longer used or maintained",
        ],
      },
      {
        term: "Long-Term",
        emoji: "🏗️",
        items: [
          "Apply for Microsoft's nonprofit hardware grant program",
          "Set a 3-year hardware refresh cycle — devices older than 5 years are security liabilities",
        ],
      },
    ],
  },
  {
    id: 3,
    icon: "🔑",
    title: "Bad Password Hygiene",
    colorHex: "#fb7185",
    stat: "#1",
    statLabel: "cause of account takeovers worldwide",
    description:
      "Reused passwords, shared credentials, and weak passwords are the #1 cause of account takeovers. When one account is breached in a data leak, attackers use automated tools to try those credentials across every major service within minutes.",
    risks: [
      "Credential stuffing attacks test millions of password combinations per second",
      "Shared passwords mean there's no way to revoke access when someone leaves",
      "A single compromised email account can expose your entire donor database",
    ],
    actions: [
      {
        term: "This Week",
        emoji: "⚡",
        items: [
          "Sign up for Bitwarden (free for nonprofits) and start saving credentials there",
          "Change any password shared with a former employee immediately",
        ],
      },
      {
        term: "This Month",
        emoji: "📆",
        items: [
          "Roll out Bitwarden to every staff member and volunteer with system access",
          "Enforce a minimum 16-character passphrase policy",
        ],
      },
      {
        term: "Long-Term",
        emoji: "🏗️",
        items: [
          "Eliminate all shared accounts — every person gets their own login",
          "Audit who has access to each system and remove anyone who no longer needs it",
        ],
      },
    ],
  },
  {
    id: 4,
    icon: "💾",
    title: "Lack of Robust Backups",
    colorHex: "#fb7185",
    stat: "93%",
    statLabel: "of companies without backups close within 1 year of a major incident",
    description:
      "Without tested, isolated backups, a ransomware attack or accidental deletion is permanent. Many organizations discover their backups don't actually work — or were also encrypted — only after a disaster has already occurred.",
    risks: [
      "Ransomware specifically targets and deletes connected backup drives before encrypting files",
      "Cloud sync (Dropbox, Google Drive) is NOT a backup — if you delete a file, it syncs the deletion",
      "Untested backups fail when you need them most — often due to corruption",
    ],
    actions: [
      {
        term: "This Week",
        emoji: "⚡",
        items: [
          "Identify your most critical data (donor records, financial files, volunteer lists)",
          "Set up automated cloud backup with Backblaze ($7/month) or iDrive",
        ],
      },
      {
        term: "This Month",
        emoji: "📆",
        items: [
          "Implement the 3-2-1 rule: 3 copies, 2 different media, 1 offsite/cloud",
          "Do a test restore — actually try to recover a file from your backup",
        ],
      },
      {
        term: "Long-Term",
        emoji: "🏗️",
        items: [
          "Schedule quarterly restore tests on your calendar",
          "Keep at least one backup offline (external drive stored offsite) to survive ransomware",
        ],
      },
    ],
  },
  {
    id: 5,
    icon: "📋",
    title: "Poor IT Procedures",
    colorHex: "#fbbf24",
    stat: "~30%",
    statLabel: "of breaches involve a current or former insider",
    description:
      "When there's no process for onboarding, offboarding, or access changes, accounts accumulate. Former employees, old volunteers, and ex-board members retain access to your systems — often for years. Every dormant account is an unlocked door.",
    risks: [
      "Disgruntled former employees can access systems months after leaving",
      "No change management means no one knows what's installed or who has access",
      "Undocumented systems become unmaintainable — and unfixable after an incident",
    ],
    actions: [
      {
        term: "This Week",
        emoji: "⚡",
        items: [
          "List every person with access to your systems, email, and cloud accounts",
          "Revoke access for anyone who is no longer active in your organization",
        ],
      },
      {
        term: "This Month",
        emoji: "📆",
        items: [
          "Write a one-page offboarding checklist: disable email, revoke app access, change shared passwords",
          "Create a simple access log — a spreadsheet of who has access to what",
        ],
      },
      {
        term: "Long-Term",
        emoji: "🏗️",
        items: [
          "Use a single sign-on provider (Google Workspace or Microsoft 365) so you can disable all access in one click",
          "Review access quarterly — treat it like a fire drill",
        ],
      },
    ],
  },
  {
    id: 6,
    icon: "🔐",
    title: "No Multi-Factor Authentication",
    colorHex: "#f43f5e",
    stat: "99.9%",
    statLabel: "of account-compromise attacks stopped by MFA",
    description:
      "A password alone is no longer sufficient protection for any account. MFA adds a second verification step — a code on your phone — so stolen passwords are useless without your physical device.",
    risks: [
      "Phishing, data breaches, and malware all steal passwords — MFA makes them worthless",
      "Email accounts without MFA are the master key to every other account (password resets)",
      "Business Email Compromise (BEC) fraud cost nonprofits $2.9 billion in 2023",
    ],
    actions: [
      {
        term: "This Week",
        emoji: "⚡",
        items: [
          "Enable MFA on your email provider (Gmail/Outlook) — highest priority action on this page",
          "Enable MFA on your bank and donation platforms (PayPal, Stripe, Classy)",
        ],
      },
      {
        term: "This Month",
        emoji: "📆",
        items: [
          "Enable MFA on every account that offers it — cloud storage, social media, accounting software",
          "Install an authenticator app (Google Authenticator or Authy) — more secure than SMS codes",
        ],
      },
      {
        term: "Long-Term",
        emoji: "🏗️",
        items: [
          "Make MFA mandatory for all new accounts as an organizational policy",
          "Consider hardware security keys (YubiKey) for your highest-privilege accounts",
        ],
      },
    ],
  },
  {
    id: 7,
    icon: "🎓",
    title: "No Security Awareness Training",
    colorHex: "#fb7185",
    stat: "91%",
    statLabel: "of cyberattacks begin with a phishing email",
    description:
      "Technology alone cannot protect an organization. 91% of cyberattacks begin with a phishing email that a person clicks. If your staff and volunteers can't recognize manipulation tactics — fake invoices, urgent wire requests, spoofed emails — every other safeguard can be bypassed in seconds.",
    risks: [
      "A single staff member clicking a phishing link can hand attackers full network access",
      "Social engineering exploits trust — attackers impersonate your ED, your bank, or the IRS",
      "Volunteers cycle in and out quickly, creating a constantly undertrained entry point",
    ],
    actions: [
      {
        term: "This Week",
        emoji: "⚡",
        items: [
          "Share a phishing example with your team and walk through the red flags together",
          "Bookmark KnowBe4's free phishing resources for nonprofits",
        ],
      },
      {
        term: "This Month",
        emoji: "📆",
        items: [
          "Complete one free training module from CISA's cybersecurity training library",
          "Run a simulated phishing test using Google's Phishing Quiz",
        ],
      },
      {
        term: "Long-Term",
        emoji: "🏗️",
        items: [
          "Build a 10-minute 'Security 101' into every volunteer onboarding session",
          "Do quarterly awareness updates — attackers change tactics, your team should too",
        ],
      },
    ],
  },
];

const PRACTICES = [
  {
    frequency: "Daily",
    icon: "☀️",
    gradient: "from-yellow-500/20 to-orange-500/10",
    borderColor: "#fbbf2440",
    accentColor: "#fbbf24",
    items: [
      "Verify any unexpected payment request or wire transfer by calling the sender directly — never reply to the email",
      "Lock your computer when stepping away, even in a trusted office",
      "Check that your email didn't receive suspicious login alerts or password reset requests",
    ],
  },
  {
    frequency: "Weekly",
    icon: "📅",
    gradient: "from-blue-500/20 to-cyan-500/10",
    borderColor: "#60a5fa40",
    accentColor: "#60a5fa",
    items: [
      "Review bank and donation platform transactions for anything unrecognized",
      "Confirm backups ran successfully (your backup tool should send a status email)",
      "Check for pending software updates and apply them before the week ends",
    ],
  },
  {
    frequency: "Monthly",
    icon: "🗓️",
    gradient: "from-violet-500/20 to-purple-500/10",
    borderColor: "#a78bfa40",
    accentColor: "#a78bfa",
    items: [
      "Review who has access to your systems — remove anyone who no longer needs it",
      "Test restoring one file from your backup to confirm it actually works",
      "Check haveibeenpwned.com for any new breaches involving your domain",
      "Review your email forwarding rules — attackers often set up silent forwards after compromise",
    ],
  },
  {
    frequency: "Yearly",
    icon: "📆",
    gradient: "from-emerald-500/20 to-teal-500/10",
    borderColor: "#34d39940",
    accentColor: "#34d399",
    items: [
      "Run a full security health check (like Aegis) to see what's changed in your exposure",
      "Review and update your incident response checklist",
      "Rotate critical passwords (banking, email admin, donation platform)",
      "Audit third-party apps and integrations — revoke anything unused",
      "Review cyber insurance coverage and make sure it matches your current risk",
    ],
  },
];

const RISK_CHAINS = [
  {
    icon: "🔒",
    title: "The 'Everything Gets Locked' Attack (Ransomware)",
    colorHex: "#f43f5e",
    plain: "Imagine showing up to work one morning and nothing opens. Not a single file. This is ransomware — and it usually starts with one email.",
    steps: [
      {
        label: "A convincing fake email arrives",
        sub: "It looks like a package notice, a DocuSign request, or a message from a familiar contact — easy to miss",
      },
      {
        label: "Someone clicks it — invisible software installs",
        sub: "Without security tools running, nothing warns them. The software is now quietly active in the background",
      },
      {
        label: "Overnight, it spreads to every computer on your network",
        sub: "Shared drives, printers, other laptops — anything connected gets infected while everyone is home",
      },
      {
        label: "Every file is scrambled with a digital lock",
        sub: "Donor lists, financial records, program data — all unreadable. Only the attacker has the key",
      },
      {
        label: "The backup drive was connected — it's locked too",
        sub: "You try to restore from backup, but the attack got there first. There's nothing to fall back on",
      },
    ],
    outcome: "The attacker demands $10,000–$50,000 to unlock your files. Even if you pay, there's no guarantee. And they likely already copied everything before locking it.",
    scale: "💸 $50K+ average recovery cost for small nonprofits",
  },
  {
    icon: "📧",
    title: "The 'Fake Email, Real Money Transfer' Scam",
    colorHex: "#fb7185",
    plain: "This one doesn't need any technical skill at all — just a stolen password and some patience. It's how nonprofits lose six figures in a single afternoon.",
    steps: [
      {
        label: "A staff member's password was stolen — from an unrelated website",
        sub: "Maybe a shopping site or an old app had a breach years ago. That password is now on a list sold to attackers",
      },
      {
        label: "The attacker tries it on your email — and it works",
        sub: "Without a second login step (like a phone confirmation), one stolen password is all it takes to get inside",
      },
      {
        label: "They quietly read your emails for weeks",
        sub: "They learn names, relationships, how your director writes, which vendors you pay, and when money moves",
      },
      {
        label: "A perfectly written email goes out from your director's real account",
        sub: '"Hey, I need you to wire $3,500 to this vendor today — I\'m in back-to-back meetings. Please handle urgently."',
      },
      {
        label: "The money is sent before anyone realizes",
        sub: "It was the real account, in the real writing style, with real context. There was no obvious sign anything was wrong",
      },
    ],
    outcome: "The wire transfer cannot be reversed. The attacker now also has your full donor list, grant proposals, and board contacts — and may sell or publish them.",
    scale: "📉 Average loss per incident: $130,000",
  },
  {
    icon: "👤",
    title: "The 'Slow, Invisible Theft' (Data Breach)",
    colorHex: "#fbbf24",
    plain: "Not every attack is loud and dramatic. Some attackers just want your data — and they'll take weeks to copy it without ever being noticed.",
    steps: [
      {
        label: "Your organization is running software with a known security hole",
        sub: "Think of it like a cracked window everyone in the neighborhood knows about — automated tools scan the entire internet looking for these",
      },
      {
        label: "An attacker slips in completely undetected",
        sub: "With no security tools running, there's no alarm, no warning, no sign anything is wrong. To your computers, it looks like normal activity",
      },
      {
        label: "They quietly copy your files over days or weeks",
        sub: "Donor records. Financial statements. Client intake forms. All copied to the attacker's server, one folder at a time",
      },
      {
        label: "You have no way to know what was accessed or when",
        sub: "Without proper logging, you can't answer 'what did they take?' — and that becomes its own legal problem",
      },
      {
        label: "Months later, a donor or client tells you something is wrong",
        sub: "Someone calls saying their information was used for fraud — details only your organization would have had",
      },
    ],
    outcome: "You're legally required to notify every affected person — sometimes hundreds of donors and clients. Your state may fine you. Funders find out via Google. You still don't know exactly what was taken.",
    scale: "⚖️ Notification + fines: $25,000–$80,000+",
  },
];

const DANGERS = [
  {
    icon: "💸",
    title: "Financial Fraud & Wire Transfer Scams",
    colorHex: "#f43f5e",
    stat: "$130K",
    statLabel: "avg BEC loss per incident",
    body: "Business Email Compromise is the fastest-growing cybercrime targeting nonprofits. Attackers compromise or spoof your executive's email and instruct staff to wire funds or change direct deposit accounts. This money came from donors and will never be recovered.",
  },
  {
    icon: "📋",
    title: "Donor Data Exposure",
    colorHex: "#fb7185",
    stat: "72 hrs",
    statLabel: "breach notification window in most states",
    body: "Your donor database contains names, addresses, giving history, and often payment information. A breach exposes the people who trusted you most, triggers state notification laws, and can permanently destroy donor relationships built over decades.",
  },
  {
    icon: "🔒",
    title: "Ransomware & Operational Paralysis",
    colorHex: "#f43f5e",
    stat: "48 hrs",
    statLabel: "downtime has direct human consequences for mission-critical orgs",
    body: "Ransomware doesn't just encrypt files — it shuts you down. Food banks can't print distribution lists. Shelters lose intake records. Youth programs lose contact with families. For mission-critical organizations, downtime isn't just an IT problem.",
  },
  {
    icon: "⚖️",
    title: "Compliance & Legal Liability",
    colorHex: "#fbbf24",
    stat: "Personal",
    statLabel: "board liability possible under HIPAA, COPPA, and CCPA",
    body: "If your nonprofit handles health data, children's information, or California residents' data, a breach is a legal event. Board members can face personal liability. Cyber insurance won't pay if basic hygiene wasn't in place before the incident.",
  },
  {
    icon: "🏛️",
    title: "Grant & Funding Jeopardy",
    colorHex: "#a78bfa",
    stat: "Growing",
    statLabel: "number of grants now require basic cyber hygiene",
    body: "An increasing number of federal grants, foundation grants, and corporate partnerships now require a basic cybersecurity posture as a condition of funding. A public breach — even a small one — can trigger grant reviews and disqualify you from future funding.",
  },
  {
    icon: "👥",
    title: "Reputation & Community Trust",
    colorHex: "#60a5fa",
    stat: "Decade",
    statLabel: "how long full trust recovery can take after a breach",
    body: "Your nonprofit's greatest asset is trust. The communities you serve, volunteers who give their time, and donors who give their money all operate on trust. A single breach that leaks client data or loses donor funds can undo years of relationship-building.",
  },
];

/* ─── SVG ILLUSTRATIONS ─────────────────────────────────── */

function HeroShield() {
  return (
    <svg viewBox="0 0 360 300" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full max-w-sm">
      {/* Outer glow */}
      <ellipse cx="180" cy="160" rx="140" ry="120" fill="rgba(139,92,246,0.06)" />
      {/* Shield */}
      <path d="M180 18 L295 58 L295 148 Q295 228 180 265 Q65 228 65 148 L65 58 Z"
        stroke="rgba(139,92,246,0.45)" strokeWidth="1.5" fill="rgba(139,92,246,0.06)" />
      <path d="M180 42 L272 74 L272 145 Q272 210 180 242 Q88 210 88 145 L88 74 Z"
        stroke="rgba(139,92,246,0.25)" strokeWidth="1" fill="rgba(139,92,246,0.03)" />
      {/* Lock */}
      <rect x="152" y="142" width="56" height="44" rx="9" fill="rgba(139,92,246,0.35)" stroke="rgba(139,92,246,0.7)" strokeWidth="1.5" />
      <path d="M163 142 L163 126 Q163 108 180 108 Q197 108 197 126 L197 142"
        stroke="rgba(139,92,246,0.7)" strokeWidth="2.5" strokeLinecap="round" fill="none" />
      <circle cx="180" cy="160" r="7" fill="rgba(255,255,255,0.6)" />
      <rect x="177" y="160" width="6" height="11" rx="2" fill="rgba(255,255,255,0.6)" />
      {/* Circuit nodes */}
      <circle cx="65" cy="148" r="5" fill="rgba(96,165,250,0.5)" />
      <line x1="65" y1="148" x2="24" y2="120" stroke="rgba(96,165,250,0.3)" strokeWidth="1" />
      <circle cx="24" cy="120" r="4" fill="rgba(96,165,250,0.4)" />
      <line x1="24" y1="120" x2="4" y2="120" stroke="rgba(96,165,250,0.25)" strokeWidth="1" />
      <circle cx="295" cy="148" r="5" fill="rgba(139,92,246,0.5)" />
      <line x1="295" y1="148" x2="336" y2="120" stroke="rgba(139,92,246,0.3)" strokeWidth="1" />
      <circle cx="336" cy="120" r="4" fill="rgba(139,92,246,0.4)" />
      <line x1="336" y1="120" x2="356" y2="120" stroke="rgba(139,92,246,0.25)" strokeWidth="1" />
      {/* Threat orbs */}
      <circle cx="48" cy="60" r="14" fill="rgba(244,63,94,0.12)" stroke="rgba(244,63,94,0.4)" strokeWidth="1" />
      <text x="48" y="65" textAnchor="middle" fontSize="12" fill="rgba(244,63,94,0.9)">⚠</text>
      <circle cx="312" cy="60" r="12" fill="rgba(251,113,133,0.12)" stroke="rgba(251,113,133,0.4)" strokeWidth="1" />
      <text x="312" y="65" textAnchor="middle" fontSize="10" fill="rgba(251,113,133,0.9)">⚠</text>
      <circle cx="180" cy="16" r="10" fill="rgba(244,63,94,0.12)" stroke="rgba(244,63,94,0.35)" strokeWidth="1" />
      <text x="180" y="21" textAnchor="middle" fontSize="9" fill="rgba(244,63,94,0.8)">⚠</text>
      {/* Attack lines (deflected) */}
      <line x1="48" y1="60" x2="120" y2="100" stroke="rgba(244,63,94,0.25)" strokeWidth="1" strokeDasharray="4 3" />
      <line x1="312" y1="60" x2="240" y2="100" stroke="rgba(251,113,133,0.25)" strokeWidth="1" strokeDasharray="4 3" />
      <line x1="180" y1="16" x2="180" y2="48" stroke="rgba(244,63,94,0.25)" strokeWidth="1" strokeDasharray="4 3" />
      {/* Grid scan lines */}
      <line x1="0" y1="80" x2="360" y2="80" stroke="rgba(139,92,246,0.07)" strokeWidth="0.5" />
      <line x1="0" y1="200" x2="360" y2="200" stroke="rgba(139,92,246,0.07)" strokeWidth="0.5" />
      <line x1="0" y1="260" x2="360" y2="260" stroke="rgba(139,92,246,0.07)" strokeWidth="0.5" />
    </svg>
  );
}

function PillarArt({ pillar }: { pillar: (typeof PILLARS)[0] }) {
  const c = pillar.colorHex;
  return (
    <div
      className="relative overflow-hidden rounded-2xl h-44 flex items-center justify-center mb-6"
      style={{
        background: `radial-gradient(ellipse at 50% 60%, ${c}20 0%, ${c}06 55%, transparent 80%)`,
        border: `1px solid ${c}35`,
      }}
    >
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 480 176" preserveAspectRatio="xMidYMid slice">
        {/* Dot grid */}
        {Array.from({ length: 7 }, (_, row) =>
          Array.from({ length: 17 }, (_, col) => (
            <circle key={`${row}-${col}`} cx={col * 30 + 15} cy={row * 26 + 13} r="1.5"
              fill={c} opacity={(((row * 17 + col) * 37) % 100) / 400 + 0.04} />
          ))
        )}
        {/* Corner brackets */}
        <path d="M0 0 L36 0 L36 2 L2 2 L2 36 L0 36 Z" fill={c} opacity="0.35" />
        <path d="M480 0 L444 0 L444 2 L478 2 L478 36 L480 36 Z" fill={c} opacity="0.35" />
        <path d="M0 176 L36 176 L36 174 L2 174 L2 140 L0 140 Z" fill={c} opacity="0.35" />
        <path d="M480 176 L444 176 L444 174 L478 174 L478 140 L480 140 Z" fill={c} opacity="0.35" />
        {/* Cross hairs */}
        <line x1="0" y1="88" x2="480" y2="88" stroke={c} strokeWidth="0.5" opacity="0.15" />
        <line x1="240" y1="0" x2="240" y2="176" stroke={c} strokeWidth="0.5" opacity="0.15" />
      </svg>
      <div className="relative z-10 text-center">
        <div className="text-6xl leading-none mb-3 drop-shadow-lg">{pillar.icon}</div>
        <div className="text-xs font-black uppercase tracking-[0.25em] px-3 py-1 rounded-full"
          style={{ color: c, background: c + "22", border: `1px solid ${c}45` }}>
          Pillar {pillar.id}
        </div>
      </div>
      {/* Stat badge */}
      <div className="absolute bottom-3 right-4 text-right">
        <div className="text-xl font-black" style={{ color: c }}>{pillar.stat}</div>
        <div className="text-[10px] text-muted leading-tight max-w-[140px]">{pillar.statLabel}</div>
      </div>
    </div>
  );
}

function PracticeArt({ p }: { p: (typeof PRACTICES)[0] }) {
  return (
    <div className={`relative overflow-hidden rounded-xl h-28 mb-4 flex items-center justify-center bg-gradient-to-br ${p.gradient}`}
      style={{ border: `1px solid ${p.borderColor}` }}>
      <svg className="absolute inset-0 w-full h-full opacity-30" viewBox="0 0 320 112" preserveAspectRatio="xMidYMid slice">
        {Array.from({ length: 5 }, (_, row) =>
          Array.from({ length: 10 }, (_, col) => (
            <circle key={`${row}-${col}`} cx={col * 34 + 17} cy={row * 24 + 12} r="1.5"
              fill={p.accentColor} opacity={0.3} />
          ))
        )}
      </svg>
      <div className="relative z-10 text-center">
        <div className="text-4xl mb-1">{p.icon}</div>
        <div className="text-xs font-bold uppercase tracking-widest" style={{ color: p.accentColor }}>{p.frequency}</div>
      </div>
    </div>
  );
}

function DangerArt({ d }: { d: (typeof DANGERS)[0] }) {
  const c = d.colorHex;
  return (
    <div className="relative overflow-hidden rounded-xl h-28 mb-4 flex items-center justify-center"
      style={{ background: `radial-gradient(ellipse at center, ${c}18 0%, ${c}05 70%)`, border: `1px solid ${c}30` }}>
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 320 112" preserveAspectRatio="xMidYMid slice">
        {Array.from({ length: 4 }, (_, row) =>
          Array.from({ length: 9 }, (_, col) => (
            <circle key={`${row}-${col}`} cx={col * 38 + 19} cy={row * 28 + 14} r="1.5"
              fill={c} opacity={0.15} />
          ))
        )}
      </svg>
      <div className="relative z-10 text-center">
        <div className="text-4xl mb-1">{d.icon}</div>
        <div className="font-black text-lg leading-none" style={{ color: c }}>{d.stat}</div>
        <div className="text-[10px] text-muted mt-0.5">{d.statLabel}</div>
      </div>
    </div>
  );
}

/* ─── TABS ───────────────────────────────────────────────── */

type TabId = "pillars" | "practices" | "chains" | "dangers";

const TABS: { id: TabId; label: string; icon: string; desc: string }[] = [
  { id: "pillars", label: "The 7 Pillars", icon: "🛡️", desc: "Core vulnerabilities" },
  { id: "practices", label: "Regular Practices", icon: "📅", desc: "Build lasting habits" },
  { id: "chains", label: "Risk Chains", icon: "🔗", desc: "How gaps cascade" },
  { id: "dangers", label: "The Big Dangers", icon: "⚠️", desc: "What's truly at stake" },
];

/* ─── MAIN COMPONENT ─────────────────────────────────────── */

export default function LearnAndPrevent() {
  const nav = useNavigate();
  const [activeTab, setActiveTab] = useState<TabId>("pillars");
  const [activePillar, setActivePillar] = useState(0);

  return (
    <div className="bg-aurora min-h-full">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <Brand />
        <button
          onClick={() => nav("/")}
          className="rounded-full border border-white/10 bg-white/5 px-5 py-2 text-sm font-medium text-muted transition hover:border-brand-400/40 hover:text-brand-300"
        >
          ← Back to Health Check
        </button>
      </header>

      <main className="mx-auto max-w-6xl px-6 pb-24 pt-2">
        {/* ── Hero ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-14 grid items-center gap-10 lg:grid-cols-2"
        >
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-brand-500/30 bg-brand-500/10 px-4 py-1.5 text-sm font-medium text-brand-300">
              <span className="h-2 w-2 rounded-full bg-brand-400" />
              Education & Prevention Guide
            </div>
            <h1 className="text-5xl font-extrabold leading-tight tracking-tight sm:text-6xl">
              Know the Threats.{" "}
              <span className="bg-gradient-to-r from-brand-400 to-accent-400 bg-clip-text text-transparent">
                Defend Your Mission.
              </span>
            </h1>
            <p className="mt-5 max-w-lg text-lg leading-relaxed text-muted">
              Nonprofits are targeted 3× more often than for-profit businesses — and hit harder because
              they have fewer defenses. Use the tabs below to explore vulnerabilities, build habits, understand
              attack chains, and see what's really at stake.
            </p>
            <div className="mt-6 flex flex-wrap gap-4">
              <div className="rounded-xl border border-risk-crit/30 bg-risk-crit/10 px-4 py-3">
                <div className="text-2xl font-black text-risk-crit">3×</div>
                <div className="text-xs text-muted">more targeted than<br />for-profit orgs</div>
              </div>
              <div className="rounded-xl border border-brand-500/30 bg-brand-500/10 px-4 py-3">
                <div className="text-2xl font-black text-brand-300">7</div>
                <div className="text-xs text-muted">core pillars of<br />vulnerability</div>
              </div>
              <div className="rounded-xl border border-risk-low/30 bg-risk-low/10 px-4 py-3">
                <div className="text-2xl font-black text-risk-low">Free</div>
                <div className="text-xs text-muted">fixes exist for<br />every pillar</div>
              </div>
            </div>
          </div>
          <div className="flex justify-center lg:justify-end">
            <HeroShield />
          </div>
        </motion.div>

        {/* ── Tab Bar ── */}
        <div className="mb-10 flex gap-3 overflow-x-auto pb-1">
          {TABS.map((tab) => {
            const isActive = activeTab === tab.id;
            const COLOR: Record<string, { hex: string; bg: string; border: string; label: string }> = {
              pillars:   { hex: "#a78bfa", bg: "rgba(139,92,246,0.2)",  border: "rgba(167,139,250,0.6)", label: "#ddd6fe" },
              practices: { hex: "#60a5fa", bg: "rgba(59,130,246,0.2)",  border: "rgba(96,165,250,0.6)",  label: "#bfdbfe" },
              chains:    { hex: "#fbbf24", bg: "rgba(251,191,36,0.18)", border: "rgba(251,191,36,0.6)",  label: "#fde68a" },
              dangers:   { hex: "#fb7185", bg: "rgba(244,63,94,0.18)",  border: "rgba(251,113,133,0.6)", label: "#fecdd3" },
            };
            const c = COLOR[tab.id];
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={isActive
                  ? { background: c.bg, borderColor: c.border, boxShadow: `0 0 0 1px ${c.hex}40, 0 4px 20px ${c.hex}20` }
                  : {}}
                className={`flex-none rounded-2xl border px-7 py-5 text-left transition-all duration-200 ${
                  isActive
                    ? "border-transparent"
                    : "border-white/8 bg-white/4 hover:border-white/18 hover:bg-white/7"
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-3xl">{tab.icon}</span>
                  <div>
                    <div
                      className="text-base font-extrabold leading-tight tracking-tight"
                      style={isActive ? { color: c.label } : { color: "var(--color-fg)" }}
                    >
                      {tab.label}
                    </div>
                    <div
                      className="text-xs mt-0.5 font-medium"
                      style={isActive ? { color: c.hex } : { color: "var(--color-muted)" }}
                    >
                      {tab.desc}
                    </div>
                  </div>
                </div>
                {isActive && (
                  <div className="mt-3 h-1 rounded-full" style={{ background: `linear-gradient(90deg, ${c.hex}, transparent)` }} />
                )}
              </button>
            );
          })}
        </div>

        {/* ── Tab Content ── */}
        <AnimatePresence mode="wait">
          {activeTab === "pillars" && (
            <TabPanel key="pillars">
              <PillarsTab activePillar={activePillar} setActivePillar={setActivePillar} />
            </TabPanel>
          )}
          {activeTab === "practices" && (
            <TabPanel key="practices">
              <PracticesTab />
            </TabPanel>
          )}
          {activeTab === "chains" && (
            <TabPanel key="chains">
              <ChainsTab />
            </TabPanel>
          )}
          {activeTab === "dangers" && (
            <TabPanel key="dangers">
              <DangersTab />
            </TabPanel>
          )}
        </AnimatePresence>

        {/* ── CTA ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="card card-glow mt-14 p-10 text-center"
        >
          <div className="mb-3 text-4xl">🎯</div>
          <h2 className="text-3xl font-extrabold">Ready to see where your organization stands?</h2>
          <p className="mx-auto mt-3 max-w-lg text-muted">
            Aegis runs a free 2-minute security health check that identifies which of these
            7 pillars are actively exposed for your specific organization — and tells you exactly what to do first.
          </p>
          <button
            onClick={() => nav("/")}
            className="mt-7 rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 px-10 py-4 text-lg font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110"
          >
            Run My Free Health Check →
          </button>
        </motion.div>
      </main>
    </div>
  );
}

/* ─── TAB WRAPPER ────────────────────────────────────────── */

function TabPanel({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.25 }}
    >
      {children}
    </motion.div>
  );
}

/* ─── PILLARS TAB ────────────────────────────────────────── */

function PillarsTab({ activePillar, setActivePillar }: {
  activePillar: number;
  setActivePillar: (i: number) => void;
}) {
  const pillar = PILLARS[activePillar];

  return (
    <div className="flex gap-5 min-h-[600px]">
      {/* Sidebar */}
      <div className="w-60 flex-none space-y-1.5">
        {PILLARS.map((p, i) => (
          <button
            key={p.id}
            onClick={() => setActivePillar(i)}
            className={`w-full rounded-xl border px-4 py-3 text-left transition-all duration-150 ${
              activePillar === i
                ? "border-transparent shadow-[0_0_0_1.5px_var(--active-color)]"
                : "border-white/8 bg-white/3 hover:bg-white/6"
            }`}
            style={activePillar === i
              ? { background: p.colorHex + "18", ["--active-color" as string]: p.colorHex + "60" }
              : {}}
          >
            <div className="flex items-center gap-2.5">
              <span className="text-xl">{p.icon}</span>
              <div className="min-w-0">
                <div className="text-[11px] font-bold uppercase tracking-wider text-muted">
                  Pillar {p.id}
                </div>
                <div className={`truncate text-xs font-semibold leading-tight ${activePillar === i ? "text-fg" : "text-fg/70"}`}>
                  {p.title}
                </div>
              </div>
            </div>
            {activePillar === i && (
              <div className="mt-1.5 h-0.5 rounded-full" style={{ background: p.colorHex + "60" }} />
            )}
          </button>
        ))}
      </div>

      {/* Detail panel */}
      <AnimatePresence mode="wait">
        <motion.div
          key={pillar.id}
          initial={{ opacity: 0, x: 10 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -10 }}
          transition={{ duration: 0.2 }}
          className="card flex-1 p-7 overflow-y-auto"
        >
          <PillarArt pillar={pillar} />

          <h2 className="text-2xl font-extrabold mb-1">{pillar.title}</h2>
          <p className="text-muted leading-relaxed mb-6">{pillar.description}</p>

          {/* Risks */}
          <div className="mb-6 rounded-xl border p-4"
            style={{ borderColor: pillar.colorHex + "30", background: pillar.colorHex + "0a" }}>
            <p className="mb-3 text-xs font-bold uppercase tracking-widest" style={{ color: pillar.colorHex }}>
              ⚠ Key Risks
            </p>
            <ul className="space-y-2">
              {pillar.risks.map((r) => (
                <li key={r} className="flex items-start gap-2.5 text-sm text-fg/85">
                  <span className="mt-0.5 flex-none text-lg" style={{ color: pillar.colorHex }}>›</span>
                  {r}
                </li>
              ))}
            </ul>
          </div>

          {/* Action timeline */}
          <div className="grid gap-3 sm:grid-cols-3">
            {pillar.actions.map((a) => (
              <div key={a.term} className="rounded-xl border border-white/8 bg-white/3 p-4">
                <div className="mb-2 flex items-center gap-1.5">
                  <span>{a.emoji}</span>
                  <span className="text-xs font-bold text-brand-300">{a.term}</span>
                </div>
                <ul className="space-y-2">
                  {a.items.map((item) => (
                    <li key={item} className="flex items-start gap-2 text-xs leading-snug text-fg/75">
                      <span className="mt-0.5 flex-none text-risk-low">✓</span>
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Pillar nav arrows */}
          <div className="mt-6 flex justify-between">
            <button
              disabled={activePillar === 0}
              onClick={() => setActivePillar(activePillar - 1)}
              className="rounded-full border border-white/10 px-4 py-1.5 text-sm text-muted transition hover:border-white/25 hover:text-fg disabled:opacity-30"
            >
              ← Previous
            </button>
            <span className="self-center text-xs text-muted">{activePillar + 1} / {PILLARS.length}</span>
            <button
              disabled={activePillar === PILLARS.length - 1}
              onClick={() => setActivePillar(activePillar + 1)}
              className="rounded-full border border-white/10 px-4 py-1.5 text-sm text-muted transition hover:border-white/25 hover:text-fg disabled:opacity-30"
            >
              Next →
            </button>
          </div>
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

/* ─── PRACTICES TAB ──────────────────────────────────────── */

function PracticesTab() {
  return (
    <div>
      <div className="mb-8">
        <h2 className="text-3xl font-extrabold tracking-tight">Build Habits, Not Just Defenses</h2>
        <p className="mt-2 max-w-2xl text-muted">
          Security isn't a one-time project. These habits separate organizations that survive incidents from
          those that don't — and most take under 10 minutes.
        </p>
      </div>
      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {PRACTICES.map((p, i) => (
          <motion.div
            key={p.frequency}
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35, delay: i * 0.07 }}
            className="card p-5"
          >
            <PracticeArt p={p} />
            <ul className="space-y-3">
              {p.items.map((item) => (
                <li key={item} className="flex items-start gap-2 text-sm leading-snug text-fg/80">
                  <span className="mt-0.5 flex-none" style={{ color: p.accentColor }}>•</span>
                  {item}
                </li>
              ))}
            </ul>
          </motion.div>
        ))}
      </div>

      {/* Summary callout */}
      <div className="mt-8 card p-6 flex items-start gap-5">
        <div className="text-4xl">💡</div>
        <div>
          <h3 className="font-semibold mb-1">The 5-Minute Rule</h3>
          <p className="text-sm text-muted leading-relaxed">
            If a security habit takes more than 5 minutes, staff won't do it consistently. Start with the
            daily and weekly checks — they're fast, high-impact, and build the instincts that catch threats before
            they become incidents. The monthly and yearly tasks are scheduled, not remembered.
          </p>
        </div>
      </div>
    </div>
  );
}

/* ─── CHAINS TAB ─────────────────────────────────────────── */

function ChainsTab() {
  return (
    <div>
      <div className="mb-8">
        <h2 className="text-3xl font-extrabold tracking-tight">How One Small Thing Leads to Disaster</h2>
        <p className="mt-2 max-w-2xl text-muted">
          Attacks don't happen all at once — they unfold step by step, each gap making the next step easier.
          These are real scenarios that happen to nonprofits every year, told in plain terms.
        </p>
      </div>
      <div className="space-y-8">
        {RISK_CHAINS.map((chain, i) => (
          <motion.div
            key={chain.title}
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: i * 0.1 }}
            className="card overflow-hidden"
          >
            {/* Header */}
            <div className="flex items-start gap-4 border-b border-white/6 px-6 py-5"
              style={{ background: chain.colorHex + "10" }}>
              <span className="text-3xl mt-0.5">{chain.icon}</span>
              <div>
                <h3 className="text-xl font-extrabold leading-tight">{chain.title}</h3>
                <div className="mt-1 text-sm font-semibold" style={{ color: chain.colorHex }}>{chain.scale}</div>
                <p className="mt-2 text-sm leading-relaxed text-muted max-w-2xl">{chain.plain}</p>
              </div>
            </div>

            <div className="p-6">
              {/* Step-by-step numbered list */}
              <p className="mb-4 text-xs font-bold uppercase tracking-widest text-muted">How it unfolds →</p>
              <ol className="space-y-3 mb-6">
                {chain.steps.map((step, j) => (
                  <li key={step.label} className="flex items-start gap-4">
                    {/* Number */}
                    <div
                      className="mt-0.5 flex h-7 w-7 flex-none items-center justify-center rounded-full text-xs font-black"
                      style={{ background: chain.colorHex + "25", color: chain.colorHex, border: `1.5px solid ${chain.colorHex}50` }}
                    >
                      {j + 1}
                    </div>
                    {/* Content */}
                    <div className="flex-1 rounded-xl border border-white/8 bg-white/3 px-4 py-3">
                      <div className="font-semibold text-fg text-sm">{step.label}</div>
                      <div className="text-xs text-muted mt-1 leading-relaxed">{step.sub}</div>
                    </div>
                    {/* Connector */}
                    {j < chain.steps.length - 1 && (
                      <div className="absolute" /> /* spacer — visual handled by space-y-3 */
                    )}
                  </li>
                ))}
              </ol>

              {/* Outcome */}
              <div className="rounded-xl border-2 p-5" style={{
                borderColor: chain.colorHex + "50",
                background: chain.colorHex + "0d",
              }}>
                <div className="flex items-start gap-3">
                  <span className="text-2xl mt-0.5">💥</span>
                  <div>
                    <div className="text-sm font-extrabold uppercase tracking-wider mb-1.5" style={{ color: chain.colorHex }}>
                      What ends up happening
                    </div>
                    <p className="text-sm leading-relaxed text-fg/90">{chain.outcome}</p>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="mt-6 card p-6 flex items-start gap-5">
        <div className="text-4xl">💡</div>
        <div>
          <h3 className="font-semibold mb-1">The Good News: You Only Need to Break One Link</h3>
          <p className="text-sm text-muted leading-relaxed">
            Every chain above has five steps — and stopping <em>any one of them</em> breaks the whole attack.
            Enabling two-step login (Pillar 6) alone stops the fake email scam even if the password was already stolen.
            A working backup (Pillar 4) makes ransomware an inconvenience instead of a catastrophe.
            You don't have to fix everything at once — start with one, and each fix makes you meaningfully safer.
          </p>
        </div>
      </div>
    </div>
  );
}

/* ─── DANGERS TAB ────────────────────────────────────────── */

function DangersTab() {
  return (
    <div>
      <div className="mb-8">
        <h2 className="text-3xl font-extrabold tracking-tight">What's Actually at Stake</h2>
        <p className="mt-2 max-w-2xl text-muted">
          These aren't hypothetical scenarios. Every one of these consequences happens to nonprofits
          every year — organizations just like yours, serving communities just like yours.
        </p>
      </div>
      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
        {DANGERS.map((d, i) => (
          <motion.div
            key={d.title}
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35, delay: i * 0.07 }}
            className="card p-5"
          >
            <DangerArt d={d} />
            <h3 className="mb-2 font-semibold">{d.title}</h3>
            <p className="text-sm leading-relaxed text-muted">{d.body}</p>
          </motion.div>
        ))}
      </div>

      <div className="mt-8 card border-risk-crit/20 bg-risk-crit/5 p-6 flex items-start gap-5">
        <div className="text-4xl">🚨</div>
        <div>
          <h3 className="font-semibold mb-1 text-risk-high">The Compounding Effect</h3>
          <p className="text-sm text-muted leading-relaxed">
            These dangers rarely arrive alone. A ransomware attack also triggers donor data exposure,
            which triggers breach notification laws, which triggers funder scrutiny, which threatens
            your next grant cycle — all from a single unpatched computer or one clicked phishing email.
            Nonprofits don't fail cybersecurity audits; they close their doors.
          </p>
        </div>
      </div>
    </div>
  );
}
