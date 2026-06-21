import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Brand } from "../components/Brand";
import { useScan } from "../store";
import type { OrgType } from "../lib/types";

const ORG_TYPES: { value: OrgType; label: string }[] = [
  { value: "food-bank", label: "Food bank" },
  { value: "donation-center", label: "Donation center" },
  { value: "youth-nonprofit", label: "Youth / family nonprofit" },
  { value: "community-org", label: "Community org" },
  { value: "other", label: "Other" },
];

export default function Onboarding() {
  const nav = useNavigate();
  const { start } = useScan();

  const [orgName, setOrgName] = useState("");
  const [domain, setDomain] = useState("");
  const [emails, setEmails] = useState("");
  const [orgType, setOrgType] = useState<OrgType>("food-bank");

  const fillExample = () => {
    setOrgName("GRACE Community Food Bank");
    setDomain("gracefoodbank.org");
    setEmails("director@gracefoodbank.org\nvolunteers@gracefoodbank.org\nbookkeeper@gracefoodbank.org");
    setOrgType("food-bank");
  };

  const canSubmit = orgName.trim() && domain.trim();

  const submit = () => {
    if (!canSubmit) return;
    start({
      orgName: orgName.trim(),
      domain: domain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, ""),
      emails: emails
        .split(/[\n,]/)
        .map((e) => e.trim())
        .filter(Boolean),
      orgType,
    });
    nav("/scanning");
  };

  return (
    <div className="bg-aurora min-h-full">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <Brand />
        <div className="flex items-center gap-3">
          <button
            onClick={() => nav("/learn")}
            className="rounded-full border border-brand-500/40 bg-brand-500/10 px-5 py-2 text-sm font-medium text-brand-300 transition hover:bg-brand-500/20"
          >
            📚 Learn & Prevent
          </button>
          <button
            onClick={() => nav("/triage")}
            className="rounded-full border border-risk-high/40 bg-risk-crit/10 px-5 py-2 text-sm font-medium text-risk-high transition hover:bg-risk-crit/20"
          >
            ⚑ Something already happened?
          </button>
          <span className="hidden rounded-full border border-white/10 px-5 py-2 text-sm font-medium text-muted sm:inline">
            Free • No software to install
          </span>
        </div>
      </header>

      <main className="mx-auto grid max-w-6xl items-center gap-12 px-6 pb-16 pt-6 lg:grid-cols-2">
        {/* Pitch side */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="mb-5">
            <div className="mb-2 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.18em] text-muted">
              <span className="text-brand-400">★</span> Our Team Motto
            </div>
            <p className="text-2xl font-extrabold leading-snug"
              style={{ background: "linear-gradient(90deg, #c4b5fd 0%, #60a5fa 50%, #34d399 100%)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>
              Protecting the Organizations that Protect Our Communities
            </p>
          </div>
          <h1 className="text-4xl font-extrabold leading-[1.1] tracking-tight sm:text-5xl">
            Find out what an{" "}
            <span className="bg-gradient-to-r from-brand-400 to-accent-400 bg-clip-text text-transparent">
              AI attacker
            </span>{" "}
            already knows about your nonprofit.
          </h1>
          <p className="mt-5 max-w-md text-[15px] leading-relaxed text-muted">
            Small nonprofits hold donor lists, financial records and volunteer data — but
            rarely have anyone watching for breaches. Aegis runs a 2-minute health check and
            tells you, in plain English, what's exposed, what could happen, and exactly what
            to do next.
          </p>

          <ul className="mt-7 space-y-3 text-sm">
            {[
              "See which of your data is exposed — and the damage if it leaks",
              "Understand the most likely AI-powered attack against you",
              "Get a prioritized, jargon-free action plan",
            ].map((t) => (
              <li key={t} className="flex items-start gap-3 text-fg/90">
                <span className="mt-0.5 grid h-5 w-5 flex-none place-items-center rounded-full bg-brand-500/20 text-brand-300">
                  ✓
                </span>
                {t}
              </li>
            ))}
          </ul>
        </motion.div>

        {/* Form side */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="card card-glow p-7"
        >
          <h2 className="text-xl font-semibold">Start your free health check</h2>
          <p className="mt-1 text-sm text-muted">
            We only use this to scan public exposure. Nothing is shared.
          </p>

          <div className="mt-6 space-y-4">
            <Field label="Organization name">
              <input
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="GRACE Community Food Bank"
                className="input"
              />
            </Field>

            <Field label="Website / email domain">
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="gracefoodbank.org"
                className="input"
              />
            </Field>

            <Field label="Staff emails to check (one per line, optional)">
              <textarea
                value={emails}
                onChange={(e) => setEmails(e.target.value)}
                rows={3}
                placeholder="director@gracefoodbank.org"
                className="input resize-none"
              />
            </Field>

            <Field label="Organization type">
              <div className="flex flex-wrap gap-2">
                {ORG_TYPES.map((t) => (
                  <button
                    key={t.value}
                    onClick={() => setOrgType(t.value)}
                    className={`rounded-full border px-3 py-1.5 text-xs transition ${
                      orgType === t.value
                        ? "border-brand-400 bg-brand-500/20 text-brand-200"
                        : "border-white/10 text-muted hover:border-white/25"
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </Field>
          </div>

          <button
            onClick={submit}
            disabled={!canSubmit}
            className="mt-6 w-full rounded-xl bg-gradient-to-r from-brand-500 to-accent-500 py-3 font-semibold text-white shadow-lg shadow-brand-600/30 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Run my health check →
          </button>
          <button
            onClick={fillExample}
            className="mt-3 w-full text-center text-xs text-muted underline-offset-4 hover:text-brand-300 hover:underline"
          >
            Try it with a sample food bank
          </button>
        </motion.div>
      </main>

      <style>{`
        .input {
          width: 100%;
          border-radius: 0.75rem;
          background: rgba(255,255,255,0.04);
          border: 1px solid rgba(255,255,255,0.1);
          padding: 0.7rem 0.9rem;
          font-size: 0.9rem;
          color: var(--color-fg);
          outline: none;
          transition: border-color .15s, box-shadow .15s;
        }
        .input:focus { border-color: var(--color-brand-400); box-shadow: 0 0 0 3px rgba(139,92,246,0.18); }
        .input::placeholder { color: #6b6b85; }
      `}</style>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-muted">{label}</span>
      {children}
    </label>
  );
}
