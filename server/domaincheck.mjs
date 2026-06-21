// Domain security check — performs REAL DNS lookups (no API key, no third-party
// service) to tell a nonprofit whether attackers can spoof their domain in email.
// We check the three records that decide "can someone send mail that looks like
// it came from you?": SPF, DMARC and DKIM, plus MX (do you receive mail at all).
// Everything here reads live public DNS — nothing is simulated.

import { promises as dns } from "node:dns";
import { normalizeDomain } from "./crawl.mjs";

const DNS_TIMEOUT_MS = 6000;

// Common DKIM selectors used by the big mail providers. DKIM keys live at
// `<selector>._domainkey.<domain>` and there's no way to enumerate the selector
// from DNS, so we probe the well-known ones. Finding one proves DKIM is set up;
// finding none is "not detected" (they could use a custom selector), never a
// hard "fail".
const DKIM_SELECTORS = [
  "google", "default", "selector1", "selector2", "k1", "k2", "dkim",
  "mail", "s1", "s2", "smtp", "zoho", "mandrill", "mxvault",
  "fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3",
];

/** Race a DNS promise against a timeout so one slow resolver can't hang us. */
function withTimeout(promise) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("dns_timeout")), DNS_TIMEOUT_MS)
    ),
  ]);
}

/** resolveTxt → flat array of full record strings ("" if none / lookup fails). */
async function txt(name) {
  try {
    const records = await withTimeout(dns.resolveTxt(name));
    // Each record is an array of chunks that must be concatenated.
    return records.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

async function mx(name) {
  try {
    return await withTimeout(dns.resolveMx(name));
  } catch {
    return [];
  }
}

/**
 * Check the spoofing-protection posture of `domain` via live DNS.
 * Returns a list of plain-language checks; never throws on missing records
 * (a missing record IS the finding). Throws only on an invalid domain.
 */
export async function checkDomainSecurity(domain) {
  const host = normalizeDomain(domain);
  if (!host || !/^[a-z0-9.\-]+\.[a-z]{2,}$/i.test(host)) {
    throw new Error("invalid_domain");
  }

  const [rootTxt, dmarcTxt, mxRecords] = await Promise.all([
    txt(host),
    txt(`_dmarc.${host}`),
    mx(host),
  ]);

  const checks = [];

  /* ---------------------------- SPF ---------------------------- */
  const spf = rootTxt.find((r) => /^v=spf1\b/i.test(r.trim()));
  if (!spf) {
    checks.push({
      id: "spf",
      label: "SPF",
      status: "fail",
      severity: "high",
      title: "No SPF record — anyone can send email as your domain",
      detail:
        "SPF tells the world which mail servers are allowed to send for you. With none, a scammer " +
        "can send 'donation' and 'invoice' emails that appear to come from your real address.",
      evidence: `No v=spf1 TXT record on ${host}`,
    });
  } else {
    const strict = /[-]all\b/.test(spf);
    const soft = /[~?]all\b/.test(spf);
    checks.push({
      id: "spf",
      label: "SPF",
      status: strict ? "pass" : "warn",
      severity: strict ? "low" : "medium",
      title: strict
        ? "SPF record present and strict"
        : "SPF present, but not strict",
      detail: strict
        ? "Only your approved mail servers can send as you, and others are hard-rejected."
        : soft
          ? "SPF exists but ends in a soft-fail (~all/?all), so spoofed mail may still slip through. Tightening to -all is stronger."
          : "SPF exists but doesn't clearly reject unauthorized senders. Consider ending it with -all.",
      evidence: spf.slice(0, 180),
    });
  }

  /* --------------------------- DMARC --------------------------- */
  const dmarc = dmarcTxt.find((r) => /^v=DMARC1\b/i.test(r.trim()));
  if (!dmarc) {
    checks.push({
      id: "dmarc",
      label: "DMARC",
      status: "fail",
      severity: "high",
      title: "No DMARC record — spoofed email isn't blocked or reported",
      detail:
        "DMARC is what actually tells inboxes to reject mail that fakes your domain. Without it, " +
        "impersonation emails to your donors and staff can land in the inbox looking legitimate.",
      evidence: `No v=DMARC1 TXT record on _dmarc.${host}`,
    });
  } else {
    const policy = (dmarc.match(/\bp=(none|quarantine|reject)\b/i)?.[1] || "none").toLowerCase();
    const enforced = policy === "quarantine" || policy === "reject";
    checks.push({
      id: "dmarc",
      label: "DMARC",
      status: policy === "reject" ? "pass" : policy === "quarantine" ? "warn" : "warn",
      severity: policy === "reject" ? "low" : policy === "quarantine" ? "medium" : "high",
      title:
        policy === "reject"
          ? "DMARC fully enforced (p=reject)"
          : policy === "quarantine"
            ? "DMARC partially enforced (p=quarantine)"
            : "DMARC present but not enforced (p=none)",
      detail: enforced
        ? policy === "reject"
          ? "Mail that fakes your domain is rejected outright. This is the recommended setting."
          : "Spoofed mail is sent to spam rather than rejected. Moving to p=reject is the strongest setting."
        : "p=none only monitors — it does NOT stop spoofing. Once you've confirmed legitimate mail passes, move to p=quarantine then p=reject.",
      evidence: dmarc.slice(0, 180),
    });
  }

  /* ---------------------------- MX ----------------------------- */
  checks.push({
    id: "mx",
    label: "Mail (MX)",
    status: mxRecords.length ? "pass" : "warn",
    severity: "low",
    title: mxRecords.length
      ? "Mail servers are configured (MX records found)"
      : "No MX records — this domain doesn't appear to receive email",
    detail: mxRecords.length
      ? "Your domain is set up to receive mail, so SPF/DMARC/DKIM above are what protect it."
      : "No mail servers are listed. If you don't use this domain for email, attackers can still spoof it unless SPF/DMARC are set — so the records above still matter.",
    evidence: mxRecords.length
      ? mxRecords.map((m) => m.exchange).slice(0, 3).join(", ")
      : `No MX records on ${host}`,
  });

  /* --------------------------- DKIM ---------------------------- */
  // Probe common selectors in parallel; stop reporting after the first hit.
  const dkimHits = await Promise.all(
    DKIM_SELECTORS.map(async (sel) => {
      const recs = await txt(`${sel}._domainkey.${host}`);
      return recs.some((r) => /v=DKIM1|k=rsa|p=/i.test(r)) ? sel : null;
    })
  );
  const dkimSelector = dkimHits.find(Boolean);
  checks.push({
    id: "dkim",
    label: "DKIM",
    status: dkimSelector ? "pass" : "warn",
    severity: dkimSelector ? "low" : "medium",
    title: dkimSelector
      ? `DKIM signing detected (selector "${dkimSelector}")`
      : "No DKIM found at common selectors",
    detail: dkimSelector
      ? "Your outgoing mail is cryptographically signed, which helps inboxes trust it's really from you."
      : "We didn't find DKIM at the usual selector names. You may use a custom selector — but if not, " +
        "enabling DKIM (your email provider has a one-click option) strengthens SPF + DMARC.",
    evidence: dkimSelector
      ? `${dkimSelector}._domainkey.${host}`
      : `Checked ${DKIM_SELECTORS.length} common selectors, none found`,
  });

  // Overall spoofability headline: if SPF or DMARC is failing, the domain is
  // realistically spoofable regardless of the softer checks.
  const order = { low: 0, medium: 1, high: 2, critical: 3 };
  const worst = checks.reduce(
    (w, c) => (order[c.severity] > order[w] ? c.severity : w),
    "low"
  );
  const spoofable =
    checks.find((c) => c.id === "dmarc")?.status === "fail" ||
    checks.find((c) => c.id === "spf")?.status === "fail" ||
    checks.find((c) => c.id === "dmarc")?.title.includes("not enforced");

  return { domain: host, checks, worst, spoofable: Boolean(spoofable) };
}
