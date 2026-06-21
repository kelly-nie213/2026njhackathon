// Domain reputation / threat-intelligence check — asks live blocklists & threat
// feeds whether a domain is currently flagged for malware or phishing. This is
// REAL: every verdict comes from an external source's live answer. We never ask
// an LLM to "guess" if a domain is compromised (that would hallucinate and go
// stale). Sources we can't reach — or that need an API key you haven't set — are
// reported honestly as "not checked", never as a pass.
//
// Sources:
//   • URLhaus (abuse.ch)        — malware URL/host feed. No key.
//   • OpenPhish community feed   — active phishing URLs. No key.
//   • Google Safe Browsing      — phishing/malware blocklist. Optional key (GOOGLE_SAFE_BROWSING_KEY).
//   • VirusTotal                — 70+ engines. Optional key (VIRUSTOTAL_API_KEY).

import { normalizeDomain } from "./crawl.mjs";

const TIMEOUT_MS = 9000;
const UA = "Aegis-Reputation/1.0";
const FEED_TTL_MS = 1000 * 60 * 30; // cache the OpenPhish feed for 30 min

const SEV_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

let phishFeed = null;
let phishFeedAt = 0;

function timeout(ms) {
  return AbortSignal.timeout(ms);
}

/** Does a feed URL belong to `host` (exact host or a subdomain)? */
function urlMatchesHost(urlStr, host) {
  try {
    const h = new URL(urlStr).hostname.replace(/^www\./, "").toLowerCase();
    return h === host || h.endsWith("." + host);
  } catch {
    return false;
  }
}

/* ------------------------------- URLhaus ------------------------------- */
async function checkURLhaus(host) {
  try {
    // abuse.ch added auth in 2024 — a free Auth-Key (auth.abuse.ch) is required.
    const key = process.env.ABUSE_CH_AUTH_KEY || process.env.URLHAUS_API_KEY;
    const headers = { "content-type": "application/x-www-form-urlencoded", "user-agent": UA };
    if (key) headers["Auth-Key"] = key;
    const res = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      headers,
      body: `host=${encodeURIComponent(host)}`,
      signal: timeout(TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false };
    const data = await res.json().catch(() => null);
    if (!data || !data.query_status) return { ok: false };
    if (data.query_status === "no_results") return { ok: true, listed: false };
    if (data.query_status === "ok") {
      const urls = Array.isArray(data.urls) ? data.urls : [];
      const online = urls.filter((u) => u.url_status === "online").length;
      return {
        ok: true,
        listed: true,
        count: Number(data.url_count) || urls.length,
        online,
        threats: [...new Set(urls.map((u) => u.threat).filter(Boolean))].slice(0, 4),
      };
    }
    return { ok: false }; // invalid_host / auth required / etc.
  } catch {
    return { ok: false };
  }
}

/* ------------------------------ OpenPhish ------------------------------ */
async function getPhishFeed() {
  if (phishFeed && Date.now() - phishFeedAt < FEED_TTL_MS) return phishFeed;
  try {
    const res = await fetch("https://openphish.com/feed.txt", {
      headers: { "user-agent": UA },
      signal: timeout(TIMEOUT_MS),
    });
    if (!res.ok) return phishFeed; // keep stale cache if any
    const text = await res.text();
    phishFeed = text.split("\n").map((l) => l.trim()).filter(Boolean);
    phishFeedAt = Date.now();
    return phishFeed;
  } catch {
    return phishFeed;
  }
}

async function checkOpenPhish(host) {
  const feed = await getPhishFeed();
  if (!feed) return { ok: false };
  const hits = feed.filter((u) => urlMatchesHost(u, host));
  return { ok: true, listed: hits.length > 0, count: hits.length };
}

/* -------------------------- Google Safe Browsing ----------------------- */
async function checkSafeBrowsing(host) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key) return { ok: false, noKey: true };
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
      {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": UA },
        body: JSON.stringify({
          client: { clientId: "aegis", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: `http://${host}/` }, { url: `https://${host}/` }],
          },
        }),
        signal: timeout(TIMEOUT_MS),
      }
    );
    if (!res.ok) return { ok: false };
    const data = await res.json().catch(() => ({}));
    const matches = Array.isArray(data.matches) ? data.matches : [];
    return { ok: true, listed: matches.length > 0, threats: [...new Set(matches.map((m) => m.threatType))] };
  } catch {
    return { ok: false };
  }
}

/* ------------------------------ VirusTotal ----------------------------- */
async function checkVirusTotal(host) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return { ok: false, noKey: true };
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(host)}`, {
      headers: { "x-apikey": key, "user-agent": UA },
      signal: timeout(TIMEOUT_MS),
    });
    if (!res.ok) return { ok: false };
    const data = await res.json().catch(() => null);
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) return { ok: false };
    const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
    return { ok: true, listed: malicious > 0, malicious, total: malicious + (stats.harmless || 0) + (stats.undetected || 0) };
  } catch {
    return { ok: false };
  }
}

/**
 * Check `domain` against live threat-intel sources. Throws only on an invalid
 * domain. Returns per-source checks (only for sources we actually reached), plus
 * a transparent list of sources we could NOT check.
 */
export async function checkReputation(domain) {
  const host = normalizeDomain(domain);
  if (!host || !/^[a-z0-9.\-]+\.[a-z]{2,}$/i.test(host)) {
    throw new Error("invalid_domain");
  }

  const [urlhaus, openphish, gsb, vt] = await Promise.all([
    checkURLhaus(host),
    checkOpenPhish(host),
    checkSafeBrowsing(host),
    checkVirusTotal(host),
  ]);

  const checks = [];
  const notChecked = [];

  // URLhaus
  if (urlhaus.ok) {
    checks.push(
      urlhaus.listed
        ? {
            id: "urlhaus", label: "URLhaus", status: "fail",
            severity: urlhaus.online ? "critical" : "high",
            title: `Listed on URLhaus (${urlhaus.count} malware URL${urlhaus.count === 1 ? "" : "s"})`,
            detail: `abuse.ch's URLhaus has recorded malware being distributed from this domain${urlhaus.online ? ` — ${urlhaus.online} still live` : " (currently offline)"}. This usually means the site is compromised.`,
            evidence: urlhaus.threats?.length ? urlhaus.threats.join(", ") : "see urlhaus.abuse.ch",
          }
        : {
            id: "urlhaus", label: "URLhaus", status: "pass", severity: "low",
            title: "Not listed on URLhaus", detail: "No known malware URLs are associated with this domain.",
            evidence: "query_status: no_results",
          }
    );
  } else {
    notChecked.push({
      name: "URLhaus",
      reason: process.env.ABUSE_CH_AUTH_KEY || process.env.URLHAUS_API_KEY
        ? "source unavailable"
        : "needs free abuse.ch Auth-Key (set ABUSE_CH_AUTH_KEY)",
    });
  }

  // OpenPhish
  if (openphish.ok) {
    checks.push(
      openphish.listed
        ? {
            id: "openphish", label: "OpenPhish", status: "fail", severity: "critical",
            title: "Active phishing page detected (OpenPhish)",
            detail: "This domain appears in OpenPhish's live feed of active phishing URLs — a strong sign it's compromised or malicious.",
            evidence: `${openphish.count} URL(s) in feed`,
          }
        : {
            id: "openphish", label: "OpenPhish", status: "pass", severity: "low",
            title: "Not in the OpenPhish feed", detail: "No active phishing pages on this domain in the current feed.",
            evidence: "not present in feed",
          }
    );
  } else {
    notChecked.push({ name: "OpenPhish", reason: "feed unavailable" });
  }

  // Google Safe Browsing
  if (gsb.ok) {
    checks.push(
      gsb.listed
        ? {
            id: "gsb", label: "Safe Browsing", status: "fail", severity: "critical",
            title: "Flagged by Google Safe Browsing",
            detail: "Google's blocklist flags this domain — browsers like Chrome will warn or block visitors.",
            evidence: (gsb.threats || []).join(", ") || "threat match",
          }
        : {
            id: "gsb", label: "Safe Browsing", status: "pass", severity: "low",
            title: "Clean on Google Safe Browsing", detail: "Not on Google's malware/phishing blocklist.",
            evidence: "no threat match",
          }
    );
  } else {
    notChecked.push({ name: "Google Safe Browsing", reason: gsb.noKey ? "no API key (set GOOGLE_SAFE_BROWSING_KEY)" : "source unavailable" });
  }

  // VirusTotal
  if (vt.ok) {
    checks.push(
      vt.listed
        ? {
            id: "virustotal", label: "VirusTotal", status: "fail",
            severity: vt.malicious >= 3 ? "critical" : "high",
            title: `${vt.malicious} security vendor(s) flag this domain (VirusTotal)`,
            detail: "Multiple antivirus/URL-scanning engines on VirusTotal consider this domain malicious or suspicious.",
            evidence: `${vt.malicious}/${vt.total} engines`,
          }
        : {
            id: "virustotal", label: "VirusTotal", status: "pass", severity: "low",
            title: "Clean on VirusTotal", detail: "No engines on VirusTotal flag this domain.",
            evidence: `0/${vt.total} engines`,
          }
    );
  } else {
    notChecked.push({ name: "VirusTotal", reason: vt.noKey ? "no API key (set VIRUSTOTAL_API_KEY)" : "source unavailable" });
  }

  // If we couldn't reach ANY source, say so honestly rather than imply "clean".
  if (checks.length === 0) {
    checks.push({
      id: "none", label: "Reputation", status: "warn", severity: "medium",
      title: "Couldn't reach any reputation source",
      detail: "We couldn't get a live answer from the threat-intel feeds right now. Try again later; this is not a clean bill of health.",
      evidence: "all sources unavailable",
    });
  }

  const flagged = checks.some((c) => c.status === "fail");
  const worst = checks.reduce((w, c) => (SEV_ORDER[c.severity] > SEV_ORDER[w] ? c.severity : w), "low");
  const sourcesChecked = checks.filter((c) => c.id !== "none").length;

  return { domain: host, flagged, worst, checks, notChecked, sourcesChecked };
}
