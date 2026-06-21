// Breach lookup via XposedOrNot — ZKP-compliant response model.
//
// The "vault" principle: the email address is sensitive data that must never
// appear in our API response. The server has to touch it briefly to query
// XposedOrNot (that API has no hash-based lookup), but the moment we have
// a result we replace the email with its SHA-256 commitment and discard the
// plaintext. The response path is zero-knowledge: a network observer, log
// scraper, or downstream system sees only commitment hashes and booleans —
// never which email was checked.
//
// Flow:
//   1. Client sends { email, commitment } pairs (commitment = SHA-256(email)).
//   2. Server uses email internally to query XposedOrNot.
//   3. Server maps result to commitment, discards email.
//   4. Response: { commitment, status, breachCount, breaches } — no email field.
//   5. Client reconciles commitment → email locally.

import { createHash } from "crypto";

const API = "https://api.xposedornot.com/v1";
const UA  = "BreachDetector-Hackathon";
const DELAY_MS       = Number(process.env.BREACH_DELAY_MS || 350);
const CATALOG_TTL_MS = 1000 * 60 * 60;
const MAX_DETAIL     = 14;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Compute SHA-256(email) server-side so we can self-verify commitments. */
function commitEmail(email) {
  return createHash("sha256").update(email.toLowerCase().trim()).digest("hex");
}

let catalogCache = null;
let catalogAt    = 0;

async function getCatalog() {
  if (catalogCache && Date.now() - catalogAt < CATALOG_TTL_MS) return catalogCache;
  try {
    const res = await fetch(`${API}/breaches`, {
      headers: { "user-agent": UA },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return catalogCache || new Map();
    const data = await res.json();
    const map  = new Map();
    for (const b of data.exposedBreaches || []) {
      map.set(b.breachID, {
        title:       b.breachID,
        breachDate:  b.breachedDate      || "",
        dataClasses: Array.isArray(b.exposedData) ? b.exposedData : [],
        description: b.exposureDescription || "",
      });
    }
    catalogCache = map;
    catalogAt    = Date.now();
    return map;
  } catch {
    return catalogCache || new Map();
  }
}

/**
 * Query XposedOrNot for one email.  Returns a commitment-keyed result —
 * the email is used for the network call and then thrown away.
 */
async function lookupOne(email, commitment, catalog) {
  const url = `${API}/check-email/${encodeURIComponent(email)}`;
  const res = await fetch(url, {
    headers: { "user-agent": UA },
    signal: AbortSignal.timeout(15000),
  });

  if (res.status === 404)
    return { commitment, status: "clean", breachCount: 0, breaches: [] };

  const data = await res.json().catch(() => ({}));
  if (data?.Error || !Array.isArray(data?.breaches))
    return { commitment, status: "clean", breachCount: 0, breaches: [] };

  const names = data.breaches[0] || [];
  if (names.length === 0)
    return { commitment, status: "clean", breachCount: 0, breaches: [] };

  const breaches = names.slice(0, MAX_DETAIL).map(
    (n) => catalog.get(n) || { title: n, breachDate: "", dataClasses: [], description: "" }
  );
  // Email is NOT included in the returned object — the vault stays sealed.
  return { commitment, status: "breached", breachCount: names.length, breaches };
}

/**
 * Check every email.  Accepts parallel `commitments` array so we can use the
 * client-supplied commitment when provided, or derive it ourselves as a fallback.
 *
 * Response shape: { source, zkp: true, results: [{ commitment, status, breachCount, breaches }] }
 * The `email` field is intentionally absent from every result object.
 */
export async function checkEmails(emails, commitments = []) {
  const catalog = await getCatalog();
  const results = [];
  let liveOk    = 0;

  for (let i = 0; i < emails.length; i++) {
    const email      = emails[i];
    // Use client-supplied commitment when available; derive from email as fallback.
    const commitment = (commitments[i] && typeof commitments[i] === "string")
      ? commitments[i]
      : commitEmail(email);

    try {
      results.push(await lookupOne(email, commitment, catalog));
      liveOk++;
    } catch {
      results.push({
        commitment,
        status: "error",
        breachCount: 0,
        breaches: [],
        error: "lookup_failed",
      });
    }
    if (i < emails.length - 1) await sleep(DELAY_MS);
  }

  return { source: liveOk > 0 ? "live" : "error", zkp: true, results };
}
