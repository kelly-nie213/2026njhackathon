// Breach lookup via XposedOrNot (https://xposedornot.com) — a free public API
// that needs NO key. check-email returns the breach names an address appears in;
// we enrich each name with date + exposed-data-classes from the breach catalog.
// If the API is unreachable we fall back to deterministic simulated data so the
// demo still runs (flagged as source: "demo" so the UI can say so).

const API = "https://api.xposedornot.com/v1";
const UA = "BreachDetector-Hackathon";
const DELAY_MS = Number(process.env.BREACH_DELAY_MS || 350); // be polite to the free API
const CATALOG_TTL_MS = 1000 * 60 * 60; // cache the breach catalog for an hour
const MAX_DETAIL = 14; // cap per-email breach detail rows (count stays accurate)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let catalogCache = null;
let catalogAt = 0;

/** name -> { title, breachDate, dataClasses, description } for enrichment. */
async function getCatalog() {
  if (catalogCache && Date.now() - catalogAt < CATALOG_TTL_MS) return catalogCache;
  try {
    const res = await fetch(`${API}/breaches`, {
      headers: { "user-agent": UA },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return catalogCache || new Map();
    const data = await res.json();
    const map = new Map();
    for (const b of data.exposedBreaches || []) {
      map.set(b.breachID, {
        title: b.breachID,
        breachDate: b.breachedDate || "",
        dataClasses: Array.isArray(b.exposedData) ? b.exposedData : [],
        description: b.exposureDescription || "",
      });
    }
    catalogCache = map;
    catalogAt = Date.now();
    return map;
  } catch {
    return catalogCache || new Map();
  }
}

async function lookupOne(email, catalog) {
  const url = `${API}/check-email/${encodeURIComponent(email)}`;
  const res = await fetch(url, {
    headers: { "user-agent": UA },
    signal: AbortSignal.timeout(15000),
  });
  // 404 / {"Error":"Not found"} both mean "this address isn't in any known breach".
  if (res.status === 404) return { email, status: "clean", breachCount: 0, breaches: [] };
  const data = await res.json().catch(() => ({}));
  if (data?.Error || !Array.isArray(data?.breaches)) {
    return { email, status: "clean", breachCount: 0, breaches: [] };
  }
  const names = data.breaches[0] || [];
  if (names.length === 0) return { email, status: "clean", breachCount: 0, breaches: [] };
  const breaches = names.slice(0, MAX_DETAIL).map((n) =>
    catalog.get(n) || { title: n, breachDate: "", dataClasses: [], description: "" }
  );
  return { email, status: "breached", breachCount: names.length, breaches };
}

/** Check every email against XposedOrNot; simulate per-email only if it fails. */
export async function checkEmails(emails) {
  const catalog = await getCatalog();
  const results = [];
  let liveOk = 0;
  for (let i = 0; i < emails.length; i++) {
    try {
      results.push(await lookupOne(emails[i], catalog));
      liveOk++;
    } catch {
      results.push(simulate(emails[i]));
    }
    if (i < emails.length - 1) await sleep(DELAY_MS);
  }
  return { source: liveOk > 0 ? "live" : "demo", results };
}

/* ----------------------- deterministic fallback ----------------------- */

const BREACH_POOL = [
  { title: "LinkedIn", breachDate: "2021-06-22", dataClasses: ["Email addresses", "Full names", "Job titles", "Phone numbers"] },
  { title: "Collection #1", breachDate: "2019-01-07", dataClasses: ["Email addresses", "Passwords"] },
  { title: "Adobe", breachDate: "2013-10-04", dataClasses: ["Email addresses", "Password hints", "Passwords", "Usernames"] },
  { title: "Canva", breachDate: "2019-05-24", dataClasses: ["Email addresses", "Geographic locations", "Names", "Passwords", "Usernames"] },
  { title: "Dropbox", breachDate: "2012-07-01", dataClasses: ["Email addresses", "Passwords"] },
  { title: "MyFitnessPal", breachDate: "2018-02-01", dataClasses: ["Email addresses", "IP addresses", "Passwords", "Usernames"] },
];

function hash(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function simulate(email) {
  const h = hash(email.toLowerCase());
  if (h % 5 === 0) return { email, status: "clean", breachCount: 0, breaches: [], simulated: true };
  const count = 1 + (h % 4);
  const breaches = [];
  const seen = new Set();
  for (let i = 0; i < count; i++) {
    const b = BREACH_POOL[(h + i * 2654435761) % BREACH_POOL.length];
    if (seen.has(b.title)) continue;
    seen.add(b.title);
    breaches.push({ ...b });
  }
  return { email, status: "breached", breachCount: breaches.length, breaches, simulated: true };
}
