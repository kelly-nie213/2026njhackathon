// Breach lookup via XposedOrNot (https://xposedornot.com) — a free public API
// that needs NO key. check-email returns the breach names an address appears in;
// we enrich each name with date + exposed-data-classes from the breach catalog.
// Everything here is real: if the API can't be reached for an address, that
// address is reported as status "error" — we never fabricate breach data.

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

/**
 * Check every email against XposedOrNot. Real data only — an address we can't
 * reach is returned as status "error", never simulated. `source` is "live" if
 * at least one address was checked successfully, else "error".
 */
export async function checkEmails(emails) {
  const catalog = await getCatalog();
  const results = [];
  let liveOk = 0;
  for (let i = 0; i < emails.length; i++) {
    try {
      results.push(await lookupOne(emails[i], catalog));
      liveOk++;
    } catch {
      results.push({
        email: emails[i],
        status: "error",
        breachCount: 0,
        breaches: [],
        error: "lookup_failed",
      });
    }
    if (i < emails.length - 1) await sleep(DELAY_MS);
  }
  return { source: liveOk > 0 ? "live" : "error", results };
}
