// Breach lookup via LeakCheck (https://leakcheck.io) public API — free, NO key.
//   GET /api/public?check=<email>
//   breached -> {"success":true,"found":N,"fields":[...],"sources":[{name,date}]}
//   clean    -> {"success":false,"error":"Not found"}   (HTTP 200)
// `fields` lists the kinds of data exposed across the breaches (password, id,
// phone, ssn, ...). Everything here is real: an address we can't check is
// reported as status "error" — we never fabricate breach data.
//
// (Switched off XposedOrNot: its keyless API aggressively rate-limited our IP
// and HIBP's email API requires a paid key. LeakCheck's public endpoint is free.)

const API = "https://leakcheck.io/api/public";
const UA = "BreachDetector-Hackathon";
const DELAY_MS = Number(process.env.BREACH_DELAY_MS || 350); // be polite to the free API

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// LeakCheck `fields` are terse machine names; humanize the common ones for the UI.
const FIELD_LABELS = {
  password: "Passwords",
  id: "Account ID",
  username: "Usernames",
  name: "Full name",
  first_name: "First name",
  last_name: "Last name",
  middle_name: "Middle name",
  profile_name: "Profile name",
  email: "Email addresses",
  phone: "Phone numbers",
  address: "Physical addresses",
  city: "City",
  state: "State",
  zip: "ZIP code",
  country: "Country",
  dob: "Date of birth",
  gender: "Gender",
  ssn: "Social Security numbers",
  ip: "IP addresses",
  ip1: "IP addresses",
  ip2: "IP addresses",
  origin: "Account origin",
  company_name: "Employer",
};

function humanizeFields(fields) {
  const out = [];
  for (const f of Array.isArray(fields) ? fields : []) {
    const label = FIELD_LABELS[f] || f.replace(/_/g, " ");
    if (!out.includes(label)) out.push(label);
  }
  return out;
}

async function lookupOne(email) {
  const url = `${API}?check=${encodeURIComponent(email)}`;
  const res = await fetch(url, {
    headers: { "user-agent": UA, accept: "application/json" },
    signal: AbortSignal.timeout(15000),
  });
  // Non-OK status (429 rate-limit, 5xx, ...) is a failure to check, NOT a clean
  // result — throw so the caller records it as "error", never a false "no breach".
  if (!res.ok) throw new Error(`leakcheck ${res.status}`);
  const data = await res.json().catch(() => ({}));

  if (data?.success === true) {
    const dataClasses = humanizeFields(data.fields);
    const sources = Array.isArray(data.sources) ? data.sources : [];
    const breaches = sources.map((s) => ({
      title: s.name || "Unknown source",
      breachDate: s.date ? `${s.date}-01`.slice(0, 10) : "",
      dataClasses,
      description: "",
    }));
    return {
      email,
      status: "breached",
      breachCount: typeof data.found === "number" ? data.found : breaches.length,
      breaches,
    };
  }

  // success:false with "Not found" => genuinely clean. Any other error (e.g.
  // "Too many requests", "Invalid email") is a failed check, not a clean one.
  const err = String(data?.error || "");
  if (/not found/i.test(err)) return { email, status: "clean", breachCount: 0, breaches: [] };
  throw new Error(err || "unexpected response");
}

/**
 * Check every email against LeakCheck. Real data only — an address we can't
 * reach is returned as status "error", never simulated. `source` is "live" if
 * at least one address was checked successfully, else "error".
 */
export async function checkEmails(emails) {
  const results = [];
  let liveOk = 0;
  for (let i = 0; i < emails.length; i++) {
    let result = null;
    // Retry transient failures (429 rate-limit / 5xx) with exponential backoff
    // before giving up and recording the address as "error".
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        result = await lookupOne(emails[i]);
        liveOk++;
        break;
      } catch (e) {
        const msg = String(e?.message);
        const rateLimited = /\b429\b|too many requests/i.test(msg);
        if (attempt < 2 && rateLimited) {
          await sleep(DELAY_MS * Math.pow(3, attempt + 1)); // ~1s, ~3s
          continue;
        }
        result = {
          email: emails[i],
          status: "error",
          breachCount: 0,
          breaches: [],
          error: rateLimited ? "rate_limited" : "lookup_failed",
        };
      }
    }
    results.push(result);
    if (i < emails.length - 1) await sleep(DELAY_MS);
  }
  return { source: liveOk > 0 ? "live" : "error", results };
}
