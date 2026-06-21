// BreachDetector crawler — walks the WHOLE public site (breadth-first, following
// links found on every page, not just the homepage) and extracts the kind of
// personal data an attacker would harvest first: staff emails, personal names
// and phone numbers. Runs server-side (no browser CORS limits) and never logs
// in or touches anything non-public.

const FETCH_TIMEOUT_MS = 9000;
// Safety rails so a giant site (e.g. a blog with thousands of posts) can't run
// forever: stop after MAX_PAGES pages OR once the overall time budget is spent.
const MAX_PAGES = 200;
const TIME_BUDGET_MS = 60000;
// Pages fetched in parallel each wave — faster crawl without hammering the host.
const CONCURRENCY = 6;
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 BreachDetector/1.0";

// Pages most likely to expose people: contact/about/team/board/staff.
const PRIORITY_HINTS = [
  "contact", "about", "team", "staff", "people", "board", "leadership",
  "directors", "director", "our-team", "who-we-are", "volunteer", "members",
];

// Mailboxes that are roles, not people — don't turn these into "names".
const ROLE_MAILBOXES = new Set([
  "info", "contact", "admin", "hello", "help", "support", "office", "mail",
  "volunteer", "volunteers", "donate", "donations", "give", "team", "board",
  "media", "press", "news", "jobs", "careers", "hr", "noreply", "no-reply",
  "donotreply", "webmaster", "sales", "general", "enquiries", "inquiries",
  "events", "membership", "outreach", "communications", "marketing", "billing",
]);

// Titles we trust as a signal that the preceding capitalized words are a person.
const TITLE_RE =
  /(Executive Director|Deputy Director|Managing Director|Program Director|Development Director|Director|President|Vice President|CEO|CFO|COO|Founder|Co-?Founder|Chair(?:person|man|woman)?|Treasurer|Secretary|Coordinator|Manager|Officer|Pastor|Principal|Superintendent|Board Member|Trustee)/;

// Common capitalized words that look like names to a regex but never are.
// If any token of a candidate name is in here, we drop it.
const NAME_STOPWORDS = new Set(
  [
    "the", "our", "your", "this", "that", "these", "those", "and", "for", "with",
    "about", "contact", "home", "read", "more", "learn", "view", "click", "here",
    "new", "now", "all", "get", "join", "sign", "email", "phone", "name", "co",
    "board", "member", "members", "staff", "team", "annual", "report", "reports",
    "privacy", "policy", "terms", "donate", "donation", "volunteer", "volunteers",
    "program", "programs", "event", "events", "news", "press", "media", "blog",
    "youth", "leadership", "service", "services", "community", "foundation",
    "association", "council", "committee", "chapter", "branch", "region", "regional",
    "national", "international", "global", "local", "chief", "officer", "election",
    "guide", "center", "centre", "east", "west", "north", "south", "united",
    "states", "america", "american", "city", "county", "state", "school", "schools",
    "college", "university", "church", "ministry", "fund", "trust", "group", "inc",
    "llc", "department", "office", "mission", "vision", "history", "story", "stories",
    "support", "donors", "donor", "sponsor", "sponsors", "partner", "partners",
    "president", "vice", "student", "students", "junior", "senior", "org", "gmail",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "monday", "tuesday",
    "wednesday", "thursday", "friday", "saturday", "sunday",
  ].map((w) => w.toLowerCase())
);

const ASSET_EXT_RE = /\.(png|jpe?g|gif|svg|webp|css|js|ico|woff2?|ttf|pdf|mp4|webm)$/i;
const JUNK_EMAIL_DOMAINS = [
  "example.com", "example.org", "domain.com", "email.com", "sentry.io",
  "wixpress.com", "wix.com", "squarespace.com", "godaddy.com", "shopify.com",
  "yourdomain.com", "sentry-next.wixpress.com",
];

function timedFetch(url) {
  return fetch(url, {
    headers: { "user-agent": UA, accept: "text/html,application/xhtml+xml" },
    redirect: "follow",
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
}

/** Normalize "aylus.org", "https://aylus.org/x" → "https://aylus.org". */
export function normalizeDomain(input) {
  let d = String(input || "").trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "");
  return d;
}

function sameSite(linkHost, baseHost) {
  return linkHost === baseHost || linkHost === "www." + baseHost || "www." + linkHost === baseHost;
}

/** Strip scripts/styles/tags and decode the handful of entities that matter. */
function visibleText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&#0?39;|&apos;/gi, "'")
    .replace(/&#0?38;/g, "&")
    .replace(/\s+/g, " ");
}

function extractEmails(html) {
  const found = new Set();
  // Catch both plain text and mailto: links (often obfuscated as %20 etc).
  const re = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
  for (const m of html.matchAll(re)) {
    const email = m[0].toLowerCase();
    if (ASSET_EXT_RE.test(email)) continue;
    const domain = email.split("@")[1] || "";
    if (JUNK_EMAIL_DOMAINS.some((j) => domain.endsWith(j))) continue;
    if (/\.(png|jpg|jpeg|gif|svg|webp|js|css)$/i.test(domain)) continue;
    if (email.length > 60) continue;
    found.add(email);
  }
  return found;
}

function nameFromEmail(email) {
  const local = email.split("@")[0];
  if (ROLE_MAILBOXES.has(local)) return null;
  // first.last / first_last / first-last
  const parts = local.split(/[._\-]/).filter((p) => /^[a-z]{2,}$/i.test(p));
  if (parts.length >= 2 && parts.length <= 3) {
    // Drop org-ish locals like "aylus.org" → "Aylus Org".
    if (parts.some((p) => NAME_STOPWORDS.has(p.toLowerCase()))) return null;
    return parts.map((p) => p[0].toUpperCase() + p.slice(1)).join(" ");
  }
  return null;
}

function extractNamesFromText(text) {
  const names = new Set();
  // "Jane Q. Public, Executive Director" style — high precision, title-anchored.
  const re = new RegExp(
    `([A-Z][a-z]+(?:\\s+[A-Z]\\.?)?(?:\\s+[A-Z][a-z]+){1,2})\\s*(?:,|–|—|-|\\bis\\b|\\n)?\\s*(?:our\\s+)?${TITLE_RE.source}`,
    "g"
  );
  for (const m of text.matchAll(re)) {
    const name = m[1].trim().replace(/\s+/g, " ");
    const tokens = name.split(" ");
    if (tokens.length < 2) continue;
    // Reject if any word is a generic/org term (drops "Chief Philanthropy", etc.).
    if (tokens.some((t) => NAME_STOPWORDS.has(t.replace(/\.$/, "").toLowerCase()))) continue;
    names.add(name);
  }
  return names;
}

function extractPhones(text) {
  const found = new Set();
  const re = /(?:\+?1[\s.\-]?)?\(?([2-9]\d{2})\)?[\s.\-]?(\d{3})[\s.\-]?(\d{4})\b/g;
  for (const m of text.matchAll(re)) {
    // Reject matches that are part of a longer digit run (e.g. IDs, zips).
    const before = text[m.index - 1];
    const after = text[m.index + m[0].length];
    if (/\d/.test(before || "") || /\d/.test(after || "")) continue;
    const pretty = `(${m[1]}) ${m[2]}-${m[3]}`;
    found.add(pretty);
  }
  return found;
}

function extractLinks(html, base) {
  const links = new Set();
  for (const m of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1], base);
      if (u.protocol !== "http:" && u.protocol !== "https:") continue;
      u.hash = "";
      links.add(u.toString());
    } catch {
      /* ignore malformed hrefs */
    }
  }
  return [...links];
}

/** Priority score so high-value pages (contact/team/board) get crawled first. */
function score(href) {
  const path = href.toLowerCase();
  return PRIORITY_HINTS.reduce((s, hint) => (path.includes(hint) ? s + 1 : s), 0);
}

/** Stable de-dup key for a URL: drop hash + query so we don't loop on ?utm= etc. */
function pageKey(u) {
  const url = new URL(u);
  url.hash = "";
  url.search = "";
  // Treat "/path" and "/path/" as the same page.
  if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString();
}

/**
 * Crawl the entire public site at `domain` breadth-first — every page we fetch
 * has its own links discovered and queued, so we reach sub-pages, sub-sub-pages
 * and so on, not just the homepage. Bounded by MAX_PAGES and TIME_BUDGET_MS so
 * it always terminates. Best-effort: individual page failures are swallowed so
 * one dead link can't sink the whole scan.
 */
export async function crawlDomain(domain) {
  const host = normalizeDomain(domain);
  if (!host || !/^[a-z0-9.\-]+\.[a-z]{2,}$/i.test(host)) {
    throw new Error("invalid_domain");
  }

  const emails = new Set();
  const names = new Set();
  const phones = new Set();
  const pagesScanned = [];
  const startedAt = Date.now();

  // `seen` = every URL already visited OR queued (so we never enqueue twice).
  const seen = new Set();
  // `frontier` = URLs still waiting to be crawled.
  const frontier = [];

  // Reach the live homepage (prefer https, fall back to www / http).
  let home;
  let homeHtml = "";
  for (const candidate of [`https://${host}/`, `https://www.${host}/`, `http://${host}/`]) {
    try {
      const res = await timedFetch(candidate);
      if (res.ok) {
        home = res.url;
        homeHtml = await res.text();
        break;
      }
    } catch {
      /* try next */
    }
  }
  if (!home) throw new Error("unreachable");

  const baseHost = new URL(home).hostname.replace(/^www\./, "");

  const ingest = (html) => {
    for (const e of extractEmails(html)) emails.add(e);
    const text = visibleText(html);
    for (const n of extractNamesFromText(text)) names.add(n);
    for (const p of extractPhones(text)) phones.add(p);
  };

  // Queue a link if it's on the same site, not an asset, and not seen before.
  const enqueue = (href) => {
    let key;
    try {
      const u = new URL(href);
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      const h = u.hostname.replace(/^www\./, "");
      if (!sameSite(h, baseHost)) return;
      if (ASSET_EXT_RE.test(u.pathname)) return;
      key = pageKey(href);
    } catch {
      return;
    }
    if (seen.has(key)) return;
    seen.add(key);
    frontier.push(key);
  };

  // Seed from the homepage (already fetched) and queue everything it links to.
  seen.add(pageKey(home));
  pagesScanned.push(home);
  ingest(homeHtml);
  for (const link of extractLinks(homeHtml, home)) enqueue(link);

  // Breadth-first: each wave fetches up to CONCURRENCY pages in parallel and
  // feeds their newly-discovered links back into the frontier.
  while (
    frontier.length > 0 &&
    pagesScanned.length < MAX_PAGES &&
    Date.now() - startedAt < TIME_BUDGET_MS
  ) {
    // Visit the most promising pages first.
    frontier.sort((a, b) => score(b) - score(a));
    const slots = Math.min(CONCURRENCY, MAX_PAGES - pagesScanned.length);
    const batch = frontier.splice(0, slots);

    await Promise.all(
      batch.map(async (url) => {
        try {
          const res = await timedFetch(url);
          if (!res.ok) return;
          const ct = res.headers.get("content-type") || "";
          if (!ct.includes("html")) return;
          const html = await res.text();
          ingest(html);
          pagesScanned.push(res.url);
          // Make sure a redirected URL isn't re-queued later.
          seen.add(pageKey(res.url));
          for (const link of extractLinks(html, res.url)) enqueue(link);
        } catch {
          /* skip dead/slow page */
        }
      })
    );
  }

  // Derive additional names from the email local-parts we found.
  for (const e of emails) {
    const n = nameFromEmail(e);
    if (n) names.add(n);
  }

  return {
    domain: host,
    pagesScanned,
    emails: [...emails].sort(),
    names: [...names].sort(),
    phones: [...phones].sort(),
  };
}
