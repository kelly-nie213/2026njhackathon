// BreachDetector crawler — walks the WHOLE public site (breadth-first, following
// links found on every page, not just the homepage) and extracts the kind of
// personal data an attacker would harvest first: staff emails, personal names
// and phone numbers. Runs server-side (no browser CORS limits) and never logs
// in or touches anything non-public.

import { assertPublicHost } from "./safefetch.mjs";

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

// Titles split by trust level.
// STRONG titles almost never appear inside product/feature names, so on their own
// they're a reliable "the preceding words are a person" signal.
// WEAK titles ("Manager", "Officer", "Coordinator") show up constantly in product
// names — "Google Tag Manager", "Ad Manager", "Password Manager" — so for those we
// ALSO require the candidate's first word to be a recognizable given name.
const STRONG_TITLE_SRC =
  "Executive Director|Deputy Director|Managing Director|Program Director|Development Director|Director|Vice President|President|CEO|CFO|COO|CTO|Co-?Founder|Founder|Chair(?:person|man|woman)?|Treasurer|Secretary|Pastor|Principal|Superintendent|Board Member|Trustee";
const WEAK_TITLE_SRC = "Coordinator|Manager|Officer";
const TITLE_SRC = `(?:${STRONG_TITLE_SRC}|${WEAK_TITLE_SRC})`;
const STRONG_TITLE_RE = new RegExp(`^(?:${STRONG_TITLE_SRC})$`, "i");

// Common given names — used to confirm that something the regex thinks is a name
// really starts like a person's name. Keeps recall reasonable while killing
// product-name false positives. (Not exhaustive; strong titles are the other path.)
const COMMON_FIRST_NAMES = new Set(
  (
    "james robert john michael david william richard joseph thomas charles christopher daniel matthew anthony mark donald steven andrew paul joshua kenneth kevin brian george timothy ronald edward jason jeffrey ryan jacob gary nicholas eric jonathan stephen larry justin scott brandon benjamin samuel gregory alexander patrick frank raymond jack dennis jerry tyler aaron jose henry adam douglas nathan peter zachary kyle walter harold jeremy ethan carl keith roger gerald christian terry sean arthur austin noah lawrence jesse joe bryan billy jordan albert dylan bruce gabriel alan juan logan wayne ralph roy eugene randy vincent russell louis philip bobby johnny bradley " +
    "mary patricia jennifer linda elizabeth barbara susan jessica sarah karen lisa nancy betty margaret sandra ashley kimberly emily donna michelle dorothy carol amanda melissa deborah stephanie rebecca sharon laura cynthia kathleen amy angela shirley anna brenda pamela emma nicole helen samantha katherine christine debra rachel carolyn janet catherine maria heather diane ruth julie olivia joyce virginia victoria kelly lauren christina joan evelyn judith megan andrea cheryl hannah jacqueline martha gloria teresa ann sara madison frances kathryn janice jean abigail alice julia judy sophia grace denise amber marilyn danielle beverly isabella theresa diana natalie brittany charlotte marie kayla alexis lori " +
    "mohammed muhammad ahmed ali omar hassan ibrahim yusuf fatima aisha layla zainab mei wei ling jing chen hiro yuki kenji sofia mateo santiago diego carlos luis miguel jorge javier ana elena ivan olga sergei dmitri raj priya amit sanjay anita deepak vijay arjun ananya kwame amara chidi ngozi jin min seo ji-woo aaliyah malik jamal imani kofi sven lars anders ingrid freya"
  )
    .split(/\s+/)
    .filter(Boolean)
);

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

// Words drawn from the site's own domain that should never be treated as a
// person's name (e.g. "google" from google.com). We deliberately skip any token
// that is also a common first name (so "grace" from grace-foodbank.org still
// counts as a real name if a staffer is called Grace).
function brandRejectTokens(host) {
  const labels = host.toLowerCase().split(".");
  labels.pop(); // drop the TLD (.com/.org/...)
  // Drop a 2nd-level public suffix label like the "co" in "co.uk".
  if (labels.length > 1 && ["co", "com", "org", "net", "gov", "edu", "ac"].includes(labels[labels.length - 1])) {
    labels.pop();
  }
  const tokens = new Set();
  for (const label of labels) {
    if (label === "www") continue;
    for (const part of label.split("-")) {
      if (part.length >= 3 && !COMMON_FIRST_NAMES.has(part)) tokens.add(part);
    }
  }
  return tokens;
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

function nameFromEmail(email, brand) {
  const local = email.split("@")[0];
  if (ROLE_MAILBOXES.has(local)) return null;
  // first.last / first_last / first-last
  const parts = local.split(/[._\-]/).filter((p) => /^[a-z]{2,}$/i.test(p));
  if (parts.length >= 2 && parts.length <= 3) {
    const lower = parts.map((p) => p.toLowerCase());
    // Drop org-ish locals ("aylus.org" → "Aylus Org") and brand tokens.
    if (lower.some((p) => NAME_STOPWORDS.has(p) || brand.has(p))) return null;
    // A first.last mailbox is reliable only if it starts like a real given name.
    if (!COMMON_FIRST_NAMES.has(lower[0])) return null;
    return parts.map((p) => p[0].toUpperCase() + p.slice(1)).join(" ");
  }
  return null;
}

function extractNamesFromText(text, brand) {
  const names = new Set();
  // "Jane Q. Public, Executive Director" style — title-anchored, then gated so we
  // don't mistake product names ("Google Tag Manager") for people.
  const re = new RegExp(
    `([A-Z][a-z]+(?:\\s+[A-Z]\\.?)?(?:\\s+[A-Z][a-z]+){1,2})\\s*(?:,|–|—|-|\\bis\\b|\\n)?\\s*(?:our\\s+)?(${TITLE_SRC})`,
    "g"
  );
  for (const m of text.matchAll(re)) {
    const name = m[1].trim().replace(/\s+/g, " ");
    const title = m[2];
    const tokens = name.split(" ");
    if (tokens.length < 2) continue;
    const lower = tokens.map((t) => t.replace(/\.$/, "").toLowerCase());
    // Reject generic/org terms ("Chief Philanthropy", "Annual Report", …).
    if (lower.some((t) => NAME_STOPWORDS.has(t))) continue;
    // Reject the site's own brand words ("Google Tag", "Acme Foundation", …).
    if (lower.some((t) => brand.has(t))) continue;
    // Accept only if it reads like a person: a known given name, OR a strong
    // leadership title that products don't borrow. Weak titles (Manager/Officer)
    // require the given-name check, which is what kills "… Password Manager".
    const knownFirstName = COMMON_FIRST_NAMES.has(lower[0]);
    const strongTitle = STRONG_TITLE_RE.test(title);
    if (!knownFirstName && !strongTitle) continue;
    names.add(name);
  }
  return names;
}

function extractPhones(text) {
  const found = new Set();
  // North-American format. Area code and exchange must both start 2-9 (NANP rule).
  const re = /(?:\+?1[\s.\-]?)?\(?([2-9]\d{2})\)?[\s.\-]?([2-9]\d{2})[\s.\-]?(\d{4})\b/g;
  for (const m of text.matchAll(re)) {
    // Reject matches that are part of a longer digit run (e.g. IDs, zips).
    const before = text[m.index - 1];
    const after = text[m.index + m[0].length];
    if (/\d/.test(before || "") || /\d/.test(after || "")) continue;
    const [, area, exch, line] = m;
    // Reject service codes (N11 like 411/911) in the area code or exchange.
    if (/^[2-9]11$/.test(area) || /^[2-9]11$/.test(exch)) continue;
    // Reject the reserved "fictional" range 555-0100…555-0199 used in examples.
    if (exch === "555" && line >= "0100" && line <= "0199") continue;
    found.add(`(${area}) ${exch}-${line}`);
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
  // SSRF guard: refuse hosts that resolve to internal/loopback/metadata IPs.
  await assertPublicHost(host);

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
  const brand = brandRejectTokens(baseHost);

  const ingest = (html) => {
    for (const e of extractEmails(html)) emails.add(e);
    const text = visibleText(html);
    for (const n of extractNamesFromText(text, brand)) names.add(n);
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
    const n = nameFromEmail(e, brand);
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
