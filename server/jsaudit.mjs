// JS Auditor — fetches the JavaScript a website actually ships to visitors
// (external <script src> files plus inline <script> blocks) and runs fast,
// dependency-free static analysis over it to surface likely BUGS and SECURITY
// RISKS: hardcoded secrets, XSS sinks, insecure (http://) calls, dangerous
// code-exec patterns, leftover debug code, and known-vulnerable library
// versions. Runs server-side (no CORS limits), never executes the code, and
// only reads what's already public.

import { normalizeDomain } from "./crawl.mjs";

const FETCH_TIMEOUT_MS = 9000;
const MAX_SCRIPTS = 12; // how many JS files we download & scan
const MAX_BYTES = 2_000_000; // skip absurdly large bundles
const TIME_BUDGET_MS = 45000;
const PER_PATTERN_CAP = 6; // don't flood the report with the same issue
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 AegisJSAuditor/1.0";

function timedFetch(url, accept) {
  return fetch(url, {
    headers: { "user-agent": UA, accept },
    redirect: "follow",
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
}

// Hosts that legitimately appear as http:// inside JS (XML/SVG namespaces,
// schema markup, loopback) — matching these is noise, not mixed content.
const HTTP_ALLOW = [
  "www.w3.org", "schema.org", "www.schema.org", "ns.adobe.com",
  "localhost", "127.0.0.1", "purl.org", "xmlns.com", "ogp.me",
];

// ── Static rules ──────────────────────────────────────────────────────────
// Each rule scans raw JS text. `category` drives the UI grouping; `severity`
// drives ordering/coloring. Keep regexes anchored enough to stay precise.
const RULES = [
  // —— Hardcoded secrets / credentials ——
  {
    id: "aws-key", category: "security", severity: "critical",
    title: "Hardcoded AWS access key",
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    detail: "An AWS access-key ID is embedded in client-side code. Anyone can read it and may pair it with a leaked secret to access your cloud account.",
  },
  {
    id: "google-key", category: "security", severity: "high",
    title: "Exposed Google API key",
    re: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    detail: "A Google API key is shipped to the browser. If it isn't restricted to your domain, attackers can run up usage/billing on your account.",
  },
  {
    id: "stripe-secret", category: "security", severity: "critical",
    title: "Stripe SECRET key in browser code",
    re: /\bsk_live_[0-9A-Za-z]{16,}\b/g,
    detail: "A live Stripe SECRET key never belongs in front-end code — it can charge cards, issue refunds, and read payment data. Rotate it immediately.",
  },
  {
    id: "slack-token", category: "security", severity: "high",
    title: "Slack token exposed",
    re: /\bxox[baprs]-[0-9A-Za-z\-]{10,}\b/g,
    detail: "A Slack token is embedded in the page. It can be used to read or post messages in your workspace.",
  },
  {
    id: "private-key", category: "security", severity: "critical",
    title: "Private key embedded in code",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    detail: "A cryptographic private key is shipped to visitors. This should be treated as fully compromised and rotated.",
  },
  {
    id: "jwt", category: "security", severity: "medium",
    title: "Hardcoded JWT / bearer token",
    re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,}\b/g,
    detail: "A JSON Web Token is baked into the code. If it's still valid, it may grant an attacker the same access as the user it was issued for.",
  },
  {
    id: "generic-secret", category: "security", severity: "medium",
    title: "Possible hardcoded credential",
    re: /\b(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    detail: "A key/secret/password appears to be assigned a literal value in client code. Some are meant to be public (e.g. Firebase config), but verify none are real secrets.",
  },
  // —— XSS / code-execution sinks ——
  {
    id: "eval", category: "security", severity: "high",
    title: "Use of eval()",
    re: /\beval\s*\(/g,
    detail: "eval() runs arbitrary strings as code. If any part of that string comes from user input or the URL, it's a direct path to cross-site scripting (XSS).",
  },
  {
    id: "new-function", category: "security", severity: "medium",
    title: "Dynamic code via new Function()",
    re: /\bnew\s+Function\s*\(/g,
    detail: "new Function() compiles strings into code, just like eval(). Attacker-controlled input reaching it leads to script injection.",
  },
  {
    id: "document-write", category: "security", severity: "medium",
    title: "document.write()",
    re: /\bdocument\.write(?:ln)?\s*\(/g,
    detail: "document.write() injects raw HTML. With untrusted data it enables XSS, and it also blocks/breaks page rendering — a common bug source.",
  },
  {
    id: "inner-html", category: "security", severity: "medium",
    title: "Assignment to innerHTML / outerHTML",
    re: /\.(?:inner|outer)HTML\s*=/g,
    detail: "Writing unsanitized values into innerHTML lets malicious markup execute. Prefer textContent, or sanitize before inserting.",
  },
  {
    id: "insert-html", category: "security", severity: "medium",
    title: "insertAdjacentHTML()",
    re: /\.insertAdjacentHTML\s*\(/g,
    detail: "insertAdjacentHTML parses its argument as HTML. Untrusted input here can inject scripts.",
  },
  {
    id: "timer-string", category: "security", severity: "medium",
    title: "setTimeout/setInterval with a string",
    re: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/g,
    detail: "Passing a string (instead of a function) to a timer makes it behave like eval() — avoid it.",
  },
  // —— Transport / config ——
  {
    id: "insecure-http", category: "security", severity: "medium",
    title: "Insecure http:// request",
    re: /["'`(]\s*(http:\/\/[^"'`)\s]+)/g,
    detail: "Code talks to a resource over plain http://. On an https site this is mixed content — it can be intercepted or modified in transit.",
    capture: 1,
    filter: (m) => {
      try {
        const host = new URL(m).hostname;
        return !HTTP_ALLOW.includes(host);
      } catch {
        return false;
      }
    },
  },
  {
    id: "ws-insecure", category: "security", severity: "low",
    title: "Insecure ws:// websocket",
    re: /["'`]\s*(ws:\/\/[^"'`\s]+)/g,
    detail: "An unencrypted websocket (ws://) can be read or tampered with on the network. Use wss://.",
    capture: 1,
  },
  {
    id: "ls-secret", category: "security", severity: "low",
    title: "Token/secret stored in localStorage",
    re: /(?:local|session)Storage\.setItem\s*\(\s*["'][^"']*(?:token|secret|password|auth|jwt)/gi,
    detail: "Auth tokens in localStorage are readable by any script on the page, so one XSS bug exposes them. httpOnly cookies are safer.",
  },
  // —— Bugs / code quality / hygiene ——
  {
    id: "todo", category: "bug", severity: "low",
    title: "Unfinished code (TODO/FIXME/HACK)",
    re: /(?:\/\/|\/\*)[^\n*]{0,40}\b(?:TODO|FIXME|HACK|XXX|BUG)\b/gi,
    detail: "A developer note marks this code as incomplete or known-broken. Worth reviewing before relying on it.",
  },
  {
    id: "debugger", category: "bug", severity: "low",
    title: "Leftover debugger statement",
    re: /\bdebugger\s*;/g,
    detail: "A debugger; statement shipped to production. It halts execution when devtools are open and shouldn't be live.",
  },
  {
    id: "empty-catch", category: "bug", severity: "low",
    title: "Empty catch block (errors swallowed)",
    re: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/g,
    detail: "Errors are caught and silently ignored. This hides failures and makes real bugs very hard to diagnose.",
  },
  {
    id: "sourcemap", category: "bug", severity: "low",
    title: "Source map reference exposed",
    re: /\/\/[#@]\s*sourceMappingURL=/g,
    detail: "The bundle points to a source map. If that .map file is also published, your original (un-minified) source is downloadable.",
  },
];

// Known-vulnerable library versions, detected from the banner comment most
// libraries leave at the top of their file. Precise and high-signal.
const LIBRARY_RULES = [
  {
    id: "jquery-old", category: "security", severity: "medium",
    name: "jQuery", re: /jQuery (?:JavaScript Library )?v?(\d+)\.(\d+)\.(\d+)/i,
    vulnerable: (maj, min) => maj < 3 || (maj === 3 && min < 5),
    detail: "jQuery before 3.5.0 has published XSS vulnerabilities (CVE-2020-11022 / 11023). Upgrade to the latest 3.x.",
  },
  {
    id: "angularjs-eol", category: "security", severity: "high",
    name: "AngularJS", re: /AngularJS v(\d+)\.(\d+)\.(\d+)/i,
    vulnerable: (maj) => maj === 1,
    detail: "AngularJS 1.x reached end-of-life in 2022 and no longer receives security fixes. Migrate off it.",
  },
  {
    id: "bootstrap-old", category: "security", severity: "low",
    name: "Bootstrap", re: /Bootstrap v(\d+)\.(\d+)\.(\d+)/i,
    vulnerable: (maj, min) => maj < 4 || (maj === 4 && min < 3),
    detail: "Bootstrap before 4.3.1 has known XSS issues in its data-* attributes. Upgrade.",
  },
];

/** Count which 1-based line `index` falls on, and return that line trimmed. */
function locate(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  let start = text.lastIndexOf("\n", index - 1) + 1;
  let end = text.indexOf("\n", index);
  if (end === -1) end = text.length;
  let snippet = text.slice(start, end).trim();
  // Minified files are one giant line — window the snippet around the match.
  if (snippet.length > 160) {
    const rel = index - start;
    const from = Math.max(0, rel - 60);
    snippet = (from > 0 ? "…" : "") + snippet.slice(from, rel + 100).trim() + "…";
  }
  return { line, snippet };
}

function scanText(text, file, party) {
  const findings = [];
  // Collapse repeats on the same line (minified bundles are one long line, so
  // the same sink can match dozens of times) — one row per rule+line.
  const seen = new Set();
  for (const rule of RULES) {
    let count = 0;
    rule.re.lastIndex = 0;
    for (const m of text.matchAll(rule.re)) {
      const value = rule.capture ? m[rule.capture] : m[0];
      if (rule.filter && !rule.filter(value)) continue;
      if (count >= PER_PATTERN_CAP) break;
      const { line, snippet } = locate(text, m.index);
      const key = `${rule.id}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      count++;
      findings.push({
        id: rule.id, category: rule.category, severity: rule.severity,
        title: rule.title, detail: rule.detail, file, party, line, snippet,
      });
    }
  }
  // Outdated-library checks (one finding per library per file at most).
  for (const lib of LIBRARY_RULES) {
    const m = lib.re.exec(text);
    if (!m) continue;
    const [maj, min, patch] = [+m[1], +m[2], +(m[3] || 0)];
    if (!lib.vulnerable(maj, min, patch)) continue;
    const { line } = locate(text, m.index);
    findings.push({
      id: lib.id, category: lib.category, severity: lib.severity,
      title: `Outdated ${lib.name} (${maj}.${min}.${patch})`,
      detail: lib.detail, file, party, line,
      snippet: m[0].trim(),
    });
  }
  return findings;
}

/** Pull external script URLs and inline script bodies out of the homepage. */
function extractScripts(html, baseUrl, baseHost) {
  const external = [];
  const inline = [];
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = m[1] || "";
    const type = (/\btype\s*=\s*["']([^"']+)["']/i.exec(attrs) || [])[1] || "";
    // Skip JSON/template payloads — they're data, not executable JS.
    if (/json|ld\+json|template|text\/html/i.test(type)) continue;
    const srcMatch = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs);
    if (srcMatch) {
      try {
        const u = new URL(srcMatch[1], baseUrl);
        if (u.protocol === "http:" || u.protocol === "https:") external.push(u.toString());
      } catch {
        /* ignore */
      }
    } else if (m[2] && m[2].trim().length > 0) {
      inline.push(m[2]);
    }
  }
  // First-party scripts first; they're "your code" and matter most.
  const party = (url) => {
    try {
      return new URL(url).hostname.replace(/^www\./, "") === baseHost ? 0 : 1;
    } catch {
      return 1;
    }
  };
  external.sort((a, b) => party(a) - party(b));
  return { external, inline };
}

function shortName(url, baseHost) {
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./, "");
    const file = u.pathname.split("/").pop() || u.pathname;
    return host === baseHost ? file : `${host}/${file}`;
  } catch {
    return url;
  }
}

/**
 * Audit the JavaScript served at `domain`. Fetches the homepage, collects the
 * scripts it loads (external + inline), downloads up to MAX_SCRIPTS of them,
 * and statically scans each for bugs and security risks. Best-effort: a script
 * that fails to download is skipped, never fatal.
 */
export async function auditDomainJs(domain) {
  const host = normalizeDomain(domain);
  if (!host || !/^[a-z0-9.\-]+\.[a-z]{2,}$/i.test(host)) {
    throw new Error("invalid_domain");
  }
  const startedAt = Date.now();

  // Reach the homepage (prefer https, fall back to www / http).
  let home, html;
  for (const candidate of [`https://${host}/`, `https://www.${host}/`, `http://${host}/`]) {
    try {
      const res = await timedFetch(candidate, "text/html,application/xhtml+xml");
      if (res.ok) {
        home = res.url;
        html = await res.text();
        break;
      }
    } catch {
      /* try next */
    }
  }
  if (!home) throw new Error("unreachable");

  const baseHost = new URL(home).hostname.replace(/^www\./, "");
  const { external, inline } = extractScripts(html, home, baseHost);

  const findings = [];
  const scripts = [];

  // Inline scripts count as first-party homepage code.
  inline.forEach((code, i) => {
    const file = `${baseHost} (inline #${i + 1})`;
    scripts.push({ file, url: home, party: 0, bytes: code.length, inline: true });
    findings.push(...scanText(code, file, 0));
  });

  // Download & scan external scripts up to our caps / time budget.
  for (const url of external.slice(0, MAX_SCRIPTS)) {
    if (Date.now() - startedAt > TIME_BUDGET_MS) break;
    try {
      const res = await timedFetch(url, "application/javascript,text/javascript,*/*");
      if (!res.ok) continue;
      const len = Number(res.headers.get("content-length") || 0);
      if (len > MAX_BYTES) continue;
      const code = await res.text();
      if (code.length > MAX_BYTES) continue;
      const isFirst = (() => {
        try {
          return new URL(url).hostname.replace(/^www\./, "") === baseHost ? 0 : 1;
        } catch {
          return 1;
        }
      })();
      const file = shortName(url, baseHost);
      scripts.push({ file, url, party: isFirst, bytes: code.length, inline: false });
      findings.push(...scanText(code, file, isFirst));
    } catch {
      /* skip unreachable/slow script */
    }
  }

  // Order: severity desc, then security before bugs.
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort(
    (a, b) =>
      sevRank[a.severity] - sevRank[b.severity] ||
      (a.category === b.category ? 0 : a.category === "security" ? -1 : 1)
  );

  const counts = { critical: 0, high: 0, medium: 0, low: 0, security: 0, bug: 0 };
  for (const f of findings) {
    counts[f.severity]++;
    counts[f.category]++;
  }

  return {
    domain: host,
    scriptsScanned: scripts,
    externalFound: external.length,
    findings,
    counts,
  };
}
