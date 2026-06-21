// Web security check — looks at HOW the site is served (not its code): the TLS
// certificate, the http→https redirect, and the HTTP security headers a browser
// relies on (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
// Permissions-Policy) plus cookie flags. All real: a live TLS handshake + one
// HTTPS request. Nothing is simulated; a missing header IS the finding.
//
// In OWASP terms these are "Security Misconfiguration" (A05) weaknesses — each
// absent header leaves a specific attack class (XSS, clickjacking, MITM, …)
// unmitigated.

import tls from "node:tls";
import { normalizeDomain } from "./crawl.mjs";

const TIMEOUT_MS = 8000;
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 AegisWebSec/1.0";

const SEV_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

/** Live TLS handshake → { authorized, daysLeft } or null if HTTPS unreachable. */
function getCert(host) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (done) return;
      done = true;
      resolve(v);
    };
    try {
      const socket = tls.connect(
        { host, port: 443, servername: host, timeout: TIMEOUT_MS },
        () => {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          let daysLeft = null;
          if (cert && cert.valid_to) {
            daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
          }
          socket.end();
          finish({ authorized, daysLeft, error: authorized ? null : socket.authorizationError });
        }
      );
      socket.on("error", () => finish(null));
      socket.on("timeout", () => {
        socket.destroy();
        finish(null);
      });
    } catch {
      finish(null);
    }
  });
}

/** Does http:// redirect to https://? Returns "redirect" | "non-https" | "none" | "no-http". */
async function httpRedirect(host) {
  try {
    const res = await fetch(`http://${host}/`, {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": UA },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location") || "";
      return /^https:/i.test(loc) ? "redirect" : "non-https";
    }
    if (res.status >= 200 && res.status < 300) return "none"; // served over plain http
    return "no-http";
  } catch {
    return "no-http"; // http not served at all — fine, https-only
  }
}

/**
 * Inspect the transport + header security posture of `domain`. Throws only on an
 * invalid domain; a missing record/header is reported, not thrown.
 */
export async function checkWebSecurity(domain) {
  const host = normalizeDomain(domain);
  if (!host || !/^[a-z0-9.\-]+\.[a-z]{2,}$/i.test(host)) {
    throw new Error("invalid_domain");
  }

  // Fetch the homepage over https (fall back to www) and read its headers.
  let res = null;
  let finalUrl = "";
  for (const candidate of [`https://${host}/`, `https://www.${host}/`]) {
    try {
      const r = await fetch(candidate, {
        headers: { "user-agent": UA, accept: "text/html" },
        redirect: "follow",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      res = r;
      finalUrl = r.url;
      break;
    } catch {
      /* try next */
    }
  }

  const [cert, redirect] = await Promise.all([getCert(host), httpRedirect(host)]);
  const h = (name) => (res ? res.headers.get(name) : null);
  const checks = [];

  /* ----------------------------- HTTPS / TLS ----------------------------- */
  if (!res && !cert) {
    checks.push({
      id: "https", label: "HTTPS", status: "fail", severity: "critical",
      title: "Site is not reachable over HTTPS",
      detail: "We couldn't establish a secure (HTTPS) connection. Without it, everything visitors send — logins, donations — travels in the clear.",
      evidence: `No TLS on ${host}:443`,
    });
  } else if (cert && cert.authorized === false) {
    checks.push({
      id: "https", label: "HTTPS", status: "fail", severity: "high",
      title: "TLS certificate is invalid or untrusted",
      detail: "The certificate didn't validate, so browsers show a scary warning and the connection can't be fully trusted.",
      evidence: String(cert.error || "certificate not trusted"),
    });
  } else {
    checks.push({
      id: "https", label: "HTTPS", status: "pass", severity: "low",
      title: "Served over HTTPS with a trusted certificate",
      detail: "Traffic between visitors and your site is encrypted.",
      evidence: finalUrl || `https://${host}`,
    });
    // Certificate expiry (only meaningful when HTTPS works).
    if (cert && typeof cert.daysLeft === "number") {
      const d = cert.daysLeft;
      checks.push({
        id: "cert-expiry", label: "Certificate",
        status: d <= 0 ? "fail" : d <= 21 ? "warn" : "pass",
        severity: d <= 0 ? "critical" : d <= 21 ? "medium" : "low",
        title: d <= 0 ? "TLS certificate has expired"
          : d <= 21 ? `TLS certificate expires soon (${d} days)`
          : `TLS certificate valid (${d} days left)`,
        detail: d <= 21
          ? "An expired or soon-to-expire certificate makes the site unreachable or throws security warnings. Set up auto-renewal (most hosts/Let's Encrypt do this for free)."
          : "Plenty of validity left; just make sure auto-renewal is on.",
        evidence: `valid_to in ${d} day(s)`,
      });
    }
  }

  /* --------------------------- http → https ----------------------------- */
  checks.push({
    id: "redirect", label: "HTTP→HTTPS",
    status: redirect === "redirect" || redirect === "no-http" ? "pass" : redirect === "non-https" ? "warn" : "fail",
    severity: redirect === "none" ? "medium" : redirect === "non-https" ? "medium" : "low",
    title: redirect === "redirect" ? "Plain http:// redirects to https://"
      : redirect === "no-http" ? "No insecure http:// listener"
      : redirect === "non-https" ? "http:// redirects, but not to https"
      : "http:// is served without redirecting to https",
    detail: redirect === "none"
      ? "Visitors who type your address without 'https' stay on an unencrypted connection an attacker can read or modify. Force a redirect to https."
      : "Visitors are kept on the encrypted version of the site.",
    evidence: `http test: ${redirect}`,
  });

  // Only grade headers if we actually got an HTTPS response to read them from.
  if (res) {
    /* ------------------------------- HSTS ------------------------------- */
    const hsts = h("strict-transport-security");
    checks.push({
      id: "hsts", label: "HSTS",
      status: hsts ? "pass" : "warn",
      severity: hsts ? "low" : "medium",
      title: hsts ? "HSTS enabled (forces HTTPS)" : "No HSTS header",
      detail: hsts
        ? "Browsers will refuse to load your site over plain http, blocking downgrade attacks."
        : "Without HSTS, an attacker on the same network can strip HTTPS and intercept traffic (SSL-stripping / man-in-the-middle). Add Strict-Transport-Security.",
      evidence: hsts || "header absent",
    });

    /* -------------------------------- CSP ------------------------------- */
    const csp = h("content-security-policy");
    checks.push({
      id: "csp", label: "CSP",
      status: csp ? "pass" : "fail",
      severity: csp ? "low" : "medium",
      title: csp ? "Content-Security-Policy present" : "No Content-Security-Policy",
      detail: csp
        ? "A CSP limits what scripts can run, which is the strongest defense against cross-site scripting (XSS)."
        : "CSP is the single strongest mitigation against XSS — the #1 web attack. Without it, an injected script (from a widget, comment field, or bad link) runs with full access to your page.",
      evidence: csp ? csp.slice(0, 120) : "header absent",
    });

    /* ---------------------- Clickjacking protection --------------------- */
    const xfo = h("x-frame-options");
    const frameAncestors = csp && /frame-ancestors/i.test(csp);
    const framed = Boolean(xfo) || frameAncestors;
    checks.push({
      id: "x-frame-options", label: "Clickjacking",
      status: framed ? "pass" : "warn",
      severity: framed ? "low" : "medium",
      title: framed ? "Clickjacking protection in place" : "No clickjacking protection",
      detail: framed
        ? "Other sites can't load yours inside a hidden frame to trick your users."
        : "Without X-Frame-Options (or CSP frame-ancestors), an attacker can load your site invisibly and overlay fake buttons to trick a logged-in admin (clickjacking).",
      evidence: xfo || (frameAncestors ? "CSP frame-ancestors" : "header absent"),
    });

    /* ------------------------- MIME sniffing ---------------------------- */
    const nosniff = (h("x-content-type-options") || "").toLowerCase().includes("nosniff");
    checks.push({
      id: "nosniff", label: "MIME-sniffing",
      status: nosniff ? "pass" : "warn",
      severity: "low",
      title: nosniff ? "MIME-sniffing disabled (nosniff)" : "No X-Content-Type-Options: nosniff",
      detail: nosniff
        ? "Browsers won't second-guess file types, preventing a non-script from being run as code."
        : "Without nosniff, a browser may 'guess' an uploaded/served file is JavaScript and execute it. Add X-Content-Type-Options: nosniff.",
      evidence: h("x-content-type-options") || "header absent",
    });

    /* ------------------------- Referrer-Policy -------------------------- */
    const ref = h("referrer-policy");
    checks.push({
      id: "referrer", label: "Referrer-Policy",
      status: ref ? "pass" : "warn",
      severity: "low",
      title: ref ? "Referrer-Policy set" : "No Referrer-Policy",
      detail: ref
        ? "Limits what URL information leaks to other sites your pages link to."
        : "Without a Referrer-Policy, full URLs (which can contain tokens) may leak to third-party sites via the Referer header.",
      evidence: ref || "header absent",
    });

    /* ------------------------ Permissions-Policy ------------------------ */
    const perm = h("permissions-policy") || h("feature-policy");
    checks.push({
      id: "permissions", label: "Permissions-Policy",
      status: perm ? "pass" : "warn",
      severity: "low",
      title: perm ? "Permissions-Policy set" : "No Permissions-Policy",
      detail: perm
        ? "Restricts powerful browser features (camera, mic, location), limiting damage if a script is compromised."
        : "Without a Permissions-Policy, a compromised script or embedded widget could access the camera, microphone, or location.",
      evidence: perm || "header absent",
    });

    /* --------------------------- Cookie flags --------------------------- */
    const cookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    if (cookies.length) {
      const weak = cookies.filter((c) => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c));
      checks.push({
        id: "cookies", label: "Cookies",
        status: weak.length ? "warn" : "pass",
        severity: weak.length ? "medium" : "low",
        title: weak.length ? `${weak.length} cookie(s) missing Secure/HttpOnly` : "Cookies use Secure + HttpOnly",
        detail: weak.length
          ? "Cookies without Secure/HttpOnly can be stolen over http or by a script (session hijacking). Set Secure, HttpOnly, and SameSite."
          : "Session cookies are protected from network sniffing and script access.",
        evidence: `${cookies.length} Set-Cookie header(s)`,
      });
    }
  }

  const worst = checks.reduce(
    (w, c) => (SEV_ORDER[c.severity] > SEV_ORDER[w] ? c.severity : w),
    "low"
  );
  // Simple letter grade from the deductions, for an at-a-glance headline.
  const penalty = { critical: 45, high: 30, medium: 12, low: 0 };
  let score = 100;
  for (const c of checks) if (c.status !== "pass") score -= penalty[c.severity];
  score = Math.max(0, score);
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  return { domain: host, checks, worst, grade, https: Boolean(res && (!cert || cert.authorized !== false)) };
}
