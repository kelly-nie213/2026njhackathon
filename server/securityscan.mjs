/**
 * Free, zero-API-key security checks for a domain.
 *
 * Sources used:
 *   Cloudflare DNS-over-HTTPS  — DMARC / SPF / DKIM / MX / A lookups
 *   crt.sh                     — Certificate transparency, subdomain discovery
 *   Shodan InternetDB          — Open ports + CVEs on the resolved IP (free, no key)
 *   RDAP.org                   — Domain registration / expiry data
 *   Direct HTTP fetch          — Security headers, exposed sensitive paths, robots.txt
 *
 * All checks run in parallel via Promise.allSettled — one failure can't sink the rest.
 */

const UA = "Aegis-SecurityScanner/1.0 (nonprofit-hackathon)";

const tf = (url, init = {}) =>
  fetch(url, {
    signal: AbortSignal.timeout(12000),
    headers: { "user-agent": UA },
    ...init,
  });

/* ─── DNS via Cloudflare DoH ──────────────────────────────── */

async function doh(name, type) {
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      {
        headers: { accept: "application/dns-json", "user-agent": UA },
        signal: AbortSignal.timeout(8000),
      }
    );
    return r.ok ? r.json() : null;
  } catch {
    return null;
  }
}

/* ─── 1. Email security (DMARC / SPF / DKIM / MX) ─────────── */

async function checkEmailSecurity(domain) {
  const [dmarcRes, spfRes, mxRes] = await Promise.all([
    doh(`_dmarc.${domain}`, "TXT"),
    doh(domain, "TXT"),
    doh(domain, "MX"),
  ]);

  // DMARC
  const dmarcRecord = dmarcRes?.Answer?.find((a) =>
    String(a.data ?? "").includes("v=DMARC1")
  );
  let dmarcPolicy = null;
  if (dmarcRecord) {
    const m = String(dmarcRecord.data).match(/p=([a-z]+)/i);
    dmarcPolicy = m ? m[1].toLowerCase() : "none";
  }

  // SPF
  const spfRecord = spfRes?.Answer?.find((a) => {
    const d = String(a.data ?? "");
    return d.includes("v=spf1");
  });
  const spfRaw = spfRecord ? String(spfRecord.data) : "";
  const spfPolicy = spfRaw.includes("-all")
    ? "fail"
    : spfRaw.includes("~all")
      ? "softfail"
      : spfRaw.includes("+all")
        ? "pass_all"
        : spfRaw
          ? "neutral"
          : null;

  // MX
  const mxRecords = (mxRes?.Answer ?? [])
    .filter((a) => a.type === 15)
    .map((a) => String(a.data ?? ""));
  const emailProvider = detectEmailProvider(mxRecords);

  // DKIM — probe common selectors in parallel
  const selectors = ["google", "selector1", "selector2", "default", "mail", "dkim", "k1", "k2"];
  const dkimChecks = await Promise.all(
    selectors.map((s) => doh(`${s}._domainkey.${domain}`, "TXT"))
  );
  const hasDKIM = dkimChecks.some((r) =>
    r?.Answer?.some((a) => String(a.data ?? "").includes("v=DKIM1"))
  );

  return {
    dmarcPolicy,
    hasSPF: Boolean(spfRecord),
    spfPolicy,
    hasDKIM,
    emailProvider,
    mxCount: mxRecords.length,
  };
}

function detectEmailProvider(mxRecords) {
  const s = mxRecords.join(" ").toLowerCase();
  if (s.includes("google") || s.includes("googlemail")) return "Google Workspace";
  if (s.includes("outlook") || s.includes("microsoft") || s.includes("office365"))
    return "Microsoft 365";
  if (s.includes("protonmail")) return "ProtonMail";
  if (s.includes("zoho")) return "Zoho Mail";
  if (s.includes("mxroute")) return "MXRoute";
  if (mxRecords.length === 0) return null;
  return "Custom / Self-hosted";
}

/* ─── 2. HTTP security headers ────────────────────────────── */

async function checkSecurityHeaders(domain) {
  for (const url of [`https://${domain}/`, `https://www.${domain}/`]) {
    try {
      const res = await fetch(url, {
        method: "GET",
        redirect: "follow",
        headers: { "user-agent": UA },
        signal: AbortSignal.timeout(12000),
      });
      const h = {};
      res.headers.forEach((v, k) => {
        h[k.toLowerCase()] = v;
      });
      return {
        url: res.url,
        isHTTPS: res.url.startsWith("https"),
        hasHSTS: Boolean(h["strict-transport-security"]),
        hasXFrame: Boolean(h["x-frame-options"]),
        hasXContent: Boolean(h["x-content-type-options"]),
        hasCSP: Boolean(h["content-security-policy"]),
        server: h["server"] ?? null,
        poweredBy: h["x-powered-by"] ?? null,
        statusCode: res.status,
      };
    } catch {
      continue;
    }
  }
  return null;
}

/* ─── 3. Certificate transparency / subdomains (crt.sh) ───── */

async function checkCertTransparency(domain) {
  try {
    const res = await tf(`https://crt.sh/?q=%.${domain}&output=json`, {
      headers: { accept: "application/json", "user-agent": UA },
    });
    if (!res.ok) return { subdomains: [], sensitiveSubdomains: [], certCount: 0 };
    const data = await res.json();
    if (!Array.isArray(data)) return { subdomains: [], sensitiveSubdomains: [], certCount: 0 };

    const subs = new Set();
    for (const cert of data) {
      for (const name of String(cert.name_value ?? "").split("\n")) {
        const clean = name.replace(/^\*\./, "").toLowerCase().trim();
        if (clean && clean !== domain && clean.endsWith(`.${domain}`)) subs.add(clean);
      }
    }
    const all = [...subs].slice(0, 40);
    const sensitive = all.filter((s) =>
      /admin|portal|staff|internal|login|vpn|remote|dev|staging|test|old|backup|beta|cms|wp|panel|intranet|dashboard|manage|control/.test(
        s
      )
    );
    return { subdomains: all, sensitiveSubdomains: sensitive, certCount: data.length };
  } catch {
    return { subdomains: [], sensitiveSubdomains: [], certCount: 0 };
  }
}

/* ─── 4. Shodan InternetDB (free, no key needed) ───────────── */

async function checkShodan(domain) {
  try {
    const dns = await doh(domain, "A");
    const ip = dns?.Answer?.find((a) => a.type === 1)?.data;
    if (!ip) return null;

    const res = await tf(`https://internetdb.shodan.io/${ip}`);
    if (!res.ok) return { ip, ports: [], cves: [], tags: [] };
    const data = await res.json();
    if (data?.detail === "No information available")
      return { ip, ports: [], cves: [], tags: [] };

    return {
      ip,
      ports: (data.ports ?? []).slice(0, 20),
      cves: (data.vulns ?? []).slice(0, 15),
      tags: data.tags ?? [],
    };
  } catch {
    return null;
  }
}

/* ─── 5. Domain expiry via RDAP ────────────────────────────── */

async function checkDomainExpiry(domain) {
  try {
    const res = await tf(`https://rdap.org/domain/${domain}`, {
      headers: { accept: "application/rdap+json", "user-agent": UA },
    });
    if (!res.ok) return null;
    const data = await res.json();
    const expEvent = (data.events ?? []).find((e) => e.eventAction === "expiration");
    const expiry = expEvent?.eventDate ? new Date(expEvent.eventDate) : null;
    const daysLeft = expiry ? Math.floor((expiry - Date.now()) / 86400000) : null;
    return {
      expiry: expiry?.toISOString() ?? null,
      daysLeft,
      isExpiringSoon: daysLeft !== null && daysLeft < 60,
    };
  } catch {
    return null;
  }
}

/* ─── 6. Exposed sensitive paths ───────────────────────────── */

const SENSITIVE_PATHS = [
  { path: "/.env",           label: ".env config file (may contain passwords and API keys)" },
  { path: "/.git/config",    label: "Git repository config (exposes codebase and history)" },
  { path: "/wp-login.php",   label: "WordPress admin login (exposed to brute-force attacks)" },
  { path: "/wp-admin/",      label: "WordPress dashboard" },
  { path: "/phpmyadmin/",    label: "phpMyAdmin (direct database access)" },
  { path: "/adminer.php",    label: "Adminer database management tool" },
  { path: "/admin/",         label: "Admin panel (publicly accessible)" },
  { path: "/.DS_Store",      label: "macOS folder metadata (reveals directory structure)" },
  { path: "/xmlrpc.php",     label: "WordPress XML-RPC (common attack entry point)" },
  { path: "/server-status",  label: "Apache server-status page (exposes internal metrics)" },
  { path: "/.htpasswd",      label: ".htpasswd credentials file" },
  { path: "/config.php",     label: "config.php (may contain database credentials)" },
];

async function checkExposedPaths(domain) {
  const base = `https://${domain}`;
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async ({ path, label }) => {
      try {
        const res = await fetch(base + path, {
          method: "GET",
          redirect: "manual",
          headers: { "user-agent": UA },
          signal: AbortSignal.timeout(7000),
        });
        // 200 = exposed; 403 = exists but blocked (still worth noting for some paths)
        if (res.status === 200) return { path, label, status: res.status };
        return null;
      } catch {
        return null;
      }
    })
  );
  return results.filter(Boolean);
}

/* ─── 7. robots.txt sensitive path disclosure ──────────────── */

async function checkRobots(domain) {
  try {
    const res = await tf(`https://${domain}/robots.txt`);
    if (!res.ok) return { exists: false, sensitiveDisallows: [] };
    const text = await res.text();
    const sensitive = [];
    for (const line of text.split("\n")) {
      const m = line.match(/^Disallow:\s*(.+)/i);
      if (m) {
        const p = m[1].trim();
        if (
          /admin|login|member|staff|internal|private|secure|portal|backup|api\/|dashboard|config|cms|panel|manage/.test(
            p
          )
        ) {
          sensitive.push(p);
        }
      }
    }
    return { exists: true, sensitiveDisallows: sensitive.slice(0, 10) };
  } catch {
    return { exists: false, sensitiveDisallows: [] };
  }
}

/* ─── Build Finding objects from raw results ─────────────────
   Findings follow the same shape as the deterministic scan.ts
   findings so the Dashboard can render them identically.
────────────────────────────────────────────────────────────── */

function buildFindings(email, headers, certs, shodan, expiry, paths, robots, domain) {
  const findings = [];

  // ── Email security ──────────────────────────────────────────
  if (email) {
    if (!email.dmarcPolicy) {
      findings.push({
        id: "live-dmarc",
        category: "email-security",
        severity: "critical",
        title: "No DMARC record — anyone can send email pretending to be you",
        detail:
          "DMARC is a free DNS setting that tells mail servers worldwide: 'reject emails claiming to be from us that fail our checks.' Without it, attackers can send perfectly-addressed donation requests, wire-transfer demands, or board updates using your real domain — and your donors can't tell the difference.",
        evidence: `No DMARC TXT record found at _dmarc.${domain}`,
        source: "Cloudflare DNS check",
      });
    } else if (email.dmarcPolicy === "none") {
      findings.push({
        id: "live-dmarc",
        category: "email-security",
        severity: "high",
        title: "DMARC is in 'monitor only' mode — forged emails still reach inboxes",
        detail:
          "You have a DMARC record, but p=none means spoofed emails from your domain still deliver successfully — it only logs them. Change to p=quarantine (sends fakes to spam) or p=reject (blocks them entirely) to actually stop impersonation.",
        evidence: `_dmarc.${domain} → p=none (monitoring only, no enforcement)`,
        source: "Cloudflare DNS check",
      });
    }

    if (!email.hasSPF) {
      findings.push({
        id: "live-spf",
        category: "email-security",
        severity: "high",
        title: "No SPF record — no authorized sender list for your domain",
        detail:
          "SPF lists which mail servers are allowed to send email on your behalf. Without it, anyone's server can send email as you. Free to add through your DNS host — takes under 5 minutes.",
        evidence: `No SPF TXT record found on ${domain}`,
        source: "Cloudflare DNS check",
      });
    } else if (email.spfPolicy !== "fail") {
      findings.push({
        id: "live-spf",
        category: "email-security",
        severity: "medium",
        title: "SPF record is too permissive — unauthorized senders aren't hard-blocked",
        detail: `Your SPF ends with '${email.spfPolicy === "softfail" ? "~all" : "+all"}' instead of '-all'. Unauthorized senders get a warning at best, not a rejection. Change the ending to '-all' to actually enforce it.`,
        evidence: `SPF on ${domain}: uses ${email.spfPolicy} policy (not strict -all)`,
        source: "Cloudflare DNS check",
      });
    }

    if (!email.hasDKIM) {
      findings.push({
        id: "live-dkim",
        category: "email-security",
        severity: "medium",
        title: "No DKIM signing detected — emails can be forged or tampered in transit",
        detail:
          "DKIM adds a digital signature to your outgoing emails so recipients can verify they weren't altered. Without it, attackers can more convincingly forge your emails. Enable DKIM through your email provider's DNS settings.",
        evidence: `No DKIM TXT record found on common selectors (_domainkey.${domain})`,
        source: "Cloudflare DNS check",
      });
    }

    if (email.emailProvider) {
      const isEnterprise =
        email.emailProvider === "Google Workspace" ||
        email.emailProvider === "Microsoft 365";
      findings.push({
        id: "live-email-provider",
        category: "email-security",
        severity: "low",
        title: `Email hosted on ${email.emailProvider}`,
        detail: isEnterprise
          ? `Good news: ${email.emailProvider} has strong built-in security. Verify MFA is enforced for every staff account and check the admin security dashboard.`
          : `Your email is on ${email.emailProvider}. Confirm MFA is enabled and that you control the DNS settings needed to publish DKIM and DMARC records.`,
        evidence: `MX records for ${domain} resolve to ${email.emailProvider}`,
        source: "Cloudflare DNS check",
      });
    }
  }

  // ── HTTP security headers ───────────────────────────────────
  if (headers) {
    if (!headers.isHTTPS) {
      findings.push({
        id: "live-https",
        category: "domain-exposure",
        severity: "critical",
        title: "Website accessible over unencrypted HTTP",
        detail:
          "Any data entered on your site — contact forms, donation amounts, volunteer info — can be read by anyone on the same network. Free HTTPS certificates are available via Let's Encrypt through most web hosts.",
        evidence: `Site loaded over plain HTTP: ${headers.url}`,
        source: "HTTP header check",
      });
    } else if (!headers.hasHSTS) {
      findings.push({
        id: "live-hsts",
        category: "domain-exposure",
        severity: "medium",
        title: "HTTPS not enforced (HSTS missing) — downgrade attacks possible",
        detail:
          "HSTS tells browsers to always use HTTPS, even if someone visits a plain http:// link. Without it, an attacker can intercept the first unencrypted request before HTTPS loads. Enable HSTS in your web server or hosting control panel.",
        evidence: `Missing Strict-Transport-Security header on ${headers.url}`,
        source: "HTTP header check",
      });
    }

    if (!headers.hasXContent) {
      findings.push({
        id: "live-xcontent",
        category: "domain-exposure",
        severity: "low",
        title: "Missing X-Content-Type-Options security header",
        detail:
          "This one-line header stops browsers from guessing file types, which prevents a class of script-injection attacks. Add 'X-Content-Type-Options: nosniff' in your server config or hosting panel.",
        evidence: `No X-Content-Type-Options on ${headers.url}`,
        source: "HTTP header check",
      });
    }

    if (!headers.hasCSP) {
      findings.push({
        id: "live-csp",
        category: "domain-exposure",
        severity: "low",
        title: "No Content Security Policy (CSP) header",
        detail:
          "CSP tells browsers which scripts and resources are allowed to run on your site, blocking injected malicious scripts even if an attacker finds a way to insert them. Worth adding if your site accepts any user input.",
        evidence: `No Content-Security-Policy header on ${headers.url}`,
        source: "HTTP header check",
      });
    }

    if (headers.poweredBy) {
      findings.push({
        id: "live-powered-by",
        category: "domain-exposure",
        severity: "low",
        title: `Server reveals technology stack: ${headers.poweredBy}`,
        detail:
          "Advertising the exact software your server runs helps attackers quickly look up known vulnerabilities for that version. Remove or obscure the X-Powered-By header in your server config.",
        evidence: `X-Powered-By: ${headers.poweredBy} in response from ${headers.url}`,
        source: "HTTP header check",
      });
    }

    if (headers.server && /\d/.test(headers.server)) {
      findings.push({
        id: "live-server-header",
        category: "domain-exposure",
        severity: "low",
        title: `Server version disclosed: ${headers.server}`,
        detail:
          "Your web server is advertising its exact version number. Attackers use this to look up version-specific exploits. Configure your server to hide or minimize this header.",
        evidence: `Server: ${headers.server} in response headers`,
        source: "HTTP header check",
      });
    }
  }

  // ── Certificate transparency / subdomains ───────────────────
  if (certs) {
    if (certs.sensitiveSubdomains.length > 0) {
      findings.push({
        id: "live-subdomains-sensitive",
        category: "domain-exposure",
        severity: "high",
        title: `${certs.sensitiveSubdomains.length} sensitive subdomain${certs.sensitiveSubdomains.length > 1 ? "s" : ""} discovered via certificate logs`,
        detail:
          "Certificate transparency logs are public records of every SSL certificate ever issued. They reveal subdomains you may have forgotten — old staff portals, dev sites, or CMS installs running outdated software. Attackers actively monitor these logs.",
        evidence: certs.sensitiveSubdomains.slice(0, 4).join(", ") +
          (certs.sensitiveSubdomains.length > 4 ? ` +${certs.sensitiveSubdomains.length - 4} more` : ""),
        source: "Certificate Transparency (crt.sh)",
      });
    } else if (certs.subdomains.length > 8) {
      findings.push({
        id: "live-subdomains",
        category: "domain-exposure",
        severity: "medium",
        title: `${certs.subdomains.length} subdomains found — audit for forgotten services`,
        detail:
          "A large number of subdomains increases your attack surface. Old subdomains from past vendors or projects may be running outdated, vulnerable software. Review each one and decommission anything no longer in use.",
        evidence: `${certs.subdomains.length} unique subdomains in certificate transparency logs`,
        source: "Certificate Transparency (crt.sh)",
      });
    }
  }

  // ── Shodan InternetDB ───────────────────────────────────────
  if (shodan) {
    if (shodan.cves && shodan.cves.length > 0) {
      findings.push({
        id: "live-cves",
        category: "domain-exposure",
        severity: "critical",
        title: `${shodan.cves.length} known security vulnerabilit${shodan.cves.length > 1 ? "ies" : "y"} on your server`,
        detail:
          "Shodan — a public internet scanner — has recorded that your server is running software with published security flaws. These are known vulnerabilities with attack tools already circulating online. This needs urgent attention.",
        evidence: `${shodan.ip}: ${shodan.cves.slice(0, 4).join(", ")}${shodan.cves.length > 4 ? ` +${shodan.cves.length - 4} more` : ""}`,
        source: "Shodan InternetDB",
      });
    }

    const DANGER_PORTS = { 21: "FTP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 11211: "Memcached", 9200: "Elasticsearch" };
    const dangerousPorts = shodan.ports.filter((p) => DANGER_PORTS[p]);
    if (dangerousPorts.length > 0) {
      findings.push({
        id: "live-open-ports-critical",
        category: "domain-exposure",
        severity: "critical",
        title: `Database or legacy service exposed to the internet: ${dangerousPorts.map((p) => DANGER_PORTS[p]).join(", ")}`,
        detail:
          "Services like databases and FTP should never be directly accessible from the public internet. Automated bots scan for these constantly and try default credentials within seconds of finding them. Restrict access to known IP addresses only using your server's firewall.",
        evidence: `${shodan.ip} — exposed ports: ${dangerousPorts.join(", ")}`,
        source: "Shodan InternetDB",
      });
    } else if (shodan.ports.length > 3) {
      findings.push({
        id: "live-open-ports",
        category: "domain-exposure",
        severity: "low",
        title: `${shodan.ports.length} internet-facing ports detected`,
        detail:
          "Standard ports (80, 443) are expected. Each additional open port is an additional attack surface. Review and close anything not required to be publicly accessible.",
        evidence: `${shodan.ip} — ports: ${shodan.ports.slice(0, 8).join(", ")}${shodan.ports.length > 8 ? "…" : ""}`,
        source: "Shodan InternetDB",
      });
    }
  }

  // ── Domain expiry (RDAP) ────────────────────────────────────
  if (expiry && expiry.daysLeft !== null) {
    if (expiry.daysLeft < 0) {
      findings.push({
        id: "live-expiry",
        category: "domain-exposure",
        severity: "critical",
        title: "Domain has already expired — anyone can register it",
        detail:
          "Your domain has passed its expiry date. If available, an attacker can register it immediately and redirect your web address and email to a phishing site that looks exactly like yours — targeting your donors.",
        evidence: `Domain expired ${new Date(expiry.expiry).toLocaleDateString()}`,
        source: "RDAP domain registry",
      });
    } else if (expiry.daysLeft < 30) {
      findings.push({
        id: "live-expiry",
        category: "domain-exposure",
        severity: "critical",
        title: `Domain expires in ${expiry.daysLeft} days — renew immediately`,
        detail:
          "If your domain lapses, attackers can register it within minutes of it becoming available and redirect your visitors and email to a phishing site. Renew now and enable auto-renewal so this never happens again.",
        evidence: `Domain expires ${new Date(expiry.expiry).toLocaleDateString()}`,
        source: "RDAP domain registry",
      });
    } else if (expiry.daysLeft < 60) {
      findings.push({
        id: "live-expiry",
        category: "domain-exposure",
        severity: "high",
        title: `Domain expires in ${expiry.daysLeft} days — enable auto-renew now`,
        detail:
          "Enable auto-renewal with your domain registrar so it never lapses. A lapsed domain is an attacker's opportunity to hijack your identity, redirect your donors, and impersonate your organization.",
        evidence: `Domain expires ${new Date(expiry.expiry).toLocaleDateString()}`,
        source: "RDAP domain registry",
      });
    }
  }

  // ── Exposed sensitive paths ─────────────────────────────────
  if (paths && paths.length > 0) {
    const critical = paths.filter((p) =>
      ["/.env", "/.git/config", "/phpmyadmin/", "/adminer.php", "/.htpasswd"].includes(p.path)
    );
    const warn = paths.filter((p) => !critical.find((c) => c.path === p.path));

    if (critical.length > 0) {
      findings.push({
        id: "live-exposed-critical",
        category: "domain-exposure",
        severity: "critical",
        title: `Critical file${critical.length > 1 ? "s" : ""} publicly accessible: ${critical.map((p) => p.path).join(", ")}`,
        detail:
          "These files should never be publicly readable. A .env file typically contains database passwords, API keys, and payment credentials. A .git/config exposes your entire codebase and commit history, which may include hard-coded secrets.",
        evidence: `HTTP 200 response from https://${domain}${critical[0].path}`,
        source: "Direct HTTP check",
      });
    }

    if (warn.length > 0) {
      findings.push({
        id: "live-exposed-paths",
        category: "domain-exposure",
        severity: "high",
        title: `${warn.length} sensitive path${warn.length > 1 ? "s" : ""} exposed: ${warn.slice(0, 2).map((p) => p.path).join(", ")}`,
        detail:
          "Publicly-accessible admin panels are targets for automated bots that test thousands of password combinations per minute. These should be firewalled to specific IP addresses, or the URL changed to a non-standard path.",
        evidence: warn.map((p) => p.path).join(", ") + ` accessible at https://${domain}`,
        source: "Direct HTTP check",
      });
    }
  }

  // ── robots.txt path disclosure ──────────────────────────────
  if (robots && robots.sensitiveDisallows.length > 0) {
    findings.push({
      id: "live-robots",
      category: "domain-exposure",
      severity: "low",
      title: "robots.txt reveals sensitive internal paths",
      detail:
        "robots.txt tells search engines which pages to ignore — but attackers read it as a roadmap to pages you're trying to hide. Admin panels, backup directories, and private sections are now labeled for them. Consider keeping robots.txt minimal.",
      evidence: `Sensitive Disallow entries: ${robots.sensitiveDisallows.slice(0, 3).join(", ")}`,
      source: "robots.txt analysis",
    });
  }

  // Sort: critical first, then by category for grouping
  const ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9));

  return findings;
}

/* ─── Main export ────────────────────────────────────────────
   Run everything in parallel; one failure doesn't block others.
──────────────────────────────────────────────────────────── */

export async function runSecurityScan(domain) {
  const [emailR, headersR, certsR, shodanR, expiryR, pathsR, robotsR] =
    await Promise.allSettled([
      checkEmailSecurity(domain),
      checkSecurityHeaders(domain),
      checkCertTransparency(domain),
      checkShodan(domain),
      checkDomainExpiry(domain),
      checkExposedPaths(domain),
      checkRobots(domain),
    ]);

  const v = (r) => (r.status === "fulfilled" ? r.value : null);
  const email   = v(emailR);
  const headers = v(headersR);
  const certs   = v(certsR);
  const shodan  = v(shodanR);
  const expiry  = v(expiryR);
  const paths   = v(pathsR) ?? [];
  const robots  = v(robotsR);

  const findings = buildFindings(email, headers, certs, shodan, expiry, paths, robots, domain);

  return {
    domain,
    scannedAt: new Date().toISOString(),
    findings,
    meta: {
      emailProvider: email?.emailProvider ?? null,
      ip: shodan?.ip ?? null,
      domainExpiryDays: expiry?.daysLeft ?? null,
      subdomainCount: certs?.subdomains.length ?? 0,
      sensitiveSubdomains: certs?.sensitiveSubdomains ?? [],
      openPorts: shodan?.ports ?? [],
      cves: shodan?.cves ?? [],
      exposedPaths: paths,
      isHTTPS: headers?.isHTTPS ?? false,
    },
  };
}
