// SSRF guard — shared by every module that opens a connection to a user-supplied
// host (crawl, web-security, js-audit). The domain regex in those modules already
// rejects raw IP literals and bare "localhost" (they have no dot+TLD), so the one
// remaining vector is a *domain that resolves to an internal IP*: an attacker
// registers evil.com → 169.254.169.254 (cloud metadata) or points an internal DNS
// name at 10.x. assertPublicHost resolves the host first and refuses to let the
// server reach any private/loopback/link-local/reserved address.
//
// Limitation (acceptable for this app): there's a small TOCTOU window between this
// DNS resolution and the actual fetch (a classic DNS-rebinding race). Closing it
// fully means pinning the connection to the resolved IP via a custom dispatcher;
// for a public-recon tool a private-IP block on the resolved address is the
// pragmatic 95% fix and is what matters once this is deployed off localhost.

import { promises as dns } from "node:dns";
import net from "node:net";

/** True if an IPv4 dotted-quad is in a private / loopback / reserved range. */
function isPrivateV4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true; // unparseable → treat as unsafe
  }
  const [a, b] = p;
  if (a === 0) return true; // 0.0.0.0/8 "this host"
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
  if (a === 192 && b === 0 && p[2] === 0) return true; // 192.0.0/24 IETF
  if (a === 192 && b === 0 && p[2] === 2) return true; // 192.0.2/24 TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18/15 benchmarking
  if (a === 198 && b === 51 && p[2] === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && p[2] === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // 224/4 multicast + 240/4 reserved + 255.255.255.255
  return false;
}

/** True if an IPv6 address is loopback / unspecified / ULA / link-local / etc. */
function isPrivateV6(ip) {
  const addr = ip.toLowerCase().split("%")[0]; // drop any zone id
  if (addr === "::1" || addr === "::") return true; // loopback / unspecified
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible — judge by the embedded v4.
  const mapped = addr.match(/(?:::ffff:|::)(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateV4(mapped[1]);
  const head = addr.replace(/^\[/, "");
  if (head.startsWith("fc") || head.startsWith("fd")) return true; // fc00::/7 ULA
  if (head.startsWith("fe8") || head.startsWith("fe9") || head.startsWith("fea") || head.startsWith("feb")) {
    return true; // fe80::/10 link-local
  }
  if (head.startsWith("ff")) return true; // ff00::/8 multicast
  if (head.startsWith("fd00:ec2") ) return true; // AWS IMDS over IPv6
  return false;
}

function isPrivateIp(ip) {
  return net.isIPv4(ip) ? isPrivateV4(ip) : net.isIPv6(ip) ? isPrivateV6(ip) : true;
}

/**
 * Resolve `host` and throw before any request is made if it points anywhere
 * internal. Throws:
 *   - "unreachable"  if the host doesn't resolve at all
 *   - "blocked_host" if ANY resolved address is private/loopback/reserved
 * On success returns the list of public addresses it resolved to.
 */
export async function assertPublicHost(host) {
  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true });
  } catch {
    throw new Error("unreachable");
  }
  if (!addrs || addrs.length === 0) throw new Error("unreachable");
  for (const { address } of addrs) {
    if (isPrivateIp(address)) throw new Error("blocked_host");
  }
  return addrs.map((a) => a.address);
}

// Exported for unit-testing the range logic in isolation.
export { isPrivateIp };
