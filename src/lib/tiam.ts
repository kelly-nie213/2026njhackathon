// TIAM — Trustless Identity & Access Management
//
// Traditional access management requires you to trust a central server:
//   "Server says user X is allowed → user X is allowed."
// If the server is compromised, every identity it vouches for is compromised.
//
// TIAM removes that trust requirement using public-key cryptography:
//   - You generate an ECDSA P-256 keypair entirely in your browser.
//   - The private key NEVER leaves your browser.
//   - To claim ownership of a domain you sign a structured message with your
//     private key.  Anyone (including our server) can verify that signature
//     using only your public key — no secret shared with us, no password, no
//     central registry.
//
// This is "trustless" because verification is pure math: the server doesn't
// need to trust a database entry; it just checks the signature.

export interface TiamKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyJwk: string;  // JSON Web Key — safe to share / store
  fingerprint: string;   // human-readable colon-hex like a TLS cert
}

export interface DomainClaim {
  domain: string;
  timestamp: string;
  publicKey: string;  // JWK
  signature: string;  // base64-encoded DER signature
  fingerprint: string;
  message: string;    // the exact string that was signed — needed to re-verify
}

export interface StoredIdentity {
  publicKeyJwk: string;
  fingerprint: string;
  domain: string;
  createdAt: string;
}

const STORAGE_KEY = "aegis:tiam:identity";

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** SHA-256 fingerprint of the JWK string, formatted as colon-pairs. */
async function buildFingerprint(jwk: string): Promise<string> {
  const data = new TextEncoder().encode(jwk);
  const hex = toHex(await crypto.subtle.digest("SHA-256", data));
  const pairs = hex.slice(0, 32).match(/.{2}/g)!;
  return pairs.join(":").toUpperCase();
}

/**
 * Generate a fresh ECDSA P-256 keypair.
 * P-256 (secp256r1) is widely supported and gives 128-bit security.
 * Keys are extractable so the public key can be shared / stored.
 */
export async function generateKeyPair(): Promise<TiamKeyPair> {
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const publicKeyJwk = JSON.stringify(jwk, null, 2);
  const fingerprint = await buildFingerprint(publicKeyJwk);
  return {
    publicKey: keys.publicKey,
    privateKey: keys.privateKey,
    publicKeyJwk,
    fingerprint,
  };
}

/**
 * Sign a domain-ownership claim.
 * The message format is deterministic so any verifier can reconstruct it.
 *
 * Message = "tiam:v1:domain-claim:<domain>:<iso-timestamp>"
 */
export async function signDomainClaim(
  domain: string,
  keyPair: TiamKeyPair
): Promise<DomainClaim> {
  const timestamp = new Date().toISOString();
  const message = `tiam:v1:domain-claim:${domain}:${timestamp}`;
  const data = new TextEncoder().encode(message);
  const sigBuf = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    keyPair.privateKey,
    data
  );
  const signature = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
  return {
    domain,
    timestamp,
    publicKey: keyPair.publicKeyJwk,
    signature,
    fingerprint: keyPair.fingerprint,
    message,
  };
}

/**
 * Verify a DomainClaim using only the public key it carries.
 * Returns true iff the signature is valid for the embedded message.
 * No secret, no central server — pure math.
 */
export async function verifyDomainClaim(claim: DomainClaim): Promise<boolean> {
  try {
    const jwk = JSON.parse(claim.publicKey);
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const data = new TextEncoder().encode(claim.message);
    const sigBytes = Uint8Array.from(atob(claim.signature), (c) => c.charCodeAt(0));
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey,
      sigBytes,
      data
    );
  } catch {
    return false;
  }
}

export function storeIdentity(identity: StoredIdentity): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(identity));
}

export function loadIdentity(): StoredIdentity | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw) as StoredIdentity; } catch { return null; }
}

export function clearIdentity(): void {
  localStorage.removeItem(STORAGE_KEY);
}

// ── Server-side TIAM auth (Phase 3) ──────────────────────────────────────────

export interface TiamAuthResult {
  verified: boolean;
  organization?: string;
  permissions?: string[];
  reason?: string;
}

/** Register the public key with the server. No password, no email. */
export async function registerWithServer(
  keyPair: TiamKeyPair,
  organization: string
): Promise<{ fingerprint: string; organization: string }> {
  const res = await fetch("/api/tiam/register", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ publicKeyJwk: keyPair.publicKeyJwk, organization }),
  });
  if (!res.ok) throw new Error("registration_failed");
  return res.json();
}

/**
 * Full challenge-response authentication:
 *   1. Ask server for a one-time challenge string.
 *   2. Sign it with the private key (private key never leaves browser).
 *   3. Send signature to server for math verification.
 *   Server learns: "this keypair is valid" — nothing else.
 */
export async function authenticateWithServer(
  keyPair: TiamKeyPair
): Promise<TiamAuthResult> {
  // Step 1: get challenge
  const challengeRes = await fetch("/api/tiam/challenge", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ fingerprint: keyPair.fingerprint }),
  });
  if (!challengeRes.ok) return { verified: false, reason: "challenge_request_failed" };
  const { challenge } = await challengeRes.json() as { challenge: string };

  // Step 2: sign the challenge — private key stays in browser memory
  const data   = new TextEncoder().encode(challenge);
  const sigBuf = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    keyPair.privateKey,
    data
  );
  const signature = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));

  // Step 3: verify — server checks math only
  const verifyRes = await fetch("/api/tiam/verify", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ fingerprint: keyPair.fingerprint, signature }),
  });
  if (!verifyRes.ok) return { verified: false, reason: "verification_request_failed" };
  return verifyRes.json() as Promise<TiamAuthResult>;
}
