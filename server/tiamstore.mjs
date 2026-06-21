// TIAM identity store — no passwords, no emails, public keys only.
//
// Registration stores: publicKey + organization + permissions.
// Authentication is challenge-response:
//   1. Client asks for a challenge (one-time string tied to their fingerprint).
//   2. Client signs the challenge with their private key (which never leaves the browser).
//   3. Server verifies the signature using the stored public key.
//   4. Server learns: "this keypair is valid" — nothing else.
//
// The vault (private key) is NEVER accessed by the server.
// The server only validates the math.

import { createHash } from "crypto";

// fingerprint → { publicKeyJwk, organization, permissions, registeredAt }
const identities = new Map();

// fingerprint → { challenge, expiresAt }  — consumed on first successful verify
const pendingChallenges = new Map();

function fingerprintFromJwk(jwkString) {
  return createHash("sha256")
    .update(jwkString)
    .digest("hex")
    .slice(0, 32)
    .toUpperCase()
    .match(/.{2}/g)
    .join(":");
}

export function registerIdentity(publicKeyJwk, organization) {
  const fingerprint = fingerprintFromJwk(publicKeyJwk);
  identities.set(fingerprint, {
    publicKeyJwk,
    organization: organization || "Unknown",
    permissions:  ["scan", "verify"],
    registeredAt: new Date().toISOString(),
  });
  return { fingerprint, organization, permissions: ["scan", "verify"] };
}

export function issueChallenge(fingerprint) {
  if (!identities.has(fingerprint)) {
    throw Object.assign(new Error("identity_not_found"), { status: 404 });
  }
  const nonce     = createHash("sha256")
    .update(`${fingerprint}:${Date.now()}:${Math.random()}`)
    .digest("hex")
    .slice(0, 24);
  const timestamp = Date.now();
  const challenge = `tiam:v1:login:${fingerprint}:${timestamp}:${nonce}`;
  pendingChallenges.set(fingerprint, { challenge, expiresAt: timestamp + 5 * 60_000 });
  return { challenge };
}

export async function verifyChallenge(fingerprint, signatureB64) {
  const identity = identities.get(fingerprint);
  if (!identity) return { verified: false, reason: "identity_not_found" };

  const pending = pendingChallenges.get(fingerprint);
  if (!pending || Date.now() > pending.expiresAt) {
    return { verified: false, reason: "challenge_expired_or_missing" };
  }

  try {
    // Node 18+ ships SubtleCrypto — same API as the browser.
    const { subtle } = await import("node:crypto");
    const jwk        = JSON.parse(identity.publicKeyJwk);
    const publicKey  = await subtle.importKey(
      "jwk", jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const data = new TextEncoder().encode(pending.challenge);
    const sig  = Buffer.from(signatureB64, "base64");
    const ok   = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, sig, data);

    if (ok) {
      pendingChallenges.delete(fingerprint); // one-time use
      return {
        verified:     true,
        organization: identity.organization,
        permissions:  identity.permissions,
      };
    }
    return { verified: false, reason: "invalid_signature" };
  } catch {
    return { verified: false, reason: "verification_error" };
  }
}

export function getIdentity(fingerprint) {
  const id = identities.get(fingerprint);
  if (!id) return null;
  // Never return the raw JWK in a listing — fingerprint is the public identifier.
  return { fingerprint, organization: id.organization, permissions: id.permissions, registeredAt: id.registeredAt };
}

export function listIdentities() {
  return [...identities.entries()].map(([fp, id]) => ({
    fingerprint:  fp,
    organization: id.organization,
    permissions:  id.permissions,
    registeredAt: id.registeredAt,
  }));
}
