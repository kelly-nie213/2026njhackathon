// Zero-Knowledge Proof utilities — commitment scheme using Web Crypto API.
//
// Core idea: you can *prove* you know an email (or that it appears in a
// breach database) without ever revealing the email itself.
//
// How it works:
//   commitment = SHA-256(email + ":" + random_salt)
//   prefix     = first 8 hex chars of commitment
//
// The client sends only `prefix` to the server.  The server returns every
// commitment that starts with those 8 chars.  The client then checks locally
// whether its full commitment appears in the list — learning the answer
// without the server ever seeing the raw email.  This is the same k-anonymity
// model that HaveIBeenPwned uses for password range queries.

export interface ZkpProof {
  commitment: string; // SHA-256(email:salt) — 64 hex chars
  salt: string;       // random 16-byte hex — stays in the browser
  prefix: string;     // first 8 hex chars — the only thing sent to a server
}

export interface ZkpStep {
  label: string;
  value: string;
  highlight?: boolean;
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomSaltHex(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(16)).buffer);
}

/** SHA-256 of the normalized email alone (deterministic — useful for display). */
export async function hashEmail(email: string): Promise<string> {
  const data = new TextEncoder().encode(email.toLowerCase().trim());
  return toHex(await crypto.subtle.digest("SHA-256", data));
}

/**
 * Build a ZKP commitment: commitment = SHA-256(email:salt).
 * Salt is generated fresh each call so the commitment is unlinkable across
 * separate proofs of the same email.
 */
export async function createZkpProof(email: string): Promise<ZkpProof> {
  const salt = randomSaltHex();
  const data = new TextEncoder().encode(`${email.toLowerCase().trim()}:${salt}`);
  const commitment = toHex(await crypto.subtle.digest("SHA-256", data));
  return { commitment, salt, prefix: commitment.slice(0, 8) };
}

/**
 * Verify that a proof is consistent: re-derive the commitment from the
 * original email + stored salt and compare to what was recorded.
 */
export async function verifyZkpProof(email: string, proof: ZkpProof): Promise<boolean> {
  const data = new TextEncoder().encode(`${email.toLowerCase().trim()}:${proof.salt}`);
  const derived = toHex(await crypto.subtle.digest("SHA-256", data));
  return derived === proof.commitment;
}

/** Build the annotated step list shown in the UI walkthrough. */
export async function buildZkpSteps(email: string, proof: ZkpProof): Promise<ZkpStep[]> {
  return [
    { label: "Your email (stays in your browser)", value: email },
    { label: "Random one-time salt (generated locally)", value: proof.salt },
    {
      label: "Commitment = SHA-256(email + salt)",
      value: proof.commitment,
      highlight: true,
    },
    {
      label: "Only the prefix is sent to the server",
      value: proof.prefix + "…",
      highlight: true,
    },
    {
      label: "Server returns all commitments that start with that prefix",
      value: `[${proof.prefix}…, ${proof.prefix.slice(0, 4)}b2a9…, ${proof.prefix.slice(0, 4)}f17c…]`,
    },
    {
      label: "You check locally: is your full commitment in the list?",
      value: `${proof.commitment} ∈ list  →  result revealed locally`,
      highlight: true,
    },
  ];
}
