// Client-side Merkle proof verification.
//
// The server gives us: { leaf, proof: [{hash, side},...], root }
// We recompute the root from the leaf + proof path.
// If our computed root matches the server's root → the commitment is provably in the set.
// We learn nothing about any other commitment in the tree.

export interface MerkleProofStep {
  hash: string;
  side: "left" | "right";
}

export interface MerkleProof {
  leaf: string;
  proof: MerkleProofStep[];
  root: string;
}

async function sha256hex(a: string, b: string): Promise<string> {
  const input = new Uint8Array(
    (a + b).match(/.{2}/g)!.map(h => parseInt(h, 16))
  );
  const buf = await crypto.subtle.digest("SHA-256", input);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Verify a Merkle membership proof in the browser.
 * Returns true iff the leaf's hash path recomputes to the expected root.
 * No server call required — pure math.
 */
export async function verifyMerkleProof({ leaf, proof, root }: MerkleProof): Promise<boolean> {
  let current = leaf;
  for (const { hash, side } of proof) {
    current = await (side === "left"
      ? sha256hex(hash, current)
      : sha256hex(current, hash));
  }
  return current === root;
}

/** Fetch a membership proof for a commitment from the server. */
export async function fetchMerkleProof(commitment: string): Promise<MerkleProof | null> {
  try {
    const res = await fetch("/api/merkle-proof", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ commitment }),
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

/** Fetch the current Merkle root (public state of the commitment set). */
export async function fetchMerkleRoot(): Promise<{ root: string | null; size: number } | null> {
  try {
    const res = await fetch("/api/merkle-root");
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}
