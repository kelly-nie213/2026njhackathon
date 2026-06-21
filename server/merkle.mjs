// Merkle tree for cryptographic membership proofs.
//
// What it does:
//   Stores all breach commitment hashes in a binary tree.
//   The root hash is a single fingerprint of the entire set.
//   For any commitment, we can produce a proof: a path of sibling hashes
//   that lets anyone recompute the root — proving the commitment is in the set
//   without revealing any other commitments.
//
// Why this matters for ZKP:
//   The client receives: { leaf: commitment, proof: [...], root }
//   It computes: hash(hash(leaf + sibling) + sibling2) ... → must equal root
//   If it does, the commitment is provably in the set.
//   No other entry is revealed. The server's full set stays private.

import { createHash } from "crypto";

function sha256pair(a, b) {
  return createHash("sha256").update(Buffer.from(a + b, "hex")).digest("hex");
}

export class MerkleTree {
  constructor() {
    this.leaves = []; // commitment hashes in insertion order
    this._levels = [[]];
    this.root = null;
  }

  // Add a commitment to the tree and rebuild.
  add(commitment) {
    if (this.leaves.includes(commitment)) return; // idempotent
    this.leaves.push(commitment);
    this._rebuild();
  }

  _rebuild() {
    if (this.leaves.length === 0) { this._levels = [[]]; this.root = null; return; }
    let level = this.leaves.slice();
    this._levels = [level];
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(sha256pair(level[i], level[i + 1] ?? level[i]));
      }
      this._levels.push(next);
      level = next;
    }
    this.root = level[0];
  }

  // Return a membership proof for a commitment.
  // Proof = array of { hash, side } where side tells the verifier which side to place the sibling.
  getProof(commitment) {
    const idx = this.leaves.indexOf(commitment);
    if (idx === -1) return null;
    const proof = [];
    let pos = idx;
    for (let lvl = 0; lvl < this._levels.length - 1; lvl++) {
      const isRight   = pos % 2 === 1;
      const siblingPos = isRight ? pos - 1 : pos + 1;
      const sibling    = this._levels[lvl][siblingPos] ?? this._levels[lvl][pos];
      proof.push({ hash: sibling, side: isRight ? "left" : "right" });
      pos = Math.floor(pos / 2);
    }
    return { leaf: commitment, proof, root: this.root };
  }

  get size() { return this.leaves.length; }
}

// Verify a proof without the full tree — pure math, works client-side too.
export function verifyProof(leaf, proof, expectedRoot) {
  let current = leaf;
  for (const { hash, side } of proof) {
    current = side === "left"
      ? sha256pair(hash, current)
      : sha256pair(current, hash);
  }
  return current === expectedRoot;
}

// One shared tree per server process.
export const breachMerkleTree = new MerkleTree();
