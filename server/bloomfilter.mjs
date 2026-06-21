// Bloom filter — probabilistic data structure for privacy-preserving breach lookup.
//
// What it does:
//   add(commitment)  → set k bits in a 512k-bit array
//   test(commitment) → check those k bits
//   → "definitely NOT in set"  (all k bits not set)
//   → "PROBABLY in set"        (all k bits set — can have false positives, never false negatives)
//
// Why this matters for ZKP:
//   The client downloads the filter once (~64KB).
//   It then checks SHA-256(email) locally — the server sees NOTHING.
//   Only when the filter says "probably breached" do we query the server to confirm.
//   Clean emails that pass the filter check never reach the server at all.
//
// Parameters chosen for the hackathon:
//   m = 524,288 bits (64KB)  — small enough to download in one request
//   k = 7 hash functions     — optimal for ~1% FP rate at low density
//   Capacity: ~25k items at <1% FP, ~100k items at ~10% FP

import { Buffer } from "buffer";

const FILTER_BITS = 524_288; // 512k bits = 64KB
const NUM_HASHES  = 7;

export class BloomFilter {
  constructor(sizeBits = FILTER_BITS, numHashes = NUM_HASHES) {
    this.sizeBits  = sizeBits;
    this.numHashes = numHashes;
    this.bits      = new Uint8Array(Math.ceil(sizeBits / 8));
    this.count     = 0; // items added
  }

  // Derive k independent bit-positions from a 32-byte (64 hex char) commitment.
  // Each group of 4 bytes → uint32 → mod m.  No BigInt needed; stays in safe int range.
  _positions(hexHash) {
    const bytes = Buffer.from(hexHash, "hex"); // 32 bytes
    const pos   = [];
    for (let i = 0; i < this.numHashes; i++) {
      const offset = (i * 4) % (bytes.length - 3); // 0,4,8,12,16,20,24 (all ≤28)
      const num    = bytes.readUInt32BE(offset);
      pos.push(num % this.sizeBits);
    }
    return pos;
  }

  add(hexHash) {
    for (const p of this._positions(hexHash)) {
      this.bits[p >>> 3] |= 1 << (p & 7);
    }
    this.count++;
  }

  // Returns false  → definitely not in set (zero false negatives)
  // Returns true   → probably in set    (small false positive rate)
  test(hexHash) {
    return this._positions(hexHash).every(p => !!(this.bits[p >>> 3] & (1 << (p & 7))));
  }

  serialize() {
    return {
      bits:      Buffer.from(this.bits).toString("base64"),
      sizeBits:  this.sizeBits,
      numHashes: this.numHashes,
      count:     this.count,
    };
  }

  static deserialize({ bits, sizeBits, numHashes }) {
    const f  = new BloomFilter(sizeBits, numHashes);
    f.bits   = new Uint8Array(Buffer.from(bits, "base64"));
    f.count  = 0; // count not encoded in bits, leave as approximation
    return f;
  }
}

// One shared filter per server process.
// Populated with BREACHED commitments only — so "probably in filter" means "probably breached."
export const breachBloomFilter = new BloomFilter();
