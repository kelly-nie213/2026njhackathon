// Client-side Bloom filter — mirrors the server's BloomFilter exactly.
//
// The client downloads the filter once (~64KB binary, base64-encoded).
// It then checks SHA-256(email) locally — the server receives nothing.
//
// Result semantics:
//   false  → definitely NOT in the breach set (zero false negatives)
//   true   → probably in the breach set (small false positive rate ~1%)
//
// The filter only contains BREACHED commitments, so:
//   "definitely not in filter" → show as clean, skip server query entirely
//   "probably in filter"       → still confirm with server (eliminates FP)

export interface BloomFilterMeta {
  bits: string;      // base64-encoded Uint8Array
  sizeBits: number;
  numHashes: number;
  count: number;     // approximate items added
}

class ClientBloomFilter {
  private bits: Uint8Array;
  private sizeBits: number;
  private numHashes: number;
  readonly count: number;

  constructor(meta: BloomFilterMeta) {
    this.sizeBits  = meta.sizeBits;
    this.numHashes = meta.numHashes;
    this.count     = meta.count;
    const binary   = atob(meta.bits);
    this.bits      = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) this.bits[i] = binary.charCodeAt(i);
  }

  // Must match the server's _positions() exactly.
  private positions(hexHash: string): number[] {
    const bytes = new Uint8Array(hexHash.match(/.{2}/g)!.map(h => parseInt(h, 16)));
    const pos: number[] = [];
    for (let i = 0; i < this.numHashes; i++) {
      const off = (i * 4) % (bytes.length - 3);
      // big-endian uint32 — matches Node's Buffer.readUInt32BE
      const num = ((bytes[off] << 24) | (bytes[off+1] << 16) | (bytes[off+2] << 8) | bytes[off+3]) >>> 0;
      pos.push(num % this.sizeBits);
    }
    return pos;
  }

  test(hexHash: string): boolean {
    return this.positions(hexHash).every(p => !!(this.bits[p >>> 3] & (1 << (p & 7))));
  }
}

let cached: ClientBloomFilter | null = null;
let cachedAt = 0;
const TTL_MS = 5 * 60_000; // re-fetch every 5 min so new breached commitments appear

export async function fetchBloomFilter(): Promise<ClientBloomFilter | null> {
  if (cached && Date.now() - cachedAt < TTL_MS) return cached;
  try {
    const res = await fetch("/api/bloom-filter");
    if (!res.ok) return null;
    const meta: BloomFilterMeta = await res.json();
    cached   = new ClientBloomFilter(meta);
    cachedAt = Date.now();
    return cached;
  } catch {
    return null;
  }
}

export function invalidateBloomCache(): void {
  cached   = null;
  cachedAt = 0;
}

/**
 * Check a commitment (SHA-256 hex of an email) against the local filter.
 * Returns:
 *   null   → filter unavailable (fall back to server)
 *   false  → definitely not breached (skip server entirely)
 *   true   → probably breached (confirm with server)
 */
export async function checkCommitmentLocally(commitment: string): Promise<boolean | null> {
  const filter = await fetchBloomFilter();
  if (!filter) return null;
  return filter.test(commitment);
}
