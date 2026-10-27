// In-memory transport observer. Never signs, generates entropy, or persists data.
import { hodlBytewordsDecode, hodlCrc32 } from "./psbt-ur.js";
import { sha256 } from "./hashes.js";
import { aexbDecode, aexbVerify } from "./aexb.js";
import { verifyAexbTransaction } from "./aexb-transaction.js";
const MAX_BYTES = 2065600,
  MAX_PARTS = 512,
  MAX_FRAME = 20000;
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const crc = (a) => new DataView(hodlCrc32(a).buffer).getUint32(0);
function fail(code) {
  throw new Error(code);
}
// Canonical CBOR unsigned integers / byte strings only, with bounded lengths.
function reader(bytes) {
  let at = 0;
  const head = (major) => {
    if (at >= bytes.length) fail("CBOR_TRUNCATED");
    const h = bytes[at++];
    if (h >> 5 !== major) fail("CBOR_TYPE");
    const n = h & 31;
    if (n < 24) return n;
    const width = { 24: 1, 25: 2, 26: 4 }[n];
    if (!width || at + width > bytes.length) fail("CBOR_LENGTH");
    let v = 0;
    for (let i = 0; i < width; i++) v = v * 256 + bytes[at++];
    if (v < { 1: 24, 2: 256, 4: 65536 }[width]) fail("CBOR_NONCANONICAL");
    return v;
  };
  return {
    uint: () => head(0),
    array: () => head(4),
    bstr: () => {
      const n = head(2);
      if (n > MAX_BYTES || at + n > bytes.length) fail("CBOR_LENGTH");
      const b = bytes.slice(at, at + n);
      at += n;
      return b;
    },
    end: () => {
      if (at !== bytes.length) fail("CBOR_TRAILING");
    },
  };
}
// Deterministic BCR fountain fragment selection, ported from Foundation Devices'
// ur2 fountain_utils/random_sampler/xoshiro256 (2020), BSD-2-Clause-Patent.
// See src/licenses/ur2.txt. This PRNG selects public transport fragments only.
function indexes(seq, count, checksum) {
  if (seq <= count) return [seq - 1];
  const seed = new Uint8Array(8),
    view = new DataView(seed.buffer);
  view.setUint32(0, seq);
  view.setUint32(4, checksum);
  const digest = sha256(seed),
    d = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
  const s = [0, 8, 16, 24].map((i) => d.getBigUint64(i)),
    mask = (1n << 64n) - 1n;
  const rot = (v, n) => ((v << n) | (v >> (64n - n))) & mask;
  const random = () => {
    const out = (rot((s[1] * 5n) & mask, 7n) * 9n) & mask,
      t = (s[1] << 17n) & mask;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rot(s[3], 45n);
    return Number(out) / 18446744073709551616;
  };
  const weights = Array.from({ length: count }, (_, i) => 1 / (i + 1)),
    total = weights.reduce((a, b) => a + b, 0);
  const p = weights.map((x) => (x * count) / total),
    small = [],
    large = [],
    prob = [],
    alias = [];
  for (let i = count - 1; i >= 0; i--) (p[i] < 1 ? small : large).push(i);
  while (small.length && large.length) {
    const a = small.pop(),
      g = large.pop();
    prob[a] = p[a];
    alias[a] = g;
    p[g] += p[a] - 1;
    (p[g] < 1 ? small : large).push(g);
  }
  for (const i of [...small, ...large]) prob[i] = 1;
  const r1 = random(),
    r2 = random(),
    i = Math.min(count - 1, Math.floor(count * r1)),
    degree = (r2 < prob[i] ? i : alias[i]) + 1;
  const remaining = Array.from({ length: count }, (_, i) => i),
    chosen = [];
  while (remaining.length)
    chosen.push(
      remaining.splice(
        Math.min(remaining.length - 1, Math.floor(random() * remaining.length)),
        1,
      )[0],
    );
  return chosen.slice(0, degree);
}
export class UrCapture {
  constructor() {
    this.clear();
  }
  clear() {
    for (const r of this.rows?.values() || []) r.data.fill(0);
    this.done?.fill(0);
    this.rows = new Map();
    this.meta = null;
    this.done = null;
  }
  progress() {
    return {
      received: this.rows.size,
      total: this.meta?.count || 0,
      complete: !!this.done,
    };
  }
  receive(raw) {
    if (typeof raw !== "string" || raw.length > MAX_FRAME) fail("FRAME_LIMIT");
    const m = raw
      .trim()
      .toLowerCase()
      .match(/^ur:([a-z0-9-]+)\/(?:(\d+)-(\d+)\/)?([a-z]+)$/);
    if (!m) fail("INVALID_UR");
    if (m[1] !== "x-btc-anti-exfil") fail("UR_TYPE");
    const temporary = [], retained = new Set();
    const own = bytes => { temporary.push(bytes); return bytes; };
    try {
    const payload = own(hodlBytewordsDecode(m[4]));
    if (!m[2]) {
      if (this.meta) fail("MIXED_MESSAGE");
      const r = reader(payload),
        b = own(r.bstr());
      r.end();
      retained.add(b);
      return { complete: true, bytes: b };
    }
    const seq = Number(m[2]),
      count = Number(m[3]);
    if (
      !Number.isInteger(seq) ||
      seq < 1 ||
      seq > 0xffffffff ||
      count < 1 ||
      count > MAX_PARTS
    )
      fail("PART_LIMIT");
    const r = reader(payload);
    if (r.array() !== 5) fail("PART_FORMAT");
    if (r.uint() !== seq || r.uint() !== count) fail("PART_SEQUENCE");
    const length = r.uint(),
      checksum = r.uint(),
      data = own(r.bstr());
    r.end();
    if (
      !length ||
      length > MAX_BYTES ||
      !data.length ||
      data.length > 8192 ||
      Math.ceil(length / data.length) !== count
    )
      fail("PART_LIMIT");
    const meta = { count, length, checksum, size: data.length };
    if (this.meta && Object.keys(meta).some((k) => meta[k] !== this.meta[k]))
      fail("MIXED_MESSAGE");
    if (this.done) return { complete: true, bytes: this.done.slice() };
    let bits = 0n;
    for (const i of indexes(seq, count, checksum)) bits |= 1n << BigInt(i);
    // Bounded row-echelon elimination retains at most count rows, including mixed
    // fountain frames. Inconsistent equations fail, rather than replacing rows.
    for (let i = 0; i < count; i++)
      if (bits & (1n << BigInt(i))) {
        const row = this.rows.get(i);
        if (row) {
          bits ^= row.bits;
          for (let j = 0; j < data.length; j++) data[j] ^= row.data[j];
        } else {
          this.meta = meta;
          this.rows.set(i, { bits, data });
          retained.add(data);
          break;
        }
      }
    if (bits === 0n && data.some((x) => x)) fail("CONFLICTING_FRAME");
    if (this.rows.size !== count) return this.progress();
    const parts = new Array(count);
    for (let i = count - 1; i >= 0; i--) {
      const row = this.rows.get(i),
        b = own(row.data.slice());
      for (let j = i + 1; j < count; j++)
        if (row.bits & (1n << BigInt(j)))
          for (let k = 0; k < b.length; k++) b[k] ^= parts[j][k];
      parts[i] = b;
    }
    const full = own(new Uint8Array(count * meta.size));
    parts.forEach((b, i) => {
      full.set(b, i * meta.size);
      b.fill(0);
    });
    const joined = own(full.slice(0, length));
    full.fill(0);
    if (crc(joined) !== checksum) {
      this.clear();
      fail("MESSAGE_CHECKSUM");
    }
    const cbor = reader(joined),
      bytes = own(cbor.bstr());
    cbor.end();
    joined.fill(0);
    this.done = bytes;
    retained.add(bytes);
    return { complete: true, bytes: bytes.slice() };
    } finally {
      for (const bytes of temporary) if (!retained.has(bytes)) bytes.fill(0);
    }
  }
}
function wipeMessage(bytes, decoded) {
  bytes?.fill(0);
  if (!decoded) return;
  for (const value of Object.values(decoded))
    if (value instanceof Uint8Array) value.fill(0);
  for (const value of Object.values(decoded.package || {}))
    if (value instanceof Uint8Array) value.fill(0);
  for (const slot of decoded.slots || [])
    for (const value of Object.values(slot))
      if (value instanceof Uint8Array) value.fill(0);
}
export class AexbCapture {
  constructor() {
    this.clear();
  }
  clear() {
    for (const entry of this.messages?.values() || [])
      wipeMessage(entry.bytes, entry.decoded);
    this.messages = new Map();
    this.transactionResult = null;
  }
  accept(input) {
    if (!(input instanceof Uint8Array) || input.length > MAX_BYTES)
      fail("MESSAGE_LIMIT");
    if (
      input[0] !== 65 ||
      input[1] !== 69 ||
      input[2] !== 88 ||
      input[3] !== 84
    )
      fail("AEXT_ENVELOPE_REQUIRED");
    const bytes = input.slice();
    let decoded, retained = false;
    try {
    decoded = aexbDecode(bytes);
    if (![2, 3, 4].includes(decoded.stage)) fail("CAPTURE_STAGE");
    const previous = this.messages.get(decoded.stage);
    if (previous) {
      if (!equal(bytes, previous.bytes)) fail("STAGE_CONFLICT");
      return this.snapshot();
    }
    const first = this.messages.values().next().value?.decoded;
    if (
      first &&
      (first.network !== decoded.network ||
        !equal(first.sessionId, decoded.sessionId) ||
        !equal(first.psbtDigest, decoded.psbtDigest))
    )
      fail("SESSION_MISMATCH");
    this.messages.set(decoded.stage, { bytes, decoded });
    retained = true;
    return this.snapshot();
    } finally {
      // Duplicate/rejected messages must not leave unnecessary owned copies.
      if (!retained) wipeMessage(bytes, decoded);
    }
  }
  snapshot() {
    const stages = [...this.messages.keys()].sort(),
      get = (s) => this.messages.get(s)?.decoded;
    return {
      stages,
      verdict: stages.length === 3 ? aexbVerify(get(4), get(3), get(2)) : null,
    };
  }
  finish() {
    if (this.messages.size !== 3) return null;
    const totalSlots = this.messages.get(4).decoded.slots.length;
    try {
      const proof = this.snapshot().verdict;
      if (!proof.ok) return { ok: false, reason: proof.reason || proof.slots?.find(slot => !slot.ok)?.reason || "VERIFICATION_FAILED", checkedSlots: 0, totalSlots };
      return { ...this.checkTransaction(), totalSlots };
    } catch {
      return { ok: false, reason: "VERIFICATION_UNAVAILABLE", checkedSlots: 0, totalSlots };
    } finally {
      // Completion never keeps the transcript waiting for a human acknowledgement.
      this.clear();
    }
  }
  checkTransaction() {
    const proof = this.snapshot();
    if (!proof.verdict?.ok) return null;
    if (!this.transactionResult) this.transactionResult = verifyAexbTransaction(this.messages.get(3).decoded, this.messages.get(4).decoded);
    return { ...this.transactionResult };
  }
}
