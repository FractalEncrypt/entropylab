// BIP340 / Taproot nonce compare. R is the first 32 bytes of a 64/65-byte sig.

// The defined Taproot sighash bytes (BIP341): the three base types, each with
// or without ANYONECANPAY. SIGHASH_DEFAULT (0x00) exists only as the 64-byte
// form — an appended 0x00 suffix byte is invalid, and every other undefined
// suffix is invalid too.
export const TAPROOT_SIGHASH_BYTES = new Set([0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

// A Schnorr signature is exactly 64 bytes, or 65 with a defined sighash
// suffix. The first signature byte is R's x-coordinate and says nothing
// about the encoding, so Schnorr-vs-DER is never decided by it (issue #333).
export function hodlLooksSchnorr(item) {
  return !!item && (item.length === 64 || (item.length === 65 && TAPROOT_SIGHASH_BYTES.has(item[64])));
}

export function hodlParseSchnorr(raw) {
  if (!hodlLooksSchnorr(raw)) return null;
  return {
    r: raw.slice(0, 32),
    s: raw.slice(32, 64),
    sighash: raw.length === 65 ? raw[64] : 0,
    raw,
  };
}

// Taproot policy problems, with the commitment direction named: NONE and
// SINGLE (± ANYONECANPAY) drop outputs; ANYONECANPAY|ALL keeps every output
// but drops the other inputs; an undefined byte is not a policy at all
// (issue #333).
export function hodlTapSighashProblems(declared, suffix, hodlSighashLabel) {
  const problems = [];
  const describe = (value, whose, verb) => {
    if (value === 0 || value === 1) return null; // DEFAULT and ALL commit to everything
    const label = hodlSighashLabel(value);
    if (!TAPROOT_SIGHASH_BYTES.has(value)) return whose + " " + verb + " " + label + ", not a defined Taproot sighash byte.";
    if ((value & 0x7f) !== 1) return whose + " " + verb + " " + label + ", which does not commit to all shown outputs.";
    return whose + " " + verb + " " + label + ", which does not commit to all shown inputs.";
  };
  const declaredProblem = declared === null ? null : describe(declared, "The PSBT", "requests");
  if (declaredProblem) problems.push(declaredProblem);
  const suffixProblem = suffix === null ? null : describe(suffix, "This Schnorr signature", "uses");
  if (suffixProblem) problems.push(suffixProblem);
  if (declared !== null && suffix !== null && declared !== suffix && !((declared === 0 || declared === 1) && (suffix === 0 || suffix === 1))) {
    problems.push("The PSBT-declared policy and the Schnorr signature's sighash byte disagree.");
  }
  return problems;
}

export function hodlTapKeySigs(entries, hodlFind) {
  return hodlFind(entries, 19).filter((entry) => entry.keydata.length === 0).map((entry) => {
    const parsed = hodlParseSchnorr(entry.val);
    return parsed
      ? Object.assign({ pubkey: new Uint8Array(), source: "tap-key" }, parsed)
      : { pubkey: new Uint8Array(), r: null, s: null, sighash: null, raw: entry.val, source: "tap-key" };
  });
}

export function hodlTapScriptSigs(entries, hodlFind) {
  // Keydata is the 32-byte x-only key plus the 32-byte leaf hash; anything
  // shorter is a lookalike the consensus layer never verifies.
  return hodlFind(entries, 20).filter((entry) => entry.keydata.length === 64).map((entry) => {
    const parsed = hodlParseSchnorr(entry.val);
    const pubkey = entry.keydata.slice(0, 32);
    const leafHash = entry.keydata.slice(32, 64);
    return parsed
      ? Object.assign({ pubkey, leafHash, source: "tap-script" }, parsed)
      : { pubkey, leafHash, r: null, s: null, sighash: null, raw: entry.val, source: "tap-script" };
  });
}

// R values group by their hex encoding, exactly like hodlCompareNonces in
// app.js groups ECDSA r values.
function hodlSchnorrRHex(bytes) {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

// BIP340 nonce reuse. Every same-key same-R pair is a key leak: BIP341's
// signature message commits to the input index and, for script path, to the
// leaf hash, and key path and script path sign different messages
// (ext_flag) — so two valid signatures with one R under one x-only key are
// always on different messages, and s1 - s2 = (e1 - e2)*d reveals the key.
// One R and one key with the same s is one signature copied into two fields
// (same e, so the same message): it leaks nothing and is not reported. A
// pair whose s is missing is reported (fail closed). Same R under different
// keys is not reuse and is not reported. A record without a parsed R or without a
// 32-byte x-only key cannot be compared: it counts in `incomplete`, never
// silently skipped.
export function hodlCompareSchnorrNonces(records, hodlEq) {
  const reused = [];
  let incomplete = 0;
  const comparable = [];
  for (const record of records) {
    if (!record.r || record.r.length !== 32 || !record.pubkey || record.pubkey.length !== 32) {
      incomplete++;
      continue;
    }
    comparable.push(record);
  }
  // Group by R and compare only within a group, like hodlCompareNonces:
  // identical attacker-supplied R values collapse into one quadratic bucket,
  // so total candidate pairs are bounded before any result pair is allocated.
  const byR = new Map();
  for (const record of comparable) {
    const tag = hodlSchnorrRHex(record.r);
    let group = byR.get(tag);
    if (!group) byR.set(tag, (group = []));
    group.push(record);
  }
  let comparisons = 0;
  for (const group of byR.values()) {
    comparisons += group.length * (group.length - 1) / 2;
    if (comparisons > 32768) throw new Error("Nonce comparison limit exceeded: too many signatures share the same r value.");
  }
  for (const group of byR.values()) {
    if (group.length < 2) continue;
    for (let first = 0; first < group.length; first++)
      for (let second = first + 1; second < group.length; second++) {
        const a = group[first], b = group[second];
        if (!hodlEq(a.pubkey, b.pubkey)) continue;
        if (a.s && b.s && hodlEq(a.s, b.s)) continue; // the same signature twice
        reused.push([a, b]);
      }
  }
  return { reused, incomplete };
}
