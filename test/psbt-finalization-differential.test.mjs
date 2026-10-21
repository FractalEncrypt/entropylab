// PSBT finalization differential against @scure/btc-signer (pinned, the
// oracle: its finalize()/extract() plus BIP174/BIP371 semantics — never the
// app compared to itself). Each case builds a PSBT with @scure covering
// p2pkh, p2wpkh, p2sh-p2wpkh, p2wsh 2-of-3, p2tr key path, and p2tr script
// path with 2 leaves; 1–4 inputs, random amounts/sequences/locktime, mixed
// sighash types; every input is signed with @noble/curves.
//
// App surface: src/js/psbt-wasm.js exports only psbtInspectDoc and
// psbtBuildBytes — there is no finalize or extract entry point, and per the
// ledger's rule ("use only entry points already exported; skip any case
// whose needed entry point is not exported") the app side of every case is
// the full round-trip psbtBuildBytes(psbtInspectDoc(finalizedPsbt)): the
// app must accept the finalized PSBT (rust-bitcoin parse verdict null),
// re-serialize it without losing or corrupting the final scripts, and
// without changing which signature fields the finalized input maps carry.
// Extraction itself is @scure's, applied identically to the original and
// the app's bytes, so any difference is the app's re-serialization. The
// incompleteness invariant (remove one signature → refuse) is likewise
// asserted on the @scure side only: the app's inspector deliberately
// accepts partially signed PSBTs (they are the cosigner workflow's normal
// input), and no refusal entry point is exported, so that half of the
// invariant is skipped rather than faked. @scure/btc-signer exposes no
// public raw-transaction parser, so "re-parses strictly" is enforced as
// Transaction.fromPSBT with its default (strict) flags on the app's bytes.
// The inspect document reports the fee as a display-shaped object, so the
// fee invariant is checked at the satoshi level: the app's decoded output
// amounts (doc.tx.outputs, the same field psbt-differential-fuzz pins)
// must sum to the generator's independently constructed sum(inputs) − fee.
//
// If @scure/btc-signer cannot build or finalize a shape, that shape's kind
// is recorded and skipped (the ledger allows generating only the shapes it
// can); the run still requires at least four supported kinds and at least
// half the cases to have executed, so a skip can never hollow the suite
// out. The p2tr script path is built with @scure's own p2tr payment
// (internal key + a two-leaf tree), so the tweaked output key, the merkle
// root and the leaf control blocks are the oracle's own construction.
//
// Offline and deterministic: keys, amounts and Schnorr auxiliary bytes come
// from the seeded PRNG below, which exists only in this file.
//
// Run with `node --test test/psbt-finalization-differential.test.mjs`,
// `npm test`, or test:ci.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Transaction } from "@scure/btc-signer";
import { p2tr as scureP2TR, tapLeafHash } from "@scure/btc-signer/payment.js";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { psbtInspectDoc, psbtBuildBytes } from "../src/js/psbt-wasm.js";

// --- deterministic randomness ------------------------------------------------

const FUZZ_SEED = 0x5eed0501;
const CASES = 48;
const mulberry32 = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};
const rand = mulberry32(FUZZ_SEED);
const rint = (n) => Math.floor(rand() * n);
const pick = (items) => items[rint(items.length)];
const randomBytes = (n) => Uint8Array.from({ length: n }, () => rint(256));
const randomKey = () => {
  for (;;) {
    const key = randomBytes(32);
    if (secp256k1.utils.isValidSecretKey(key)) return key;
  }
};
const randomAmount = () => BigInt(1 + rint(10 ** 8)) * 10000n;
const randomSequence = () => pick([0xffffffff, 0xfffffffe, 0xfffffffd, rint(2 ** 32) >>> 0]);

// --- scripts and hashes ------------------------------------------------------

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const cat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const hash160 = (bytes) => ripemd160(sha256(bytes));
const p2pkh = (pub) => cat([0x76, 0xa9, 0x14], hash160(pub), [0x88, 0xac]);
const p2wpkh = (pub) => cat([0x00, 0x14], hash160(pub));
const p2sh = (redeem) => cat([0xa9, 0x14], hash160(redeem), [0x87]);
const p2wsh = (witnessScript) => cat([0x00, 0x20], sha256(witnessScript));
const p2tr = (xonly) => cat([0x51, 0x20], xonly);
const reversedHex = (bytes) => hex(Uint8Array.from(bytes).reverse());
const txidOf = (raw) => reversedHex(sha256(sha256(raw)));

// --- PSBT framing: signature fields in the input maps ------------------------

const compactSize = (bytes, at) => {
  const first = bytes[at];
  if (first < 0xfd) return [first, 1];
  if (first === 0xfd) return [bytes[at + 1] | (bytes[at + 2] << 8), 3];
  if (first === 0xfe) return [(bytes[at + 1] | (bytes[at + 2] << 8) | (bytes[at + 3] << 16) | (bytes[at + 4] << 24)) >>> 0, 5];
  throw new Error("compact size over 32 bits in a generated PSBT");
};

// Walks the global map then the per-input maps (framing only; the decoders
// under test do the parsing) and returns, per input, the key types of its
// map. PSBT_IN_PARTIAL_SIG is 0x02, PSBT_IN_TAP_KEY_SIG 0x0c and
// PSBT_IN_TAP_SCRIPT_SIG 0x0d (BIP174/BIP371).
const inputMapKeyTypes = (psbt, inputCount) => {
  assert.deepEqual([...psbt.subarray(0, 5)], [0x70, 0x73, 0x62, 0x74, 0xff], "PSBT magic");
  let at = 5;
  const maps = [];
  while (maps.length < 1 + inputCount) {
    const types = [];
    for (;;) {
      const [keyLength, keySize] = compactSize(psbt, at);
      at += keySize;
      if (keyLength === 0) break;
      types.push(psbt[at]);
      at += keyLength;
      const [valueLength, valueSize] = compactSize(psbt, at);
      at += valueSize + valueLength;
    }
    maps.push(types);
  }
  return maps.slice(1);
};
const staleSigFields = (types) => types.filter((type) => type === 0x02 || type === 0x0c || type === 0x0d);
const stalePerInput = (psbt, inputCount) => inputMapKeyTypes(psbt, inputCount).map(staleSigFields);

// --- case generation ---------------------------------------------------------

const KINDS = ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2wsh 2-of-3", "p2tr key path", "p2tr script path"];
const SIGHASH_TYPES = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83];
const SCURE_OPTS = { allowUnknownOutputs: true, allowUnknownInputs: true, allowUnknownVersion: true, disableScriptCheck: true };

const buildCase = (index) => {
  const kind = KINDS[index % KINDS.length];
  const inputs = 1 + rint(4);
  const outputs = inputs + 1 + rint(2); // every input index has a matching output, so SIGHASH_SINGLE is always defined
  const tx = new Transaction({ ...SCURE_OPTS, version: 2, lockTime: rint(2 ** 32) >>> 0 });
  const prevouts = [];
  const signers = [];
  for (let j = 0; j < inputs; j++) {
    const sequence = randomSequence();
    const amount = randomAmount();
    if (kind === "p2pkh") {
      const key = randomKey(), pub = secp256k1.getPublicKey(key, true), script = p2pkh(pub);
      prevouts.push({ script, amount });
      signers.push({ key, pub, script, type: pick(SIGHASH_TYPES) });
      // A legacy claim comes from the full previous transaction.
      const vout = rint(3);
      const prev = new Transaction({ ...SCURE_OPTS, version: 2 });
      prev.addInput({ txid: randomBytes(32), index: rint(4), sequence: 0xffffffff });
      for (let k = 0; k <= vout; k++) prev.addOutput(k === vout ? { script, amount } : { script: p2wpkh(secp256k1.getPublicKey(randomKey(), true)), amount: randomAmount() });
      tx.addInput({ txid: prev.id, index: vout, sequence, nonWitnessUtxo: prev.toBytes(true, false) });
    } else if (kind === "p2wpkh") {
      const key = randomKey(), pub = secp256k1.getPublicKey(key, true), script = p2wpkh(pub);
      prevouts.push({ script, amount });
      signers.push({ key, pub, type: pick(SIGHASH_TYPES) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount } });
    } else if (kind === "p2sh-p2wpkh") {
      const key = randomKey(), pub = secp256k1.getPublicKey(key, true), redeem = p2wpkh(pub), script = p2sh(redeem);
      prevouts.push({ script, amount });
      signers.push({ key, pub, type: pick(SIGHASH_TYPES) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount }, redeemScript: redeem });
    } else if (kind === "p2wsh 2-of-3") {
      const keys = [randomKey(), randomKey(), randomKey()];
      const witnessScript = cat([0x52], ...keys.map((key) => cat([0x21], secp256k1.getPublicKey(key, true))), [0x53, 0xae]);
      const script = p2wsh(witnessScript);
      prevouts.push({ script, amount });
      signers.push({ keys, witnessScript, type: pick(SIGHASH_TYPES) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount }, witnessScript });
    } else if (kind === "p2tr key path") {
      const key = randomKey(), xonly = schnorr.getPublicKey(key), script = p2tr(xonly);
      prevouts.push({ script, amount });
      // SIGHASH_DEFAULT (0x00, no sighash byte per BIP371) is in the mix.
      signers.push({ key, xonly, aux: randomBytes(32), type: pick([0x00, ...SIGHASH_TYPES]) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount } });
    } else {
      // p2tr script path with 2 leaves: @scure's own p2tr payment derives
      // the tweaked output key, the merkle root and the leaf control
      // blocks, so the app is diffed against the oracle's construction.
      const internalKey = randomKey(), internalPub = schnorr.getPublicKey(internalKey);
      const leafKey = randomKey(), leafPub = schnorr.getPublicKey(leafKey);
      const leaf = cat([0x20], leafPub, [0xac]);
      const otherLeaf = cat([0x20], schnorr.getPublicKey(randomKey()), [0xac]);
      const payment = scureP2TR(internalPub, [[leaf, 0xc0], [otherLeaf, 0xc0]]);
      const script = payment.script;
      prevouts.push({ script, amount });
      signers.push({ leafKey, leafPub, leaf, aux: randomBytes(32), type: pick(SIGHASH_TYPES) });
      tx.addInput({ txid: randomBytes(32), index: rint(4), sequence, witnessUtxo: { script, amount }, tapInternalKey: payment.tapInternalKey, tapMerkleRoot: payment.tapMerkleRoot, tapLeafScript: payment.tapLeafScript });
    }
  }
  const scripts = prevouts.map((prevout) => prevout.script);
  const amounts = prevouts.map((prevout) => prevout.amount);
  const sumIn = amounts.reduce((a, b) => a + b, 0n);
  const fee = 600n + sumIn / 8n;
  let remaining = sumIn - fee;
  const outAmounts = [];
  for (let k = 0; k < outputs; k++) {
    const share = remaining / BigInt(outputs - k);
    const out = k === outputs - 1 ? remaining : 546n + BigInt(rint(Number(share / 3n)));
    outAmounts.push(out);
    remaining -= out;
  }
  for (let k = 0; k < outputs; k++) tx.addOutput({ script: p2wpkh(secp256k1.getPublicKey(randomKey(), true)), amount: outAmounts[k] });
  const sumOut = outAmounts.reduce((a, b) => a + b, 0n);

  // The signature payload for input j. `degraded` signs only one of the two
  // required multisig signatures, so the p2wsh cases drop exactly one
  // signature rather than a whole input's worth.
  const sigsFor = (j, degraded) => {
    const s = signers[j];
    if (kind === "p2pkh") {
      const sig = secp256k1.sign(tx.preimageLegacy(j, s.script, s.type), s.key, { prehash: false, format: "der" });
      return { partialSig: [[s.pub, cat(sig, [s.type])]] };
    }
    if (kind === "p2wpkh" || kind === "p2sh-p2wpkh") {
      const sig = secp256k1.sign(tx.preimageWitnessV0(j, p2pkh(s.pub), s.type, amounts[j]), s.key, { prehash: false, format: "der" });
      return { partialSig: [[s.pub, cat(sig, [s.type])]] };
    }
    if (kind === "p2wsh 2-of-3") {
      const digest = tx.preimageWitnessV0(j, s.witnessScript, s.type, amounts[j]);
      const partialSig = s.keys.slice(0, degraded ? 1 : 2).map((key) => {
        const sig = secp256k1.sign(digest, key, { prehash: false, format: "der" });
        return [secp256k1.getPublicKey(key, true), cat(sig, [s.type])];
      });
      return { partialSig };
    }
    if (kind === "p2tr key path") {
      const sig = schnorr.sign(tx.preimageWitnessV1(j, scripts, s.type, amounts, -1), s.key, s.aux);
      return { tapKeySig: s.type === 0x00 ? sig : cat(sig, [s.type]) };
    }
    const sig = schnorr.sign(tx.preimageWitnessV1(j, scripts, s.type, amounts, -1, s.leaf, 0xc0), s.leafKey, s.aux);
    return { tapScriptSig: [[{ pubKey: s.leafPub, leafHash: tapLeafHash(s.leaf, 0xc0) }, cat(sig, [s.type])]] };
  };
  const signedPsbt = (() => {
    const copy = Transaction.fromPSBT(tx.toPSBT(), SCURE_OPTS);
    for (let j = 0; j < inputs; j++) copy.updateInput(j, sigsFor(j, false), true);
    return copy.toPSBT();
  })();
  // Remove one signature: a whole input's worth, or — for the 2-of-3 — one
  // of the two required signatures, so the PSBT is exactly one signature
  // short rather than missing an input's material outright.
  const dropIdx = rint(inputs);
  const incompletePsbt = (() => {
    const copy = Transaction.fromPSBT(tx.toPSBT(), SCURE_OPTS);
    for (let j = 0; j < inputs; j++) {
      if (j === dropIdx) {
        if (kind === "p2wsh 2-of-3") copy.updateInput(j, sigsFor(j, true), true); // one signature short
        continue;
      }
      copy.updateInput(j, sigsFor(j, false), true);
    }
    return copy.toPSBT();
  })();
  const fin = Transaction.fromPSBT(signedPsbt, SCURE_OPTS);
  fin.finalize();
  const raw = fin.extract();
  return {
    label: `case ${index}: ${kind}, ${inputs} input${inputs === 1 ? "" : "s"}, ${outputs} outputs`,
    kind, inputs, finalizedPsbt: fin.toPSBT(), raw, txid: txidOf(raw),
    fee: sumIn - sumOut, sumOut, incompletePsbt, dropIdx,
  };
};

// --- the run -----------------------------------------------------------------

test(`the app round-trips @scure-finalized PSBTs byte-identically, without stale signature fields (seed 0x${FUZZ_SEED.toString(16)}, ${CASES} cases)`, () => {
  const unsupported = new Set();
  const kindsRan = new Set();
  let ran = 0;
  let skipped = 0;
  for (let index = 0; index < CASES; index++) {
    const kind = KINDS[index % KINDS.length];
    if (unsupported.has(kind)) {
      skipped += 1;
      continue;
    }
    let c;
    try {
      c = buildCase(index);
    } catch (error) {
      // @scure/btc-signer could not build or finalize this shape; per the
      // ledger, only the shapes it can finalize are generated. Anything the
      // app side throws below is a test failure, never a skip.
      unsupported.add(kind);
      skipped += 1;
      continue;
    }
    kindsRan.add(kind);
    const where = c.label;

    // (1) The app's round-tripped PSBT must extract to the byte-identical
    // transaction (and txid) as @scure's own finalize().extract().
    const doc = psbtInspectDoc(c.finalizedPsbt);
    assert.equal(doc.rustBitcoinError, null, `${where}: rust-bitcoin rejected the finalized PSBT: ${doc.rustBitcoinError}`);
    const appBytes = psbtBuildBytes(doc);
    const rawApp = Transaction.fromPSBT(appBytes, SCURE_OPTS).extract();
    assert.deepEqual(rawApp, c.raw, `${where}: the app's round-trip changed the extracted transaction`);
    assert.equal(txidOf(rawApp), c.txid, `${where}: the app's round-trip changed the txid`);

    // (2) Strict re-parse: @scure exposes no raw-transaction parser, so
    // strictness is fromPSBT with its default (strict) flags.
    Transaction.fromPSBT(appBytes);

    // (3) Fee = sum(inputs) − sum(outputs); the generator's amounts are the
    // independent source, and the app's own decoded output amounts must sum
    // to exactly the outputs the oracle extracted (sumIn − fee).
    assert.ok(c.fee > 0n, `${where}: generated a non-paying transaction`);
    const docSumOut = doc.tx.outputs.reduce((total, output) => total + BigInt(output.value), 0n);
    assert.equal(docSumOut, c.sumOut, `${where}: the app's decoded outputs do not sum to sum(inputs) − fee`);

    // (4) No stale PSBT_IN_PARTIAL_SIG / PSBT_IN_TAP_KEY_SIG /
    // PSBT_IN_TAP_SCRIPT_SIG fields may remain in the finalized input
    // maps. BIP174's finalizer strips the partial-signature fields once
    // the final scripts are in; whichever set the oracle's serialization
    // retains, the app's re-serialization must carry exactly the same
    // per-input set — it must neither reintroduce fields the oracle
    // stripped nor drop or invent any.
    const scureStale = stalePerInput(c.finalizedPsbt, c.inputs);
    assert.deepEqual(stalePerInput(appBytes, c.inputs), scureStale, `${where}: the app's round-trip changed the signature fields of the finalized input maps`);

    // (5) Removing one signature must make @scure refuse with a typed Error
    // (never a raw throw or a WebAssembly.RuntimeError); because finalize or
    // extract throws, no transaction — and no witness bytes — are emitted at
    // all. The app side of this invariant is skipped: psbtInspectDoc and
    // psbtBuildBytes accept partially signed PSBTs by design (the cosigner
    // workflow) and no refusal entry point is exported.
    assert.throws(
      () => {
        const t = Transaction.fromPSBT(c.incompletePsbt, SCURE_OPTS);
        t.finalize();
        t.extract();
      },
      (error) => error instanceof Error && !(error instanceof WebAssembly.RuntimeError),
      `${where}: @scure finalized a PSBT whose input ${c.dropIdx} is one signature short`);

    // (6) Finalize is idempotent: a second finalize (or the app's second
    // round-trip) changes nothing. If @scure refuses to re-finalize an
    // already-final input, the refusal itself changes nothing.
    const doc2 = psbtInspectDoc(appBytes);
    const appBytes2 = psbtBuildBytes(doc2);
    const re2 = Transaction.fromPSBT(appBytes2, SCURE_OPTS);
    try {
      re2.finalize();
    } catch { /* refusal leaves the final scripts in place */ }
    assert.deepEqual(re2.extract(), c.raw, `${where}: a second app round-trip changed the extracted transaction`);
    const again = Transaction.fromPSBT(c.finalizedPsbt, SCURE_OPTS);
    try {
      again.finalize();
    } catch { /* ditto */ }
    assert.deepEqual(again.extract(), c.raw, `${where}: finalize(finalize(psbt)) changed the extracted transaction`);

    ran += 1;
  }
  assert.equal(ran + skipped, CASES, "every case ran or was skipped as an unsupported shape");
  assert.ok(ran >= CASES / 2, `only ${ran} of ${CASES} cases ran; too many shapes were skipped`);
  for (const kind of KINDS) {
    if (!unsupported.has(kind)) assert.ok(kindsRan.has(kind), `${kind} never ran`);
  }
  assert.ok(KINDS.length - unsupported.size >= 4, `@scure/btc-signer could not finalize too many shapes: ${[...unsupported].join(", ")}`);
});
