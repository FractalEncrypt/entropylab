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
// leave no stale signature fields (PSBT_IN_PARTIAL_SIG, PSBT_IN_TAP_KEY_SIG,
// PSBT_IN_TAP_SCRIPT_SIG) in any finalized input map. Extraction itself is
// @scure's, applied identically to the original and the app's bytes, so
// any difference is the app's re-serialization. The incompleteness
// invariant (remove one signature → refuse) is asserted on the @scure
// side, and honestly on the app side: the app's inspector deliberately
// accepts partially signed PSBTs (they are the cosigner workflow's normal
// input) and no refusal entry point is exported, so what is asserted is
// what the app does — it inspects the one-signature-short PSBT without a
// rust-bitcoin error, and its re-serialization is still not finalizable:
// the app must not complete it. @scure/btc-signer exposes no
// public raw-transaction parser, so "re-parses strictly" is enforced as
// Transaction.fromPSBT with its default (strict) flags on the app's bytes.
// The inspect document reports the fee as a display-shaped object, and no
// existing test pins the field or shape in which an input's decoded
// amount is reported (psbt-differential-fuzz pins only doc.tx.outputs's
// plain satoshi values; doc.tx.inputs carries txid/vout/scriptSig/
// sequence only), so the fee invariant is pinned to satoshi values, never
// to display formats: the app's decoded output amounts must sum to the
// generator's independently constructed sum(outputs), each of the app's
// decoded input amounts must be the generator's amount for that input
// wherever the document reports it, and the fee the document reports
// must be exactly sum(inputs) − sum(outputs).
//
// If @scure/btc-signer refuses to build or finalize a shape — a documented
// limitation of the oracle — the refusal is recognized by error message and
// only that shape's kind is skipped, and named in the run's summary;
// anything else buildCase throws (a bug in this generator, or a @scure
// upgrade that rewords its errors) fails the run. The run requires both
// taproot kinds, every p2tr script-path case, and at most one kind's worth
// of skips, so a skip can never hollow the suite out. The p2tr script path
// is built with @scure's own p2tr payment (internal key + a two-leaf tree
// in its TaprootScriptTree shape: { script, leafVersion } leaves, 0xc0
// being BIP341's base tapscript leaf version), so the tweaked output key,
// the merkle root and the leaf control blocks are the oracle's own
// construction.
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
// map. PSBT_IN_PARTIAL_SIG is 0x02 (BIP174); PSBT_IN_TAP_KEY_SIG is 0x13
// and PSBT_IN_TAP_SCRIPT_SIG 0x14 (BIP371). BIP174's 0x0c and 0x0d are
// the PSBT_IN_HASH160 and PSBT_IN_HASH256 preimage fields, not signatures.
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
const staleSigFields = (types) => types.filter((type) => type === 0x02 || type === 0x13 || type === 0x14);
const stalePerInput = (psbt, inputCount) => inputMapKeyTypes(psbt, inputCount).map(staleSigFields);

// --- case generation ---------------------------------------------------------

const KINDS = ["p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2wsh 2-of-3", "p2tr key path", "p2tr script path"];
const SIGHASH_TYPES = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83];
const SCURE_OPTS = { allowUnknownOutputs: true, allowUnknownInputs: true, allowUnknownVersion: true, disableScriptCheck: true };
// The only errors that may skip a case: @scure/btc-signer refusing to
// build or finalize a shape (a documented limitation of the oracle, not a
// bug in this generator). Refusals are recognized by message fragment, so
// a generator bug — or a @scure upgrade that rewords its errors — fails
// the run instead of silently skipping coverage.
const SCURE_REFUSALS = ["Unknown input", "Unknown output", "Cannot finalize", "Cannot extract", "not supported"];

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
      const payment = scureP2TR(internalPub, [{ script: leaf, leafVersion: 0xc0 }, { script: otherLeaf, leafVersion: 0xc0 }]);
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
      // Key path: no leaf hash, only the BIP341 common signature message.
      const sig = schnorr.sign(tx.preimageWitnessV1(j, scripts, s.type, amounts), s.key, s.aux);
      return { tapKeySig: s.type === 0x00 ? sig : cat(sig, [s.type]) };
    }
    // Script path: BIP342 extends the preimage with the tapleaf hash (and
    // the code-separator position, absent here), so the leaf hash — the
    // same value that keys the tapScriptSig map — is passed to @scure.
    const leafHash = tapLeafHash(s.leaf, 0xc0);
    const sig = schnorr.sign(tx.preimageWitnessV1(j, scripts, s.type, amounts, leafHash), s.leafKey, s.aux);
    return { tapScriptSig: [[{ pubKey: s.leafPub, leafHash }, cat(sig, [s.type])]] };
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
    fee: sumIn - sumOut, sumOut, amounts, incompletePsbt, dropIdx,
  };
};

// --- the app's reported amounts ----------------------------------------------

// psbtInspectDoc reports the fee as a display-shaped object, and no
// existing test pins the field or shape in which an input's decoded
// amount is reported (psbt-differential-fuzz pins only doc.tx.outputs's
// plain satoshi values; doc.tx.inputs carries txid/vout/scriptSig/
// sequence only). Amounts are therefore pinned to satoshi values, never
// to display formats or user-facing copy: whatever a reported field
// carries, one of its readings must be the exact satoshi amount — a plain
// satoshi integer, or the BTC decimal of the same value. Integer strings
// are read as sats only (a BTC display of a random satoshi amount always
// carries decimals), so digit runs inside hex blobs cannot collide with
// an amount through a spurious BTC reading.
const satoshisIn = (leaf) => {
  if (leaf === null || leaf === undefined) return [];
  if (typeof leaf === "bigint") return [leaf];
  if (typeof leaf === "number" && Number.isFinite(leaf)) return [BigInt(Math.round(leaf)), BigInt(Math.round(leaf * 1e8))];
  if (typeof leaf === "string") {
    const out = [];
    for (const token of leaf.replace(/[\s,]/g, "").match(/\d+\.\d+|\d+/g) || []) {
      const [whole, frac = ""] = token.split(".");
      out.push(BigInt(whole));
      if (frac !== "") out.push(BigInt(whole + frac.padEnd(8, "0").slice(0, 8)));
    }
    return out;
  }
  if (typeof leaf === "object") return Object.values(leaf).flatMap(satoshisIn);
  return [];
};
// The fee the document reports, wherever the key naming it lives; like
// the amounts, only the satoshi value is pinned, never the display shape.
const feeReadings = (doc) => {
  const out = [];
  const walk = (node) => {
    if (node === null || node === undefined || typeof node !== "object") return;
    for (const [key, leaf] of Object.entries(node)) {
      if (/fee/i.test(key)) out.push(...satoshisIn(leaf));
      else if (leaf !== null && typeof leaf === "object") walk(leaf);
    }
  };
  walk(doc);
  return out;
};

// --- the run -----------------------------------------------------------------

test(`the app round-trips @scure-finalized PSBTs byte-identically, without stale signature fields (seed 0x${FUZZ_SEED.toString(16)}, ${CASES} cases)`, () => {
  const unsupported = new Set();
  let ran = 0;
  let skipped = 0;
  let scriptPathRan = 0;
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
      // Only a documented @scure/btc-signer limitation may skip a case,
      // and only when the refusal is recognized by message: anything else
      // — a bug in this generator, or a @scure upgrade that rewords its
      // errors — fails the run here instead of silently skipping
      // coverage. Anything the app side throws below is a test failure,
      // never a skip.
      if (!(error instanceof Error) || !SCURE_REFUSALS.some((fragment) => String(error.message).includes(fragment))) throw error;
      unsupported.add(kind);
      skipped += 1;
      continue;
    }
    if (kind === "p2tr script path") scriptPathRan += 1;
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
    // independent source. The app's decoded output amounts must sum to the
    // generator's sum(outputs); each of the app's decoded input amounts —
    // pinned to the satoshi value wherever the document reports it, since
    // no existing test pins the field or shape — must be the generator's
    // amount for that input; and the fee the document reports, in whatever
    // display shape, must be exactly sum(inputs) − sum(outputs).
    assert.ok(c.fee > 0n, `${where}: generated a non-paying transaction`);
    const docSumOut = doc.tx.outputs.reduce((total, output) => total + BigInt(output.value), 0n);
    assert.equal(docSumOut, c.sumOut, `${where}: the app's decoded outputs do not sum to sum(inputs) − fee`);
    const docReadings = satoshisIn(doc);
    doc.tx.inputs.forEach((input, j) => {
      assert.ok(
        docReadings.includes(c.amounts[j]),
        `${where}: the app's reported amount for input ${j} is not the generator's ${c.amounts[j]} sats; tx-level entry: ${JSON.stringify(input).slice(0, 300)}`);
    });
    const fees = feeReadings(doc);
    assert.ok(fees.length > 0, `${where}: psbtInspectDoc reported no readable fee`);
    assert.ok(fees.includes(c.fee), `${where}: the app's reported fee is not sum(inputs) − sum(outputs) = ${c.fee} sats`);

    // (4) No stale signature fields may remain in any finalized input map:
    // BIP174's finalizer strips PSBT_IN_PARTIAL_SIG (0x02) and BIP371's
    // PSBT_IN_TAP_KEY_SIG (0x13) / PSBT_IN_TAP_SCRIPT_SIG (0x14) once the
    // final scripts are in. Absence is asserted directly, on BOTH sides —
    // equality with the oracle alone would pass if both retained the same
    // stale field — and the per-input field sets must still match the
    // oracle's as a second check.
    const noStaleFields = Array.from({ length: c.inputs }, () => []);
    const scureStale = stalePerInput(c.finalizedPsbt, c.inputs);
    assert.deepEqual(scureStale, noStaleFields, `${where}: @scure's finalized input maps retain stale signature fields`);
    const appStale = stalePerInput(appBytes, c.inputs);
    assert.deepEqual(appStale, noStaleFields, `${where}: the app's round-trip retained stale signature fields`);
    assert.deepEqual(appStale, scureStale, `${where}: the app's round-trip changed the signature fields of the finalized input maps`);

    // (5) Removing one signature must make @scure refuse with a typed Error
    // (never a raw throw or a WebAssembly.RuntimeError); because finalize or
    // extract throws, no transaction — and no witness bytes — are emitted at
    // all. The app has no refusal path to assert — psbtInspectDoc and
    // psbtBuildBytes accept partially signed PSBTs by design (the cosigner
    // workflow's normal input) and no finalize or extract entry point is
    // exported — so the honest app-side assertion is what the app actually
    // does with the incomplete PSBT: it must inspect it without a
    // rust-bitcoin error, and its re-serialization must still be one
    // signature short — the app must not complete it.
    assert.throws(
      () => {
        const t = Transaction.fromPSBT(c.incompletePsbt, SCURE_OPTS);
        t.finalize();
        t.extract();
      },
      (error) => error instanceof Error && !(error instanceof WebAssembly.RuntimeError),
      `${where}: @scure finalized a PSBT whose input ${c.dropIdx} is one signature short`);
    const incompleteDoc = psbtInspectDoc(c.incompletePsbt);
    assert.equal(incompleteDoc.rustBitcoinError, null, `${where}: the app refused to inspect a partially signed PSBT (the cosigner workflow's normal input)`);
    const incompleteBytes = psbtBuildBytes(incompleteDoc);
    assert.throws(
      () => {
        const t = Transaction.fromPSBT(incompleteBytes, SCURE_OPTS);
        t.finalize();
        t.extract();
      },
      (error) => error instanceof Error && !(error instanceof WebAssembly.RuntimeError),
      `${where}: the app's round-trip completed a PSBT whose input ${c.dropIdx} is one signature short`);

    // (6) The app's round-trip is stable: a second app round-trip must
    // reproduce the same PSBT bytes and extract to the same transaction.
    // The PSBT is already final, so it is extracted as it is, with no catch:
    // @scure 2.4.0's finalize() strips partialSig, and a second finalize()
    // of a non-Taproot input always throws "Not enough partial sign", which
    // would test @scure rather than the app.
    const doc2 = psbtInspectDoc(appBytes);
    const appBytes2 = psbtBuildBytes(doc2);
    assert.deepEqual(appBytes2, appBytes, `${where}: a second app round-trip changed the PSBT bytes`);
    assert.deepEqual(Transaction.fromPSBT(appBytes2, SCURE_OPTS).extract(), c.raw, `${where}: a second app round-trip changed the extracted transaction`);

    ran += 1;
  }
  assert.ok(ran >= CASES / 2, `only ${ran} of ${CASES} cases ran; too many shapes were skipped: ${[...unsupported].join(", ") || "none"}`);
  assert.ok(unsupported.size <= 1 && skipped <= CASES / KINDS.length, `@scure/btc-signer refused more than one shape (${skipped} cases skipped): ${[...unsupported].join(", ")}`);
  for (const kind of ["p2tr key path", "p2tr script path"]) {
    assert.ok(!unsupported.has(kind), `@scure/btc-signer refused the taproot shape "${kind}"; its BIP341/BIP371 coverage would be skipped`);
  }
  assert.equal(scriptPathRan, CASES / KINDS.length, "a p2tr script-path case was skipped: every script-path case must actually be built");
});
