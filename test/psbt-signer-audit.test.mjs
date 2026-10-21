// Adversarial fixtures for the PSBT Signer Audit policy engine
// (src/js/psbt-signer-audit.js). Expected findings are written from the
// merged engineering spec, never from running the engine.
// Run with `npm test`.
import test from "node:test";
import assert from "node:assert/strict";
import { auditSigner, SIGNER_AUDIT_CODES } from "../src/js/psbt-signer-audit.js";

const P1_HEX = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const P2_HEX = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const DERIV_VALUE = "12345678" + "54000080" + "00000080" + "00000080" + "00000000" + "00000000";
const SCRIPT1 = "0014" + "22".repeat(20);
const SCRIPT2 = "0014" + "33".repeat(20);
const SCRIPT3 = "0014" + "44".repeat(20);

const pair = (key, value, name, decoded) => ({ key, value, name, ...(decoded ? { decoded } : {}) });

const baseDoc = (overrides = {}) => ({
  tx: {
    version: 2,
    locktime: 0,
    inputs: [{ txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 }],
    outputs: [{ value: 100000, scriptPubKey: SCRIPT1 }],
  },
  globals: [{ key: "00", value: "aa", name: "PSBT_GLOBAL_UNSIGNED_TX" }],
  inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
  ]],
  outputs: [[]],
  fee: { known: true, sats: "50000" },
  psbtVersion: 0,
  ...overrides,
});

const changeDoc = (overrides = {}) => {
  const d = baseDoc();
  d.tx.outputs = [
    { value: 100000, scriptPubKey: SCRIPT1 },
    { value: 40000, scriptPubKey: SCRIPT2 },
  ];
  d.outputs = [[], [pair("06" + P1_HEX, DERIV_VALUE, "PSBT_OUT_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/1" })]];
  d.fee = { known: true, sats: "10000" };
  return { ...d, ...overrides };
};

const withSig = (doc, pubkey, lastByte) => {
  const d = structuredClone(doc);
  d.inputs[0].push(pair("02" + pubkey, "11".repeat(71) + lastByte, "PSBT_IN_PARTIAL_SIG", {
    pubkey,
    signature: "11".repeat(71),
    sighash: "SIGHASH_ALL",
  }));
  return d;
};

const f10Docs = () => {
  const before = baseDoc();
  const after = withSig(before, P1_HEX, "01");
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1_HEX, valid: true }] };
  return { before, after, verification };
};

test("SIGNER_AUDIT_CODES is frozen and complete", () => {
  assert.ok(Object.isFrozen(SIGNER_AUDIT_CODES));
  for (const code of ["DOC_UNDECODABLE", "TX_REORDERED", "SIGNATURE_ADDED", "FINALIZED", "CHANGE_VERIFIED"]) {
    assert.ok(SIGNER_AUDIT_CODES.includes(code), `missing ${code}`);
  }
});

test("F1 a changed destination output fails the audit", () => {
  const before = baseDoc();
  const after = baseDoc({ tx: { ...before.tx, outputs: [{ value: 100000, scriptPubKey: SCRIPT2 }] } });
  const report = auditSigner(before, after);
  assert.equal(report.verdict, "fail");
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["TX_OUTPUT_CHANGED", "critical"]]);
  assert.equal(report.findings[0].evidence.index, 0);
  assert.equal(report.findings[0].evidence.field, "output[0].scriptPubKey");
  assert.equal(report.findings[0].evidence.kind, "changed");
  assert.equal(report.checks.transactionBody, "changed");
  assert.equal(report.checks.metadata, "unchanged");
});

test("F2 a replaced change output is a transaction change and a wallet mismatch", () => {
  const before = changeDoc();
  const after = changeDoc({ tx: { ...before.tx, outputs: [before.tx.outputs[0], { value: 40000, scriptPubKey: SCRIPT3 }] } });

  const noWallet = auditSigner(before, after);
  assert.deepEqual(noWallet.findings.map((f) => [f.code, f.severity]), [["TX_OUTPUT_CHANGED", "critical"]]);
  assert.equal(noWallet.findings[0].evidence.index, 1);

  const wallet = { fingerprints: ["12345678"], scriptPubKeys: [before.tx.outputs[1].scriptPubKey] };
  const mismatch = auditSigner(before, after, { wallet });
  assert.deepEqual(mismatch.findings.map((f) => [f.code, f.severity]), [
    ["TX_OUTPUT_CHANGED", "critical"],
    ["CHANGE_NOT_FROM_WALLET", "critical"],
  ]);
  assert.equal(mismatch.findings[1].evidence.index, 1);
  assert.equal(mismatch.findings[1].evidence.fingerprint, "12345678");
  assert.equal(mismatch.checks.changeOutputs, "not_from_wallet");

  const unverified = auditSigner(before, after, { wallet: { fingerprints: ["12345678"] } });
  assert.deepEqual(unverified.findings.map((f) => [f.code, f.severity]), [
    ["TX_OUTPUT_CHANGED", "critical"],
    ["CHANGE_UNVERIFIED", "warning"],
  ]);
});

test("F3/F4 an amount change moves the fee and is not a separate finding", () => {
  const before = changeDoc();
  const after = changeDoc({
    tx: { ...before.tx, outputs: [{ value: 99000, scriptPubKey: SCRIPT1 }, before.tx.outputs[1]] },
    fee: { known: true, sats: "11000" },
  });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["TX_OUTPUT_CHANGED", "critical"]]);
  assert.equal(report.findings[0].evidence.field, "output[0].value");
  assert.equal(report.findings[0].evidence.before, 100000);
  assert.equal(report.findings[0].evidence.after, 99000);
  assert.equal(report.stats.feeBefore, 10000);
  assert.equal(report.stats.feeAfter, 11000);
  assert.equal(report.stats.feeAfter, report.stats.feeBefore + 1000);
});

test("F5 a changed prevout fails the audit", () => {
  const before = baseDoc();
  const after = baseDoc({ tx: { ...before.tx, inputs: [{ ...before.tx.inputs[0], txid: "33".repeat(32) }] } });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["TX_INPUT_CHANGED", "critical"]]);
  assert.equal(report.findings[0].evidence.field, "input[0].txid");

  const voutAfter = baseDoc({ tx: { ...before.tx, inputs: [{ ...before.tx.inputs[0], vout: 1 }] } });
  const voutReport = auditSigner(before, voutAfter);
  assert.deepEqual(voutReport.findings.map((f) => [f.code, f.severity]), [["TX_INPUT_CHANGED", "critical"]]);
  assert.equal(voutReport.findings[0].evidence.field, "input[0].vout");
});

test("F6 a changed sequence fails the audit", () => {
  const before = baseDoc();
  const after = baseDoc({ tx: { ...before.tx, inputs: [{ ...before.tx.inputs[0], sequence: 4294967293 }] } });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["TX_INPUT_CHANGED", "critical"]]);
  assert.equal(report.findings[0].evidence.field, "input[0].sequence");
  assert.equal(report.findings[0].evidence.before, 4294967295);
  assert.equal(report.findings[0].evidence.after, 4294967293);
});

test("F7 locktime and version changes fail the audit", () => {
  const before = baseDoc();
  const locktimeAfter = baseDoc({ tx: { ...before.tx, locktime: 800000 } });
  const locktimeReport = auditSigner(before, locktimeAfter);
  assert.deepEqual(locktimeReport.findings.map((f) => [f.code, f.severity]), [["TX_LOCKTIME_CHANGED", "critical"]]);
  assert.equal(locktimeReport.findings[0].evidence.before, 0);
  assert.equal(locktimeReport.findings[0].evidence.after, 800000);

  const versionAfter = baseDoc({ tx: { ...before.tx, version: 1 } });
  const versionReport = auditSigner(before, versionAfter);
  assert.deepEqual(versionReport.findings.map((f) => [f.code, f.severity]), [["TX_VERSION_CHANGED", "critical"]]);
});

test("F8 a reordered transaction is reported once and suppresses per-index changes", () => {
  const base = baseDoc();
  const inputs = [
    { txid: "11".repeat(32), vout: 0, scriptSig: "", sequence: 4294967295 },
    { txid: "22".repeat(32), vout: 1, scriptSig: "", sequence: 4294967295 },
  ];
  const before = baseDoc({ tx: { ...base.tx, inputs: [inputs[0], inputs[1]] }, inputs: [[], []] });
  const after = baseDoc({ tx: { ...base.tx, inputs: [inputs[1], inputs[0]] }, inputs: [[], []] });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["TX_REORDERED", "critical"]]);
  assert.equal(report.findings[0].evidence.dimension, "inputs");
  assert.deepEqual(report.findings[0].evidence.order, [1, 0]);
  assert.equal(report.verdict, "fail");

  const outputs = [
    { value: 100000, scriptPubKey: SCRIPT1 },
    { value: 40000, scriptPubKey: SCRIPT2 },
  ];
  const outBefore = baseDoc({ tx: { ...base.tx, outputs: [outputs[0], outputs[1]] }, outputs: [[], []] });
  const outAfter = baseDoc({ tx: { ...base.tx, outputs: [outputs[1], outputs[0]] }, outputs: [[], []] });
  const outReport = auditSigner(outBefore, outAfter);
  assert.deepEqual(outReport.findings.map((f) => [f.code, f.severity]), [["TX_REORDERED", "critical"]]);
  assert.equal(outReport.findings[0].evidence.dimension, "outputs");
  assert.deepEqual(outReport.findings[0].evidence.order, [1, 0]);
});

test("F9 a changed UTXO declaration is transaction-critical", () => {
  const before = baseDoc();
  const after = baseDoc({ inputs: [[
    pair("01", "dd", "PSBT_IN_WITNESS_UTXO", { value: "149000", scriptPubKey: SCRIPT1 }),
    before.inputs[0][1],
  ]] });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["UTXO_DECLARATION_CHANGED", "critical"]]);
  assert.equal(report.findings[0].evidence.index, 0);
  assert.equal(report.findings[0].evidence.name, "PSBT_IN_WITNESS_UTXO");
  assert.equal(report.findings[0].evidence.kind, "changed");
  assert.equal(report.findings[0].evidence.beforeValue, 150000);
  assert.equal(report.findings[0].evidence.afterValue, 149000);
  assert.equal(report.checks.utxoDeclarations, "changed");
  assert.equal(report.checks.transactionBody, "unchanged");
});

test("F9b a changed non-witness UTXO declaration is transaction-critical", () => {
  const before = baseDoc({ inputs: [[
    pair("00", "aa", "PSBT_IN_NON_WITNESS_UTXO", { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "150000", scriptPubKey: SCRIPT1 } }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
  ]] });
  const after = baseDoc({ inputs: [[
    pair("00", "bb", "PSBT_IN_NON_WITNESS_UTXO", { txid: "11".repeat(32), outputCount: 1, prevout: { vout: 0, value: "149000", scriptPubKey: SCRIPT1 } }),
    before.inputs[0][1],
  ]] });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["UTXO_DECLARATION_CHANGED", "critical"]]);
  assert.equal(report.findings[0].evidence.name, "PSBT_IN_NON_WITNESS_UTXO");
  assert.equal(report.findings[0].evidence.beforeValue, 150000);
  assert.equal(report.findings[0].evidence.afterValue, 149000);
});

test("F10 a verified signature addition is the only finding", () => {
  const { before, after, verification } = f10Docs();
  const report = auditSigner(before, after, { verification });
  assert.equal(report.verdict, "pass");
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
  assert.equal(report.findings[0].evidence.index, 0);
  assert.equal(report.findings[0].evidence.name, "PSBT_IN_PARTIAL_SIG");
  assert.equal(report.findings[0].evidence.pubkey, P1_HEX);
  assert.equal(report.findings[0].evidence.sighashAppended, 1);
  assert.equal(report.checks.transactionBody, "unchanged");
  assert.equal(report.checks.utxoDeclarations, "unchanged");
  assert.equal(report.checks.signatures, "valid");
  assert.equal(report.checks.sighashPolicy, "full_commitment");
  assert.equal(report.checks.signerKeys, "match");
  assert.equal(report.checks.metadata, "unchanged");
});

test("F11-F13 SIGHASH_NONE, SINGLE and ANYONECANPAY are flagged", () => {
  const before = baseDoc();
  for (const [lastByte, appended] of [["02", 2], ["03", 3], ["81", 0x81]]) {
    const after = withSig(before, P1_HEX, lastByte);
    const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1_HEX, valid: true }] };
    const report = auditSigner(before, after, { verification });
    assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [
      ["SIGNATURE_ADDED", "info"],
      ["SIGHASH_WEAK", "critical"],
    ]);
    assert.equal(report.findings[1].evidence.appended, appended);
    assert.equal(report.verdict, "fail");
    assert.equal(report.checks.sighashPolicy, "weak");
  }
});

test("F13b a weak sighash the original PSBT declared is not flagged", () => {
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("03", "02000000", "PSBT_IN_SIGHASH_TYPE", { sighash: "SIGHASH_NONE", sighashType: 2 }),
  ]] });
  const after = withSig(before, P1_HEX, "02");
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1_HEX, valid: true }] };
  const report = auditSigner(before, after, { verification });
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
  assert.equal(report.checks.sighashPolicy, "weak_as_requested");
  assert.equal(report.verdict, "pass");
});

test("F13c declaration-only weak values are warnings", () => {
  for (const value of ["02000000", "03000000", "81000000"]) {
    const before = baseDoc();
    const after = baseDoc({ inputs: [[
      ...before.inputs[0],
      pair("03", value, "PSBT_IN_SIGHASH_TYPE", { sighash: "SIGHASH_NONE", sighashType: parseInt(value.slice(0, 2), 16) }),
    ]] });
    const report = auditSigner(before, after);
    assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["SIGHASH_DECLARATION_ADDED", "warning"]]);
    assert.equal(report.verdict, "pass");
  }
});

test("F14 Taproot SIGHASH_DEFAULT is clean", () => {
  const xonly = P1_HEX.slice(2);
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("17", xonly, "PSBT_IN_TAP_INTERNAL_KEY", { xonly }),
  ]] });
  const after = structuredClone(before);
  after.inputs[0].push(pair("13", "11".repeat(64), "PSBT_IN_TAP_KEY_SIG", { signature: "11".repeat(64), sighash: "SIGHASH_DEFAULT" }));
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_TAP_KEY_SIG", pubkey: null, valid: true }] };
  const report = auditSigner(before, after, { verification });
  assert.equal(report.verdict, "pass");
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
  assert.equal(report.findings[0].evidence.sighashAppended, 0);
  assert.equal(report.checks.sighashPolicy, "full_commitment");
});

test("F15 an unexpected signer pubkey fails the audit", () => {
  const before = baseDoc();
  const after = withSig(before, P2_HEX, "01");
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P2_HEX, valid: true }] };
  const report = auditSigner(before, after, { verification });
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["UNEXPECTED_SIGNER", "critical"]]);
  assert.equal(report.findings[0].evidence.pubkey, P2_HEX);
  assert.deepEqual(report.findings[0].evidence.expectedKeys, [P1_HEX]);
  assert.equal(report.verdict, "fail");
  assert.equal(report.checks.signerKeys, "unexpected");
});

test("F15b a cosigner key named by the original PSBT is expected", () => {
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("06" + P2_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P2_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/1" }),
    pair("02" + P1_HEX, "11".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P1_HEX, signature: "11".repeat(71), sighash: "SIGHASH_ALL" }),
  ]] });
  const after = structuredClone(before);
  after.inputs[0].push(pair("02" + P2_HEX, "22".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P2_HEX, signature: "22".repeat(71), sighash: "SIGHASH_ALL" }));
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P2_HEX, valid: true }] };
  const report = auditSigner(before, after, { verification });
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
});

test("F16 a fingerprint mismatch is critical and suppresses METADATA_CHANGED", () => {
  const before = baseDoc();
  const after = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, "87654321" + DERIV_VALUE.slice(8), "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "87654321", path: "m/84'/0'/0'/0/0" }),
  ]] });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["FINGERPRINT_MISMATCH", "critical"]]);
  assert.equal(report.findings[0].evidence.fingerprintBefore, "12345678");
  assert.equal(report.findings[0].evidence.fingerprintAfter, "87654321");
});

test("F16b a derivation path mismatch is critical", () => {
  const before = baseDoc();
  const after = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE.slice(0, -8) + "01000000", "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/1" }),
  ]] });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["FINGERPRINT_MISMATCH", "critical"]]);
  assert.equal(report.findings[0].evidence.pathBefore, "m/84'/0'/0'/0/0");
  assert.equal(report.findings[0].evidence.pathAfter, "m/84'/0'/0'/0/1");
});

test("F17 an unexpected metadata addition is a warning, not a failure", () => {
  const before = baseDoc();
  const after = baseDoc({ inputs: [[...before.inputs[0], pair("04", "51", "PSBT_IN_REDEEM_SCRIPT")]] });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["METADATA_ADDED", "warning"]]);
  assert.equal(report.findings[0].evidence.scope, "input-map");
  assert.equal(report.findings[0].evidence.index, 0);
  assert.equal(report.findings[0].evidence.name, "PSBT_IN_REDEEM_SCRIPT");
  assert.equal(report.verdict, "pass");
  assert.equal(report.checks.metadata, "additions");

  const proprietaryAfter = baseDoc({ globals: [...before.globals, pair("fc01", "aa", "PSBT_GLOBAL_PROPRIETARY")] });
  const proprietaryReport = auditSigner(before, proprietaryAfter);
  assert.deepEqual(proprietaryReport.findings.map((f) => [f.code, f.severity]), [["METADATA_ADDED", "warning"]]);
});

test("F18 a derivation for a new signature is enrichment", () => {
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("06" + P2_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P2_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/1" }),
  ]] });
  const after = structuredClone(before);
  after.inputs[0].push(pair("06" + P2_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P2_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/1" }));
  after.inputs[0].push(pair("02" + P2_HEX, "22".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P2_HEX, signature: "22".repeat(71), sighash: "SIGHASH_ALL" }));
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P2_HEX, valid: true }] };
  const report = auditSigner(before, after, { verification });
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [
    ["METADATA_ENRICHMENT", "info"],
    ["SIGNATURE_ADDED", "info"],
  ]);
  assert.equal(report.verdict, "pass");
});

test("F18b enrichment consistency: unmatched derivation, verified output, global xpub", () => {
  const before = baseDoc();
  const unmatched = baseDoc({ inputs: [[...before.inputs[0], pair("06" + P2_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P2_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/1" })]] });
  const unmatchedReport = auditSigner(before, unmatched);
  assert.deepEqual(unmatchedReport.findings.map((f) => [f.code, f.severity]), [["METADATA_ADDED", "warning"]]);

  const outBefore = changeDoc({ outputs: [[], []] });
  const outAfter = changeDoc();
  const wallet = { fingerprints: ["12345678"], scriptPubKeys: [outAfter.tx.outputs[1].scriptPubKey] };
  const verifiedReport = auditSigner(outBefore, outAfter, { wallet });
  assert.deepEqual(verifiedReport.findings.map((f) => [f.code, f.severity]), [
    ["METADATA_ENRICHMENT", "info"],
    ["CHANGE_VERIFIED", "info"],
  ]);
  const noWalletReport = auditSigner(outBefore, outAfter);
  assert.deepEqual(noWalletReport.findings.map((f) => [f.code, f.severity]), [["METADATA_ADDED", "warning"]]);

  const xpubAfter = baseDoc({ globals: [...before.globals, pair("01aa", "bb", "PSBT_GLOBAL_XPUB")] });
  const xpubReport = auditSigner(before, xpubAfter);
  assert.deepEqual(xpubReport.findings.map((f) => [f.code, f.severity]), [["METADATA_ENRICHMENT", "info"]]);
});

test("F19 finalization-only change is a verified transition", () => {
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("03", "01000000", "PSBT_IN_SIGHASH_TYPE", { sighash: "SIGHASH_ALL", sighashType: 1 }),
    pair("02" + P1_HEX, "11".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P1_HEX, signature: "11".repeat(71), sighash: "SIGHASH_ALL" }),
  ]] });
  const after = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("08", "aa", "PSBT_IN_FINAL_SCRIPTWITNESS"),
  ]] });
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_FINAL_SCRIPTWITNESS", pubkey: P1_HEX, valid: true }] };
  const report = auditSigner(before, after, { verification });
  assert.equal(report.verdict, "pass");
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["FINALIZED", "info"]]);
  assert.ok(report.findings[0].evidence.finalFields.includes("PSBT_IN_FINAL_SCRIPTWITNESS"));
  assert.ok(report.findings[0].evidence.removedFields.includes("PSBT_IN_BIP32_DERIVATION"));
  assert.equal(report.findings.some((f) => f.code === "FIELD_REMOVED"), false);
  assert.equal(report.findings.some((f) => f.code === "SIGNATURE_REMOVED"), false);
});

test("F19b unverified finalization fails closed", () => {
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
  ]] });
  const after = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("08", "aa", "PSBT_IN_FINAL_SCRIPTWITNESS"),
  ]] });
  const noSignatures = auditSigner(before, after, { verification: { complete: false, signatures: [] } });
  assert.deepEqual(noSignatures.findings.map((f) => [f.code, f.severity]), [["FINALIZATION_INVALID", "critical"]]);
  assert.equal(noSignatures.findings[0].evidence.reason, "no_signatures");
  assert.equal(noSignatures.verdict, "fail");

  const invalid = auditSigner(before, after, { verification: { complete: true, signatures: [{ index: 0, name: "PSBT_IN_FINAL_SCRIPTWITNESS", pubkey: P1_HEX, valid: false }] } });
  assert.equal(invalid.findings[0].evidence.reason, "signature_invalid");

  const unchecked = auditSigner(before, after, { verification: { complete: true, signatures: [{ index: 0, name: "PSBT_IN_FINAL_SCRIPTWITNESS", pubkey: P1_HEX, valid: null }] } });
  assert.equal(unchecked.findings[0].evidence.reason, "unverified");
});

test("F19c finalization never clears the UTXO, unknown pairs or final fields", () => {
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("03", "01000000", "PSBT_IN_SIGHASH_TYPE", { sighash: "SIGHASH_ALL", sighashType: 1 }),
    pair("02" + P1_HEX, "11".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P1_HEX, signature: "11".repeat(71), sighash: "SIGHASH_ALL" }),
  ]] });
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_FINAL_SCRIPTWITNESS", pubkey: P1_HEX, valid: true }] };

  const droppedUtxo = baseDoc({ inputs: [[pair("08", "aa", "PSBT_IN_FINAL_SCRIPTWITNESS")]] });
  const utxoReport = auditSigner(before, droppedUtxo, { verification });
  assert.deepEqual(utxoReport.findings.map((f) => [f.code, f.severity]), [
    ["UTXO_DECLARATION_CHANGED", "critical"],
    ["FINALIZED", "info"],
  ]);

  const withUnknown = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("03", "01000000", "PSBT_IN_SIGHASH_TYPE", { sighash: "SIGHASH_ALL", sighashType: 1 }),
    pair("02" + P1_HEX, "11".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P1_HEX, signature: "11".repeat(71), sighash: "SIGHASH_ALL" }),
    pair("fc01", "aa", null),
  ]] });
  const unknownAfter = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("08", "aa", "PSBT_IN_FINAL_SCRIPTWITNESS"),
  ]] });
  const unknownReport = auditSigner(withUnknown, unknownAfter, { verification });
  assert.deepEqual(unknownReport.findings.map((f) => [f.code, f.severity]), [
    ["FIELD_REMOVED", "critical"],
    ["FINALIZED", "info"],
  ]);

  const finalBefore = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("08", "aa", "PSBT_IN_FINAL_SCRIPTWITNESS"),
  ]] });
  const finalAfter = baseDoc({ inputs: [[pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 })]] });
  const finalReport = auditSigner(finalBefore, finalAfter, { verification });
  assert.deepEqual(finalReport.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_REMOVED", "critical"]]);
});

test("F20 a pre-existing signature removed or changed fails", () => {
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("02" + P1_HEX, "11".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P1_HEX, signature: "11".repeat(71), sighash: "SIGHASH_ALL" }),
  ]] });
  const removed = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
  ]] });
  const removedReport = auditSigner(before, removed);
  assert.deepEqual(removedReport.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_REMOVED", "critical"]]);
  assert.equal(removedReport.findings[0].evidence.index, 0);
  assert.equal(removedReport.findings[0].evidence.name, "PSBT_IN_PARTIAL_SIG");

  const changed = structuredClone(before);
  changed.inputs[0][2] = pair("02" + P1_HEX, "11".repeat(71) + "81", "PSBT_IN_PARTIAL_SIG", { pubkey: P1_HEX, signature: "11".repeat(71), sighash: "SIGHASH_ALL" });
  const changedReport = auditSigner(before, changed);
  assert.deepEqual(changedReport.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_CHANGED", "critical"]]);
});

test("F20b cosigner signatures unchanged produce no findings", () => {
  const before = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("06" + P2_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P2_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/1" }),
    pair("02" + P1_HEX, "11".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P1_HEX, signature: "11".repeat(71), sighash: "SIGHASH_ALL" }),
    pair("02" + P2_HEX, "22".repeat(71) + "01", "PSBT_IN_PARTIAL_SIG", { pubkey: P2_HEX, signature: "22".repeat(71), sighash: "SIGHASH_ALL" }),
  ]] });
  const after = structuredClone(before);
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings, []);
  assert.equal(report.verdict, "pass");
});

test("F21 nonce verdicts surface in findings and checks", () => {
  const { before, after, verification } = f10Docs();
  const reuse = auditSigner(before, after, { verification, nonce: { status: "reuse" } });
  assert.deepEqual(reuse.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["NONCE_REUSE", "critical"],
  ]);
  assert.equal(reuse.verdict, "fail");

  const possible = auditSigner(before, after, { verification, nonce: { status: "possible" } });
  assert.deepEqual(possible.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["NONCE_REUSE_POSSIBLE", "warning"],
  ]);
  assert.equal(possible.verdict, "pass");

  const crossKey = auditSigner(before, after, { verification, nonce: { status: "cross-key" } });
  assert.deepEqual(crossKey.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["NONCE_CROSS_KEY", "critical"],
  ]);

  const incomplete = auditSigner(before, after, { verification, nonce: { status: "incomplete" } });
  assert.deepEqual(incomplete.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["NONCE_COVERAGE_INCOMPLETE", "warning"],
  ]);

  const clean = auditSigner(before, after, { verification, nonce: { status: "clean" } });
  assert.deepEqual(clean.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
  assert.equal(clean.checks.nonceReuse, "none_found");
});

test("F22 anti-exfil verified, failed and unavailable", () => {
  const { before, after, verification } = f10Docs();
  const verified = auditSigner(before, after, { verification, antiExfil: { status: "verified", signer: "jade" } });
  assert.deepEqual(verified.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
  assert.equal(verified.checks.antiExfil, "verified");
  assert.equal(verified.verdict, "pass");

  const failed = auditSigner(before, after, { verification, antiExfil: { status: "failed", signer: "jade" } });
  assert.deepEqual(failed.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["ANTIEXFIL_FAILED", "critical"],
  ]);
  assert.equal(failed.verdict, "fail");

  const unavailable = auditSigner(before, after, { verification });
  assert.deepEqual(unavailable.findings.map((f) => [f.code, f.severity]), [["SIGNATURE_ADDED", "info"]]);
  assert.equal(unavailable.checks.antiExfil, "not_available");
});

test("F23 fail closed on an undecodable input", () => {
  const before = baseDoc();
  const after = baseDoc({
    inputs: [[...before.inputs[0], pair("03", "02000000", "PSBT_IN_SIGHASH_TYPE", { sighash: "SIGHASH_NONE", sighashType: 2 })]],
    sanitize: { duplicateKeys: { state: "problem", findings: [], truncated: false } },
  });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [
    ["DOC_UNDECODABLE", "critical"],
    ["SIGHASH_DECLARATION_ADDED", "warning"],
  ]);
  assert.equal(report.findings[0].evidence.side, "after");
  assert.equal(report.findings[0].evidence.reason, "duplicate_keys");
  assert.equal(report.verdict, "fail");

  const beforeBroken = baseDoc({ rustBitcoinError: "duplicate key" });
  const symmetric = auditSigner(beforeBroken, baseDoc());
  assert.deepEqual(symmetric.findings.map((f) => [f.code, f.severity]), [["DOC_UNDECODABLE", "critical"]]);
  assert.equal(symmetric.findings[0].evidence.side, "before");
  assert.equal(symmetric.findings[0].evidence.reason, "rust_bitcoin_error");
});

test("F24 an unchecked signature fails closed", () => {
  const { before, after } = f10Docs();
  const exhausted = auditSigner(before, after, { verification: { complete: false, signatures: [] } });
  assert.deepEqual(exhausted.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["SIGNATURE_UNVERIFIED", "critical"],
  ]);
  assert.equal(exhausted.findings[1].evidence.reason, "budget_exhausted");
  assert.equal(exhausted.verdict, "fail");

  const unavailable = auditSigner(before, after);
  assert.deepEqual(unavailable.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["SIGNATURE_UNVERIFIED", "critical"],
  ]);
  assert.equal(unavailable.findings[1].evidence.reason, "verification_unavailable");
});

test("F25 metadata removal fails; global xpub and proprietary changes follow severity", () => {
  const before = changeDoc();
  const after = changeDoc({ outputs: [[], []] });
  const removed = auditSigner(before, after);
  assert.deepEqual(removed.findings.map((f) => [f.code, f.severity]), [["METADATA_REMOVED", "critical"]]);
  assert.equal(removed.findings[0].evidence.scope, "output-map");
  assert.equal(removed.findings[0].evidence.index, 1);
  assert.equal(removed.verdict, "fail");

  const xpubBefore = baseDoc({ globals: [...baseDoc().globals, pair("01aa", "aa", "PSBT_GLOBAL_XPUB")] });
  const xpubChanged = baseDoc({ globals: [...baseDoc().globals, pair("01aa", "bb", "PSBT_GLOBAL_XPUB")] });
  const xpubChangedReport = auditSigner(xpubBefore, xpubChanged);
  assert.deepEqual(xpubChangedReport.findings.map((f) => [f.code, f.severity]), [["METADATA_CHANGED", "critical"]]);

  const xpubRemoved = baseDoc();
  const xpubRemovedReport = auditSigner(xpubBefore, xpubRemoved);
  assert.deepEqual(xpubRemovedReport.findings.map((f) => [f.code, f.severity]), [["METADATA_REMOVED", "critical"]]);

  const propBefore = baseDoc({ globals: [...baseDoc().globals, pair("fc01", "aa", "PSBT_GLOBAL_PROPRIETARY")] });
  const propAfter = baseDoc({ globals: [...baseDoc().globals, pair("fc01", "bb", "PSBT_GLOBAL_PROPRIETARY")] });
  const propReport = auditSigner(propBefore, propAfter);
  assert.deepEqual(propReport.findings.map((f) => [f.code, f.severity]), [["METADATA_CHANGED", "warning"]]);
});

test("F26 sighash declaration changed, mismatch, undefined and removed", () => {
  const beforeDeclared = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("03", "01000000", "PSBT_IN_SIGHASH_TYPE", { sighash: "SIGHASH_ALL", sighashType: 1 }),
  ]] });
  const changed = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
    pair("03", "02000000", "PSBT_IN_SIGHASH_TYPE", { sighash: "SIGHASH_NONE", sighashType: 2 }),
  ]] });
  const changedReport = auditSigner(beforeDeclared, changed);
  assert.deepEqual(changedReport.findings.map((f) => [f.code, f.severity]), [["SIGHASH_DECLARATION_CHANGED", "critical"]]);

  const mismatchAfter = withSig(beforeDeclared, P1_HEX, "02");
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1_HEX, valid: true }] };
  const mismatchReport = auditSigner(beforeDeclared, mismatchAfter, { verification });
  assert.deepEqual(mismatchReport.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["SIGHASH_MISMATCH", "critical"],
    ["SIGHASH_WEAK", "critical"],
  ]);
  assert.equal(mismatchReport.findings[1].evidence.appended, 2);
  assert.equal(mismatchReport.findings[1].evidence.declared, 1);
  assert.equal(mismatchReport.findings[1].evidence.source, "original");

  const undefinedAfter = baseDoc({ inputs: [[
    ...baseDoc().inputs[0],
    pair("03", "04000000", "PSBT_IN_SIGHASH_TYPE"),
  ]] });
  const undefinedReport = auditSigner(baseDoc(), undefinedAfter);
  assert.deepEqual(undefinedReport.findings.map((f) => [f.code, f.severity]), [["SIGHASH_UNDEFINED", "critical"]]);
  assert.equal(undefinedReport.findings[0].evidence.source, "declared");

  const removed = baseDoc({ inputs: [[
    pair("01", "cc", "PSBT_IN_WITNESS_UTXO", { value: "150000", scriptPubKey: SCRIPT1 }),
    pair("06" + P1_HEX, DERIV_VALUE, "PSBT_IN_BIP32_DERIVATION", { pubkey: P1_HEX, fingerprint: "12345678", path: "m/84'/0'/0'/0/0" }),
  ]] });
  const removedReport = auditSigner(beforeDeclared, removed);
  assert.deepEqual(removedReport.findings.map((f) => [f.code, f.severity]), [["SIGHASH_DECLARATION_CHANGED", "critical"]]);
});

test("F27 identical PSBTs pass with no findings", () => {
  const before = baseDoc();
  const after = baseDoc();
  const report = auditSigner(before, after);
  assert.equal(report.equal, true);
  assert.equal(report.verdict, "pass");
  assert.deepEqual(report.findings, []);
  assert.equal(report.checks.signatures, "none_added");
});

test("F28 an invalid signature fails", () => {
  const { before, after } = f10Docs();
  const verification = { complete: true, signatures: [{ index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1_HEX, valid: false }] };
  const report = auditSigner(before, after, { verification });
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [
    ["SIGNATURE_ADDED", "info"],
    ["SIGNATURE_INVALID", "critical"],
  ]);
  assert.equal(report.checks.signatures, "invalid");
  assert.equal(report.verdict, "fail");
});

test("F29 MuSig2 material added is a warning", () => {
  const before = baseDoc();
  const after = baseDoc({ inputs: [[...before.inputs[0], pair("1a", "11", "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS")]] });
  const report = auditSigner(before, after);
  assert.deepEqual(report.findings.map((f) => [f.code, f.severity]), [["MUSIG2_MATERIAL_ADDED", "warning"]]);
  assert.equal(report.verdict, "pass");
});
