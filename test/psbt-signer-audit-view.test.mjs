// Rendering tests for the PSBT Signer Audit view (src/js/psbt-signer-audit-view.js).
//
// The expected wording is the approved UI plan's per-code lines (the
// specification for this feature), asserted as short stable substrings;
// structural hooks are data-audit-* attributes, never classes. The check
// tones come from the same approved table. The diff-caption expectations
// pin the documented editor default ("before = the PSBT in the editor ·
// after = the pasted PSBT.") against the new optional labels.
// Run with `npm test`.
import test from "node:test";
import assert from "node:assert/strict";
import { SIGNER_AUDIT_CODES } from "../src/js/psbt-signer-audit.js";
import { comparePsbtDocs } from "../src/js/psbt-diff.js";
import { psbtDiffHtml } from "../src/js/psbt-editor.js";
import { psbtSignerAuditErrorHtml, psbtSignerAuditHtml } from "../src/js/psbt-signer-audit-view.js";

const P1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SCRIPT = "0014" + "22".repeat(20);

const INFO_CODES = new Set(["SIGNATURE_ADDED", "FINALIZED", "METADATA_ENRICHMENT", "CHANGE_VERIFIED"]);
const WARNING_CODES = new Set(["METADATA_CHANGED", "MUSIG2_MATERIAL_ADDED", "METADATA_ADDED", "SIGHASH_DECLARATION_INVALID", "CHANGE_UNVERIFIED", "NONCE_REUSE_POSSIBLE", "NONCE_COVERAGE_INCOMPLETE", "ORIGIN_INCONSISTENT"]);

// One minimal finding per code, carrying the evidence shape the engine
// emits for it (src/js/psbt-signer-audit.js).
const findingFor = (code) => {
  const evidence = {
    DOC_UNDECODABLE: { side: "after", reason: "rust_bitcoin_error" },
    TX_REORDERED: { dimension: "outputs", order: [1, 0] },
    TX_INPUT_CHANGED: { index: 0, field: "input[0].txid", kind: "changed", before: "aa".repeat(32), after: "bb".repeat(32) },
    TX_OUTPUT_CHANGED: { index: 1, field: "output[1].value", kind: "changed", before: 100000, after: 99000 },
    TX_VERSION_CHANGED: { field: "version", kind: "changed", before: 2, after: 1 },
    TX_LOCKTIME_CHANGED: { field: "locktime", kind: "changed", before: 0, after: 800000 },
    UTXO_DECLARATION_CHANGED: { index: 0, name: "PSBT_IN_WITNESS_UTXO", kind: "changed", beforeValue: 150000, afterValue: 149000 },
    UNEXPECTED_SIGNER: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, expectedKeys: [P1] },
    SIGNATURE_CHANGED: { index: 0, name: "PSBT_IN_PARTIAL_SIG" },
    SIGNATURE_REMOVED: { index: 0, name: "PSBT_IN_PARTIAL_SIG" },
    SIGNATURE_MALFORMED: { index: 0, name: "PSBT_IN_PARTIAL_SIG", decodeError: "signature is too short" },
    SIGNATURE_INVALID: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1 },
    SIGNATURE_UNVERIFIED: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, reason: "budget_exhausted" },
    SIGHASH_WEAK: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, appended: 2 },
    SIGHASH_MISMATCH: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, appended: 2, declared: 1, source: "original" },
    SIGHASH_UNDEFINED: { index: 0, source: "appended", value: 4 },
    SIGHASH_DECLARATION_CHANGED: { index: 0, before: "01000000", after: "02000000" },
    SIGHASH_DECLARATION_ADDED: { index: 0, value: 2 },
    SIGHASH_DECLARATION_INVALID: { index: 0 },
    FINALIZATION_INVALID: { index: 0, reason: "signature_invalid", removedFields: ["PSBT_IN_PARTIAL_SIG"] },
    FINALIZED: { index: 0, finalFields: ["PSBT_IN_FINAL_SCRIPTWITNESS"], removedFields: ["PSBT_IN_PARTIAL_SIG"], signatures: 1 },
    FIELD_REMOVED: { index: 0, key: "06" + P1, name: "PSBT_IN_BIP32_DERIVATION" },
    FINGERPRINT_MISMATCH: { scope: "input-map", index: 0, name: "PSBT_IN_BIP32_DERIVATION", pubkey: P1, fingerprintBefore: "12345678", fingerprintAfter: "87654321" },
    METADATA_REMOVED: { scope: "output-map", index: 1, key: "06" + P1, name: "PSBT_OUT_BIP32_DERIVATION" },
    METADATA_CHANGED: { scope: "global", index: null, key: "01aa", name: "PSBT_GLOBAL_XPUB", before: "aa", after: "bb" },
    METADATA_ADDED: { scope: "input-map", index: 0, key: "0451", name: "PSBT_IN_REDEEM_SCRIPT" },
    METADATA_ENRICHMENT: { scope: "input-map", index: 0, key: "06" + P1, name: "PSBT_IN_BIP32_DERIVATION" },
    CHANGE_NOT_FROM_WALLET: { index: 1, scriptPubKey: SCRIPT, fingerprint: "12345678" },
    CHANGE_UNVERIFIED: { index: 1, scriptPubKey: SCRIPT, fingerprint: "12345678" },
    CHANGE_VERIFIED: { index: 1, scriptPubKey: SCRIPT, fingerprint: "12345678" },
    NONCE_REUSE: {},
    NONCE_CROSS_KEY: {},
    NONCE_REUSE_POSSIBLE: {},
    NONCE_COVERAGE_INCOMPLETE: {},
    ANTIEXFIL_FAILED: { signer: "jade" },
    SIGNER_UNKNOWN: { index: 0, pubkeys: [P1] },
    MUSIG2_MATERIAL_ADDED: { index: 0, name: "PSBT_IN_MUSIG2_PUB_NONCE" },
    ORIGIN_INCONSISTENT: { scope: "input-map", index: 0, name: "PSBT_IN_BIP32_DERIVATION", fingerprint: "12345678", reason: "mismatch" },
    SIGNATURE_ADDED: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: P1, sighashAppended: 1 },
  }[code] ?? {};
  const severity = INFO_CODES.has(code) ? "info" : WARNING_CODES.has(code) ? "warning" : "critical";
  return { code, severity, scope: evidence.scope ?? null, index: evidence.index ?? null, field: null, evidence };
};

const reportFor = (findings, overrides = {}) => ({
  verdict: findings.some((f) => f.severity === "critical") ? "fail" : "pass",
  equal: findings.length === 0,
  checks: {
    transactionBody: "unchanged",
    utxoDeclarations: "unchanged",
    signatures: "none_added",
    sighashPolicy: "none",
    signerKeys: "no_new_signatures",
    metadata: "unchanged",
    nonceReuse: "not_checked",
    antiExfil: "not_available",
    changeOutputs: "not_checked",
  },
  findings,
  stats: { inputs: 1, outputs: 1, newSignatures: 0, feeBefore: null, feeAfter: null },
  diff: null,
  ...overrides,
});

const versionBumpDocs = () => {
  const before = { tx: { version: 2, locktime: 0, inputs: [], outputs: [] }, globals: [], inputs: [], outputs: [] };
  const after = { tx: { version: 3, locktime: 0, inputs: [], outputs: [] }, globals: [], inputs: [], outputs: [] };
  return { before, after, diff: comparePsbtDocs(before, after) };
};

// The approved one-line wording per code, as a short stable substring.
const WORDING = {
  DOC_UNDECODABLE: "could not be read safely",
  TX_REORDERED: "changed the order of the outputs",
  TX_INPUT_CHANGED: "is not what you sent",
  TX_OUTPUT_CHANGED: "is not what you sent",
  TX_VERSION_CHANGED: "transaction version changed",
  TX_LOCKTIME_CHANGED: "locktime changed",
  UTXO_DECLARATION_CHANGED: "claims to spend was changed",
  UNEXPECTED_SIGNER: "signed by a key your PSBT does not name",
  SIGNATURE_CHANGED: "was altered",
  SIGNATURE_REMOVED: "was removed",
  SIGNATURE_MALFORMED: "is malformed",
  SIGNATURE_INVALID: "does not verify",
  SIGNATURE_UNVERIFIED: "could not be checked",
  SIGHASH_WEAK: "does not commit to the whole transaction",
  SIGHASH_MISMATCH: "different sighash than declared",
  SIGHASH_UNDEFINED: "undefined sighash value",
  SIGHASH_DECLARATION_CHANGED: "changed or removed the sighash declaration",
  SIGHASH_DECLARATION_ADDED: "A weak sighash was declared",
  SIGHASH_DECLARATION_INVALID: "declares an invalid sighash",
  FINALIZATION_INVALID: "could not be verified",
  FINALIZED: "was finalized",
  FIELD_REMOVED: "without valid finalization",
  FINGERPRINT_MISMATCH: "origin changed",
  METADATA_REMOVED: "removed PSBT data",
  METADATA_CHANGED: "changed PSBT data",
  METADATA_ADDED: "added PSBT data",
  METADATA_ENRICHMENT: "added expected data",
  CHANGE_NOT_FROM_WALLET: "does not belong to the loaded key",
  CHANGE_UNVERIFIED: "could not be verified",
  CHANGE_VERIFIED: "is change back to your wallet",
  NONCE_REUSE: "reuses a nonce",
  NONCE_CROSS_KEY: "under two different keys",
  NONCE_REUSE_POSSIBLE: "Possible nonce reuse",
  NONCE_COVERAGE_INCOMPLETE: "did not cover every signature",
  ANTIEXFIL_FAILED: "anti-exfiltration check failed",
  SIGNER_UNKNOWN: "names no signing keys",
  MUSIG2_MATERIAL_ADDED: "MuSig2 signing data was added",
  ORIGIN_INCONSISTENT: "does not match the global xpub",
  SIGNATURE_ADDED: "New signature on input 0",
};

test("every signer-audit code renders its approved wording line", () => {
  assert.equal(SIGNER_AUDIT_CODES.length, 39, "fixture: the engine freezes 39 codes");
  for (const code of SIGNER_AUDIT_CODES) {
    assert.ok(WORDING[code], `fixture: approved wording for ${code}`);
    const html = psbtSignerAuditHtml(reportFor([findingFor(code)]), null, null, "mainnet");
    assert.ok(html.includes(`data-audit-code="${code}"`), `${code}: the row hook is missing`);
    assert.ok(html.includes(WORDING[code]), `${code}: approved wording "${WORDING[code]}" is missing`);
  }
});

test("SIGHASH_DECLARATION_ADDED renders its three severity wordings", () => {
  const base = findingFor("SIGHASH_DECLARATION_ADDED");
  const info = psbtSignerAuditHtml(reportFor([{ ...base, severity: "info", evidence: { index: 0, value: 1 } }]), null, null, "mainnet");
  assert.ok(info.includes("full-commitment sighash"));
  const requested = psbtSignerAuditHtml(reportFor([{ ...base, severity: "warning" }]), null, null, "mainnet");
  assert.ok(requested.includes("the one your PSBT requested"));
  const weak = psbtSignerAuditHtml(reportFor([{ ...base, severity: "critical" }]), null, null, "mainnet");
  assert.ok(weak.includes("A weak sighash was declared"));
});

test("the three verdict tiers render their approved headlines", () => {
  const clean = psbtSignerAuditHtml(reportFor([]), null, null, "mainnet");
  assert.ok(clean.includes('data-audit-verdict="pass"'));
  assert.ok(clean.includes("No changes to your transaction"));
  const warned = psbtSignerAuditHtml(reportFor([findingFor("METADATA_ADDED")]), null, null, "mainnet");
  assert.ok(warned.includes('data-audit-verdict="pass-warnings"'));
  assert.ok(warned.includes("Your transaction is unchanged — review the warnings below"));
  const failed = psbtSignerAuditHtml(reportFor([findingFor("TX_LOCKTIME_CHANGED")]), null, null, "mainnet");
  assert.ok(failed.includes('data-audit-verdict="fail"'));
  assert.ok(failed.includes("Do not broadcast this PSBT"));
});

test("the closing limitation note always renders", () => {
  for (const findings of [[], [findingFor("METADATA_ADDED")], [findingFor("NONCE_REUSE")]]) {
    const html = psbtSignerAuditHtml(reportFor(findings), null, null, "mainnet");
    assert.ok(html.includes("does not prove the signing device or its firmware is trustworthy"));
  }
});

test("a group lists at most 8 findings, then one …and N more line; the verdict counts every finding", () => {
  const warnings = Array.from({ length: 10 }, (_, i) => ({
    code: "METADATA_ADDED",
    severity: "warning",
    scope: "input-map",
    index: i,
    field: null,
    evidence: { scope: "input-map", index: i, key: "0451", name: "PSBT_IN_REDEEM_SCRIPT" },
  }));
  const html = psbtSignerAuditHtml(reportFor(warnings), null, null, "mainnet");
  assert.equal((html.match(/data-audit-code="METADATA_ADDED"/g) || []).length, 8);
  assert.ok(html.includes("…and 2 more."));
  // A critical finding anywhere fails the verdict, listed or not: the cap
  // limits only what is shown, never what counts.
  const failed = psbtSignerAuditHtml(reportFor([...warnings, findingFor("TX_VERSION_CHANGED")]), null, null, "mainnet");
  assert.ok(failed.includes('data-audit-verdict="fail"'));
  assert.ok(failed.includes("…and 2 more."));
});

test("within a group, critical findings render before warnings and info", () => {
  const html = psbtSignerAuditHtml(reportFor([findingFor("SIGNATURE_ADDED"), findingFor("SIGHASH_DECLARATION_INVALID"), findingFor("FIELD_REMOVED")]), null, null, "mainnet");
  const at = (code) => html.indexOf(`data-audit-code="${code}"`);
  assert.ok(at("FIELD_REMOVED") !== -1 && at("FIELD_REMOVED") < at("SIGHASH_DECLARATION_INVALID"));
  assert.ok(at("SIGHASH_DECLARATION_INVALID") < at("SIGNATURE_ADDED"));
});

test("hostile PSBT strings are escaped and bidi controls are neutralized", () => {
  const hostile = `<img src=x onerror="alert(1)">`;
  const findings = [
    { code: "METADATA_ADDED", severity: "warning", scope: "input-map", index: 0, field: null, evidence: { scope: "input-map", index: 0, key: "0451", name: hostile } },
    { code: "SIGNATURE_MALFORMED", severity: "critical", scope: "input-map", index: 0, field: null, evidence: { index: 0, name: "PSBT_IN_PARTIAL_SIG", decodeError: `bad ‮⁦signature ${hostile}` } },
    { code: "UNEXPECTED_SIGNER", severity: "critical", scope: "input-map", index: 0, field: null, evidence: { index: 0, name: "PSBT_IN_PARTIAL_SIG", pubkey: hostile, expectedKeys: [] } },
    { code: "ANTIEXFIL_FAILED", severity: "critical", scope: null, index: null, field: null, evidence: { signer: hostile } },
    { code: "CHANGE_NOT_FROM_WALLET", severity: "critical", scope: "output", index: 1, field: null, evidence: { index: 1, scriptPubKey: hostile, fingerprint: hostile } },
  ];
  const html = psbtSignerAuditHtml(reportFor(findings), null, null, "mainnet");
  assert.ok(!html.includes("<img"), "raw HTML from a PSBT string must never reach the markup");
  assert.ok(html.includes("&lt;img"), "the escaped form is shown instead");
  assert.ok(!html.includes("‮") && !html.includes("⁦"), "bidi controls are neutralized");
});

// The approved check table: every known value maps to its tone.
const CHECK_TONES = {
  transactionBody: { unchanged: "ok", changed: "bad", reordered: "bad", unknown: "warn" },
  utxoDeclarations: { unchanged: "ok", changed: "bad", unknown: "warn" },
  signatures: { valid: "ok", invalid: "bad", unverified: "bad", removed_or_changed: "bad", none_added: "muted", unknown: "warn" },
  sighashPolicy: { full_commitment: "ok", weak: "bad", weak_as_requested: "warn", mismatch: "bad", undefined: "bad", none: "muted", unknown: "warn" },
  signerKeys: { match: "ok", unexpected: "bad", unknown: "bad", no_new_signatures: "muted" },
  metadata: { unchanged: "ok", additions: "warn", mutated: "bad", unknown: "warn" },
  nonceReuse: { none_found: "ok", reuse: "bad", cross_key: "bad", possible: "warn", incomplete: "warn", not_checked: "muted", unknown: "warn" },
  antiExfil: { verified: "ok", failed: "bad", not_available: "muted", unknown: "warn" },
  changeOutputs: { verified: "ok", not_from_wallet: "bad", unverified: "warn", none_presented: "muted", not_checked: "muted", unknown: "warn" },
};

test("every check value maps to its tone, and an unrecognized value never renders green", () => {
  for (const [key, values] of Object.entries(CHECK_TONES)) {
    for (const [value, tone] of Object.entries(values)) {
      const report = reportFor([]);
      report.checks[key] = value;
      const html = psbtSignerAuditHtml(report, null, null, "mainnet");
      assert.ok(html.includes(`data-audit-check="${key}" data-audit-tone="${tone}"`), `${key}.${value} must render tone ${tone}`);
    }
  }
  const report = reportFor([]);
  report.checks.transactionBody = "a_value_this_view_predates";
  const html = psbtSignerAuditHtml(report, null, null, "mainnet");
  assert.ok(html.includes('data-audit-check="transactionBody" data-audit-tone="warn"'));
  assert.ok(!html.includes('data-audit-check="transactionBody" data-audit-tone="ok"'));
});

test("an undecodable-document report renders the error finding, unknown checks, and no diff", () => {
  const report = {
    verdict: "fail",
    equal: false,
    checks: Object.fromEntries(Object.keys(CHECK_TONES).map((key) => [key, "unknown"])),
    findings: [findingFor("DOC_UNDECODABLE")],
    stats: null,
    diff: null,
  };
  const html = psbtSignerAuditHtml(report, null, null, "mainnet");
  assert.ok(html.includes('data-audit-verdict="fail"'));
  assert.ok(html.includes('data-audit-code="DOC_UNDECODABLE"'));
  assert.ok(html.includes('data-audit-check="transactionBody" data-audit-tone="warn"'));
  assert.ok(!html.includes("<details"), "no diff block without a diff");
});

test("the parse-error note escapes its message and carries no verdict", () => {
  const html = psbtSignerAuditErrorHtml(`not base64 <script>alert(1)</script>`);
  assert.ok(html.includes("data-audit-section"));
  assert.ok(!html.includes("data-audit-verdict"));
  assert.ok(html.includes("could not be read"));
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
});

test("psbtDiffHtml labels: the default output is byte-identical, custom labels rename the sides", () => {
  const { before, after, diff } = versionBumpDocs();
  const fallback = psbtDiffHtml(diff, before, after, "mainnet");
  assert.ok(fallback.includes("before = the PSBT in the editor · after = the pasted PSBT. Only differences are listed."));
  assert.equal(psbtDiffHtml(diff, before, after, "mainnet", {}), fallback);
  assert.equal(psbtDiffHtml(diff, before, after, "mainnet", { copyIcon: () => "" }), fallback);
  const labeled = psbtDiffHtml(diff, before, after, "mainnet", { beforeLabel: "the PSBT you sent", afterLabel: "the returned PSBT" });
  assert.ok(labeled.includes("before = the PSBT you sent · after = the returned PSBT. Only differences are listed."));
  assert.ok(!labeled.includes("the PSBT in the editor"));
});

test("the view renders the collapsed technical diff with the sent/returned labels", () => {
  const { before, after, diff } = versionBumpDocs();
  const html = psbtSignerAuditHtml(reportFor([], { diff, equal: false }), before, after, "mainnet");
  assert.ok(html.includes("<details"));
  assert.ok(html.includes("before = the PSBT you sent · after = the returned PSBT."));
  assert.ok(!html.includes("the PSBT in the editor"));
});
