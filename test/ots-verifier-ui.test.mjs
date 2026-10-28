// OpenTimestamps verifier UI tests — issue #315, phase 3.
//
// DOM-free tests for the pure helpers in src/js/ots-verifier-ui.js.
// The DOM-wiring `initOtsVerifier()` is exercised manually (browser) and
// isn't unit-tested here — the repo's test suite is Node-based without
// jsdom, so this matches the established convention (see other tool
// modules that similarly don't unit-test their DOM wiring).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parseHexInput,
  formatResult,
  formatError,
  pathSummaryHtml,
  pathSummaryListHtml,
} from "../src/js/ots-verifier-ui.js";
import { OtsParseError, OtsBudgetError } from "../src/js/ots-parser.js";

// ---- parseHexInput --------------------------------------------------------

test("parseHexInput: plain hex", () => {
  const u = parseHexInput("deadbeef");
  assert.equal(u.length, 4);
  assert.deepEqual(Array.from(u), [0xde, 0xad, 0xbe, 0xef]);
});

test("parseHexInput: leading 0x prefix is stripped", () => {
  const u = parseHexInput("0xdeadbeef");
  assert.equal(u.length, 4);
  assert.equal(u[0], 0xde);
});

test("parseHexInput: uppercase is normalized", () => {
  const a = parseHexInput("DEADBEEF");
  const b = parseHexInput("deadbeef");
  assert.deepEqual(Array.from(a), Array.from(b));
});

test("parseHexInput: whitespace and commas stripped", () => {
  const u = parseHexInput("de ad  be\nef,12, 34");
  assert.deepEqual(Array.from(u), [0xde, 0xad, 0xbe, 0xef, 0x12, 0x34]);
});

test("parseHexInput: empty / whitespace-only input throws RangeError", () => {
  assert.throws(() => parseHexInput(""), RangeError);
  assert.throws(() => parseHexInput("   "), RangeError);
});

test("parseHexInput: odd length throws RangeError", () => {
  assert.throws(() => parseHexInput("abc"), RangeError);
});

test("parseHexInput: non-hex characters throw", () => {
  assert.throws(() => parseHexInput("nothex"), (e) => /non-hex/i.test(e.message));
});

test("parseHexInput: non-string input throws TypeError", () => {
  assert.throws(() => parseHexInput(123), TypeError);
  assert.throws(() => parseHexInput(undefined), TypeError);
  assert.throws(() => parseHexInput(null), TypeError);
});

// ---- formatResult ---------------------------------------------------------

test("formatResult: MATCHES includes the issue-required 'Header supplied by user' warning", () => {
  const r = formatResult({ result: "MATCHES_SUPPLIED_HEADER", paths: [], summary: { matches: 1 } });
  assert.equal(r.tone, "success");
  assert.match(r.headline, /MATCHES/);
  assert.match(r.body, /Header supplied by user/);
  assert.match(r.body, /not verified/);
});

test("formatResult: PENDING says no completed Bitcoin attestation was checked", () => {
  const r = formatResult({ result: "PENDING", paths: [], summary: { pending: 1 } });
  assert.equal(r.tone, "warning");
  assert.match(r.body, /No completed Bitcoin attestation was checked/);
  assert.match(r.body, /does not establish Bitcoin anchoring/);
});

test("formatResult: HEADER_REQUIRED asks for a block header", () => {
  const r = formatResult({ result: "HEADER_REQUIRED", paths: [], summary: {} });
  assert.equal(r.tone, "warning");
  assert.match(r.body, /Supply the block header/);
});

test("formatResult: INCOMPLETE says the proof exceeds resource limits and is not a verdict", () => {
  const r = formatResult({ result: "INCOMPLETE", reason: "too-many-ops", paths: [], summary: {} });
  assert.equal(r.tone, "warning");
  assert.match(r.body, /resource limits/);
  assert.match(r.body, /not a verdict about the proof/);
});

test("formatResult: INVALID by reason names the specific failure", () => {
  const cases = [
    ["parse:BAD_MAGIC", /not a valid OpenTimestamps proof file/],
    ["expected-digest", /does not match the expected digest/],
    ["original-file", /does not hash to the proof's file digest/],
    ["op-too-long", /4096-byte limit/],
    ["header-mismatch", /matches the supplied header/],
  ];
  for (const [reason, re] of cases) {
    const r = formatResult({ result: "INVALID", reason, paths: [], summary: {} });
    assert.equal(r.tone, "danger");
    assert.match(r.body, re, `reason ${reason}`);
  }
});

test("formatResult: INVALID tones danger and explains inconsistency", () => {
  const r = formatResult({ result: "INVALID", paths: [], summary: {} });
  assert.equal(r.tone, "danger");
  assert.match(r.body, /cryptographic inconsistency/i);
});

test("formatResult: UNSUPPORTED notes v1 scope and lists unsupported op types", () => {
  const r = formatResult({ result: "UNSUPPORTED", paths: [], summary: {} });
  assert.equal(r.tone, "neutral");
  assert.match(r.body, /v1/);
  assert.match(r.body, /keccak256/);
});

test("formatResult: unknown result returns neutral tone with the literal value", () => {
  const r = formatResult({ result: "WEIRD_NEW_STATE", paths: [], summary: {} });
  assert.equal(r.tone, "neutral");
  assert.equal(r.headline, "WEIRD_NEW_STATE");
});

// ---- formatError ----------------------------------------------------------

test("formatError: OtsParseError with code yields headline with the code", () => {
  const err = new OtsParseError("BAD_MAGIC", "wrong magic");
  const r = formatError(err);
  assert.equal(r.tone, "danger");
  assert.match(r.headline, /BAD_MAGIC/);
  assert.equal(r.body, err.message);
});

test("formatError: OtsBudgetError surfaces the resource-limit code", () => {
  const err = new OtsBudgetError("too-many-ops", "more than 1024 op nodes");
  const r = formatError(err);
  assert.equal(r.tone, "danger");
  assert.match(r.headline, /too-many-ops/);
  assert.equal(r.body, err.message);
});

test("formatError: RangeError surfaces the length-error headline", () => {
  const r = formatError(new RangeError("too short"));
  assert.equal(r.tone, "danger");
  assert.match(r.headline, /length/i);
  assert.match(r.body, /too short/);
});

test("formatError: TypeError surfaces the type-error headline", () => {
  const r = formatError(new TypeError("expected a string"));
  assert.equal(r.tone, "danger");
  assert.match(r.headline, /type/i);
  assert.match(r.body, /expected a string/);
});

test("formatError: unknown values fall back to String(err)", () => {
  const r = formatError("oops");
  assert.equal(r.tone, "danger");
  assert.match(r.body, /oops/);
});

// ---- pathSummaryHtml ------------------------------------------------------

test("pathSummaryHtml: outcome CSS class and op chain", () => {
  const html = pathSummaryHtml({ outcome: "matches", opNames: ["sha256", "append"] });
  assert.match(html, /ots-outcome-matches/);
  assert.match(html, /sha256 → append/);
});

test("pathSummaryHtml: attestation URI prefix and digest preview", () => {
  const html = pathSummaryHtml({
    outcome: "matches",
    opNames: ["sha256"],
    attestation: { type: "bitcoin", uriHex: "0588960d73d71901" },
    finalDigest: new Uint8Array(32).fill(0xab),
  });
  assert.match(html, /ots-att[^>]*>bitcoin/);
  assert.match(html, /URI 0588960d73d71901/);
  // first 16 hex chars + ellipsis (truncated preview of the 64-char digest)
  assert.match(html, /abababababababab…/);
});

test("pathSummaryHtml: HTML-escapes unsafe content", () => {
  const html = pathSummaryHtml({ outcome: "<script>alert(1)</script>", opNames: ["a&b"] });
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /a&amp;b/);
});

test("pathSummaryHtml: message-too-long path shows length/limit bytes", () => {
  const html = pathSummaryHtml({
    outcome: "message-too-long",
    opNames: ["sha256"],
    length: 5000,
    limit: 4096,
  });
  assert.match(html, /5000\/4096 bytes/);
});

test("pathSummaryHtml: empty opNames shows literal '(no ops)'", () => {
  const html = pathSummaryHtml({ outcome: "pending" });
  assert.match(html, /\(no ops\)/);
});

// ---- pathSummaryListHtml --------------------------------------------------

test("pathSummaryListHtml: empty / null / undefined input → muted message", () => {
  assert.match(pathSummaryListHtml([]), /No attestation paths/);
  assert.match(pathSummaryListHtml(null), /No attestation paths/);
  assert.match(pathSummaryListHtml(undefined), /No attestation paths/);
});

test("pathSummaryListHtml: multiple rows joined, one per path", () => {
  const html = pathSummaryListHtml([
    { outcome: "matches", opNames: ["sha256"] },
    { outcome: "pending", opNames: [] },
    { outcome: "unsupported-op", opNames: ["keccak256"], detail: "k256" },
  ]);
  const rowCount = (html.match(/ots-path-row/g) || []).length;
  assert.ok(rowCount >= 3, `expected at least 3 path rows, got ${rowCount}`);
  assert.match(html, /ots-outcome-matches/);
  assert.match(html, /ots-outcome-pending/);
  assert.match(html, /ots-outcome-unsupported-op/);
});
