import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { psbtSignerAuditHtml } from "../src/js/psbt-signer-audit-view.js";

const appSource = readFileSync(fileURLToPath(new URL("../src/js/app.js", import.meta.url)), "utf8");

// Extract a top-level function declaration from app.js, skipping strings and
// comments so a brace inside a message is not counted.
function extractFunction(source, name) {
  const marker = "function " + name + "(";
  const start = source.indexOf(marker);
  if (start === -1) throw new Error("function not found: " + name);
  let depth = 0;
  let mode = null;
  for (let i = source.indexOf("{", start); i < source.length; i++) {
    const c = source[i];
    const next = source[i + 1];
    if (mode === "//") { if (c === "\n") mode = null; continue; }
    if (mode === "/*") { if (c === "*" && next === "/") { mode = null; i++; } continue; }
    if (mode === "'" || mode === '"' || mode === "`") {
      if (c === "\\") { i++; continue; }
      if (c === mode) mode = null;
      continue;
    }
    if (c === "/" && next === "/") { mode = "//"; i++; continue; }
    if (c === "/" && next === "*") { mode = "/*"; i++; continue; }
    if (c === "'" || c === '"' || c === "`") { mode = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return source.slice(start, i + 1); }
  }
  throw new Error("unbalanced braces: " + name);
}

// app.js closes over the page's translator and coders; the tests supply the
// same shapes so one function can be evaluated on its own.
const interpolate = (text, vars = {}) => String(text).replace(/\{(\w+)\}/g, (match, key) => (Object.hasOwn(vars, key) ? String(vars[key]) : match));
const escapeHtml = (text) => String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const hexOf = (bytes) => Buffer.from(bytes).toString("hex");
const sats = (value) => (Number(value) / 1e8).toFixed(8);

function evaluate(name, scope) {
  const factory = new Function("scope", "with (scope) { return " + extractFunction(appSource, name) + "; }");
  return factory(scope);
}

const analysisSummary = evaluate("hodlPsbtAnalysisSummary", { hodlT: interpolate, hodlTAttr: (text) => String(text), hodlEscapeHtml: escapeHtml });

// A fake element with the DOM surface the extracted functions touch. The
// tests never assert on classes or copy; they read data-* attributes and the
// markup the functions build.
function fakeElement(overrides = {}) {
  const element = {
    open: false,
    innerHTML: "",
    textContent: "",
    value: "",
    id: "",
    hidden: false,
    dataset: {},
    attributes: new Map(),
    inserted: [],
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    style: {},
    hasAttribute(name) { return this.attributes.has(name); },
    getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; },
    setAttribute(name, value) { this.attributes.set(name, String(value)); },
    removeAttribute(name) { this.attributes.delete(name); },
    insertAdjacentHTML(position, html) { this.inserted.push({ position, html }); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    closest() { return null; },
    matches() { return false; },
    contains() { return false; },
    focus() {},
    blur() {},
    scrollIntoView() {},
    remove() {},
    appendChild() {},
    replaceWith() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return true; },
    getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; },
  };
  return Object.assign(element, overrides);
}

// ---- analysis rows -------------------------------------------------------

test("a completed analysis row keeps its detail in one collapsed block", () => {
  const html = analysisSummary([
    { label: "Previous outputs and fee", state: "complete", detail: "Amounts came from PSBT claims." },
    { label: "SIGHASH policy", state: "problem", detail: "A malformed policy was found." },
    { label: "Output ownership / derivation", state: "incomplete", detail: "No session key was loaded." },
  ]);
  const completeRow = html.match(/<li data-psbt-check-state='complete'>.*?<\/li>/)[0];
  assert.ok(!completeRow.includes("Amounts came from PSBT claims."), "a completed row must not carry its detail inline");
  const block = html.match(/<details class='derivation-advanced' data-psbt-analysis-details>.*?<\/details>/s)[0];
  assert.ok(block.includes("Amounts came from PSBT claims."), "the completed detail must live in the collapsed block");
  const problemRow = html.match(/<li data-psbt-check-state='problem'>.*?<\/li>/)[0];
  assert.ok(problemRow.includes("A malformed policy was found."), "a problem row keeps its detail inline");
  const incompleteRow = html.match(/<li data-psbt-check-state='incomplete'>.*?<\/li>/)[0];
  assert.ok(incompleteRow.includes("No session key was loaded."), "an incomplete row keeps its detail inline");
});

// ---- the PSBT render -----------------------------------------------------

const scriptA = new Uint8Array([0x00, 0x14, ...new Array(20).fill(0x11)]);
const scriptB = new Uint8Array([0x00, 0x14, ...new Array(20).fill(0x22)]);

function psbtFixture({ outputs = [{ amount: 50000n, script: scriptA }], inputs = 1 } = {}) {
  return {
    tx: {
      version: 2,
      locktime: 0,
      inputs: Array.from({ length: inputs }, (_, index) => ({ txid: new Uint8Array(32).fill(index + 1), vout: index })),
      outputs,
    },
    inputs: Array.from({ length: inputs }, () => []),
    outputs: outputs.map(() => []),
  };
}

// Every helper hodlRenderPsbt closes over is stubbed here, so an expected
// value is never computed by the code under test.
function renderScope(overrides = {}) {
  return {
    PSBT_RENDER_LIMIT: 500,
    document: { getElementById: () => null },
    hodlT: interpolate,
    hodlTText: interpolate,
    hodlTAttr: (text) => String(text),
    hodlEscapeHtml: escapeHtml,
    hodlHex: { encode: hexOf },
    hodlHexRev: hexOf,
    hodlEq: (a, b) => Buffer.from(a).equals(Buffer.from(b)),
    hodlSats: sats,
    hodlInspectorNetwork: () => "mainnet",
    hodlSessionOwnership: () => new Map(),
    hodlRenderOutputHtml: (output, index) => "<p class='psbt-kv'>output " + index + "</p>",
    hodlOwnershipWarning: () => "",
    hodlWitUtxo: () => null,
    hodlNonWitUtxo: () => null,
    hodlSighashPolicy: () => null,
    hodlSighashLabel: () => "SIGHASH_ALL",
    hodlPartialSigs: () => [],
    hodlTapSigsParsed: () => [],
    hodlFinalized: () => false,
    hodlAddr: () => "bc1qexample",
    hodlPublicInlineHtml: (text) => escapeHtml(text),
    hodlFind: () => [],
    hodlCompareNonces: () => ({ reused: [], possible: [], crossKey: [] }),
    hodlCompareSchnorrNonces: () => ({ reused: [], incomplete: false }),
    hodlPsbtNonceCheck: () => ({ label: "Nonce analysis", state: "complete", detail: "nonce detail" }),
    hodlPsbtReferenceVerdict: () => ({ state: "complete", problems: [], unlisted: 0 }),
    inspectPsbtInscriptions: () => ({ inputs: [], envelopes: [] }),
    cappedHtml: (items, render) => items.map(render).join(""),
    isP2tr: () => false,
    hodlPsbtAnalysisSummary: analysisSummary,
    ...overrides,
  };
}

function renderPsbt(psbt, options = {}, overrides = {}) {
  const render = evaluate("hodlRenderPsbt", renderScope(overrides));
  return render(psbt, new Uint8Array(), "2024-01-01T00:00:00.000Z", "inspect", options);
}

const glanceOf = (html) => html.match(/<p class='psbt-kv' data-psbt-glance>(.*?)<\/p>/)[1];

test("the glance line states the total, the output count and the fee", () => {
  const html = renderPsbt(psbtFixture({ outputs: [{ amount: 30000n, script: scriptA }, { amount: 20000n, script: scriptB }] }), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) });
  const glance = glanceOf(html);
  assert.ok(glance.includes("0.00050000"), "the total is the sum of the outputs");
  assert.ok(glance.includes("2 outputs"), "the count is the number of outputs");
  assert.ok(glance.includes("10000"), "the fee is the one the fees section computed");
});

test("the glance line uses the singular for one output", () => {
  const glance = glanceOf(renderPsbt(psbtFixture(), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) }));
  assert.ok(/\b1 output\b/.test(glance));
  assert.ok(!/\b1 outputs\b/.test(glance));
});

test("the glance line says the fee is unknown when it cannot be computed", () => {
  const glance = glanceOf(renderPsbt(psbtFixture()));
  assert.ok(glance.includes("fee unknown"));
  assert.ok(!glance.includes("sats"), "no fee figure is stated when the fee is unknown");
});

test("the glance line names change only when the ownership map claims an output", () => {
  const outputs = [{ amount: 30000n, script: scriptA }, { amount: 20000n, script: scriptB }];
  const owned = glanceOf(renderPsbt(psbtFixture({ outputs }), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }), hodlSessionOwnership: () => new Map([[hexOf(scriptA), {}]]) }));
  assert.ok(owned.includes("0.00030000"), "the change amount is the sum of the outputs the map claims");
  const unowned = glanceOf(renderPsbt(psbtFixture({ outputs }), {}, { hodlWitUtxo: () => ({ amount: 60000n, script: scriptA }) }));
  assert.ok(!unowned.includes("0.00030000"), "no change part without an ownership map");
});

test("the inputs section is collapsed when no input has a problem", () => {
  const html = renderPsbt(psbtFixture());
  const tag = html.match(/<details class='derivation-advanced' data-psbt-inputs[^>]*>/)[0];
  assert.ok(!/\bopen\b/.test(tag));
  assert.ok(!tag.includes("data-has-problem"));
});

test("the inputs section is open and marked when an input has a warning", () => {
  const html = renderPsbt(psbtFixture(), {}, { hodlSighashPolicy: () => { throw new Error("malformed sighash policy"); } });
  const tag = html.match(/<details class='derivation-advanced' data-psbt-inputs[^>]*>/)[0];
  assert.ok(/\bopen\b/.test(tag));
  assert.ok(tag.includes("data-has-problem"));
});

test("Show more renders inside the collapsed inputs block", () => {
  const html = renderPsbt(psbtFixture({ inputs: 3 }), { limits: { inputs: 1, outputs: 5, step: 1, format: String } });
  const open = html.indexOf("<details class='derivation-advanced' data-psbt-inputs");
  const close = html.indexOf("</details>", open);
  const button = html.indexOf("data-psbt-more='inputs'");
  assert.ok(open >= 0 && close > open);
  assert.ok(button > open && button < close, "the Show more button sits inside the inputs block");
});

test("Show more still renders a chunk and a tail for the inputs", () => {
  // The window must reach past `from`, as Show more's own repaint passes it
  // (see psbt-viz.test.mjs: limits.inputs above only.from).
  const part = renderPsbt(psbtFixture({ inputs: 3 }), { limits: { inputs: 2, outputs: 5, step: 1, format: String }, only: { kind: "inputs", from: 1 } });
  assert.equal(typeof part, "object");
  assert.ok(part.chunk.length > 0, "the new input section is rendered");
  assert.ok(!part.chunk.includes("data-psbt-inputs"), "the chunk joins the existing block, it does not open a second one");
  assert.ok(part.tail.includes("data-psbt-more='inputs'"), "the tail still carries the button");
});

// ---- Show more against a fake DOM ---------------------------------------

function showMoreHarness(render) {
  const tail = fakeElement();
  const generic = fakeElement();
  let details = fakeElement();
  let html = "";
  const output = fakeElement({
    querySelector(selector) {
      if (selector === "[data-psbt-inputs]") return details;
      if (selector === "[data-psbt-tail='inputs']") return tail;
      if (selector === "[data-psbt-tail='outputs']") return null;
      return generic;
    },
  });
  Object.defineProperty(output, "innerHTML", {
    get: () => html,
    set: (value) => { html = value; details = fakeElement(); },
  });
  const last = { kind: "psbt", parsed: {}, sourceTag: new Uint8Array(), checkedAt: "", network: "mainnet", limits: { inputs: 1, outputs: 1, step: 1 }, audit: null };
  const button = { dataset: { psbtMore: "inputs" } };
  const event = { target: { closest: (selector) => (selector === "[data-psbt-more]" ? button : null) } };
  const scope = {
    hodlPsbtLast: last,
    document: { getElementById: (id) => (id === "psbt-out" ? output : null) },
    hodlRenderPsbt: render,
    hodlRenderRawTx: render,
    hodlPsbtSignerAuditMarkup: () => "",
    hodlPsbtInsertOverall: () => {},
    hodlT: interpolate,
    hodlTText: interpolate,
    hodlTAttr: (text) => String(text),
    hodlEscapeHtml: escapeHtml,
  };
  return { scope, output, tail, event, last, get details() { return details; } };
}

test("Show more keeps the inputs block open across a repaint", () => {
  const harness = showMoreHarness(() => "<p>repainted</p>");
  harness.details.open = true;
  const showMore = evaluate("hodlPsbtShowMore", harness.scope);
  showMore(harness.event);
  assert.equal(harness.details.open, true, "the repaint must reopen the block the user had open");
});

test("Show more opens the inputs block when the new chunk carries a warning", () => {
  const harness = showMoreHarness(() => ({ chunk: "<p class='psbt-warn'>warning</p>", tail: "" }));
  const showMore = evaluate("hodlPsbtShowMore", harness.scope);
  showMore(harness.event);
  assert.equal(harness.details.open, true);
  assert.equal(harness.details.hasAttribute("data-has-problem"), true);
});

// ---- the signer audit ----------------------------------------------------

const passChecks = {
  transactionBody: "unchanged",
  utxoDeclarations: "unchanged",
  signatures: "none_added",
  sighashPolicy: "none",
  signerKeys: "no_new_signatures",
  metadata: "unchanged",
  nonceReuse: "not_checked",
  antiExfil: "not_available",
  changeOutputs: "not_checked",
};

test("the audit checks block is closed when the tier is pass", () => {
  const html = psbtSignerAuditHtml({ verdict: "pass", checks: passChecks, findings: [], stats: { newSignatures: 0 } }, null, null, "mainnet");
  const tag = html.match(/<details class="derivation-advanced" data-audit-checks[^>]*>/)[0];
  assert.ok(!/\bopen\b/.test(tag));
  assert.ok(!tag.includes("data-has-problem"));
});

test("the audit checks block is open when the tier is not pass", () => {
  const failed = psbtSignerAuditHtml({ verdict: "fail", checks: passChecks, findings: [], stats: { newSignatures: 0 } }, null, null, "mainnet");
  const failedTag = failed.match(/<details class="derivation-advanced" data-audit-checks[^>]*>/)[0];
  assert.ok(/\bopen\b/.test(failedTag));
  assert.ok(failedTag.includes("data-has-problem"));
  const warned = psbtSignerAuditHtml({ verdict: "pass", checks: passChecks, findings: [{ code: "METADATA_ADDED", severity: "warning", evidence: {} }], stats: { newSignatures: 0 } }, null, null, "mainnet");
  const warnedTag = warned.match(/<details class="derivation-advanced" data-audit-checks[^>]*>/)[0];
  assert.ok(/\bopen\b/.test(warnedTag));
  assert.ok(warnedTag.includes("data-has-problem"));
});

// ---- the overall line ----------------------------------------------------

const insertOverall = evaluate("hodlPsbtInsertOverall", { hodlT: interpolate });

function overallHarness({ tier, analysis }) {
  const section = fakeElement({ dataset: tier ? { auditTier: tier } : {} });
  const analysisElement = analysis ? { dataset: { psbtAnalysisOverall: analysis } } : null;
  const output = fakeElement({
    querySelector(selector) {
      if (selector === "[data-audit-section]") return section;
      if (selector === "[data-psbt-analysis-overall]") return analysisElement;
      return null;
    },
  });
  return { output, section };
}

const overallState = (options) => {
  const { output, section } = overallHarness(options);
  insertOverall(output);
  if (!section.inserted.length) return null;
  assert.equal(section.inserted[0].position, "beforebegin");
  return section.inserted[0].html.match(/data-psbt-overall-state='(\w+)'/)[1];
};

test("the overall line is red when the audit fails", () => {
  assert.equal(overallState({ tier: "fail", analysis: "complete" }), "bad");
  assert.equal(overallState({ tier: "pass", analysis: "problem" }), "bad");
});

test("the overall line is green only when the audit passes and the analysis is complete", () => {
  assert.equal(overallState({ tier: "pass", analysis: "complete" }), "ok");
});

test("the overall line is amber otherwise", () => {
  assert.equal(overallState({ tier: "pass-warnings", analysis: "complete" }), "warn");
  assert.equal(overallState({ tier: "pass", analysis: "incomplete" }), "warn");
});

test("no overall line without an audit", () => {
  assert.equal(overallState({ tier: undefined, analysis: "complete" }), null);
});
