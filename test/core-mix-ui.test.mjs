// Tests for the Key Station's Core wallet.dat + dice/cards method (issue #552).
// Run with: node --test test/core-mix-ui.test.mjs
//
// The wallet fixtures are the same Bitcoin Core v28.3.0 ground truth the
// core-mix suite uses; every expected hash is computed here with node:crypto,
// never with the module under test.
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { coreMixEntropy, coreMixSecrets, wipeCoreMixSecrets } from "../src/js/core-mix.js";
import { GENERATED_ROWS } from "./core-generated-fixture.mjs";
import { REF_WATCH_ONLY_RECORDS } from "./wallet-export-reference.mjs";
import { bytesToHex, hexToBytes, publicKeyForPrivate, read, sha256 } from "./wallet-export-harness.mjs";

const app = read("src/js/app.js");
const registry = read("test/secret-field-registry.test.mjs");

// The vm extraction pattern the core-importdescriptors suite uses.
const fnSource = (name) => {
  const match = app.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^}`, "m"));
  assert.ok(match, `${name} exists in app.js`);
  return match[0];
};

const fill = (text, params) => params ? text.replace(/\{(\w+)\}/g, (_, key) => String(params[key])) : text;

const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";
const REGTEST_APP_ID = 0xfabfb5da;
let walletModule = null;
const wallet = () => walletModule || (walletModule = new Function(
  `${read("src/js/sqlite-writer.js")}\n${read("src/js/sqlite-reader.js")}\n${read("src/js/wallet-export.js")}\n${read("src/js/core-wallet.js")}\nreturn { writer: hodlSqliteWriter, core: hodlCoreWallet };`)());
const walletBytes = (records) => wallet().writer.createDatabase({
  applicationId: REGTEST_APP_ID,
  tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows: records.map(([key, value]) => [hexToBytes(key), hexToBytes(value)]) }],
});

const mixDeps = { publicKeyForPrivate, sha256 };
const secretsFor = (records) => coreMixSecrets(wallet().core.parseWalletDat(walletBytes(records)), mixDeps);

function loadContext() {
  const elements = {
    "core-mix-error": { textContent: "" },
    "core-mix-summary": { hidden: true, textContent: "" },
  };
  const context = vm.createContext({
    hodlCoreMix: null,
    coreMixSecrets,
    wipeCoreMixSecrets,
    hodlCoreWallet: wallet().core,
    hodlSha256: sha256,
    hodlWalletDatDeps: () => ({ publicKeyForPrivate }),
    hodlTText: fill,
    document: { getElementById: (id) => elements[id] || null },
  });
  for (const name of ["hodlCoreMixReset", "hodlCoreMixShowError", "hodlCoreMixShowSummary", "hodlCoreMixLoadBytes"]) {
    vm.runInContext(fnSource(name), context);
  }
  return { context, elements };
}

function entropyContext({ loaded, source, transcript, dice, cards, split }) {
  const context = vm.createContext({
    hodlCoreMix: loaded,
    hodlCoreMixSource: source,
    hodlTargetWordCount: 24,
    hodlNote: fill,
    hodlSeedConfig: (words) => ({ words, bytes: 32, bits: 256, hashRolls: 99, partialWords: 23, candidates: 8 }),
    hodlDiceEntropy: dice || (() => ({ ok: true, bytes: new Uint8Array(32), sourceBits: 24, warnings: [] })),
    hodlSplitDiceString: split || ((value) => ({ rolls: [...String(value)].filter((character) => "123456".includes(character)) })),
    hodlCardsEntropy: cards || (() => ({ ok: true, hashInput: transcript, sourceBits: 11, warnings: [] })),
    hodlSha256: sha256,
    hodlHex: { encode: (bytes) => Buffer.from(bytes).toString("hex") },
    coreMixEntropy,
    document: { getElementById: (id) => id === "core-mix-transcript" ? { value: transcript } : null },
  });
  vm.runInContext(fnSource("hodlCoreMixSelectedEntropy"), context);
  return context;
}

const ENCRYPTED_ROWS = [
  ...GENERATED_ROWS,
  ["1a77616c6c657464657363726970746f72637279707465646b6579" + "00".repeat(32) + "21" + "02".repeat(33), "f0" + "01".repeat(48)],
];
const TAMPERED_ROWS = (() => {
  const rows = GENERATED_ROWS.map(([key, value]) => [key, value]);
  const record = rows.find(([key]) => key.startsWith("1377616c6c657464657363726970746f726b6579"));
  const value = hexToBytes(record[1]);
  value[1 + 8] ^= 0x01;
  record[1] = bytesToHex(value);
  return rows;
})();

test("a loaded wallet shows its name, key count and fingerprint, and the file bytes are zeroed", () => {
  const { context, elements } = loadContext();
  const bytes = walletBytes(GENERATED_ROWS);
  assert.equal(context.hodlCoreMixLoadBytes(bytes, "core.dat"), true);
  assert.ok(bytes.every((byte) => byte === 0), "the file bytes are zeroed");
  assert.equal(context.hodlCoreMix.name, "core.dat");
  assert.equal(context.hodlCoreMix.count, 1);
  assert.match(context.hodlCoreMix.fingerprint, /^[0-9a-f]{8}$/);
  assert.equal(elements["core-mix-summary"].hidden, false);
  assert.match(elements["core-mix-summary"].textContent, /core\.dat/);
  assert.match(elements["core-mix-summary"].textContent, /1 key/);
  assert.match(elements["core-mix-summary"].textContent, /fingerprint [0-9a-f]{8}/);
  assert.equal(elements["core-mix-error"].textContent, "");
  wipeCoreMixSecrets(context.hodlCoreMix.secrets);
});

test("an encrypted, watch-only or tampered wallet is refused without loading", () => {
  for (const [records, code] of [[ENCRYPTED_ROWS, /^encrypted:/], [REF_WATCH_ONLY_RECORDS, /^watch-only:/], [TAMPERED_ROWS, /^key-mismatch:/]]) {
    const { context, elements } = loadContext();
    const bytes = walletBytes(records);
    assert.equal(context.hodlCoreMixLoadBytes(bytes, "wallet.dat"), false);
    assert.equal(context.hodlCoreMix, null);
    assert.match(elements["core-mix-error"].textContent, code);
    assert.equal(elements["core-mix-summary"].hidden, true);
    assert.ok(bytes.every((byte) => byte === 0), "the file bytes are zeroed even on refusal");
  }
});

test("a file that is not a wallet is refused and zeroed", () => {
  const { context, elements } = loadContext();
  const bytes = new Uint8Array([1, 2, 3, 4]);
  assert.equal(context.hodlCoreMixLoadBytes(bytes, "bad.dat"), false);
  assert.equal(context.hodlCoreMix, null);
  assert.ok(elements["core-mix-error"].textContent.length > 0);
  assert.ok(bytes.every((byte) => byte === 0));
});

test("loading a new file wipes the previous wallet's secrets", () => {
  const { context } = loadContext();
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "first.dat"), true);
  const previous = context.hodlCoreMix.secrets;
  assert.ok(previous.every((secret) => secret.some((byte) => byte !== 0)));
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "second.dat"), true);
  for (const secret of previous) assert.ok(secret.every((byte) => byte === 0), "the old secrets are zeroed");
  wipeCoreMixSecrets(context.hodlCoreMix.secrets);
});

test("the reset zeroes every secret and drops the holder", () => {
  const { context } = loadContext();
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "wallet.dat"), true);
  const secrets = context.hodlCoreMix.secrets;
  context.hodlCoreMixReset();
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
});

test("the active key's wipe drops the wallet secrets", () => {
  const context = vm.createContext({
    hodlActiveKey: -1,
    hodlKeys: [],
    hodlCoreMix: { name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets: [new Uint8Array(32).fill(7)] },
    wipeCoreMixSecrets,
    hodlInvalidateDerivation: () => {},
    hodlLastWordCache: { clear: () => {} },
  });
  vm.runInContext(fnSource("hodlCoreMixReset"), context);
  vm.runInContext(fnSource("hodlWipeActiveKey"), context);
  const secrets = context.hodlCoreMix.secrets;
  context.hodlWipeActiveKey();
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
});

test("switching to another method drops the wallet secrets", () => {
  const context = vm.createContext({
    hodlActiveKey: -1,
    hodlKeys: [],
    hodlCoreMix: { name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets: [new Uint8Array(32).fill(7)] },
    wipeCoreMixSecrets,
    hodlCaptureKey: () => {},
    hodlNormalizeSeedMethod: () => "words",
    hodlNormalizeEntropyFormat: () => "bin",
    hodlSyncKeyModeSelect: () => {},
    hodlRenderKeyForm: () => {},
    hodlRestoreFormFields: () => {},
    hodlUpdateSeedLengthControl: () => {},
    hodlUpdateDerivationPathPreview: () => {},
    hodlQueueSegmentedControlSync: () => {},
  });
  vm.runInContext(fnSource("hodlCoreMixReset"), context);
  vm.runInContext(fnSource("hodlSetMode"), context);
  const secrets = context.hodlCoreMix.secrets;
  context.hodlSetMode("dice");
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
});

test("switching to the core wallet method keeps the loaded wallet", () => {
  const context = vm.createContext({
    hodlActiveKey: -1,
    hodlKeys: [],
    hodlCoreMix: { name: "wallet.dat", count: 1, fingerprint: "aabbccdd", secrets: [new Uint8Array(32).fill(7)] },
    wipeCoreMixSecrets,
    hodlCaptureKey: () => {},
    hodlNormalizeSeedMethod: () => "words",
    hodlNormalizeEntropyFormat: () => "bin",
    hodlSyncKeyModeSelect: () => {},
    hodlRenderKeyForm: () => {},
    hodlRestoreFormFields: () => {},
    hodlUpdateSeedLengthControl: () => {},
    hodlUpdateDerivationPathPreview: () => {},
    hodlQueueSegmentedControlSync: () => {},
  });
  vm.runInContext(fnSource("hodlCoreMixReset"), context);
  vm.runInContext(fnSource("hodlSetMode"), context);
  context.hodlSetMode("corewallet");
  assert.notEqual(context.hodlCoreMix, null);
  wipeCoreMixSecrets(context.hodlCoreMix.secrets);
});

test("the session-end sweep drops the wallet secrets and clears the transcript field", () => {
  const sweep = fnSource("hodlInitSecretFieldAutoClear");
  assert.match(sweep, /hodlCoreMixReset\(\)/, "the sweep must call the core-mix reset");
  assert.match(sweep, /"core-mix-transcript"/, "the sweep must clear the transcript field");
  // The reset it calls is the one proven above to zero every secret.
  const { context } = loadContext();
  assert.equal(context.hodlCoreMixLoadBytes(walletBytes(GENERATED_ROWS), "wallet.dat"), true);
  const secrets = context.hodlCoreMix.secrets;
  context.hodlCoreMixReset();
  assert.equal(context.hodlCoreMix, null);
  for (const secret of secrets) assert.ok(secret.every((byte) => byte === 0));
});

test("dice: the mixed entropy is coreMixEntropy over the COLDCARD transcript", () => {
  const { secrets, count, fingerprint } = secretsFor(GENERATED_ROWS);
  const loaded = { name: "wallet.dat", count, fingerprint, secrets };
  const context = entropyContext({ loaded, source: "dice", transcript: "4 1 5 2 6 3" });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, true);
  const expected = coreMixEntropy(secrets, "415263", 32, { sha256 });
  assert.deepEqual([...result.bytes], [...expected]);
  assert.equal(result.hex, Buffer.from(expected).toString("hex"));
  assert.equal(result.bits, 256);
  assert.equal(result.method, "core-wallet-mix-v1");
  assert.equal(result.notes.length, 1);
  assert.match(result.notes[0], /wallet's 1 spend secrets and the dice transcript/);
  const plain = sha256(new TextEncoder().encode("415263")).slice(0, 32);
  assert.notDeepEqual([...result.bytes], [...plain], "not the plain dice method's bytes");
  wipeCoreMixSecrets(secrets);
});

test("cards: the mixed entropy is coreMixEntropy over the card hashInput", () => {
  const { secrets, count, fingerprint } = secretsFor(GENERATED_ROWS);
  const loaded = { name: "wallet.dat", count, fingerprint, secrets };
  const hashInput = "AS 2C TD";
  const context = entropyContext({ loaded, source: "cards", transcript: "AS 2C TD", cards: () => ({ ok: true, hashInput, sourceBits: 33, warnings: [] }) });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, true);
  assert.deepEqual([...result.bytes], [...coreMixEntropy(secrets, hashInput, 32, { sha256 })]);
  assert.equal(result.sourceBits, 33);
  wipeCoreMixSecrets(secrets);
});

test("no wallet loaded is refused before any transcript is read", () => {
  const context = entropyContext({ loaded: null, source: "dice", transcript: "415263" });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, false);
  assert.match(result.error, /Choose a Bitcoin Core wallet\.dat first\./);
});

test("an invalid transcript returns the dice or card failure unchanged", () => {
  const { secrets, count, fingerprint } = secretsFor(GENERATED_ROWS);
  const loaded = { name: "wallet.dat", count, fingerprint, secrets };
  const diceFailure = { ok: false, error: "Enter at least one dice roll (faces 1–6)." };
  assert.equal(entropyContext({ loaded, source: "dice", transcript: "", dice: () => diceFailure }).hodlCoreMixSelectedEntropy(24), diceFailure);
  const cardsFailure = { ok: false, error: "Deal at least one card from a shuffled deck." };
  assert.equal(entropyContext({ loaded, source: "cards", transcript: "", cards: () => cardsFailure }).hodlCoreMixSelectedEntropy(24), cardsFailure);
  wipeCoreMixSecrets(secrets);
});

test("an empty transcript is refused by the mixer, not hashed", () => {
  const { secrets, count, fingerprint } = secretsFor(GENERATED_ROWS);
  const loaded = { name: "wallet.dat", count, fingerprint, secrets };
  const context = entropyContext({ loaded, source: "dice", transcript: " ", split: () => ({ rolls: [] }) });
  const result = context.hodlCoreMixSelectedEntropy(24);
  assert.equal(result.ok, false);
  assert.match(result.error, /empty-transcript/);
  wipeCoreMixSecrets(secrets);
});

test("the preview gate pushes corewallet before the picker is built", () => {
  const gate = app.indexOf('if (typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__) hodlKeyModes.push("corewallet");');
  const picker = app.indexOf('var hodlKeyModeSelectEl = document.createElement("select");');
  assert.ok(gate >= 0, "the preview gate exists");
  assert.ok(picker >= 0, "the picker is built");
  assert.ok(gate < picker, "the gate runs before the picker");
  assert.doesNotMatch(app, /^\s*hodlKeyModes\.push\("corewallet"\);/m, "no unconditional push");
});

test("the method has a label and a summary sub-method label", () => {
  const labels = read("src/js/i18n-labels.js");
  assert.match(labels, /corewallet: "Core wallet\.dat \+ dice\/cards"/);
  assert.match(labels, /corewallet: Object\.freeze\(\{ dice: "Dice rolls \(D6\)", cards: "Cards" \}\)/);
});

test("the registry lists the core-mix transcript", () => {
  assert.match(registry, /"core-mix-transcript"/);
});

// The vm harness supplies the mixer functions itself, so it cannot notice a
// missing import; the page would throw on the first wallet.dat.
test("app.js imports the mixer and the size cap it calls", () => {
  assert.match(app, /^import \{ coreMixEntropy, coreMixSecrets, wipeCoreMixSecrets \} from "\.\/core-mix\.js";$/m);
  assert.match(app, /^import \{ CORE_WALLET_MAX_BYTES, initCoreWallet \} from "\.\/core-wallet-ui\.js";$/m);
});

test("a wallet.dat read that finishes after a method switch is zeroed, not loaded", () => {
  const load = app.slice(app.indexOf("file.onchange = () => {"), app.indexOf("sourceSelect.onchange"));
  assert.match(load, /let bytes = new Uint8Array\(await chosen\.arrayBuffer\(\)\);\s*(?:\/\/[^\n]*\n\s*)*if \(hodlKeyMode !== "corewallet"\) \{\s*bytes\.fill\(0\);\s*return;\s*\}\s*hodlCoreMixLoadBytes\(bytes, chosen\.name\);/);
});
