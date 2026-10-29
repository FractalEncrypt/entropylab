// Secure entry P1b wiring: the session switch, its lifecycle hooks and the
// global-sync guards. The module itself is tested in secure-entry.test.mjs;
// this file pins the app-side plumbing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { createSecureSession, seedEntry, seedSet, keyEntry, sessionSet, sessionDeleteKey, sessionWipe, sessionGet } from "../src/js/secure-entry.js";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

// app.js binds the secure-entry helpers in one import statement, and the slice
// harness emits that whole statement as soon as any one of its names is
// reached. Stub every name it binds, or the emitted import collides with the
// stub declaration of the same name.
const secureEntryStubs = {
  createSecureSession: () => ({ marker: "fresh" }),
  sessionWipe: () => {},
  sessionDeleteKey: () => {},
  hodlSecureSupported: {},
};

test("hodlSecureEntryAvailable is false without preview or a supported method", async () => {
  const off = await loadAppFunctions(["hodlSecureEntryAvailable"], {
    stubs: { ...secureEntryStubs, PREVIEW: false, hodlSecureSupported: { seed: false, key: false } },
  });
  assert.equal(off.hodlSecureEntryAvailable(), false);

  const noMethods = await loadAppFunctions(["hodlSecureEntryAvailable"], {
    stubs: { ...secureEntryStubs, PREVIEW: true, hodlSecureSupported: { seed: false, key: false } },
  });
  assert.equal(noMethods.hodlSecureEntryAvailable(), false);

  const oneMethod = await loadAppFunctions(["hodlSecureEntryAvailable"], {
    stubs: { ...secureEntryStubs, PREVIEW: true, hodlSecureSupported: { seed: true, key: false } },
  });
  assert.equal(oneMethod.hodlSecureEntryAvailable(), true);
});

test("hodlSecureEntryEnd turns the switch off and wipes the session", async () => {
  const wiped = [];
  const session = { marker: "session" };
  let hashedCalls = 0;
  const mod = await loadAppFunctions(["hodlSecureEntryEnd", "hodlGlobalSyncFromCurrentInput"], {
    stubs: {
      ...secureEntryStubs,
      sessionWipe: (s) => { wiped.push(s); },
      hodlRenderGlobalSyncControl: () => {},
      hodlGlobalSyncIsHashedMode: () => { hashedCalls++; return true; },
      hodlGlobalSyncCurrentValue: () => "",
      hodlGlobalSyncCurrentBits: () => null,
      hodlApplyGlobalSync: () => { throw new Error("should not apply"); },
      hodlNewKeyState: () => ({}),
    },
    settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey"],
  });
  mod.__set.hodlSecureSession(session);
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlKeys([{ globalSync: true }]);
  mod.__set.hodlActiveKey(0);
  mod.hodlSecureEntryEnd();
  assert.equal(wiped.length, 1);
  assert.equal(wiped[0], session);
  // The switch is off: the sync path no longer short-circuits.
  mod.hodlGlobalSyncFromCurrentInput();
  assert.equal(hashedCalls, 1);
});

test("hodlSecureEntryEnd survives a throwing wipe", async () => {
  let hashedCalls = 0;
  const mod = await loadAppFunctions(["hodlSecureEntryEnd", "hodlGlobalSyncFromCurrentInput"], {
    stubs: {
      ...secureEntryStubs,
      sessionWipe: () => { throw new Error("wipe failed"); },
      hodlRenderGlobalSyncControl: () => {},
      hodlGlobalSyncIsHashedMode: () => { hashedCalls++; return true; },
      hodlGlobalSyncCurrentValue: () => "",
      hodlGlobalSyncCurrentBits: () => null,
      hodlApplyGlobalSync: () => { throw new Error("should not apply"); },
      hodlNewKeyState: () => ({}),
    },
    settable: ["hodlSecureEntryOn", "hodlSecureSession", "hodlKeys", "hodlActiveKey"],
  });
  mod.__set.hodlSecureSession({});
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlKeys([{ globalSync: true }]);
  mod.__set.hodlActiveKey(0);
  assert.doesNotThrow(() => mod.hodlSecureEntryEnd());
  mod.hodlGlobalSyncFromCurrentInput();
  assert.equal(hashedCalls, 1);
});

test("hodlSecureEntryDropKey deletes only a real key id", async () => {
  const calls = [];
  const session = { marker: "session" };
  const mod = await loadAppFunctions(["hodlSecureEntryDropKey"], {
    stubs: {
      ...secureEntryStubs,
      sessionDeleteKey: (s, id) => { calls.push([s, id]); },
    },
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession(session);
  mod.hodlSecureEntryDropKey(7);
  assert.deepEqual(calls, [[session, 7]]);
  mod.hodlSecureEntryDropKey(null);
  mod.hodlSecureEntryDropKey(undefined);
  assert.equal(calls.length, 1);
});

test("hodlSecureEntryDropKey survives a throwing delete", async () => {
  const mod = await loadAppFunctions(["hodlSecureEntryDropKey"], {
    stubs: {
      ...secureEntryStubs,
      sessionDeleteKey: () => { throw new Error("delete failed"); },
    },
    settable: ["hodlSecureSession"],
  });
  mod.__set.hodlSecureSession({});
  assert.doesNotThrow(() => mod.hodlSecureEntryDropKey(7));
});

test("hodlApplyGlobalSync is off while secure entry is on", async () => {
  const mod = await loadAppFunctions(["hodlApplyGlobalSync"], {
    stubs: {
      ...secureEntryStubs,
      hodlGlobalSyncSourceId: () => "seed:words",
      hodlSeedConfig: () => ({ bits: 128, words: 12, partialWords: 11 }),
      hodlGlobalSyncCurrentValue: () => "",
      hodlPrivateKeyValues: () => ({}),
      hodlGlobalSyncMnemonic: () => null,
      hodlGlobalSyncWordIndices: () => [],
      hodlBip39Wordlist: [],
      hodlEntropyFormats: {},
      hodlGlobalSyncNumberValue: () => "",
      hodlBip39WordIndex: new Map(),
      hodlGlobalSyncDPlusValue: () => "",
      hodlGlobalSyncDirectCardsValue: () => "",
      hodlGlobalSyncBitBoxValue: () => "",
      hodlBytesFromBits: () => new Uint8Array(),
      hodlAssertPrivateKey: () => {},
      hodlParseDerivationIndexText: () => ({ value: 0 }),
      hodlNetworkFromCoinType: () => "mainnet",
      hodlEncodeWif: () => "",
      hodlGlobalSyncSourceBits: () => "",
      hodlNewKeyState: () => ({}),
    },
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey"],
  });
  const fields = {};
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlKeys([{ fields }]);
  mod.__set.hodlActiveKey(0);
  assert.equal(mod.hodlApplyGlobalSync("1010"), false);
  assert.deepEqual(fields, {});
});

test("hodlGlobalSyncFromCurrentInput is off while secure entry is on", async () => {
  let renderCalls = 0, applyCalls = 0;
  const mod = await loadAppFunctions(["hodlGlobalSyncFromCurrentInput"], {
    stubs: {
      ...secureEntryStubs,
      hodlRenderGlobalSyncControl: () => { renderCalls++; },
      hodlApplyGlobalSync: () => { applyCalls++; },
      hodlGlobalSyncIsHashedMode: () => false,
      hodlGlobalSyncCurrentValue: () => "",
      hodlGlobalSyncCurrentBits: () => null,
      hodlNewKeyState: () => ({}),
    },
    settable: ["hodlSecureEntryOn", "hodlKeys", "hodlActiveKey"],
  });
  mod.__set.hodlSecureEntryOn(true);
  mod.__set.hodlKeys([{ globalSync: true }]);
  mod.__set.hodlActiveKey(0);
  assert.equal(mod.hodlGlobalSyncFromCurrentInput(), false);
  assert.equal(renderCalls, 1);
  assert.equal(applyCalls, 0);
});

test("the real secure session deletes one key and wipes the rest", () => {
  const session = createSecureSession();
  const seed = seedEntry(12);
  seedSet(seed, 0, 42);
  seedSet(seed, 1, 7);
  const indices = seed.indices;
  sessionSet(session, "1", "seed", seed);

  const key = keyEntry();
  sessionSet(session, "2", "key", key);

  sessionDeleteKey(session, 1);
  assert.equal(sessionGet(session, "1", "seed"), null);
  assert.deepEqual([...indices], new Array(12).fill(0));
  assert.equal(sessionGet(session, "2", "key"), key);
  assert.equal(key.wiped, false);

  sessionWipe(session);
  assert.equal(sessionGet(session, "2", "key"), null);
  assert.equal(key.wiped, true);
});

test("the wiring hooks are in the right order", () => {
  const clearStart = app.indexOf("let clearSecretFields = () => {");
  assert.ok(clearStart >= 0);
  const clearEnd = app.indexOf("hodlSyncWorkspaceCounts();", clearStart);
  assert.ok(clearEnd >= 0);
  const endCall = app.indexOf("hodlSecureEntryEnd();", clearStart);
  assert.ok(endCall >= 0 && endCall < clearEnd);

  const detachStart = app.indexOf("function hodlKeyManagerDetachFromStation(state) {");
  assert.ok(detachStart >= 0);
  const detachRelease = app.indexOf("hodlReleaseKeyConsumers(state.id);", detachStart);
  const detachDrop = app.indexOf("hodlSecureEntryDropKey(state.id);", detachStart);
  assert.ok(detachRelease >= 0 && detachDrop > detachRelease);

  const deleteStart = app.indexOf("let deletedIndex = hodlActiveKey, deletedState = state;");
  assert.ok(deleteStart >= 0);
  const deleteRelease = app.indexOf("hodlReleaseKeyConsumers(deletedState.id);", deleteStart);
  const deleteDrop = app.indexOf("hodlSecureEntryDropKey(deletedState.id);", deleteStart);
  assert.ok(deleteRelease >= 0 && deleteDrop > deleteRelease);

  for (const line of app.split("\n")) {
    if (line.includes("hodlSecureEntryOn")) assert.doesNotMatch(line, /setItem/);
  }
});
