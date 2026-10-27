// Secure entry (src/js/secure-entry.js): the session-wide switch that holds
// secrets in zeroable typed buffers instead of text fields.
//
// Contract: every entry kind validates its arguments and refuses bad input
// with a coded SecureEntryError; every buffer is zeroed when it is replaced,
// cleared, deleted or the session ends; a wiped entry refuses further
// mutation; and a turn-on/turn-off plan is dry-run in full before anything is
// committed, so a blocked plan changes nothing and never echoes secret text.
//
// Expected values: the P1a design (BIP39 word counts 12/15/18/21/24, word
// indices 0..2047, die faces 1..6, card values 0..51, capacities 1..400) and
// the BIP39 word-count rule. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SecureEntryError,
  SUPPORTED_METHODS,
  isSupported,
  seedEntry,
  seedSet,
  seedUndo,
  seedIndices,
  keyEntry,
  rollsEntry,
  rollsPush,
  rollsUndo,
  rollAt,
  rollsCopy,
  cardsEntry,
  cardsPush,
  cardsUndo,
  cardAt,
  cardsCopy,
  wipeEntry,
  createSecureSession,
  sessionGet,
  sessionSet,
  sessionDeleteKey,
  sessionWipe,
  sessionGuard,
  planTurnOn,
  commitTurnOn,
  discardPlan,
  planTurnOff,
  commitTurnOff,
} from "../src/js/secure-entry.js";

const code = (expected) => (error) => error instanceof SecureEntryError && error.code === expected;

test("seed entries accept only the five BIP39 word counts", () => {
  for (const length of [12, 15, 18, 21, 24]) {
    const entry = seedEntry(length);
    assert.equal(entry.kind, "seed");
    assert.equal(entry.length, length);
    assert.equal(entry.count, 0);
    assert.ok(entry.indices instanceof Uint16Array);
    assert.equal(entry.indices.length, length);
    assert.ok(entry.indices.every((value) => value === 0));
  }
  for (const length of [0, 1, 11, 13, 23, 25, 27, -12, 12.5, "12", null, undefined, NaN]) {
    assert.throws(() => seedEntry(length), code("BAD_LENGTH"));
  }
});

test("seedSet refuses positions and indices outside the contract", () => {
  const entry = seedEntry(12);
  assert.throws(() => seedSet(entry, -1, 0), code("BAD_POSITION"));
  assert.throws(() => seedSet(entry, 12, 0), code("BAD_POSITION"));
  assert.throws(() => seedSet(entry, 1.5, 0), code("BAD_POSITION"));
  assert.throws(() => seedSet(entry, "0", 0), code("BAD_POSITION"));
  assert.throws(() => seedSet(entry, 0, -1), code("BAD_INDEX"));
  assert.throws(() => seedSet(entry, 0, 2048), code("BAD_INDEX"));
  assert.throws(() => seedSet(entry, 0, 1.5), code("BAD_INDEX"));
  assert.throws(() => seedSet(entry, 0, "1"), code("BAD_INDEX"));
  assert.throws(() => seedSet(entry, 2, 5), code("BAD_POSITION"));
  assert.equal(entry.count, 0);
});

test("seed words fill in order and a middle word is replaced without shifting the rest", () => {
  const entry = seedEntry(12);
  const words = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
  words.forEach((index, position) => seedSet(entry, position, index));
  assert.equal(entry.count, 12);
  assert.deepEqual([...seedIndices(entry)], words);
  seedSet(entry, 5, 2047);
  assert.equal(entry.count, 12);
  const expected = words.slice();
  expected[5] = 2047;
  assert.deepEqual([...seedIndices(entry)], expected);
});

test("seedUndo zeroes the last slot and decrements the count", () => {
  const entry = seedEntry(12);
  seedSet(entry, 0, 7);
  seedSet(entry, 1, 8);
  seedUndo(entry);
  assert.equal(entry.count, 1);
  assert.equal(entry.indices[1], 0);
  assert.deepEqual([...seedIndices(entry)], [7]);
  seedUndo(entry);
  assert.equal(entry.count, 0);
  assert.equal(entry.indices[0], 0);
  assert.throws(() => seedUndo(entry), code("EMPTY"));
});

test("seedIndices returns a copy the caller owns", () => {
  const entry = seedEntry(12);
  seedSet(entry, 0, 1);
  seedSet(entry, 1, 2);
  const copy = seedIndices(entry);
  assert.ok(copy instanceof Uint16Array);
  assert.notEqual(copy.buffer, entry.indices.buffer);
  copy[0] = 999;
  assert.equal(entry.indices[0], 1);
  assert.deepEqual([...seedIndices(entry)], [1, 2]);
});

test("rolls validate their method, capacity and faces", () => {
  for (const capacity of [1, 6, 400]) {
    const entry = rollsEntry("base10", capacity);
    assert.equal(entry.kind, "rolls");
    assert.equal(entry.method, "base10");
    assert.equal(entry.count, 0);
    assert.ok(entry.rolls instanceof Uint8Array);
    assert.equal(entry.rolls.length, capacity);
  }
  for (const capacity of [0, 401, -1, 1.5, "6", null, undefined]) {
    assert.throws(() => rollsEntry("base10", capacity), code("BAD_CAPACITY"));
  }
  for (const method of ["", null, undefined, 3, {}]) {
    assert.throws(() => rollsEntry(method, 6), code("BAD_METHOD"));
  }
  const entry = rollsEntry("coleman", 6);
  for (const face of [0, 7, -1, 1.5, "3", null]) {
    assert.throws(() => rollsPush(entry, face), code("BAD_FACE"));
  }
  assert.equal(entry.count, 0);
});

test("rolls push, undo zeroes, FULL at capacity, and copies do not alias", () => {
  const entry = rollsEntry("base10", 3);
  rollsPush(entry, 1);
  rollsPush(entry, 6);
  assert.equal(entry.count, 2);
  assert.equal(rollAt(entry, 0), 1);
  assert.equal(rollAt(entry, 1), 6);
  assert.throws(() => rollAt(entry, 2), code("BAD_POSITION"));
  assert.throws(() => rollAt(entry, -1), code("BAD_POSITION"));
  const copy = rollsCopy(entry);
  assert.ok(copy instanceof Uint8Array);
  assert.notEqual(copy.buffer, entry.rolls.buffer);
  assert.deepEqual([...copy], [1, 6]);
  copy[0] = 9;
  assert.equal(entry.rolls[0], 1);
  rollsPush(entry, 3);
  assert.throws(() => rollsPush(entry, 4), code("FULL"));
  rollsUndo(entry);
  assert.equal(entry.count, 2);
  assert.equal(entry.rolls[2], 0);
  rollsUndo(entry);
  rollsUndo(entry);
  assert.throws(() => rollsUndo(entry), code("EMPTY"));
});

test("cards validate values 0..51 and behave like rolls", () => {
  const entry = cardsEntry("shuffle", 2);
  assert.equal(entry.kind, "cards");
  assert.equal(entry.method, "shuffle");
  assert.ok(entry.cards instanceof Uint8Array);
  for (const value of [-1, 52, 1.5, "0", null]) {
    assert.throws(() => cardsPush(entry, value), code("BAD_VALUE"));
  }
  cardsPush(entry, 0);
  cardsPush(entry, 51);
  assert.equal(cardAt(entry, 0), 0);
  assert.equal(cardAt(entry, 1), 51);
  assert.throws(() => cardAt(entry, 2), code("BAD_POSITION"));
  const copy = cardsCopy(entry);
  assert.notEqual(copy.buffer, entry.cards.buffer);
  assert.deepEqual([...copy], [0, 51]);
  assert.throws(() => cardsPush(entry, 5), code("FULL"));
  cardsUndo(entry);
  assert.equal(entry.count, 1);
  assert.equal(entry.cards[1], 0);
  for (const capacity of [0, 401, 2.5]) {
    assert.throws(() => cardsEntry("shuffle", capacity), code("BAD_CAPACITY"));
  }
});

test("wipeEntry zeroes every buffer and refuses later mutation", () => {
  const seed = seedEntry(12);
  seedSet(seed, 0, 42);
  const seedBuffer = seed.indices;
  wipeEntry(seed);
  assert.ok(seedBuffer.every((value) => value === 0));
  assert.equal(seed.count, 0);
  assert.equal(seed.wiped, true);
  assert.throws(() => seedSet(seed, 0, 1), code("WIPED"));
  assert.throws(() => seedUndo(seed), code("WIPED"));
  wipeEntry(seed);

  const rolls = rollsEntry("base10", 4);
  rollsPush(rolls, 5);
  const rollsBuffer = rolls.rolls;
  wipeEntry(rolls);
  assert.ok(rollsBuffer.every((value) => value === 0));
  assert.throws(() => rollsPush(rolls, 1), code("WIPED"));
  assert.throws(() => rollsUndo(rolls), code("WIPED"));

  const cards = cardsEntry("shuffle", 4);
  cardsPush(cards, 7);
  const cardsBuffer = cards.cards;
  wipeEntry(cards);
  assert.ok(cardsBuffer.every((value) => value === 0));
  assert.throws(() => cardsPush(cards, 1), code("WIPED"));
  assert.throws(() => cardsUndo(cards), code("WIPED"));

  const key = keyEntry();
  key.vault.setText("hunter2");
  assert.equal(key.vault.length, 7);
  wipeEntry(key);
  assert.equal(key.vault.length, 0);
  assert.equal(key.wiped, true);
});

test("wipeEntry refuses something that is not an entry", () => {
  assert.throws(() => wipeEntry(null), code("BAD_ENTRY"));
  assert.throws(() => wipeEntry({ kind: "nope" }), code("BAD_ENTRY"));
});

test("the session keys entries by key and method, and replacing wipes the old one", () => {
  const session = createSecureSession();
  assert.equal(session.on, false);
  assert.equal(session.generation, 0);
  assert.ok(session.entries instanceof Map);
  assert.equal(session.entries.size, 0);
  assert.equal(sessionGet(session, 3, "seed"), null);

  const first = seedEntry(12);
  seedSet(first, 0, 3);
  const firstBuffer = first.indices;
  const before = session.generation;
  sessionSet(session, 3, "seed", first);
  assert.equal(sessionGet(session, 3, "seed"), first);
  assert.ok(session.generation > before);

  const second = seedEntry(12);
  sessionSet(session, 3, "seed", second);
  assert.ok(firstBuffer.every((value) => value === 0));
  assert.equal(first.wiped, true);
  assert.equal(sessionGet(session, 3, "seed"), second);
  assert.equal(session.entries.size, 1);
});

test("sessionDeleteKey wipes only that key's entries", () => {
  const session = createSecureSession();
  const a = seedEntry(12);
  const b = rollsEntry("base10", 4);
  const c = seedEntry(12);
  sessionSet(session, 1, "seed", a);
  sessionSet(session, 1, "rolls", b);
  sessionSet(session, 2, "seed", c);
  const aBuffer = a.indices, bBuffer = b.rolls;
  const before = session.generation;
  sessionDeleteKey(session, 1);
  assert.ok(aBuffer.every((value) => value === 0));
  assert.ok(bBuffer.every((value) => value === 0));
  assert.equal(a.wiped, true);
  assert.equal(b.wiped, true);
  assert.equal(c.wiped, false);
  assert.equal(sessionGet(session, 1, "seed"), null);
  assert.equal(sessionGet(session, 1, "rolls"), null);
  assert.equal(sessionGet(session, 2, "seed"), c);
  assert.ok(session.generation > before);
});

test("sessionWipe wipes everything and turns the switch off", () => {
  const session = createSecureSession();
  const a = seedEntry(12);
  const b = keyEntry();
  b.vault.setText("secret");
  sessionSet(session, 1, "seed", a);
  sessionSet(session, 2, "key", b);
  session.on = true;
  const aBuffer = a.indices;
  const before = session.generation;
  sessionWipe(session);
  assert.ok(aBuffer.every((value) => value === 0));
  assert.equal(b.vault.length, 0);
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
  assert.ok(session.generation > before);
});

test("the guard goes stale after any wipe", () => {
  const session = createSecureSession();
  const guard = sessionGuard(session);
  assert.equal(guard.generation, session.generation);
  assert.equal(guard.current(), true);
  sessionWipe(session);
  assert.equal(guard.current(), false);
});

test("the guard goes stale after a key is deleted", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const guard = sessionGuard(session);
  assert.equal(guard.current(), true);
  sessionDeleteKey(session, 1);
  assert.equal(guard.current(), false);
});

test("the guard goes stale when an entry is replaced", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const guard = sessionGuard(session);
  assert.equal(guard.current(), true);
  sessionSet(session, 1, "seed", seedEntry(12));
  assert.equal(guard.current(), false);
});

test("planTurnOn stages every supported conversion without touching the session", () => {
  const session = createSecureSession();
  const keys = [{ keyId: 1, methods: { seed: "abandon ability" } }];
  const converters = {
    seed: (text) => {
      const entry = seedEntry(12);
      seedSet(entry, 0, text.length);
      return entry;
    },
  };
  const plan = planTurnOn(session, keys, converters);
  assert.equal(plan.ok, true);
  assert.equal(plan.blockers.length, 0);
  assert.equal(plan.staged.length, 1);
  assert.equal(plan.staged[0].keyId, 1);
  assert.equal(plan.staged[0].method, "seed");
  assert.equal(plan.staged[0].entry.kind, "seed");
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
  discardPlan(plan);
});

test("an unsupported method blocks the plan and never echoes the text", () => {
  const session = createSecureSession();
  const sentinel = "SENTINEL-DO-NOT-ECHO-9f3a";
  const plan = planTurnOn(session, [{ keyId: 7, methods: { hex: sentinel } }], {});
  assert.equal(plan.ok, false);
  assert.equal(plan.staged.length, 0);
  assert.deepEqual(plan.blockers, [{ keyId: 7, method: "hex", reason: "unsupported" }]);
  assert.equal(JSON.stringify(plan.blockers).includes(sentinel), false);
  assert.equal(JSON.stringify(plan).includes(sentinel), false);
});

test("a converter that throws is an invalid blocker, not a crash", () => {
  const session = createSecureSession();
  const sentinel = "SENTINEL-INVALID-4b2c";
  const plan = planTurnOn(session, [{ keyId: 2, methods: { seed: sentinel } }], {
    seed: () => { throw new Error("bad words"); },
  });
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: 2, method: "seed", reason: "invalid" }]);
  assert.equal(JSON.stringify(plan.blockers).includes(sentinel), false);
});

test("a known method with no converter is a no-converter blocker", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {});
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: 1, method: "seed", reason: "no-converter" }]);
});

test("planTurnOn ignores empty text and never stages it", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "", hex: "" } }], {});
  assert.equal(plan.ok, true);
  assert.equal(plan.staged.length, 0);
  assert.equal(plan.blockers.length, 0);
});

test("planTurnOn stages one entry per key and method", () => {
  const session = createSecureSession();
  const keys = [
    { keyId: 1, methods: { seed: "a", rolls: "b" } },
    { keyId: 2, methods: { seed: "c" } },
  ];
  const converters = {
    seed: () => seedEntry(12),
    rolls: () => rollsEntry("base10", 6),
  };
  const plan = planTurnOn(session, keys, converters);
  assert.equal(plan.ok, true);
  assert.equal(plan.staged.length, 3);
  assert.deepEqual(plan.staged.map((item) => `${item.keyId}:${item.method}`), ["1:seed", "1:rolls", "2:seed"]);
  discardPlan(plan);
});

test("commitTurnOn refuses a blocked plan and changes nothing", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { hex: "deadbeef" } }], {});
  assert.equal(plan.ok, false);
  const before = session.generation;
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
  assert.equal(session.generation, before);
});

test("commitTurnOn refuses a malformed plan", () => {
  const session = createSecureSession();
  assert.throws(() => commitTurnOn(session, { ok: true, staged: null }), code("PLAN_BLOCKED"));
  assert.throws(() => commitTurnOn(session, null), code("PLAN_BLOCKED"));
});

test("commitTurnOn installs every staged entry and turns the switch on", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 5); return entry; },
  });
  const before = session.generation;
  commitTurnOn(session, plan);
  assert.equal(session.on, true);
  assert.ok(session.generation > before);
  const installed = sessionGet(session, 1, "seed");
  assert.ok(installed);
  assert.equal(installed.kind, "seed");
  assert.deepEqual([...seedIndices(installed)], [5]);
});

test("commitTurnOn installs every staged entry across keys", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [
    { keyId: 1, methods: { seed: "a" } },
    { keyId: 2, methods: { rolls: "b" } },
  ], {
    seed: () => seedEntry(12),
    rolls: () => rollsEntry("base10", 6),
  });
  commitTurnOn(session, plan);
  assert.equal(session.entries.size, 2);
  assert.equal(sessionGet(session, 1, "seed").kind, "seed");
  assert.equal(sessionGet(session, 2, "rolls").kind, "rolls");
});

test("discardPlan wipes every staged entry", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 5); return entry; },
  });
  assert.equal(plan.ok, true);
  const staged = plan.staged[0].entry;
  const buffer = staged.indices;
  discardPlan(plan);
  assert.ok(buffer.every((value) => value === 0));
  assert.equal(staged.wiped, true);
  assert.equal(plan.staged.length, 0);
});

test("commitTurnOff in convert mode returns the texts and wipes the entries", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 5);
  sessionSet(session, 1, "seed", entry);
  session.on = true;
  const buffer = entry.indices;
  const plan = planTurnOff(session, { seed: (e) => `words:${seedIndices(e).length}` });
  assert.equal(plan.ok, true);
  assert.deepEqual(plan.staged, [{ keyId: 1, method: "seed", text: "words:1" }]);
  const texts = commitTurnOff(session, plan, "convert");
  assert.deepEqual(texts, [{ keyId: 1, method: "seed", text: "words:1" }]);
  assert.ok(buffer.every((value) => value === 0));
  assert.equal(entry.wiped, true);
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
});

test("planTurnOff blocks when a serializer is missing", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const plan = planTurnOff(session, {});
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: 1, method: "seed", reason: "no-serializer" }]);
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 1);
});

test("planTurnOff serializes every entry", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  sessionSet(session, 2, "rolls", rollsEntry("base10", 6));
  const plan = planTurnOff(session, {
    seed: () => "seed-text",
    rolls: () => "rolls-text",
  });
  assert.equal(plan.ok, true);
  assert.deepEqual(plan.staged, [
    { keyId: 1, method: "seed", text: "seed-text" },
    { keyId: 2, method: "rolls", text: "rolls-text" },
  ]);
});

test("commitTurnOff in clear mode wipes everything and returns no texts", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 5);
  sessionSet(session, 1, "seed", entry);
  session.on = true;
  const buffer = entry.indices;
  const texts = commitTurnOff(session, null, "clear");
  assert.deepEqual(texts, []);
  assert.ok(buffer.every((value) => value === 0));
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
});

test("commitTurnOff refuses an unknown mode", () => {
  const session = createSecureSession();
  assert.throws(() => commitTurnOff(session, null, "sideways"), code("BAD_MODE"));
});

test("commitTurnOff refuses a stale plan", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const plan = planTurnOff(session, { seed: () => "text" });
  sessionSet(session, 1, "seed", seedEntry(12));
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 1);
});

test("commitTurnOff refuses a plan whose entry was deleted", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const plan = planTurnOff(session, { seed: () => "text" });
  sessionDeleteKey(session, 1);
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_BLOCKED"));
});

test("commitTurnOff refuses a plan that misses an entry", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const plan = planTurnOff(session, { seed: () => "text" });
  sessionSet(session, 2, "seed", seedEntry(12));
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 2);
});

test("a key entry can be planned and committed", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { key: "xprv..." } }], {
    key: () => keyEntry(),
  });
  assert.equal(plan.ok, true);
  commitTurnOn(session, plan);
  const installed = sessionGet(session, 1, "key");
  assert.equal(installed.kind, "key");
  assert.equal(installed.vault.length, 0);
});

test("SUPPORTED_METHODS is frozen and every value is false in this round", () => {
  assert.ok(Object.isFrozen(SUPPORTED_METHODS));
  assert.deepEqual(Object.keys(SUPPORTED_METHODS).sort(), ["cards", "key", "rolls", "seed"]);
  for (const value of Object.values(SUPPORTED_METHODS)) assert.equal(value, false);
  for (const method of ["seed", "key", "rolls", "cards", "hex", "base10", "toString", "", null, undefined]) {
    assert.equal(isSupported(method), false);
  }
});

test("SecureEntryError carries a code and a message without the input", () => {
  const error = new SecureEntryError("BAD_INDEX", "A BIP39 word index is 0..2047.");
  assert.ok(error instanceof Error);
  assert.equal(error.name, "SecureEntryError");
  assert.equal(error.code, "BAD_INDEX");
  assert.equal(error.message, "A BIP39 word index is 0..2047.");
});
