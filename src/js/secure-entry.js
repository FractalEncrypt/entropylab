// Secure entry: the session-wide switch that holds secrets in zeroable typed
// buffers instead of text fields.
//
// A text field's value is text the page cannot erase (see passphrase-vault.js
// for the residue audit). Here a seed is word indices, a private key is bytes
// in a PassphraseVault, dice are faces and cards are values, each in a typed
// array that can be zeroed. The module has no DOM and no app imports beyond
// the vault: P1b wires it into the Key Station.
//
// Contract: every constructor and setter validates its arguments and refuses
// bad input with a coded SecureEntryError; every buffer is zeroed when it is
// replaced, cleared, deleted or the session ends; a wiped entry refuses
// further mutation; and a turn-on/turn-off plan is dry-run in full before
// anything is committed, so a blocked plan changes nothing and never echoes
// secret text.

import { PassphraseVault } from "./passphrase-vault.js";

export class SecureEntryError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = "SecureEntryError";
    this.code = code;
  }
}

const fail = (code, message) => { throw new SecureEntryError(code, message); };

const SEED_LENGTHS = new Set([12, 15, 18, 21, 24]);
const MAX_WORD_INDEX = 2048;
const MAX_CAPACITY = 400;

const isInteger = (value) => typeof value === "number" && Number.isInteger(value);

const assertLive = (entry, kind) => {
  if (!entry || typeof entry !== "object" || entry.kind !== kind) fail("BAD_ENTRY", `Not a ${kind} entry.`);
  if (entry.wiped) fail("WIPED", "This secure entry has been wiped.");
};

// The four entry kinds the module can hold. The boolean is the UI gate that
// P1b reads through isSupported(); it is false for every kind in this round,
// so the Key Station does not yet offer secure entry. Planning recognises the
// kinds themselves: a method not listed here (a "hex" number base, say) is
// never plannable.
export const SUPPORTED_METHODS = Object.freeze({ seed: false, key: false, rolls: false, cards: false });

export const isSupported = (method) => typeof method === "string"
  && Object.prototype.hasOwnProperty.call(SUPPORTED_METHODS, method)
  && SUPPORTED_METHODS[method] === true;

const isKnownMethod = (method) => typeof method === "string"
  && Object.prototype.hasOwnProperty.call(SUPPORTED_METHODS, method);

export const seedEntry = (length) => {
  if (!SEED_LENGTHS.has(length)) fail("BAD_LENGTH", "A seed entry needs 12, 15, 18, 21 or 24 words.");
  return { kind: "seed", length, indices: new Uint16Array(length), count: 0, wiped: false };
};

export const seedSet = (entry, position, index) => {
  assertLive(entry, "seed");
  if (!isInteger(position) || position < 0 || position >= entry.length) fail("BAD_POSITION", "The word position is outside the seed.");
  if (!isInteger(index) || index < 0 || index >= MAX_WORD_INDEX) fail("BAD_INDEX", "A BIP39 word index is 0..2047.");
  if (position > entry.count) fail("BAD_POSITION", "Words fill in order; this position is past the end.");
  entry.indices[position] = index;
  if (position === entry.count) entry.count += 1;
};

export const seedUndo = (entry) => {
  assertLive(entry, "seed");
  if (entry.count === 0) fail("EMPTY", "There is no word to undo.");
  entry.count -= 1;
  entry.indices[entry.count] = 0;
};

export const seedIndices = (entry) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "seed") fail("BAD_ENTRY", "Not a seed entry.");
  return entry.indices.slice(0, entry.count);
};

export const keyEntry = () => ({ kind: "key", vault: new PassphraseVault(), wiped: false });

export const rollsEntry = (method, capacity) => {
  if (typeof method !== "string" || method.length === 0) fail("BAD_METHOD", "A rolls entry needs a method tag.");
  if (!isInteger(capacity) || capacity < 1 || capacity > MAX_CAPACITY) fail("BAD_CAPACITY", "Capacity is 1..400.");
  return { kind: "rolls", method, rolls: new Uint8Array(capacity), count: 0, wiped: false };
};

export const rollsPush = (entry, face) => {
  assertLive(entry, "rolls");
  if (!isInteger(face) || face < 1 || face > 6) fail("BAD_FACE", "A die face is 1..6.");
  if (entry.count === entry.rolls.length) fail("FULL", "The rolls buffer is full.");
  entry.rolls[entry.count] = face;
  entry.count += 1;
};

export const rollsUndo = (entry) => {
  assertLive(entry, "rolls");
  if (entry.count === 0) fail("EMPTY", "There is no roll to undo.");
  entry.count -= 1;
  entry.rolls[entry.count] = 0;
};

export const rollAt = (entry, i) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "rolls") fail("BAD_ENTRY", "Not a rolls entry.");
  if (!isInteger(i) || i < 0 || i >= entry.count) fail("BAD_POSITION", "No roll at that position.");
  return entry.rolls[i];
};

export const rollsCopy = (entry) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "rolls") fail("BAD_ENTRY", "Not a rolls entry.");
  return entry.rolls.slice(0, entry.count);
};

export const cardsEntry = (method, capacity) => {
  if (typeof method !== "string" || method.length === 0) fail("BAD_METHOD", "A cards entry needs a method tag.");
  if (!isInteger(capacity) || capacity < 1 || capacity > MAX_CAPACITY) fail("BAD_CAPACITY", "Capacity is 1..400.");
  return { kind: "cards", method, cards: new Uint8Array(capacity), count: 0, wiped: false };
};

export const cardsPush = (entry, value) => {
  assertLive(entry, "cards");
  if (!isInteger(value) || value < 0 || value > 51) fail("BAD_VALUE", "A card value is 0..51.");
  if (entry.count === entry.cards.length) fail("FULL", "The cards buffer is full.");
  entry.cards[entry.count] = value;
  entry.count += 1;
};

export const cardsUndo = (entry) => {
  assertLive(entry, "cards");
  if (entry.count === 0) fail("EMPTY", "There is no card to undo.");
  entry.count -= 1;
  entry.cards[entry.count] = 0;
};

export const cardAt = (entry, i) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "cards") fail("BAD_ENTRY", "Not a cards entry.");
  if (!isInteger(i) || i < 0 || i >= entry.count) fail("BAD_POSITION", "No card at that position.");
  return entry.cards[i];
};

export const cardsCopy = (entry) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "cards") fail("BAD_ENTRY", "Not a cards entry.");
  return entry.cards.slice(0, entry.count);
};

export const wipeEntry = (entry) => {
  if (!entry || typeof entry !== "object") fail("BAD_ENTRY", "Not a secure entry.");
  if (entry.wiped) return;
  switch (entry.kind) {
    case "seed": entry.indices.fill(0); break;
    case "key":
      if (!entry.vault || typeof entry.vault.clear !== "function") fail("BAD_ENTRY", "The key entry has no vault.");
      entry.vault.clear();
      break;
    case "rolls": entry.rolls.fill(0); break;
    case "cards": entry.cards.fill(0); break;
    default: fail("BAD_ENTRY", "Not a secure entry.");
  }
  if ("count" in entry) entry.count = 0;
  entry.wiped = true;
};

const entryId = (keyId, method) => `${keyId}:${method}`;

const metaOf = (session) => {
  if (!session.meta) Object.defineProperty(session, "meta", { value: new Map(), enumerable: false, writable: true, configurable: true });
  return session.meta;
};

const splitId = (id) => {
  const at = id.lastIndexOf(":");
  return at < 0 ? { keyId: id, method: "" } : { keyId: id.slice(0, at), method: id.slice(at + 1) };
};

export const createSecureSession = () => {
  const session = { on: false, generation: 0, entries: new Map() };
  Object.defineProperty(session, "meta", { value: new Map(), enumerable: false, writable: true, configurable: true });
  return session;
};

export const sessionGet = (session, keyId, method) => session.entries.get(entryId(keyId, method)) ?? null;

export const sessionSet = (session, keyId, method, entry) => {
  if (typeof method !== "string" || method.length === 0) fail("BAD_METHOD", "A session method must be a non-empty string.");
  if (!entry || typeof entry !== "object") fail("BAD_ENTRY", "Not a secure entry.");
  const id = entryId(keyId, method);
  const previous = session.entries.get(id);
  if (previous && previous !== entry) wipeEntry(previous);
  session.entries.set(id, entry);
  metaOf(session).set(id, { keyId, method });
  session.generation += 1;
};

export const sessionDeleteKey = (session, keyId) => {
  const meta = metaOf(session);
  let removed = 0;
  for (const [id, entry] of session.entries) {
    const info = meta.get(id) ?? splitId(id);
    if (info.keyId !== keyId) continue;
    wipeEntry(entry);
    session.entries.delete(id);
    meta.delete(id);
    removed += 1;
  }
  if (removed > 0) session.generation += 1;
};

export const sessionWipe = (session) => {
  for (const entry of session.entries.values()) wipeEntry(entry);
  session.entries.clear();
  metaOf(session).clear();
  session.on = false;
  session.generation += 1;
};

export const sessionGuard = (session) => {
  const generation = session.generation;
  return { generation, current: () => session.generation === generation };
};

export const planTurnOn = (session, keys, converters) => {
  const staged = [], blockers = [];
  for (const key of Array.isArray(keys) ? keys : []) {
    const keyId = key?.keyId;
    const methods = key?.methods && typeof key.methods === "object" ? key.methods : {};
    for (const method of Object.keys(methods)) {
      const text = methods[method];
      if (text === undefined || text === null || text === "") continue;
      if (!isKnownMethod(method)) { blockers.push({ keyId, method, reason: "unsupported" }); continue; }
      const convert = converters && Object.prototype.hasOwnProperty.call(converters, method) ? converters[method] : undefined;
      if (typeof convert !== "function") { blockers.push({ keyId, method, reason: "no-converter" }); continue; }
      let entry;
      try { entry = convert(text); }
      catch { blockers.push({ keyId, method, reason: "invalid" }); continue; }
      if (!entry || typeof entry !== "object" || entry.kind !== method || entry.wiped) {
        try { wipeEntry(entry); } catch { /* not an entry */ }
        blockers.push({ keyId, method, reason: "invalid" });
        continue;
      }
      staged.push({ keyId, method, entry });
    }
  }
  return { ok: blockers.length === 0, staged, blockers };
};

export const commitTurnOn = (session, plan) => {
  if (!plan || plan.ok !== true || !Array.isArray(plan.staged)) fail("PLAN_BLOCKED", "The plan has blockers; nothing was changed.");
  for (const item of plan.staged) {
    if (!item || typeof item !== "object" || !item.entry || item.entry.kind !== item.method || item.entry.wiped) {
      fail("PLAN_BLOCKED", "The plan is not valid; nothing was changed.");
    }
  }
  for (const { keyId, method, entry } of plan.staged) sessionSet(session, keyId, method, entry);
  plan.staged = [];
  session.on = true;
  session.generation += 1;
};

export const discardPlan = (plan) => {
  if (!plan || !Array.isArray(plan.staged)) return;
  for (const item of plan.staged) {
    if (item && item.entry) { try { wipeEntry(item.entry); } catch { /* not an entry */ } }
  }
  plan.staged = [];
};

export const planTurnOff = (session, serializers) => {
  const meta = metaOf(session);
  const staged = [], blockers = [];
  for (const [id, entry] of session.entries) {
    const info = meta.get(id) ?? splitId(id);
    const { keyId, method } = info;
    const serialize = serializers && Object.prototype.hasOwnProperty.call(serializers, method) ? serializers[method] : undefined;
    if (typeof serialize !== "function") { blockers.push({ keyId, method, reason: "no-serializer" }); continue; }
    let text;
    try { text = serialize(entry); }
    catch { blockers.push({ keyId, method, reason: "invalid" }); continue; }
    if (typeof text !== "string") { blockers.push({ keyId, method, reason: "invalid" }); continue; }
    const item = { keyId, method, text };
    Object.defineProperty(item, "entry", { value: entry, enumerable: false });
    staged.push(item);
  }
  return { ok: blockers.length === 0, staged, blockers };
};

export const commitTurnOff = (session, plan, mode) => {
  if (mode === "convert") {
    if (!plan || plan.ok !== true || !Array.isArray(plan.staged)) fail("PLAN_BLOCKED", "The plan has blockers; nothing was changed.");
    if (plan.staged.length !== session.entries.size) fail("PLAN_BLOCKED", "The plan is stale; nothing was changed.");
    for (const item of plan.staged) {
      if (!item || sessionGet(session, item.keyId, item.method) !== item.entry) fail("PLAN_BLOCKED", "The plan is stale; nothing was changed.");
    }
    // Each text keeps its key and method, so the caller puts it back in the right field.
    const texts = plan.staged.map(({ keyId, method, text }) => ({ keyId, method, text }));
    sessionWipe(session);
    plan.staged = [];
    return texts;
  }
  if (mode === "clear") {
    sessionWipe(session);
    if (plan) plan.staged = [];
    return [];
  }
  fail("BAD_MODE", "Unknown turn-off mode.");
};
