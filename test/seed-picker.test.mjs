import test from "node:test";
import assert from "node:assert/strict";
import { mountSeedPicker } from "../src/js/seed-picker.js";
import { seedEntry, seedSet, seedUndo, seedIndices } from "../src/js/secure-entry.js";
import { entropyFromWordIndices } from "../src/js/bip39.js";
import { wordlist } from "../src/js/bip39-english.js";

class FakeElement {
  constructor(doc, tag) {
    this.ownerDocument = doc;
    this.tagName = String(tag).toUpperCase();
    this.childNodes = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.listeners = new Map();
    this._text = "";
    this._html = "";
    this.hidden = false;
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.isConnected = true;
    this.id = "";
  }
  get textContent() {
    if (this.childNodes.length) return this.childNodes.map((child) => child.textContent).join("");
    return this._text;
  }
  set textContent(value) {
    this.childNodes = [];
    this._text = String(value ?? "");
    this._html = "";
  }
  get innerHTML() {
    return this._html;
  }
  set innerHTML(value) {
    this.childNodes = [];
    this._text = "";
    this._html = String(value ?? "");
  }
  appendChild(node) {
    node.parentNode = this;
    this.childNodes.push(node);
    return node;
  }
  replaceChildren(...nodes) {
    for (const child of this.childNodes) child.parentNode = null;
    this.childNodes = [];
    this._text = "";
    this._html = "";
    for (const node of nodes) this.appendChild(node);
  }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === "id") this.id = String(value);
    if (name === "hidden") this.hidden = true;
    if (name === "disabled") this.disabled = true;
  }
  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }
  removeAttribute(name) {
    this.attributes.delete(name);
    if (name === "hidden") this.hidden = false;
    if (name === "disabled") this.disabled = false;
  }
  get className() {
    return this.getAttribute("class") || "";
  }
  set className(value) {
    this.setAttribute("class", value);
  }
  addEventListener(type, handler) {
    const list = this.listeners.get(type) || [];
    list.push(handler);
    this.listeners.set(type, list);
  }
  removeEventListener(type, handler) {
    const list = this.listeners.get(type) || [];
    this.listeners.set(type, list.filter((entry) => entry !== handler));
  }
  dispatchEvent(event) {
    event.target = this;
    for (const handler of [...(this.listeners.get(event.type) || [])]) handler.call(this, event);
    return true;
  }
  focus() {
    this.ownerDocument.activeElement = this;
  }
}

const makeDocument = () => {
  const listeners = new Map();
  const doc = {
    visibilityState: "visible",
    activeElement: null,
    createElement(tag) {
      return new FakeElement(doc, tag);
    },
    addEventListener(type, handler) {
      const list = listeners.get(type) || [];
      list.push(handler);
      listeners.set(type, list);
    },
    removeEventListener(type, handler) {
      const list = listeners.get(type) || [];
      listeners.set(type, list.filter((entry) => entry !== handler));
    },
    dispatch(type) {
      for (const handler of [...(listeners.get(type) || [])]) handler({ type });
    },
    listenerCount(type) {
      return (listeners.get(type) || []).length;
    },
  };
  return doc;
};

const findById = (node, id) => {
  if (!node) return null;
  if (node.id === id) return node;
  for (const child of node.childNodes) {
    const found = findById(child, id);
    if (found) return found;
  }
  return null;
};

const markupOf = (node) => {
  if (!node) return "";
  let out = node._html || "";
  if (!node.childNodes.length) out += node._text || "";
  for (const child of node.childNodes) out += markupOf(child);
  return out;
};

const occurrences = (haystack, needle) => haystack.split(needle).length - 1;

const setup = (options = {}) => {
  const doc = makeDocument();
  const host = doc.createElement("div");
  host.id = "seed-picker-host";
  const entry = seedEntry(options.length || 12);
  const changes = [];
  const picker = mountSeedPicker(host, {
    entry,
    wordlist,
    seedSet,
    seedUndo,
    seedIndices,
    entropyFromWordIndices,
    translate: options.translate || ((text) => text),
    onChange: (state) => changes.push(state),
    doc,
    win: {},
  });
  return { doc, host, entry, changes, picker };
};

const pressEnter = (field, extra = {}) => {
  let prevented = 0;
  field.dispatchEvent({ type: "keydown", key: "Enter", isComposing: false, preventDefault() { prevented += 1; }, ...extra });
  return prevented;
};

const enterWord = (ctx, word) => {
  const field = findById(ctx.host, "seed-picker-prefix");
  field.value = word;
  field.dispatchEvent({ type: "input" });
  return pressEnter(field);
};

test("a prefix lists matches in wordlist order and Enter never picks among several", () => {
  const ctx = setup();
  const field = findById(ctx.host, "seed-picker-prefix");
  field.value = "ab";
  field.dispatchEvent({ type: "input" });
  const buttons = findById(ctx.host, "seed-picker-matches").childNodes;
  assert.ok(buttons.length > 1);
  const indices = buttons.map((button) => Number(button.getAttribute("data-word-index")));
  assert.deepEqual(indices, [...indices].sort((a, b) => a - b));
  assert.ok(indices.includes(0));
  assert.equal(pressEnter(field), 1);
  assert.equal(ctx.entry.count, 0);
  field.value = "aba";
  field.dispatchEvent({ type: "input" });
  const aba = findById(ctx.host, "seed-picker-matches").childNodes;
  assert.equal(aba.length, 1);
  assert.equal(aba[0].getAttribute("data-word-index"), "0");
});

test("a complete word is picked by Enter and the chip never shows it", () => {
  const ctx = setup();
  enterWord(ctx, "abandon");
  assert.equal(ctx.entry.count, 1);
  assert.equal(ctx.entry.indices[0], 0);
  assert.equal(findById(ctx.host, "seed-picker-prefix").value, "");
  const chips = findById(ctx.host, "seed-picker-chips").childNodes;
  assert.equal(chips.length, 1);
  assert.equal(chips[0].getAttribute("data-word-position"), "1");
  assert.ok(!markupOf(chips[0]).includes("abandon"));
});

test("Enter during composition does nothing", () => {
  const ctx = setup();
  const field = findById(ctx.host, "seed-picker-prefix");
  field.value = "abandon";
  field.dispatchEvent({ type: "input" });
  assert.equal(pressEnter(field, { isComposing: true }), 1);
  assert.equal(ctx.entry.count, 0);
});

test("Backspace in an empty prefix never deletes an accepted word", () => {
  const ctx = setup();
  enterWord(ctx, "abandon");
  const field = findById(ctx.host, "seed-picker-prefix");
  field.dispatchEvent({ type: "keydown", key: "Backspace", preventDefault() {} });
  assert.equal(ctx.entry.count, 1);
});

test("a complete seed reports its checksum state", () => {
  const ctx = setup();
  for (let i = 0; i < 11; i += 1) enterWord(ctx, "abandon");
  enterWord(ctx, "about");
  assert.equal(ctx.entry.count, 12);
  assert.equal(findById(ctx.host, "seed-picker-progress").getAttribute("data-picker-state"), "checksum-ok");
  assert.equal(findById(ctx.host, "seed-picker-caveat").hidden, false);
  assert.equal(findById(ctx.host, "seed-picker-prefix").hidden, true);
  const last = ctx.changes[ctx.changes.length - 1];
  assert.equal(last.complete, true);
  assert.equal(last.checksum, "ok");

  const bad = setup();
  for (let i = 0; i < 12; i += 1) enterWord(bad, "abandon");
  assert.equal(findById(bad.host, "seed-picker-progress").getAttribute("data-picker-state"), "checksum-bad");
  assert.equal(findById(bad.host, "seed-picker-caveat").hidden, true);
});

test("undo removes the last word and focuses the prefix", () => {
  const ctx = setup();
  enterWord(ctx, "abandon");
  enterWord(ctx, "ability");
  assert.equal(ctx.entry.count, 2);
  findById(ctx.host, "seed-picker-undo").dispatchEvent({ type: "click" });
  assert.equal(ctx.entry.count, 1);
  assert.equal(ctx.doc.activeElement, findById(ctx.host, "seed-picker-prefix"));
});

test("review shows one word on request and replaces in place", () => {
  const ctx = setup();
  const words = ["abandon", "ability", "zebra", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident"];
  for (const word of words) enterWord(ctx, word);
  const before = Array.from(ctx.entry.indices);
  findById(ctx.host, "seed-picker-chips").childNodes[2].dispatchEvent({ type: "click" });
  const review = findById(ctx.host, "seed-picker-review");
  assert.equal(review.hidden, false);
  assert.ok(!markupOf(review).includes("zebra"));
  const show = findById(ctx.host, "seed-picker-review-show");
  show.checked = true;
  show.dispatchEvent({ type: "change" });
  assert.equal(occurrences(markupOf(review), "zebra"), 1);
  const replaceField = findById(ctx.host, "seed-picker-replace-prefix");
  replaceField.value = "abandon";
  replaceField.dispatchEvent({ type: "input" });
  findById(ctx.host, "seed-picker-replace-matches").childNodes[0].dispatchEvent({ type: "click" });
  findById(ctx.host, "seed-picker-replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.entry.indices[2], 0);
  assert.equal(ctx.entry.indices[0], before[0]);
  assert.equal(ctx.entry.indices[1], before[1]);
  assert.equal(ctx.entry.indices[3], before[3]);
  const afterReplace = Array.from(ctx.entry.indices);
  findById(ctx.host, "seed-picker-review-cancel").dispatchEvent({ type: "click" });
  assert.deepEqual(Array.from(ctx.entry.indices), afterReplace);
  findById(ctx.host, "seed-picker-chips").childNodes[2].dispatchEvent({ type: "click" });
  show.checked = true;
  show.dispatchEvent({ type: "change" });
  findById(ctx.host, "seed-picker-review-next").dispatchEvent({ type: "click" });
  assert.equal(show.checked, false);
  show.checked = true;
  show.dispatchEvent({ type: "change" });
  findById(ctx.host, "seed-picker-review-prev").dispatchEvent({ type: "click" });
  assert.equal(show.checked, false);
});

test("a shown word leaves the DOM when review closes", () => {
  const ctx = setup();
  for (const word of ["abandon", "ability", "zebra"]) enterWord(ctx, word);
  findById(ctx.host, "seed-picker-chips").childNodes[2].dispatchEvent({ type: "click" });
  const show = findById(ctx.host, "seed-picker-review-show");
  show.checked = true;
  show.dispatchEvent({ type: "change" });
  assert.equal(occurrences(markupOf(ctx.host), "zebra"), 1);
  findById(ctx.host, "seed-picker-review-cancel").dispatchEvent({ type: "click" });
  assert.ok(!markupOf(ctx.host).includes("zebra"), "the word stayed in the hidden review");
  ctx.doc.dispatch("hodl:conceal");
  assert.ok(!markupOf(ctx.host).includes("zebra"));
});

test("review, undo and paste never overlap", () => {
  const ctx = setup();
  enterWord(ctx, "zebra");
  findById(ctx.host, "seed-picker-chips").childNodes[0].dispatchEvent({ type: "click" });
  const review = findById(ctx.host, "seed-picker-review");
  assert.equal(review.hidden, false);
  // While a word is under review, nothing else can change the entry.
  assert.equal(findById(ctx.host, "seed-picker-undo").hidden, true);
  assert.equal(findById(ctx.host, "seed-picker-paste-open").hidden, true);
  // Opening paste (or undoing) first closes the review and drops a shown word.
  const show = findById(ctx.host, "seed-picker-review-show");
  show.checked = true;
  show.dispatchEvent({ type: "change" });
  findById(ctx.host, "seed-picker-paste-open").dispatchEvent({ type: "click" });
  assert.equal(review.hidden, true);
  assert.equal(show.checked, false);
  assert.ok(!markupOf(ctx.host).includes("zebra"));
  // Opening review closes paste and empties its field.
  const textarea = findById(ctx.host, "seed-picker-paste-text");
  textarea.value = "abandon";
  findById(ctx.host, "seed-picker-chips").childNodes[0].dispatchEvent({ type: "click" });
  assert.equal(findById(ctx.host, "seed-picker-paste").hidden, true);
  assert.equal(textarea.value, "");
  findById(ctx.host, "seed-picker-undo").dispatchEvent({ type: "click" });
  assert.equal(ctx.entry.count, 0);
  assert.equal(review.hidden, true);
});

test("paste replaces everything only when the phrase is valid", () => {
  const ctx = setup();
  enterWord(ctx, "abandon");
  const before = Array.from(ctx.entry.indices);
  findById(ctx.host, "seed-picker-paste-open").dispatchEvent({ type: "click" });
  const textarea = findById(ctx.host, "seed-picker-paste-text");
  textarea.value = "abandon ability able about above absent absorb abstract absurd abuse access";
  findById(ctx.host, "seed-picker-paste-use").dispatchEvent({ type: "click" });
  assert.equal(ctx.entry.count, 1);
  assert.deepEqual(Array.from(ctx.entry.indices), before);
  assert.equal(textarea.value, "");
  assert.ok(!markupOf(ctx.host).includes("access"));

  textarea.value = "abandon ability able about above absent absorb abstract absurd abuse access zzzz";
  findById(ctx.host, "seed-picker-paste-use").dispatchEvent({ type: "click" });
  assert.equal(ctx.entry.count, 1);
  assert.deepEqual(Array.from(ctx.entry.indices), before);
  assert.equal(textarea.value, "");

  textarea.value = "abandon ability able about above absent absorb abstract absurd abuse access accident";
  findById(ctx.host, "seed-picker-paste-use").dispatchEvent({ type: "click" });
  assert.equal(ctx.entry.count, 12);
  assert.equal(ctx.entry.indices[0], 0);
  assert.equal(ctx.entry.indices[11], wordlist.indexOf("accident"));
  assert.equal(textarea.value, "");
});

test("more than 24 matches shows no buttons", () => {
  const ctx = setup();
  const field = findById(ctx.host, "seed-picker-prefix");
  field.value = "s";
  field.dispatchEvent({ type: "input" });
  assert.equal(findById(ctx.host, "seed-picker-matches").childNodes.length, 0);
  assert.equal(findById(ctx.host, "seed-picker-narrow").hidden, false);
});

test("conceal turns Show off and clears the fields", () => {
  const ctx = setup();
  enterWord(ctx, "abandon");
  findById(ctx.host, "seed-picker-chips").childNodes[0].dispatchEvent({ type: "click" });
  const show = findById(ctx.host, "seed-picker-review-show");
  show.checked = true;
  show.dispatchEvent({ type: "change" });
  const field = findById(ctx.host, "seed-picker-prefix");
  field.value = "ab";
  field.dispatchEvent({ type: "input" });
  findById(ctx.host, "seed-picker-paste-open").dispatchEvent({ type: "click" });
  const textarea = findById(ctx.host, "seed-picker-paste-text");
  textarea.value = "abandon";
  ctx.doc.dispatch("hodl:conceal");
  assert.equal(show.checked, false);
  assert.equal(field.value, "");
  assert.equal(textarea.value, "");
  assert.equal(findById(ctx.host, "seed-picker-matches").childNodes.length, 0);
});

test("destroy empties the host and leaves the entry intact", () => {
  const ctx = setup();
  enterWord(ctx, "abandon");
  ctx.picker.destroy();
  assert.equal(ctx.host.childNodes.length, 0);
  assert.equal(ctx.entry.count, 1);
  assert.equal(ctx.entry.wiped, false);
});

test("every visible string goes through translate", () => {
  const calls = [];
  const ctx = setup({ translate: (text) => { calls.push(text); return `«${text}»`; } });
  assert.ok(calls.length > 0);
  for (const id of ["seed-picker-help", "seed-picker-note", "seed-picker-progress", "seed-picker-undo", "seed-picker-paste-open"]) {
    const node = findById(ctx.host, id);
    assert.ok(node.textContent.startsWith("«"), `${id} is translated`);
    assert.ok(node.textContent.endsWith("»"), `${id} is translated`);
  }
});
