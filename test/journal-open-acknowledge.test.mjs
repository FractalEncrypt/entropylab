// Audit finding L6: a passwordless journal envelope is keyed by PBKDF2 over
// the empty password with a public fixed salt, so anyone can forge a file the
// open path accepts. The create flow already makes the user acknowledge a
// passwordless journal ("Ready to create without a password"); the open flow
// accepted a passwordless file silently. Opening without a password now
// requires one explicit acknowledgement before the entries are installed:
// the first press of "Open journal" reveals the no-protection notice and
// installs nothing; the second press on the same file completes the open.
// Password-protected opens are unchanged — AES-GCM already fails closed on
// forged files, wrong passwords, and iterations tampering.
//
// The real app.js functions run under a stub DOM; the real journal.js crypto
// runs against a low-cost test file (the on-disk iteration floor is honored).
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  JOURNAL_MIN_ITERATIONS,
  addEntry,
  createDocument,
  deriveJournalKeys,
  emptyDocument,
  openDocument,
  sealDocument,
} from "../src/js/journal.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSlice(name) {
  let start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  if (app.slice(start - 6, start) === "async ") start -= 6;
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

const varLine = (name) => {
  const line = app.match(new RegExp(`var ${name} = [^\\n]+;`)) || app.match(new RegExp(`var hodlJournalKeys = null, hodlJournalDoc = null[^\\n]*;`));
  assert.ok(line, `var ${name}`);
  return line[0];
};

const source = [
  varLine("hodlJournalKeys"),
  varLine("hodlJournalDoc"),
  varLine("hodlJournalFileText"),
  varLine("hodlJournalOpenReadyFor"),
  varLine("hodlJournalGeneration"),
  varLine("hodlJournalFileRead"),
  varLine("hodlJournalTool"),
  loadSlice("hodlJournalError"),
  loadSlice("hodlJournalChooseFile"),
  loadSlice("hodlJournalUnlock"),
].join("\n");

const PASSWORD = "correct horse battery staple";
const noop = () => {};

const loadApp = ({ password = "", onOpen = (file, password) => openDocument(file, password) } = {}) => {
  const fields = {
    "journal-open-password": { value: password },
    "journal-error": { textContent: "" },
    "journal-open-ready": { hidden: true },
  };
  const documentStub = { getElementById: (id) => fields[id] ?? null };
  const api = new Function(
    "hodlJournalOpenDocument", "document",
    "hodlKeyManagerReset", "hodlJournalWipeNotebook", "hodlJournalHideEditor",
    "hodlJournalShowWork", "hodlShowJournalTool", "hodlJournalLog",
    "hodlJournalBackfillDerivedKeys", "hodlJournalDiscardOpened",
    `${source}; return {
      choose: hodlJournalChooseFile,
      unlock: hodlJournalUnlock,
      setFileText: (text) => { hodlJournalFileText = text; },
      state: () => ({ keys: hodlJournalKeys, doc: hodlJournalDoc }),
      openReadyVisible: () => { const el = document.getElementById("journal-open-ready"); return el ? !el.hidden : false; },
    };`,
  )(
    onOpen, documentStub,
    noop, noop, noop,
    noop, noop, noop,
    noop, noop,
  );
  return { ...api, error: () => fields["journal-error"].textContent };
};

const sealFile = async (password, label) => {
  const keys = await deriveJournalKeys(password, JOURNAL_MIN_ITERATIONS);
  const doc = emptyDocument();
  addEntry(doc, { method: "seed", input: "", phrase: "abandon ".repeat(11).trim() + " about", label });
  return JSON.stringify(await sealDocument(doc, keys));
};

const passwordlessFile = await sealFile("", "passwordless entry");
const protectedFile = await sealFile(PASSWORD, "protected entry");

test("a passwordless file is not installed until the open is acknowledged (audit L6)", async () => {
  const env = loadApp();
  env.setFileText(passwordlessFile);
  await env.unlock();
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the first open installs nothing");
  assert.ok(env.openReadyVisible(), "the no-protection acknowledgement is shown");
  await env.unlock();
  assert.ok(env.state().keys, "the acknowledged open installs the journal");
  assert.ok(!env.openReadyVisible(), "the acknowledgement clears once accepted");
});

test("a password-protected file opens on the first press, as before (audit L6)", async () => {
  const env = loadApp({ password: PASSWORD });
  env.setFileText(protectedFile);
  await env.unlock();
  assert.ok(env.state().keys, "the protected open installs the journal");
  assert.ok(!env.openReadyVisible(), "no acknowledgement is offered for a protected file");
});

test("a fresh file choice resets a pending passwordless acknowledgement (audit L6)", async () => {
  const env = loadApp();
  env.setFileText(passwordlessFile);
  await env.unlock();
  assert.ok(env.openReadyVisible(), "armed for the first file");
  await env.choose({ text: async () => passwordlessFile.replace("passwordless entry", "other entry") });
  await new Promise((resolve) => setTimeout(resolve, 0));
  await env.unlock();
  assert.deepEqual(env.state(), { keys: null, doc: null }, "the second file is not installed on its first open");
  assert.ok(env.openReadyVisible(), "the acknowledgement is armed for the new file, not inherited");
});
