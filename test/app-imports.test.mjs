// app.js import guard: every helper app.js calls must actually be imported.
//
// The unit suites load slices of app.js with the names they need injected, so
// a call to a helper that was never imported passes every test and only throws
// ReferenceError in the real page. That is how the normalizeVinWitness send
// flow shipped broken: bip352.js exported it, app.js called it, and no suite
// noticed the missing import. This guard is the static analogue of
// ci-completeness.test.mjs: it diffs the bare calls app.js makes against the
// names it imports and declares, fails on any call to a name an imported
// module exports but app.js never brought in, and fails on dead imports so
// the import block cannot rot.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

// Imported local names app.js is allowed to never use (side-effect or
// deliberately unused imports). hodlFillLocaleSelect is imported with the
// other i18n helpers but is not referenced anywhere in app.js at rock.
const DEAD_IMPORT_ALLOWLIST = Object.freeze(["hodlFillLocaleSelect"]);

const escapeRe = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const isLocalJs = (specifier) => specifier.startsWith("./") && specifier.endsWith(".js");

// A regex literal may follow an operator, an opener or one of these keywords;
// anywhere else a "/" is division. Good enough to keep quoted regex bodies
// from being mistaken for string literals.
const REGEX_AFTER = new Set(["return", "typeof", "case", "delete", "void", "in", "of", "new", "instanceof", "yield", "await", "throw", "else", "do"]);

// Blank comments and string/regex/template-literal text to spaces so call
// sites cannot hide inside prose, copy or patterns. Newlines survive so line
// numbers stay stable; template ${...} expressions stay because they are real
// code and hold most of the page's hodlT`...` calls. Length and offsets are
// preserved, so a position in the output indexes the same byte in the source.
function scan(src) {
  const out = src.split("");
  const blank = (i) => { if (out[i] !== "\n") out[i] = " "; };
  const stack = [{ mode: "code", braces: 0 }];
  let prevSig = "";
  let word = "";
  let lastWord = "";
  let i = 0;
  while (i < src.length) {
    const state = stack[stack.length - 1];
    const c = src[i];
    const d = src[i + 1];
    if (state.mode === "code") {
      if (c === "/" && d === "/") { blank(i); blank(i + 1); stack.push({ mode: "line" }); i += 2; continue; }
      if (c === "/" && d === "*") { blank(i); blank(i + 1); stack.push({ mode: "block" }); i += 2; continue; }
      if (/[\w$]/.test(c)) { word += c; i += 1; continue; }
      if (word) { lastWord = word; word = ""; prevSig = "x"; }
      if (c === "'" || c === '"') { blank(i); stack.push({ mode: "string", quote: c }); prevSig = "x"; i += 1; continue; }
      if (c === "`") { blank(i); stack.push({ mode: "template" }); prevSig = "x"; i += 1; continue; }
      if (c === "/") {
        if (prevSig === "" || "([{,;:=!&|?+-*%^~<>".includes(prevSig) || REGEX_AFTER.has(lastWord)) {
          blank(i);
          stack.push({ mode: "regex", inClass: false });
        }
        prevSig = "/";
        i += 1;
        continue;
      }
      if (c === "{") state.braces += 1;
      else if (c === "}") {
        if (state.braces === 0 && stack.length > 1) { blank(i); stack.pop(); i += 1; continue; } // closes a template ${...}
        state.braces -= 1;
      }
      if (!/\s/.test(c)) prevSig = c;
      i += 1;
      continue;
    }
    if (state.mode === "line") {
      if (c === "\n") { stack.pop(); i += 1; continue; }
      blank(i); i += 1; continue;
    }
    if (state.mode === "block") {
      if (c === "*" && d === "/") { blank(i); blank(i + 1); stack.pop(); i += 2; continue; }
      blank(i); i += 1; continue;
    }
    if (state.mode === "string") {
      if (c === "\\") { blank(i); blank(i + 1); i += 2; continue; }
      blank(i);
      if (c === state.quote) { stack.pop(); prevSig = "x"; }
      i += 1;
      continue;
    }
    if (state.mode === "regex") {
      if (c === "\\") { blank(i); blank(i + 1); i += 2; continue; }
      if (c === "[") state.inClass = true;
      else if (c === "]") state.inClass = false;
      blank(i);
      if (c === "/" && !state.inClass) { stack.pop(); prevSig = "x"; }
      i += 1;
      continue;
    }
    // template-literal text: blanked, but ${...} re-enters code mode
    if (c === "\\") { blank(i); blank(i + 1); i += 2; continue; }
    if (c === "`") { blank(i); stack.pop(); prevSig = "x"; i += 1; continue; }
    if (c === "$" && d === "{") { blank(i); blank(i + 1); stack.push({ mode: "code", braces: 0 }); i += 2; continue; }
    blank(i); i += 1;
  }
  return out.join("");
}

// Static imports, parsed from the blanked source; the specifier string is
// blanked there, so its offsets (the /d match indices) are read back from the
// raw source. Records the LOCAL name of each binding (c for `b as c`).
function parseImports(code, raw) {
  const imports = [];
  for (const m of code.matchAll(/\bimport\s+([^;]*?)\s+from(\s+);/gd)) {
    const [start, end] = m.indices[2];
    const specifier = raw.slice(start, end).trim().replace(/^["']|["']$/g, "");
    for (const name of parseImportClause(m[1])) imports.push({ ...name, specifier });
  }
  return imports;
}

function parseImportClause(clause) {
  const names = [];
  const rest = clause.trim();
  const namespace = rest.match(/^\*\s+as\s+([A-Za-z_$][\w$]*)$/);
  if (namespace) return [{ local: namespace[1], imported: "*" }];
  const named = rest.match(/\{([\s\S]*)\}/);
  const defaultName = (named ? rest.slice(0, named.index) : rest).replace(/,\s*$/, "").trim();
  if (/^[A-Za-z_$][\w$]*$/.test(defaultName)) names.push({ local: defaultName, imported: "default" });
  if (!named) return names;
  for (const entry of named[1].split(",")) {
    const part = entry.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
    if (part) names.push({ local: part[2] ?? part[1], imported: part[1] });
  }
  return names;
}

// Names a module exports: export function/const/let/class X and
// export { a, b as c } (the exported name, i.e. c for `b as c`).
function parseExports(code) {
  const names = new Set();
  const addPattern = (pattern) => {
    if (pattern.startsWith("{") || pattern.startsWith("[")) {
      for (const inner of pattern.matchAll(/([A-Za-z_$][\w$]*)\s*(?![\w$:])/g)) names.add(inner[1]);
    } else names.add(pattern);
  };
  for (const m of code.matchAll(/\bexport\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/\bexport\s+class\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/\bexport\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*|\{[^;]*?\}|\[[^;]*?\])/g)) addPattern(m[1]);
  for (const m of code.matchAll(/\bexport\s*\{([\s\S]*?)\}/g)) {
    for (const entry of m[1].split(",")) {
      const part = entry.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
      if (part) names.add(part[2] ?? part[1]);
    }
  }
  return names;
}

// Names app.js declares at top level (function, var/let/const, class).
function parseDeclared(code) {
  const depths = braceDepths(code);
  const names = new Set();
  for (const m of code.matchAll(/\b(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/g)) if (depths[m.index] === 0) names.add(m[1]);
  for (const m of code.matchAll(/\bclass\s+([A-Za-z_$][\w$]*)/g)) if (depths[m.index] === 0) names.add(m[1]);
  for (const m of code.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*|\{[^;]*?\}|\[[^;]*?\])/g)) {
    if (depths[m.index] !== 0) continue;
    if (m[1].startsWith("{") || m[1].startsWith("[")) {
      for (const inner of m[1].matchAll(/([A-Za-z_$][\w$]*)\s*(?![\w$:])/g)) names.add(inner[1]);
    } else names.add(m[1]);
  }
  return names;
}

function braceDepths(code) {
  const depths = new Int32Array(code.length);
  let depth = 0;
  for (let i = 0; i < code.length; i++) {
    depths[i] = depth;
    if (code[i] === "{") depth += 1;
    else if (code[i] === "}") depth = Math.max(0, depth - 1);
  }
  return depths;
}

// Bare calls `X(...)` to names exported by a module app.js imports from but
// app.js itself neither imports nor declares. Method calls (x.X()) and
// function/accessor definitions are not calls.
function findUnimportedCalls(code, imported, declared, exportedBy) {
  const found = new Map();
  for (const name of exportedBy.keys()) {
    if (imported.has(name) || declared.has(name)) continue;
    const re = new RegExp(`(?<![\\w$.])${escapeRe(name)}\\s*\\(`, "g");
    for (const m of code.matchAll(re)) {
      const before = code.slice(Math.max(0, m.index - 40), m.index);
      if (/(?:async\s+)?function\s*\*?\s*$/.test(before)) continue;
      if (/\b(?:get|set|static|async)\s*$/.test(before)) continue;
      found.set(name, code.slice(0, m.index).split("\n").length);
      break;
    }
  }
  return [...found.entries()].map(([name, line]) => ({ name, line }));
}

// Every way app.js's import block can rot, so the same check can be exercised
// against doctored sources below. A guard that cannot fail is not a guard.
function importProblems(appSrc, loadModule, allowlist) {
  const code = scan(appSrc);
  const imports = parseImports(code, appSrc);
  const imported = new Set(imports.map((entry) => entry.local));
  const declared = parseDeclared(code);
  const exportedBy = new Map();
  const problems = [];
  const localModules = [...new Set(imports.map((entry) => entry.specifier).filter(isLocalJs))].sort();
  for (const specifier of localModules) {
    const src = loadModule(specifier);
    if (src == null) {
      problems.push(`imports from ${specifier}, which does not exist`);
      continue;
    }
    for (const name of parseExports(scan(src))) {
      if (!exportedBy.has(name)) exportedBy.set(name, new Set());
      exportedBy.get(name).add(specifier);
    }
  }
  for (const { name, line } of findUnimportedCalls(code, imported, declared, exportedBy)) {
    problems.push(`calls ${name}() at line ${line} but neither imports nor declares it (exported by ${[...exportedBy.get(name)].join(", ")}); the page would throw ReferenceError`);
  }
  const body = code.replace(/\bimport\s+[^;]*;/g, (statement) => statement.replace(/[^\n]/g, " "));
  for (const { local, specifier } of imports) {
    if (allowlist.includes(local)) continue;
    if (!new RegExp(`(?<![\\w$])${escapeRe(local)}(?![\\w$])`).test(body)) {
      problems.push(`imports ${local} from ${specifier} but never uses it; remove the import or add it to DEAD_IMPORT_ALLOWLIST`);
    }
  }
  return problems.sort();
}

const loadModule = (specifier) => {
  const path = join("src", "js", specifier);
  return existsSync(join(root, path)) ? read(path) : null;
};

test("app.js imports every exported helper it calls and uses every name it imports", () => {
  const appSrc = read("src/js/app.js");
  const imports = parseImports(scan(appSrc), appSrc);
  assert.ok(imports.length > 50, `fixture: expected app.js's import block, found ${imports.length} imported names`);
  const localModules = new Set(imports.map((entry) => entry.specifier).filter(isLocalJs));
  assert.ok(localModules.size > 20, `fixture: expected app.js to import from many local modules, found ${localModules.size}`);
  assert.deepEqual(importProblems(appSrc, loadModule, DEAD_IMPORT_ALLOWLIST), []);
});

test("the import guard detects its own failure modes", () => {
  const miniApp = [
    "import {",
    "  usedFn,",
    "  aliased as localFn,",
    "  tplFn,",
    '} from "./mod.js";',
    'import { deadFn } from "./mod.js";',
    "",
    "function declaredFn() {}",
    'const note = "missingFn() inside a string is not a call";',
    "// missingFn(); inside a comment is not a call",
    "usedFn();",
    "localFn();",
    "declaredFn();",
    "obj.missingFn();",
    "missingFn();",
    "const html = `label ${tplFn()} tail`;",
    "",
  ].join("\n");
  const miniMod = [
    "export function usedFn() {}",
    "export function aliased() {}",
    "export function tplFn() {}",
    "export function deadFn() {}",
    "export function missingFn() {}",
    "",
  ].join("\n");
  const load = (specifier) => (specifier === "./mod.js" ? miniMod : null);
  const problems = importProblems(miniApp, load, []);
  assert.ok(
    problems.some((problem) => problem.includes("missingFn") && problem.includes("line 15") && problem.includes("./mod.js")),
    `a bare call to an exported but un-imported name must be reported with its first line: ${problems}`,
  );
  assert.ok(
    problems.some((problem) => problem.includes("deadFn") && problem.includes("never uses")),
    "an import that is never used must be reported",
  );
  for (const safe of ["usedFn", "localFn", "aliased", "tplFn", "declaredFn"]) {
    assert.ok(!problems.some((problem) => problem.includes(safe)), `${safe} is imported, declared, aliased or method-called and must not be reported`);
  }
  const allowed = importProblems(miniApp, load, ["deadFn"]);
  assert.ok(!allowed.some((problem) => problem.includes("deadFn")), "an allowlisted dead import must pass");
  assert.ok(allowed.some((problem) => problem.includes("missingFn")), "the allowlist must not hide missing imports");
});
