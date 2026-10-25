// Preview blocks hide unreleased markup from the release artifact: the release
// build strips everything between `<!-- preview -->` and `<!-- /preview -->`,
// a preview build keeps the contents and drops only the markers. The markers
// must be balanced and never nested, so a stray or unclosed marker fails the
// build instead of leaking half a feature into the release artifact.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

test("a preview block is removed from a release build and kept in a preview build", () => {
  const html = "before\n<!-- preview -->\nfeature\n<!-- /preview -->\nafter";
  assert.equal(applyPreviewBlocks(html, false), "before\nafter");
  assert.equal(applyPreviewBlocks(html, true), "before\nfeature\nafter");
});

test("multiple blocks work and text outside them is untouched", () => {
  const html = "a\n<!-- preview -->\nb\n<!-- /preview -->\nc\n<!-- preview -->\nd\n<!-- /preview -->\ne";
  assert.equal(applyPreviewBlocks(html, false), "a\nc\ne");
  assert.equal(applyPreviewBlocks(html, true), "a\nb\nc\nd\ne");
});

test("an unclosed marker throws", () => {
  assert.throws(() => applyPreviewBlocks("a\n<!-- preview -->\nb", false), /preview blocks are unbalanced/);
  assert.throws(() => applyPreviewBlocks("a\n<!-- preview -->\nb", true), /preview blocks are unbalanced/);
});

test("a nested marker throws", () => {
  const html = "<!-- preview -->\na\n<!-- preview -->\nb\n<!-- /preview -->\nc\n<!-- /preview -->";
  assert.throws(() => applyPreviewBlocks(html, false), /preview blocks are unbalanced/);
  assert.throws(() => applyPreviewBlocks(html, true), /preview blocks are unbalanced/);
});

test("a stray closing marker throws", () => {
  assert.throws(() => applyPreviewBlocks("a\n<!-- /preview -->\nb", false), /preview blocks are unbalanced/);
  assert.throws(() => applyPreviewBlocks("a\n<!-- /preview -->\nb", true), /preview blocks are unbalanced/);
});

test("an input with no markers is returned unchanged", () => {
  const html = "<div>no markers here</div>\n<p>still here</p>\n";
  assert.equal(applyPreviewBlocks(html, false), html);
  assert.equal(applyPreviewBlocks(html, true), html);
});

test("build.mjs defines __ENTROPYLAB_PREVIEW__, strips both shell copies and refuses --preview without an outside --out", () => {
  const build = readFileSync(join(root, "scripts", "build.mjs"), "utf8");
  assert.match(build, /__ENTROPYLAB_PREVIEW__:\s*preview\s*\?\s*"true"\s*:\s*"false"/);
  assert.match(build, /--preview requires --out outside the repository root/);
  assert.match(build, /applyPreviewBlocks\(read\("shell\.html"\), preview\)/);
  assert.match(build, /plugins:\s*\[previewHtml\]/);
});
