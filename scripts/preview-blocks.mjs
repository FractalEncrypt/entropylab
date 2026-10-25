// Preview blocks let unreleased markup merge into rock hidden: the release
// build strips everything between `<!-- preview -->` and `<!-- /preview -->`,
// a preview build keeps the contents and drops only the markers. The markers
// must be balanced and never nested, so a stray or unclosed marker fails the
// build instead of leaking half a feature into the release artifact.
const OPEN = "<!-- preview -->";
const CLOSE = "<!-- /preview -->";

export function applyPreviewBlocks(html, preview) {
  const out = [];
  let inside = false;
  for (const line of html.split("\n")) {
    const marker = line.trim();
    if (marker === OPEN) {
      if (inside) throw new Error("preview blocks are unbalanced");
      inside = true;
      continue;
    }
    if (marker === CLOSE) {
      if (!inside) throw new Error("preview blocks are unbalanced");
      inside = false;
      continue;
    }
    if (inside && !preview) continue;
    out.push(line);
  }
  if (inside) throw new Error("preview blocks are unbalanced");
  return out.join("\n");
}
