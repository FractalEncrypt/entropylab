// Tests for the Lightning invoice/offer card (#ln-inv-card): the shell
// markup, BOLT11 and BOLT12 rendering, the payment-secret reveal, the
// wrong-chain banner, escaping, refusals, clearing, and the QR wiring.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toWords } from "../src/js/bech32.js";
import { hex } from "../src/js/coders.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hodlInitLn, hodlLnWipeMem } from "../src/js/lightning.js";
import { MiniDocument } from "./mini-dom.mjs";

await secp256k1Ready;

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const shell = read("src/shell.html");
const appSource = read("src/js/app.js");

// BOLT11 spec example: "Please send $3 for a cup of coffee to the same peer,
// within one minute". Node id, payment hash and secret are the spec's
// published values (test/bolt11.test.mjs).
const COFFEE = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const COFFEE_NODE_ID = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad";
const COFFEE_PAYMENT_HASH = "0001020304050607080900010203040506070809000102030405060708090102";
const COFFEE_SECRET = "1111111111111111111111111111111111111111111111111111111111111111";

// BOLT11 spec example: the corrupted-checksum invoice (test/bolt11.test.mjs).
const BAD_CHECKSUM = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt";

// BOLT12 spec offer (test/bolt12.test.mjs): amount, description, issuer id.
const OFFER = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";

// BOLT12 spec offer with one blinded path (test/bolt12.test.mjs).
const OFFER_ONE_PATH = "lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zyg3vggzamrjghtt05kvkvpcp0a79gmy3nt6jsn98ad2xs8de6sl9qmgvcvs";

// BOLT12 spec testnet offer (test/bolt12.test.mjs): chains = [testnet].
const OFFER_TESTNET = "lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj";

const PUBKEY = "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619";

// A checksum-free BOLT12 encoder (the envelope has no checksum), so a
// description can carry attacker-controlled markup.
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const bigsize = (n) => {
  if (n < 0xfd) return [n];
  if (n <= 0xffff) return [0xfd, (n >> 8) & 0xff, n & 0xff];
  return [0xfe, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
};
const tlvBytes = (fields) => {
  const out = [];
  for (const [type, valueHex] of fields) {
    const value = hex.decode(valueHex);
    out.push(...bigsize(type), ...bigsize(value.length), ...value);
  }
  return new Uint8Array(out);
};
const encode = (hrp, fields) => hrp + "1" + toWords(tlvBytes(fields)).map((w) => BECH32_CHARSET[w]).join("");
const ESCAPE_OFFER = encode("lno", [
  [10, hex.encode(new TextEncoder().encode("<img src=x>"))],
  [22, PUBKEY],
]);

// The invoice card wired over a mini DOM. `#ln-go` is absent, so the node
// identity card is not initialized; the invoice card must still wire.
function invPage(network = "mainnet", qrSvg = () => "") {
  const page = new MiniDocument();
  globalThis.document = page;
  page.body.innerHTML = '<select id="ln-network"><option value="mainnet">Mainnet</option><option value="testnet">Testnet</option></select>'
    + '<textarea id="ln-inv-input"></textarea>'
    + '<button id="ln-inv-decode" type="button"></button>'
    + '<button id="ln-inv-clear" type="button"></button>'
    + '<p id="ln-inv-error" class="err" role="alert"></p>'
    + '<div id="ln-inv-out" aria-live="polite"></div>';
  page.getElementById("ln-network").value = network;
  hodlInitLn({ journalLog() {}, copyIcon: () => "", qrSvg });
  hodlLnWipeMem();
  return page;
}

const decode = (page, text) => {
  page.getElementById("ln-inv-input").value = text;
  page.getElementById("ln-inv-decode").click();
};

test("the invoice card ships in the shell after #ln-card, with its controls", () => {
  const order = ["ln-card", "ln-inv-card", "ln-inv-input", "ln-inv-decode", "ln-inv-clear", "ln-inv-error", "ln-inv-out"];
  let last = -1;
  for (const id of order) {
    const at = shell.indexOf(`id="${id}"`);
    assert.ok(at >= 0, `${id} is missing from the shell`);
    assert.ok(at > last, `${id} is out of order`);
    last = at;
  }
  assert.match(shell, /<section[^>]*id="ln-inv-card"[^>]*class="card no-print tool-card"[^>]*role="tabpanel"[^>]*hidden/);
  assert.match(shell, /id="ln-inv-error"[^>]*class="err"[^>]*role="alert"/);
  assert.match(shell, /id="ln-inv-out"[^>]*aria-live="polite"/);
});

test("a BOLT11 invoice renders amount, payment hash, node id, and the green signature line", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    const html = out.innerHTML;
    assert.ok(html.includes("0.0025"), "amount in BTC");
    assert.ok(html.includes("250000000"), "amount in msat");
    assert.ok(html.includes(COFFEE_PAYMENT_HASH), "payment hash");
    assert.ok(html.includes(COFFEE_NODE_ID), "recovered node id");
    assert.ok(html.includes("Signature valid"), "green signature line");
    assert.ok(html.includes('id="ln-inv-payment-hash"'), "payment hash copy button");
    assert.ok(html.includes('id="ln-inv-node-id"'), "node id copy button");
  } finally {
    delete globalThis.document;
  }
});

test("the payment secret stays hidden until #ln-inv-reveal is checked", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    const out = page.getElementById("ln-inv-out");
    assert.ok(!out.textContent.includes(COFFEE_SECRET), "the secret is not rendered before reveal");
    const reveal = page.getElementById("ln-inv-reveal");
    assert.ok(reveal, "the reveal checkbox is rendered");
    reveal.checked = true;
    reveal.dispatchEvent({ type: "change" });
    assert.ok(out.textContent.includes(COFFEE_SECRET), "the secret is rendered after reveal");
    assert.ok(out.innerHTML.includes('id="ln-inv-payment-secret"'), "secret copy button");
  } finally {
    delete globalThis.document;
  }
});

test("a BOLT12 offer renders the kind noun, the honesty line, and the muted signature line", () => {
  const page = invPage();
  try {
    decode(page, OFFER);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.ok(out.textContent.includes("Offer"), "kind noun");
    assert.match(out.innerHTML, /class="muted">Signature not checked/, "muted signature line");
    assert.ok(out.textContent.includes("publishes its signing key in the clear"), "published-key honesty line");
    assert.ok(out.innerHTML.includes('id="ln-inv-issuer-id"'), "issuer id copy button");
  } finally {
    delete globalThis.document;
  }
});

test("a blinded BOLT12 offer says the recipient node id is not in it", () => {
  const page = invPage();
  try {
    decode(page, OFFER_ONE_PATH);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.ok(out.textContent.includes("Recipient node id is not in this Offer"), "blinded honesty line");
    assert.ok(out.textContent.includes("counted, never followed"), "paths are counted, never followed");
  } finally {
    delete globalThis.document;
  }
});

test("a testnet offer on a mainnet page shows the .warn banner and still decodes", () => {
  const page = invPage("mainnet");
  try {
    decode(page, OFFER_TESTNET);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.match(out.innerHTML, /class="warn"/);
    assert.ok(out.textContent.includes("testnet"), "names the invoice's chain");
    assert.ok(out.textContent.includes("mainnet"), "names the page network");
    assert.ok(out.textContent.includes("Offer"), "still decoded");
  } finally {
    delete globalThis.document;
  }
});

test("a mainnet BOLT11 invoice on a testnet page shows the .warn banner and still decodes", () => {
  const page = invPage("testnet");
  try {
    decode(page, COFFEE);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.match(out.innerHTML, /class="warn"/);
    assert.ok(out.textContent.includes("mainnet"), "names the invoice's network");
    assert.ok(out.textContent.includes(COFFEE_PAYMENT_HASH), "still decoded");
  } finally {
    delete globalThis.document;
  }
});

test("an attacker-controlled description is escaped as text, not markup", () => {
  const page = invPage();
  try {
    decode(page, ESCAPE_OFFER);
    const out = page.getElementById("ln-inv-out");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    assert.equal(out.querySelector("img"), null, "no element was created from the description");
    assert.ok(out.textContent.includes("<img src=x>"), "the description is shown as text");
  } finally {
    delete globalThis.document;
  }
});

test("a corrupted checksum shows a keyed error, no rows, and no echo of the input", () => {
  const page = invPage();
  try {
    decode(page, BAD_CHECKSUM);
    const error = page.getElementById("ln-inv-error").textContent;
    assert.ok(error.length > 0, "an error is shown");
    assert.ok(!error.includes(BAD_CHECKSUM), "the input is never echoed");
    assert.equal(page.getElementById("ln-inv-out").innerHTML, "", "no rows are rendered");
  } finally {
    delete globalThis.document;
  }
});

test("Clear empties the input, the output, the error, and the reveal state", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    const reveal = page.getElementById("ln-inv-reveal");
    reveal.checked = true;
    reveal.dispatchEvent({ type: "change" });
    assert.ok(page.getElementById("ln-inv-out").innerHTML.length > 0);
    page.getElementById("ln-inv-clear").click();
    assert.equal(page.getElementById("ln-inv-input").value, "");
    assert.equal(page.getElementById("ln-inv-out").innerHTML, "");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
    // The reveal state is reset: decoding again hides the secret.
    decode(page, COFFEE);
    assert.ok(!page.getElementById("ln-inv-out").textContent.includes(COFFEE_SECRET));
  } finally {
    delete globalThis.document;
  }
});

test("hodlLnWipeMem clears the invoice card", () => {
  const page = invPage();
  try {
    decode(page, COFFEE);
    assert.ok(page.getElementById("ln-inv-out").innerHTML.length > 0);
    hodlLnWipeMem();
    assert.equal(page.getElementById("ln-inv-out").innerHTML, "");
    assert.equal(page.getElementById("ln-inv-error").textContent, "");
  } finally {
    delete globalThis.document;
  }
});

test("the QR block renders the user's own pasted string", () => {
  let seen = null;
  const page = invPage("mainnet", (text) => {
    seen = text;
    return '<svg id="qr-test"></svg>';
  });
  try {
    decode(page, COFFEE);
    assert.equal(seen, COFFEE, "the QR input is the pasted string");
    assert.ok(page.getElementById("ln-inv-out").innerHTML.includes('id="qr-test"'), "the QR is on screen");
  } finally {
    delete globalThis.document;
  }
});

test("app.js injects the QR renderer into hodlInitLn", () => {
  assert.match(appSource, /hodlInitLn\(\{[^}]*qrSvg: hodlQrSvg/);
});
