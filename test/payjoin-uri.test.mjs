import test from "node:test";
import assert from "node:assert/strict";

import { decodePayjoinUri } from "../src/js/payjoin-uri.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";

await secp256k1Ready;

// BIP 77's own example URI. Expected values are decoded by hand from the
// BIP's bech32-no-checksum rules (HRP + right-most '1' + 5-bit words, no
// checksum), not by running the code under test.
const BIP77_EXAMPLE =
  "bitcoin:tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p?amount=0.00666666&pjos=0&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ%23EX1WKV8CEC-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

const BIP77_PLUS =
  "bitcoin:tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p?amount=0.00666666&pjos=0&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ%23EX1WKV8CEC+OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ+RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

const EXPECTED = {
  address: "tb1q6q6de88mj8qkg0q5lupmpfexwnqjsr4d2gvx2p",
  amount: "0.00666666",
  pjos: "0",
  directory: { origin: "https://payjo.in", host: "payjo.in" },
  shortId: "TXJCGKTKXLUUZ",
  expiresAt: 1736218741,
  ohttp: {
    keyId: 1,
    publicKeyHex: "03ba167657cc6854e57c39d3188b5504a674370bcde264989190eea35c4145cd4c",
  },
  receiverKeyHex: "03db28458c699c002fe03bd4a020d037b7f286e2d65b04ebb6cb808f50f20c1596",
};

test("BIP 77 example URI decodes to the spec's values", () => {
  const decoded = decodePayjoinUri(BIP77_EXAMPLE, 1736218740);
  assert.equal(decoded.kind, "v2");
  assert.equal(decoded.address, EXPECTED.address);
  assert.equal(decoded.amount, EXPECTED.amount);
  assert.equal(decoded.pjos, EXPECTED.pjos);
  assert.deepEqual(decoded.directory, EXPECTED.directory);
  assert.equal(decoded.shortId, EXPECTED.shortId);
  assert.equal(decoded.expiresAt, EXPECTED.expiresAt);
  assert.deepEqual(decoded.ohttp, EXPECTED.ohttp);
  assert.equal(decoded.receiverKeyHex, EXPECTED.receiverKeyHex);
  assert.deepEqual(decoded.warnings, []);
});

test("the legacy + separator decodes identically and is flagged", () => {
  const decoded = decodePayjoinUri(BIP77_PLUS, 1736218740);
  assert.equal(decoded.kind, "v2");
  assert.equal(decoded.address, EXPECTED.address);
  assert.equal(decoded.amount, EXPECTED.amount);
  assert.equal(decoded.pjos, EXPECTED.pjos);
  assert.deepEqual(decoded.directory, EXPECTED.directory);
  assert.equal(decoded.shortId, EXPECTED.shortId);
  assert.equal(decoded.expiresAt, EXPECTED.expiresAt);
  assert.deepEqual(decoded.ohttp, EXPECTED.ohttp);
  assert.equal(decoded.receiverKeyHex, EXPECTED.receiverKeyHex);
  assert.ok(decoded.warnings.includes("plus-separator-legacy"));
});

test("expired vs not expired is decided by the caller-supplied now", () => {
  assert.ok(!decodePayjoinUri(BIP77_EXAMPLE, 1736218740).warnings.includes("expired"));
  assert.ok(!decodePayjoinUri(BIP77_EXAMPLE, 1736218741).warnings.includes("expired"));
  assert.ok(decodePayjoinUri(BIP77_EXAMPLE, 1736218742).warnings.includes("expired"));
});

test("wrong parameter order is refused for the - separator", () => {
  const wrongOrder = BIP77_EXAMPLE.replace(
    "EX1WKV8CEC-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ",
    "OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ-EX1WKV8CEC"
  );
  assert.throws(() => decodePayjoinUri(wrongOrder, 1736218740), /order/i);
});

test("duplicate fragment parameters are refused", () => {
  const duplicate = BIP77_EXAMPLE.replace("EX1WKV8CEC-OH1", "EX1WKV8CEC-EX1WKV8CEC-OH1");
  assert.throws(() => decodePayjoinUri(duplicate, 1736218740), /duplicate/i);
});

test("a missing RK parameter is refused", () => {
  const missingRk = BIP77_EXAMPLE.replace(
    "-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV",
    ""
  );
  assert.throws(() => decodePayjoinUri(missingRk, 1736218740), /missing.*RK/i);
});

test("an RK value that is not a compressed secp256k1 point is refused", () => {
  // 0x02 followed by 32 zero bytes: x = 0, x^3 + 7 = 7, and 7 is not a
  // quadratic residue mod secp256k1's p, so this is off-curve.
  const badRk = BIP77_EXAMPLE.replace(
    "RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV",
    "RK1QG" + "Q".repeat(51)
  );
  assert.throws(() => decodePayjoinUri(badRk, 1736218740), /secp256k1|curve|point/i);
});

test("a Short ID with a nonzero padding bit is refused", () => {
  const badPadding = BIP77_EXAMPLE.replace("TXJCGKTKXLUUZ", "TXJCGKTKXLUUP");
  assert.throws(() => decodePayjoinUri(badPadding, 1736218740), /padding/i);
});

test("a truncated EX value is refused", () => {
  const truncated = BIP77_EXAMPLE.replace("EX1WKV8CEC", "EX1WKV8CE");
  assert.throws(() => decodePayjoinUri(truncated, 1736218740), /padding|EX/i);
});

test("a non-bech32 character in the fragment is refused", () => {
  const nonBech32 = BIP77_EXAMPLE.replace("EX1WKV8CEC", "EX1WKV8BEC");
  assert.throws(() => decodePayjoinUri(nonBech32, 1736218740), /bech32/i);
});

test("a lowercase fragment is refused", () => {
  const lowercase = BIP77_EXAMPLE.replace("EX1WKV8CEC", "ex1wkv8cec");
  assert.throws(() => decodePayjoinUri(lowercase, 1736218740), /uppercase/i);
});

test("a v1 URI reports the endpoint and the direct-post warning", () => {
  const decoded = decodePayjoinUri(
    "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com/payjoin",
    1736218740
  );
  assert.equal(decoded.kind, "v1");
  assert.equal(decoded.address, "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
  assert.equal(decoded.amount, "1");
  assert.equal(decoded.endpoint, "https://example.com/payjoin");
  assert.deepEqual(decoded.warnings, ["v1-direct-endpoint"]);
});

test("a v1 http endpoint is refused unless it is a .onion", () => {
  assert.throws(
    () => decodePayjoinUri("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=http://example.com"),
    /https|onion/i
  );
  const onion = decodePayjoinUri(
    "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=http://example.onion/payjoin",
    1736218740
  );
  assert.equal(onion.kind, "v1");
});

test("a v2 mailbox URL must be https or http on .onion", () => {
  const plainHttp = BIP77_EXAMPLE.replace("HTTPS://PAYJO.IN", "HTTP://PAYJO.IN");
  assert.throws(() => decodePayjoinUri(plainHttp, 1736218740), /https|onion/i);
  const onion = BIP77_EXAMPLE.replace("HTTPS://PAYJO.IN", "HTTP://PAYJO.IN.onion");
  assert.equal(decodePayjoinUri(onion, 1736218740).kind, "v2");
});

test("a URI without pj is not a payjoin request", () => {
  assert.deepEqual(
    decodePayjoinUri("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1"),
    { kind: "none" }
  );
});

test("duplicate pj and bad pjos are refused", () => {
  assert.throws(
    () => decodePayjoinUri("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://a&pj=https://b"),
    /pj/i
  );
  assert.throws(
    () => decodePayjoinUri("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=2&pj=https://a"),
    /pjos/i
  );
});
