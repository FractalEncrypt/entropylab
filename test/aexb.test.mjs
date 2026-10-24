import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  AexbError,
  aexbDecode,
  aexbEncode,
  aexbEncodePackage,
  aexbVerify,
  aextDecodePackage,
  aextEncodePackage
} from "../src/js/aexb.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hashesReady } from "../src/js/hashes.js";

await secp256k1Ready;
await hashesReady;

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures", "aexb");
const readJson = (name) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));

const positive = readJson("protocol-v1-multislot-vectors.json");
const negative = readJson("protocol-v1-negative-vectors.json");
const transport = readJson("transport-v1-vectors.json");

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function flipFirstByte(bytes) {
  const out = new Uint8Array(bytes);
  out[0] ^= 1;
  return out;
}

test("positive AEXB messages decode and verify", () => {
  const byStage = new Map();
  for (const vector of positive.messages) {
    const decoded = aexbDecode(vector.message_hex);
    byStage.set(vector.stage, decoded);
    assert.equal(decoded.stage, vector.stage);
    assert.equal(decoded.network, positive.network_code);
    assert.equal(decoded.slots.length, positive.slot_count);
    assert.equal(decoded.slots[0].inputIndex, positive.slot_identifiers[0].input_index);
    assert.equal(bytesToHex(decoded.slots[0].signerPubkey), positive.slot_identifiers[0].signer_pubkey);
    assert.equal(bytesToHex(aexbEncode(decoded)), vector.message_hex);
  }

  const reveal = byStage.get(3);
  const signatures = byStage.get(4);
  const revealResult = aexbVerify(reveal);
  assert.equal(revealResult.ok, true);
  assert.equal(revealResult.verdict, "ok");
  assert.equal(revealResult.slots.length, positive.slot_count);
  assert.ok(revealResult.slots.every((slot) => slot.ok));

  const signatureResult = aexbVerify(signatures, reveal);
  assert.equal(signatureResult.ok, true);
  assert.equal(signatureResult.verdict, "ok");
  assert.equal(signatureResult.slots.length, positive.slot_count);
  assert.ok(signatureResult.slots.every((slot) => slot.ok));
});

test("positive AEXT packages decode and round-trip", () => {
  for (const vector of positive.messages) {
    const decoded = aexbDecode(vector.package_hex);
    assert.equal(decoded.stage, vector.stage);
    assert.equal(decoded.network, positive.network_code);
    assert.equal(bytesToHex(aexbEncode(decoded)), vector.message_hex);
    assert.equal(bytesToHex(aexbEncodePackage(decoded)), vector.package_hex);
  }
});

test("negative vectors fail closed with the reference error code", () => {
  for (const vector of negative.cases) {
    assert.throws(
      () => aexbDecode(vector.message_hex),
      (err) => {
        assert.ok(err instanceof AexbError);
        assert.equal(err.code, vector.expected_error);
        return true;
      }
    );
    assert.throws(
      () => aexbDecode(vector.package_hex),
      (err) => {
        assert.ok(err instanceof AexbError);
        return true;
      }
    );
  }
});

test("transport vectors round-trip", () => {
  for (const vector of transport.vectors) {
    const decoded = aextDecodePackage(vector.package_hex);
    assert.equal(decoded.stage, vector.stage);
    assert.equal(bytesToHex(aextEncodePackage(decoded)), vector.package_hex);
  }
});

test("a changed signature r fails the S2C check", () => {
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);
  const tampered = {
    ...signatures,
    slots: signatures.slots.map((slot, index) =>
      index === 0 ? { ...slot, signature: flipFirstByte(slot.signature) } : slot
    )
  };
  const result = aexbVerify(tampered, reveal);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "fail");
  assert.equal(result.slots[0].ok, false);
  assert.equal(result.slots[0].reason, "OPENING_MISMATCH");
});

test("a changed host reveal fails the commitment check", () => {
  const reveal = aexbDecode(positive.messages.find((m) => m.stage === 3).message_hex);
  const tampered = {
    ...reveal,
    slots: reveal.slots.map((slot, index) =>
      index === 0 ? { ...slot, rho: flipFirstByte(slot.rho) } : slot
    )
  };
  const result = aexbVerify(tampered);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "fail");
  assert.equal(result.slots[0].ok, false);
  assert.equal(result.slots[0].reason, "COMMITMENT_MISMATCH");
});

test("message 4 without the accepted reveal fails closed", () => {
  const signatures = aexbDecode(positive.messages.find((m) => m.stage === 4).message_hex);
  const result = aexbVerify(signatures);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, "fail");
  assert.equal(result.reason, "MISSING_REVEAL");
});
