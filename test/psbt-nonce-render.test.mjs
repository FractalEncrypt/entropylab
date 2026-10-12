import { test } from "node:test";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const pubkey = Uint8Array.from(Buffer.from("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "hex"));
// Readable DER r/s with SIGHASH_ALL, deliberately without prevouts: these
// fixtures establish a possible repeat, not a verified signature/key leak.
const signature = (r) => Uint8Array.of(0x30, 6, 2, 1, r, 2, 1, 1, 1);
const recorded = [];
const app = await loadAppFunctions(["hodlRenderPsbt", "hodlRenderRawTx"], { stubs: {
  document: { getElementById: () => null },
  hodlT: (text) => text,
  hodlTText: (text) => text,
  hodlSessionOwnership: () => new Map(),
  hodlRenderOutputHtml: () => "",
  hodlOwnershipWarning: () => "",
  hodlPublicInlineHtml: (text) => text,
  hodlPsbtReferenceVerdict: () => ({ state: "incomplete" }),
  hodlPrivForPub: () => null,
  hodlPrivFromPath: () => null,
  hodlPsbtMasterFingerprint: () => null,
  hodlPsbtRecordNonceInspection: (kind, records, tag, verdict) => recorded.push({ kind, records, verdict }),
} });

function fixture(nonces) {
  const tx = {
    version: 2, locktime: 0, segwit: false,
    inputs: nonces.map((r, vout) => ({
      txid: new Uint8Array(32).fill(0x11), vout, sequence: 0xffffffff,
      scriptSig: Uint8Array.of(9, ...signature(r), 33, ...pubkey),
    })),
    outputs: [{ amount: 1000n, script: Uint8Array.of(0x51) }],
  };
  const psbt = {
    tx: { ...tx, inputs: tx.inputs.map((input) => ({ ...input, scriptSig: new Uint8Array() })) },
    inputs: nonces.map((r) => [{ type: 2, keydata: pubkey, val: signature(r) }]),
    outputs: [[]],
  };
  return { tx, psbt };
}

for (const kind of ["psbt", "transaction"]) test(`${kind} nonce report cannot contradict a repeated-r warning with a clean line`, () => {
  // Contract: same-key repeated r must warn and must never also say no r was
  // repeated; distinct readable r values may report no repeated r.
  const render = (nonces) => {
    const { tx, psbt } = fixture(nonces);
    return kind === "psbt" ? app.hodlRenderPsbt(psbt, undefined, undefined, "nonce") : app.hodlRenderRawTx(tx, undefined, undefined, "nonce");
  };
  const distinct = render([1, 2]);
  assert.match(distinct, /No repeated ECDSA nonce/);
  const repeated = render([1, 1]);
  assert.equal(recorded.at(-1).verdict, "possible");
  // This safety-critical substring pins the absence of a false assurance,
  // without asserting styles, markup, or the full user-facing sentence.
  assert.doesNotMatch(repeated, /No repeated ECDSA nonce/);
});

