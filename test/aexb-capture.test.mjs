import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { UrCapture, AexbCapture } from "../src/js/aexb-capture.js";
import { aexbDecode, aexbEncodePackage } from "../src/js/aexb.js";
import { hashesReady } from "../src/js/hashes.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
await hashesReady;
await secp256k1Ready;
const fixture = JSON.parse(
  readFileSync(
    new URL(
      "./fixtures/aexb/protocol-v1-multislot-vectors.json",
      import.meta.url,
    ),
  ),
);
const fountain = JSON.parse(
  readFileSync(
    new URL("./fixtures/aexb/capture-fountain.json", import.meta.url),
  ),
);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const transcript = c => [...c.messages.values()].map(e=>Buffer.from(e.bytes).toString("hex")).join("\n");
const message = (stage) => fixture.messages.find((m) => m.stage === stage);
// Contract: accept only bounded, checksum-valid UR messages from one canonical
// AEXT session; identical repeats are harmless, conflicts never replace evidence.
for (const item of fountain.messages)
  test(`fountain recovery without the first cycle, stage ${item.stage}`, () => {
    const c = new UrCapture();
    let result;
    for (const frame of item.frames) {
      result = c.receive(frame);
      if (result.complete) break;
    }
    assert.equal(result.complete, true);
    assert.deepEqual(result.bytes, bytes(item.package_hex));
  });
test("published sequential frames tolerate repeats and reverse order", () => {
  const c = new UrCapture();
  let result;
  for (const frame of [...message(3).medium_ur_parts].reverse()) {
    result = c.receive(frame);
    if (!result.complete) c.receive(frame);
  }
  assert.deepEqual(result.bytes, bytes(message(3).package_hex));
});
test("wrong UR type, excessive input and checksum errors are rejected", () => {
  const c = new UrCapture();
  const f = message(2).medium_ur_parts[0];
  assert.throws(
    () => c.receive(f.replace(/X-BTC-ANTI-EXFIL/i, "crypto-psbt")),
    /TYPE/,
  );
  assert.throws(() => c.receive("a".repeat(20001)), /LIMIT/);
  assert.throws(() => c.receive(f.slice(0, -2) + "zz"));
  assert.equal(c.progress().received, 0);
});
test("interleaved message frames cannot contaminate an assembly", () => {
  const c = new UrCapture();
  c.receive(message(2).medium_ur_parts[0]);
  assert.throws(() => c.receive(message(3).medium_ur_parts[1]), /MIXED/);
  c.clear();
  assert.equal(c.progress().received, 0);
});
test("session requires all 2/3/4 stages before full verdict, any capture order", () => {
  const c = new AexbCapture();
  assert.deepEqual(c.snapshot().stages, []);
  c.accept(bytes(message(4).package_hex));
  assert.equal(c.snapshot().verdict, null);
  c.accept(bytes(message(2).package_hex));
  assert.equal(c.snapshot().verdict, null);
  c.accept(bytes(message(3).package_hex));
  assert.deepEqual(c.snapshot().stages, [2, 3, 4]);
  assert.equal(c.snapshot().verdict.ok, true);
  assert.equal(transcript(c).split("\n").length, 3);
  c.clear();
  assert.equal(transcript(c), "");
  assert.equal(c.snapshot().verdict, null);
});
test("duplicate evidence is idempotent; conflicting evidence stays rejected", () => {
  const c = new AexbCapture();
  const m = message(2);
  c.accept(bytes(m.package_hex));
  c.accept(bytes(m.package_hex));
  assert.deepEqual(c.snapshot().stages, [2]);
  const changed = aexbDecode(bytes(m.package_hex));
  changed.slots[0].messageHash[0] ^= 1;
  assert.throws(() => c.accept(aexbEncodePackage(changed)), /CONFLICT/);
  assert.equal(transcript(c), m.package_hex.toLowerCase());
});
for (const field of ["sessionId", "psbtDigest"])
  test(`reject different ${field} without losing accepted evidence`, () => {
    const c = new AexbCapture();
    c.accept(bytes(message(3).package_hex));
    const changed = aexbDecode(bytes(message(2).package_hex));
    changed[field][0] ^= 1;
    assert.throws(() => c.accept(aexbEncodePackage(changed)), /SESSION/);
    assert.deepEqual(c.snapshot().stages, [3]);
  });
test("stage 1 and raw AEXB are not camera-session messages", () => {
  const c = new AexbCapture();
  assert.throws(() => c.accept(bytes(message(1).package_hex)), /STAGE/);
  assert.throws(() => c.accept(bytes(message(2).message_hex)), /ENVELOPE/);
});
test("captured bytes are owned by the collector", () => {
  const c = new AexbCapture();
  const input = bytes(message(2).package_hex);
  c.accept(input);
  input.fill(0);
  assert.equal(transcript(c), message(2).package_hex.toLowerCase());
});

// Independent QR encoder -> bundled camera decoder -> transport collector.
test("pixels from the existing QR encoder decode into a published UR frame", async () => {
  const { encode } = await import("uqr");
  const { Worker } = await import("node:worker_threads");
  const { buildQrWorkerSource } = await import("../scripts/qr-worker-source.mjs");
  const { QR_WASM_B64 } = await import("../src/js/qr-wasm-b64.js");
  const text = message(2).medium_ur_parts[0],
    qr = encode(text, { border: 4 }),
    scale = 5,
    w = qr.size * scale;
  const pixels = new Uint8ClampedArray(w * w * 4);
  for (let y = 0; y < w; y++)
    for (let x = 0; x < w; x++) {
      const at = (y * w + x) * 4,
        v = qr.data[Math.floor(y / scale)][Math.floor(x / scale)] ? 0 : 255;
      pixels.set([v, v, v, 255], at);
    }
  const worker = new Worker(`const { parentPort } = require("node:worker_threads");
    globalThis.self = { onmessage: null, postMessage(m,t) { parentPort.postMessage(m,t); } };
    parentPort.on("message", data => self.onmessage?.({data}));
` + await buildQrWorkerSource(), {eval:true});
  const next = () => new Promise((resolve, reject) => {
    worker.once("message", resolve); worker.once("error", reject);
  });
  try {
    let ready = next();
    const wasm = Uint8Array.from(Buffer.from(QR_WASM_B64, "base64"));
    worker.postMessage({type:"init", wasm:wasm.buffer}, [wasm.buffer]);
    assert.equal((await ready).type, "ready");
    const gray = Uint8Array.from({length:w*w}, (_,i) => pixels[i*4]);
    pixels.fill(0);
    ready = next();
    worker.postMessage({type:"decode",run:1,width:w,height:w,gray:gray.buffer}, [gray.buffer]);
    const reply = await ready;
    assert.equal(reply.code, text.length);
    const payload = new Uint8Array(reply.payload);
    assert.equal(new TextDecoder().decode(payload), text);
    payload.fill(0);
  } finally { await worker.terminate(); }
});


test("conflicting fragment and whole-message checksum fail closed", async () => {
  const { hodlBytewordsDecode, hodlBytewordsEncode } = await import("../src/js/psbt-ur.js");
  const frames = message(2).medium_ur_parts;
  const words = frames[0].split("/");
  const payload = hodlBytewordsDecode(words.at(-1));
  payload[payload.length - 1] ^= 1;
  const changed = words.slice(0, -1).join("/") + "/" + hodlBytewordsEncode(payload);
  const conflict = new UrCapture(); conflict.receive(frames[0]);
  assert.throws(() => conflict.receive(changed), /CONFLICTING_FRAME/);
  const bad = new UrCapture(); bad.receive(changed);
  assert.throws(() => { for (const frame of frames.slice(1)) bad.receive(frame); }, /MESSAGE_CHECKSUM/);
  assert.equal(bad.progress().received, 0);
});

test("fountain part count is bounded before any row allocation", () => {
  const c = new UrCapture();
  const frame = message(2).medium_ur_parts[0].replace(/1-\d+/, "1-513");
  assert.throws(() => c.receive(frame), /PART_LIMIT/);
  assert.equal(c.progress().received, 0);
});

test("cross-network messages cannot enter the captured session", () => {
  const c = new AexbCapture();c.accept(bytes(message(3).package_hex));
  const changed = aexbDecode(bytes(message(2).package_hex));changed.network = 1;
  assert.throws(() => c.accept(aexbEncodePackage(changed)), /SESSION_MISMATCH/);
  assert.deepEqual(c.snapshot().stages, [3]);
});


test("camera demo success covers real PSBT signing hashes; chosen-nonce demo fails S2C despite valid ECDSA", async () => {
  const {secp256k1:curve}=await import("@noble/curves/secp256k1.js");
  const {Transaction}=await import("@scure/btc-signer");
  const demo=JSON.parse(readFileSync(new URL("./fixtures/aexb/camera-demo.json",import.meta.url)));
  for(const [name, scenario] of Object.entries(demo.scenarios)) {
    const c=new AexbCapture();
    for(const m of scenario.messages)c.accept(bytes(m.package_hex));
    const verdict=c.snapshot().verdict;
    assert.equal(verdict.ok,name==="success");
    if(name==="success") assert.deepEqual(c.checkTransaction(), {ok:true,reason:null,checkedSlots:2,totalInputs:2,checkedInputs:[0,1]});
    if(name!=="success")assert.ok(verdict.slots.every(slot=>slot.reason==="OPENING_MISMATCH"));
    const decoded=aexbDecode(bytes(scenario.messages[2].package_hex));
    const signed=Transaction.fromPSBT(new Uint8Array(Buffer.from(scenario.signed_psbt_base64,"base64")));
    for(const slot of decoded.slots) {
      assert.equal(curve.verify(slot.signature,slot.messageHash,slot.signerPubkey,{prehash:false,lowS:true}),true);
      const der=signed.getInput(slot.inputIndex).partialSig[0][1].slice(0,-1);
      assert.deepEqual(curve.Signature.fromBytes(der,"der").toBytes("compact"),slot.signature);
    }
  }
});

// Keep references deliberately: checking only an empty Map would not prove wiping.
test("clear overwrites all collector-owned message buffers before releasing them", () => {
  const c = new AexbCapture();
  for (const stage of [2,3,4]) c.accept(bytes(message(stage).package_hex));
  const retained = [...c.messages.values()].flatMap(({bytes,decoded}) => [bytes,
    ...Object.values(decoded).filter(v => v instanceof Uint8Array),
    ...decoded.slots.flatMap(slot => Object.values(slot).filter(v => v instanceof Uint8Array))]);
  assert.ok(retained.some(v => v.some(byte => byte !== 0)));
  c.clear();
  assert.ok(retained.every(v => v.every(byte => byte === 0)));
  assert.equal(c.messages.size, 0);
});
test("clear overwrites incomplete UR rows before releasing them", () => {
  const c = new UrCapture(); c.receive(message(3).medium_ur_parts[0]);
  const retained = [...c.rows.values()].map(row => row.data);
  assert.ok(retained.length > 0);
  c.clear();
  assert.ok(retained.every(v => v.every(byte => byte === 0)));
  assert.deepEqual(c.progress(), {received:0,total:0,complete:false});
});

test("synthetic transcript math cannot masquerade as embedded-PSBT validation", () => {
  const c=new AexbCapture();for(const stage of [2,3,4])c.accept(bytes(message(stage).package_hex));
  assert.equal(c.snapshot().verdict.ok,true);
  assert.deepEqual(c.checkTransaction(),{ok:false,reason:"TRANSACTION_INVALID",checkedSlots:0});
  c.clear();assert.equal(c.checkTransaction(),null);
});

test("finish returns only a verdict and wipes captured buffers before either result is shown", () => {
  const demo=JSON.parse(readFileSync(new URL("./fixtures/aexb/camera-demo.json",import.meta.url)));
  for(const [name,scenario] of Object.entries(demo.scenarios)) {
    const c=new AexbCapture();c.accept(bytes(scenario.messages[0].package_hex));
    assert.equal(c.finish(),null);assert.deepEqual(c.snapshot().stages,[2]);
    for(const m of scenario.messages.slice(1))c.accept(bytes(m.package_hex));
    const retained=[...c.messages.values()].flatMap(({bytes,decoded})=>[bytes,decoded.psbt,...decoded.slots.flatMap(s=>Object.values(s).filter(v=>v instanceof Uint8Array))]);
    const result=c.finish();assert.equal(result.ok,name==='success');
    assert.deepEqual(Object.keys(result).sort(),(name==='success'?['checkedInputs','checkedSlots','ok','reason','totalInputs','totalSlots']:['checkedSlots','ok','reason','totalSlots']));
    assert.ok(retained.every(v=>v.every(byte=>byte===0)));
    assert.equal(transcript(c),'');assert.equal(c.checkTransaction(),null);assert.deepEqual(c.snapshot().stages,[]);
  }
});

// Retain rejected temporary copies, including the assembled message on bad CRC.
test("rejected UR fragment and checksum copies are overwritten", async () => {
 const {hodlBytewordsDecode,hodlBytewordsEncode}=await import("../src/js/psbt-ur.js");
 const frames=message(3).medium_ur_parts,words=frames[0].split('/'),payload=hodlBytewordsDecode(words.at(-1));
 payload[payload.length-1]^=1;
 const changed=words.slice(0,-1).join('/')+'/'+hodlBytewordsEncode(payload);
 for(const kind of ['conflict','checksum']) {
  const c=new UrCapture();const retained=[];const slice=Uint8Array.prototype.slice;
  // Capture only sizeable transport copies, not short public PRNG digests.
  Uint8Array.prototype.slice=function(...args){const result=slice.apply(this,args);if(result.length>8)retained.push(result);return result;};
  try {
   if(kind==='conflict'){c.receive(frames[0]);assert.throws(()=>c.receive(changed),/CONFLICTING_FRAME/);}
   else {c.receive(changed);assert.throws(()=>{for(const f of frames.slice(1))c.receive(f)},/MESSAGE_CHECKSUM/);}
   c.clear();
  } finally {Uint8Array.prototype.slice=slice;}
  assert.ok(retained.length>1);assert.ok(retained.every(b=>b.every(x=>x===0)),kind+' retained nonzero rejected copies');
 }
});
