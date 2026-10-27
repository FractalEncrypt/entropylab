// Entry of the QR decoder worker. The build bundles this file (with the
// quircs decoder) into a string the page starts as a Web Worker; the page
// hands it the WebAssembly module bytes in the first message. The frame is
// copied into WASM, decoded, and both the frame and the WASM buffers are
// zeroed before the reply. Scrub overwrites the whole WASM memory and drops
// the instance; the page then terminates this worker.
//
// Protocol (after the page's { type: "init", wasm } message, which the
// bundle wrapper consumes):
//   page -> worker  { type: "decode", run, width, height, gray }  gray is a transferred ArrayBuffer
//   worker -> page  { type: "decoded", run, code, payload }       payload is a transferred ArrayBuffer when code > 0, else null
//   page -> worker  { type: "scrub" }
//   worker -> page  { type: "scrubbed" }
//   worker -> page  { type: "error", run, error: { code: "BAD_MESSAGE" } }

const OUT_CAP = 4096;
const MIN_DIM = 21;
const MAX_DIM = 4096;
const MAX_PIXELS = 4_194_304;

let wasm = null;

// The QR worker has its own WASM instance; this is the same overwrite
// pattern as the Lightning worker's retireWasm.
const scrubWasm = () => {
  if (wasm) {
    new Uint8Array(wasm.memory.buffer).fill(0);
    wasm = null;
  }
};

const fail = (run, code) => self.postMessage({ type: "error", run, error: { code } });

const init = (bytes) => {
  scrubWasm();
  wasm = new WebAssembly.Instance(new WebAssembly.Module(bytes), {}).exports;
};

if (self.__entropyLabWasmBytes instanceof ArrayBuffer) {
  init(self.__entropyLabWasmBytes);
  self.__entropyLabWasmBytes = null;
}

// A refused request still zeroes the frame it was handed: a transferred
// camera frame can hold a photographed seed QR.
const refuse = (run, gray) => {
  if (gray instanceof ArrayBuffer) new Uint8Array(gray).fill(0);
  return fail(run, "BAD_MESSAGE");
};

const decode = (run, width, height, gray, echo) => {
  if (!wasm) return refuse(run, gray);
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < MIN_DIM || height < MIN_DIM || width > MAX_DIM || height > MAX_DIM || width * height > MAX_PIXELS) {
    return refuse(run, gray);
  }
  if (!(gray instanceof ArrayBuffer) || gray.byteLength !== width * height) {
    return refuse(run, gray);
  }
  const pixels = new Uint8Array(gray);
  const grayPtr = wasm.qr_alloc(pixels.length);
  const outPtr = wasm.qr_alloc(OUT_CAP);
  let code = -1;
  let payload = null;
  try {
    new Uint8Array(wasm.memory.buffer).set(pixels, grayPtr);
    code = wasm.qr_decode(grayPtr, width, height, outPtr, OUT_CAP);
    if (code > 0) {
      payload = new Uint8Array(wasm.memory.buffer).slice(outPtr, outPtr + code).buffer;
    }
  } finally {
    pixels.fill(0);
    wasm.qr_free(grayPtr, pixels.length);
    wasm.qr_free(outPtr, OUT_CAP);
  }
  // Test hook: hand the zeroed frame back so the wipe can be observed.
  if (echo) self.postMessage({ type: "gray", gray }, [gray]);
  self.postMessage({ type: "decoded", run, code, payload }, payload ? [payload] : []);
};

self.onmessage = (event) => {
  const data = event.data;
  if (!data || typeof data !== "object") return fail(undefined, "BAD_MESSAGE");
  if (data.type === "decode") {
    return decode(data.run, data.width, data.height, data.gray, data.echo);
  }
  if (data.type === "scrub") {
    scrubWasm();
    return self.postMessage({ type: "scrubbed" });
  }
  return fail(data.run, "BAD_MESSAGE");
};
