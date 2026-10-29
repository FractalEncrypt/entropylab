// Public fixture checks; AI implementation: GPT-6 (OpenAI Codex).
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {QR_WASM_B64} from '../../src/js/qr-wasm-b64.js';
import {UrCapture,AexbCapture} from '../../src/js/aexb-capture.js';
import {hashesReady} from '../../src/js/hashes.js';
import {secp256k1Ready} from '../../src/js/secp256k1.js';
await Promise.all([hashesReady,secp256k1Ready]);
const html=readFileSync(new URL('./camera-fixtures.html',import.meta.url),'utf8');
const scenarios=JSON.parse(html.match(/const scenarios=([\s\S]*?);let scenario=/)[1]);
const fixture=JSON.parse(readFileSync(new URL('../../test/fixtures/aexb/camera-demo.json',import.meta.url)));
const wasm=new WebAssembly.Instance(new WebAssembly.Module(Buffer.from(QR_WASM_B64,'base64')),{}).exports;
let count=0;
for(const [name,scenario] of Object.entries(scenarios)) {
  const capture=new AexbCapture();
  for(const stage of [2,3,4]) {
    const reference=fixture.scenarios[name].messages.find(m=>m.stage===stage);
    assert.equal(scenario.stages[stage].length,reference.medium_ur_parts.length);
    const transport=new UrCapture();
    for(const [index,svg] of scenario.stages[stage].entries()) {
      // Rasterize the generator's exact rectangle/path grammar, then decode
      // those pixels with quircs. No QR encoder is used by this check.
      const match=svg.match(/^<svg xmlns="http:\/\/www.w3.org\/2000\/svg" viewBox="0 0 (\d+) (\d+)"><rect fill="white" width="\1" height="\2"\/><path fill="black" d="([^"]+)"\/><\/svg>$/);
      assert.ok(match,'unexpected SVG grammar');
      const [,w,h,d]=match,width=Number(w),height=Number(h);
      const pixels=new Uint8Array(width*height).fill(255);
      const command=/M(\d+),(\d+)h10v10h-10z/g;
      assert.equal(d.replace(command,''),'');
      for(const m of d.matchAll(command)) {
        const x=Number(m[1]),y=Number(m[2]);
        assert.ok(x+10<=width && y+10<=height);
        for(let dy=0;dy<10;dy++)pixels.fill(0,(y+dy)*width+x,(y+dy)*width+x+10);
      }
      const p=wasm.qr_alloc(pixels.length),out=wasm.qr_alloc(4096);
      let text;
      try {
        new Uint8Array(wasm.memory.buffer).set(pixels,p);
        const n=wasm.qr_decode(p,width,height,out,4096);
        assert.ok(n>0,'QR must decode');
        text=new TextDecoder().decode(new Uint8Array(wasm.memory.buffer,out,n));
      } finally { wasm.qr_free(p,pixels.length);wasm.qr_free(out,4096); }
      assert.equal(text,reference.medium_ur_parts[index]);
      const result=transport.receive(text);
      if(result.complete) {
        assert.equal(Buffer.from(result.bytes).toString('hex'),reference.package_hex);
        capture.accept(result.bytes); result.bytes.fill(0);
      }
      count++;
    }
    transport.clear();
  }
  const result=capture.finish();
  assert.equal(result?.ok,name==='success');
  if(name!=='success')assert.equal(result.reason,'OPENING_MISMATCH');
  console.log(name,result.ok?'PASS':result.reason);
}
console.log(`${count} displayed SVG frames decoded to exact public fixture parts.`);
