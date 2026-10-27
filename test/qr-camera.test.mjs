import test from "node:test";
import assert from "node:assert/strict";
import { CameraCapture } from "../src/js/qr-camera.js";
const video = () => ({ srcObject: null, play: async () => {}, pause() {} });
test("stop during permission request retires the late stream", async () => {
  let resolve;
  let stopped = 0;
  const c = new CameraCapture({
    getUserMedia: () => new Promise((r) => (resolve = r)),
    decode: () => null,
  });
  const v = video();
  const pending = c.start(v, "camera", () => {});
  c.stop();
  resolve({
    getTracks: () => [
      {
        stop() {
          stopped++;
        },
      },
    ],
  });
  await pending;
  assert.equal(stopped, 1);
  assert.equal(v.srcObject, null);
});
test("stop during frame decode cannot deliver stale text", async () => {
  let resolve;
  let delivered = 0,
    stopped = 0;
  const c = new CameraCapture({
    getUserMedia: async () => ({
      getTracks: () => [
        {
          stop() {
            stopped++;
          },
        },
      ],
    }),
    decode: () => new Promise((r) => (resolve = r)),
  });
  const v = video();
  await c.start(v, "camera", () => delivered++);
  c.stop();
  resolve("secret");
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(delivered, 0);
  assert.equal(stopped, 1);
  assert.equal(v.srcObject, null);
});
test("play failure releases every track", async () => {
  let stopped = 0;
  const c = new CameraCapture({
    getUserMedia: async () => ({
      getTracks: () => [
        {
          stop() {
            stopped++;
          },
        },
      ],
    }),
    decode: () => null,
  });
  const v = video();
  v.play = async () => {
    throw Error("play");
  };
  await assert.rejects(c.start(v, "", () => {}));
  assert.equal(stopped, 1);
  assert.equal(v.srcObject, null);
});


test("disconnect stops the stream and reports one disconnect without late frames", async (t) => {
  let ended, stops=0, delivered=0; const errors=[];
  const track={stop(){stops++;},addEventListener(name,fn){if(name==="ended")ended=fn;}};
  const c=new CameraCapture({getUserMedia:async()=>({getTracks:()=>[track]}),decode:()=>null});
  t.after(()=>c.stop()); const v=video();await c.start(v,"uvc",()=>delivered++,e=>errors.push(e.code));
  assert.equal(typeof ended,"function");ended();ended();
  assert.equal(stops,1);assert.equal(v.srcObject,null);assert.equal(delivered,0);
  assert.deepEqual(errors,["CAMERA_DISCONNECTED"]);
});
