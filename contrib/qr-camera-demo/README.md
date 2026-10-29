# Public anti-exfil camera demo

This standalone page displays public animated QR fixtures for the preview-only
EntropyLab anti-exfil observer. It lets a reviewer exercise successful and failed
capture without Sparrow, Kern, SeedSigner, or their anti-exfil forks. It simulates
the messages those participants display; it does not simulate their firmware.

This helper lives on a separate branch in FractalEncrypt's fork. It is not added
to PR #1262, the application UI, or release output. Maintainers can decide whether
to adopt it as a test tool, documentation example, or user-facing demonstration.

## Run the demonstration

1. Download `camera-fixtures.html` using GitHub's **Download raw file** button.
   Open the saved file in a browser on the display device. It is self-contained;
   no server, installation, network access or camera permission is needed there.
2. On the camera device, open an EntropyLab **preview build containing PR #1262**.
   Go to Transactions → Nonce Inspector → live anti-exfil QR signing ceremony.
   A release build may not expose this tool.
3. Allow Camera Access and choose the camera. In the fixture page select
   **Success: host randomness included**, then display Message 2. In EL click
   **Scan Message 2**. Keep the animation in view until capture pauses.
4. Display Message 3, click **Scan Message 3** in EL, and repeat for Message 4.
   Any order is accepted, but 2 → 3 → 4 is easiest for this demo. Older previews
   label the scan button **Scan next message**.
5. Expect **PASS**, with two supplied signatures checked on two inputs. The
   captured messages clear automatically before the result dialog. Click
   **Clear Capture** to acknowledge it.
6. Select **Dark Skippy-inspired malicious nonce substitution** and repeat.
   Expect **STOP! Do not broadcast!**, reason `OPENING_MISMATCH`. The signatures
   are valid ECDSA signatures, but their chosen nonces do not match the committed
   sign-to-contract openings. Acknowledging STOP does not make the exchange safe.

Clear an unfinished capture before switching scenarios. The page cycles QR parts
every 250 ms and displays one QR at a time. Frame count/progress may differ by
message. The reference signed PSBT is public test data and is not needed for the
camera demonstration. There is no reason to import it into a wallet or broadcast.

## Camera arrangements

- A camera-equipped tablet running EL, aimed at the fixture page on a separate
  computer, is a convenient setup.
- With a movable webcam, use one browser window per monitor or put EL and the
  fixture page side by side on one monitor. Aim at just the fixture QR; the shared
  decoder refuses multiple different payloads in a frame.
- A fixed laptop webcam cannot see its own screen. Use a second display/device,
  an external movable camera, or a suitable phone-as-webcam arrangement.

The EL device needs a browser-supported secure camera context. `127.0.0.1` refers
to that device, so a computer's loopback preview link is not a tablet-hosting URL.
Use the project's supported preview/offline setup on the camera device. Stop any
other EL camera scanner before starting this one; camera lifetimes are not yet
unified. If scanning is slow, improve focus, lighting, QR size and viewing angle.

## Inspect and reproduce

The HTML contains inline SVG frames and a small viewer script. A restrictive CSP
blocks network connections. The viewer reads no wallet or camera data and uses
no browser storage. Its source is `generate.mjs`; its data comes from the existing
[`camera-demo.json`](../../test/fixtures/aexb/camera-demo.json). The corresponding
[`generate-qr-demo.mjs`](../../scripts/generate-qr-demo.mjs) constructs the public
protocol fixtures. Inspect these rather than relying on a screenshot of PASS.

From the repository root, using the pinned Node/npm toolchain and lockfile:

```sh
npm ci
node contrib/qr-camera-demo/generate.mjs
node contrib/qr-camera-demo/verify.mjs
```

This renders the existing fixture JSON into the adjacent `camera-fixtures.html`.
It does not change the fixture data or rebuild EL. Compare the generated file's
SHA-256 with `SHA256SUMS.txt` in this directory. On Windows:

```powershell
Get-FileHash contrib/qr-camera-demo/camera-fixtures.html -Algorithm SHA256
```

`verify.mjs` rasterizes the HTML's exact SVG path grammar, decodes all 36 frames
with quircs, compares their payloads byte-for-byte with the public fixture parts,
reassembles the messages and checks PASS / `OPENING_MISMATCH`. It is an automated
check of the shipped frames, not a physical-camera test or an independent audit
of the verifier itself.

To compare protocol construction independently, copy the repository to scratch
and inspect/run `scripts/generate-qr-demo.mjs` there; do not overwrite retained
review evidence. You can also feed the decoded public messages into an independent
verifier. Regenerating this viewer alone establishes reproducibility, not an
independent cryptographic oracle.

## Limits

All fixture keys, host randomness and invented outpoints are deliberately public
and unfunded. Never use these keys for a wallet. The two-input P2WPKH examples do
not qualify hardware interoperability, multisig behavior or general security.
The failure illustrates nonce substitution; it does not implement seed extraction
or the complete Dark Skippy attack. These examples cannot prove the absence of
backdoors or cover every malicious behavior. Real transcripts must remain private.

AI implementation and documentation: GPT-6 (OpenAI Codex). This demonstration is
separate from the exact-version DeepSeek reviews of the observer implementation.
