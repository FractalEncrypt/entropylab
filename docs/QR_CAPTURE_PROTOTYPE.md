# Local Nonce Inspector QR prototype

Experimental preview-only observer. AI implementation: OpenAI Codex (GPT-6).
Upstream base checked 2026-10-27: 6025a84c007c7ce598fc91c4d82689580306f2a8.

## Current flow

1. Allow Camera Access (blue). The permission probe lists cameras, stops its
   tracks, and never decodes/records frames. Browser-prompt focus loss does not
   cancel a pending probe on a visible page; hiding the page, Clear or End still
   cancels it. Grant once, then choose a camera.
2. Scan next message becomes the blue next action. Capture M2 and M4 from the
   signer and M3 from Sparrow. Missing-message boxes/count stay explicit.
3. When all three messages arrive, validate every PSBT input context, then verify the AEXB proof AND each supplied
   signature against BIP143 SIGHASH_ALL hashes reconstructed from M3's PSBT.
4. Automatically wipe captured buffers and clear the inspector transcript before
   opening the PASS or STOP! Do not broadcast! dialog. Only non-secret verdict
   metadata remains. Walking away at this point cannot prolong owned transcript
   retention. Browser/OS copies are still outside reliable erasure guarantees.
5. Clear Capture in the dialog acknowledges the result and resets the capture.
   Escape/backdrop do not dismiss it. Failed results never authorize broadcast.

The standing Clear Capture button also cancels unfinished captures/permission.
Completed controls appear disabled; the acknowledgement/clear action is blue.
The user explicitly chose automatic clearing instead of retaining a completed
transcript for the optional later PSBT comparison. That transfer control is removed.
There is no new PSBT QR import or required additional scan. M4 is the signer's
final anti-exfil QR; Sparrow reconstructs its PSBT. M1 is not needed for this
observer check. Capture order is unrestricted, not evidence of real exchange order.

## Architecture and limits

- `aexb-capture.js`: DOM-free bounded UR/fountain assembly, canonical decoding,
  session/stage binding and held-buffer wiping. `finish()` returns only verdict
  metadata and clears in a finally block on either completed outcome.
- `aexb-transaction.js`: PSBT WASM parsing, script/key membership, recomputed
  digests and supplied-signature checks; reuses the audit/WASM BIP143 path.
- `qr-camera.js`: cancellable camera lifetime; late permission/decode and track
  disconnect handling. No recording or audio.
- `nonce-qr-capture.js`: preview-only bundled jsQR, permission/access states,
  message indicators, in-view progress and shared result modal.

Bounds: frame text 20,000 characters; 512 fountain parts; 8,192 bytes per fragment;
reconstructed message 2,065,600 bytes; 128 transaction slots; conservative 32 MiB
PSBT-by-max(input-count, slot-count) transaction work bound. One partial message at a time. Exact repeats
are harmless; conflicts never replace accepted messages. Unsupported or invalid
transaction contexts cannot produce PASS. Native/wrapped SegWit key-hash and
standard multisig have independent scure/noble fixtures.

This verifies supplied slots under PSBT UTXO claims, not complete input signature
coverage, wallet ownership, chain UTXO availability, fee/destination approval,
coordinator policy, finalization or what Sparrow actually broadcasts. Confirm
amount/destination and let the coordinator perform its broadcast gate.

## Rho confidentiality

M3 contains rho. A malicious signer can choose a base nonce known to its operator
and correctly incorporate rho. If the operator later obtains rho and the
signature, they can recover the signing key even though anti-exfil verification
passed. Completion does not make rho public. No raw transcript export, clipboard
handoff, Journal or browser-storage writes are performed by capture. The browser
is another trusted environment holding rho during an incomplete exchange.

For incomplete captures, use Clear Capture or close the tab when finished.
Automatic clearing reduces retention but cannot reliably zero immutable strings,
native decoder/video copies, OS memory, swap or crash dumps. Public camera fixtures
use deliberately public fixed keys/rho and invented unfunded outpoints; these are
not real capture exports.

## Build, dependency and review

Use pinned Node 22.23.4/npm 11.17.0 and npm ci. Preview command:
`node scripts/build.mjs --preview --out ../preview`.
Serve on loopback or another secure local browser context. No runtime downloads.
Pinned jsQR 1.4.0 was user-authorized for this local prototype; upstream review
remains necessary. Apache-2.0 jsQR and BSD-2-Clause-Patent UR2 notices live under
src/licenses and are included only in preview artifacts. Normal builds exclude
camera decoding.

Public fixture hardware scans passed earlier revisions. The newest automatic
clear/result-dialog behavior needs the requested human pass. No actual
Sparrow/SeedSigner/Kern session has yet been qualified with this observer.

The review packet beside this prototype contains source, patch, baseline,
public fixtures, exact test evidence, issue draft and review prompt. Its current
CODEX-REVIEW.txt distinguishes fresh checks from historical full-CI results and
remaining prepublication gates. Nothing is published.

## Revision 9 review corrections

All PSBT input contexts are now checked, including inputs without a supplied slot.
Non-final inputs must resolve to native P2WPKH, P2SH-P2WPKH, native P2WSH
standard m-of-n multisig or P2SH-P2WSH standard m-of-n multisig;
Taproot requests, missing/conflicting claims and unsupported sighashes fail closed.
The bounded observer additionally refuses all finalized inputs. This is a stricter
local support limit than protocol v1's allowance for finalized inputs unrelated to
the signer; the observer cannot establish their attribution and does not skip them.
PASS reports signature count, distinct checked input indexes and total input count.
It cannot infer the coordinator's expected slot set or prove complete signer coverage.
STOP includes a non-secret reason and supplied-slot count. No transcript is retained.

The pasted transcript/cache are now retired by conceal and the disclosure closes.
Incomplete QR captures still survive focus loss, tab hide and idle conceal; the UI
states this explicitly and instructs Clear Capture / End Session / close tab.
QR Clear also clears the separate pasted transcript and last inspector result.
UR temporary copies are wiped on rejection as well as success. The unused raw
transcript helper was removed. Opening uniqueness remains the upstream stricter rule. The frozen prose/reference
codec permits uniqueness per signer key over full 33-byte openings, whereas
upstream enforces global x-coordinate uniqueness (also rejecting negated openings); but bundled negative vectors require sibling-key
opening reuse to fail. This pre-existing discrepancy needs a separate reconciliation;
the QR patch does not relax the existing negative-vector contract.

## Human testing update — 2026-10-27

The user reports that on-device multisig testing with both Kern and SeedSigner
completed and everything worked as expected. This is user-reported physical-session
evidence, not an independently captured transcript audit or broad compatibility
qualification. Real session messages are not included in the review packet.
After this test, the accepted-message status was clarified to say Scan successful
while identifying the remaining messages; verification behavior is unchanged.

## M4-first workflow

When the signer displays M4, scan it into EntropyLab before scanning it into
Sparrow. Continue with that same M4 in Sparrow only after EL shows PASS. An
incomplete result or STOP is not permission to continue. EL checks the captured
proof and supplied signatures before coordinator import; Sparrow still applies
its own transaction/policy checks and broadcast gate. Clearing EL does not require
a new ceremony: keep the signer’s same M4 displayed for Sparrow.
