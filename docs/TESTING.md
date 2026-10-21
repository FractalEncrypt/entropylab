# How EntropyLab is tested

EntropyLab handles seeds, keys and transactions, so every change is tested well past "it works on my machine". This page summarises the layers and links to the detailed records. Numbers carry the date or commit they were measured at; the CI runs on each pull request are the live source.

## 1. The test suite

- **About 2,500 tests** run on every pull request (`npm run test:ci`, the CI job "complete dependency-free suite": 2,500 at rock `63752da5`, 2026-10-21). A guard test fails CI if any test file on disk is missing from that list, so no suite is silently skipped.
- **Published vectors, not our own outputs.** Expected values come from the specifications and from independent implementations: BIP 39 (TREZOR vectors), BIP 32, BIP 143, BIP 174 PSBT vectors, the official BIP 352 send-and-receive vectors (`test/fixtures/bip352-send-and-receive.json`), and Bitcoin Core's `tx_valid.json` and sighash vectors (`test/fixtures/core/`).
- **The page checks itself on load.** Before any input is wired, the page runs published vectors against its own WASM modules and refuses to start if one fails (see the README).
- **Rejected input is tested as carefully as accepted input.** Security-sensitive parsing and validation changes must include cases the code must refuse, not only cases it must accept (pull request checklist).

## 2. Differential fuzzing

Five fuzzers generate thousands of random cases and compare EntropyLab's answer with an independent implementation, case by case:

| Fuzzer | Compared against |
|---|---|
| `test/hdkey-differential-fuzz.test.mjs` | `@scure/bip32` (BIP 32 derivation, public and private) |
| `test/psbt-differential-fuzz.test.mjs` | `@scure/btc-signer` (PSBT parsing) |
| `test/sighash-differential-fuzz.test.mjs` | `@scure/btc-signer`: EntropyLab's rust-bitcoin WASM module must produce the same legacy, BIP 143 and BIP 341 digests |
| `test/psbt-editor-fuzz.test.mjs` | random edit walks through the PSBT editor, checked by the PSBT layer |
| `test/wallet-export-fuzz.test.mjs` | an independent check of every generated wallet.dat, including Bitcoin Core's load checks |

Default runs are deterministic (fixed seeds), so a CI failure always reproduces. CI also runs separate fuzz jobs: LifeHash against the C++ reference and against the official implementation, and multisig outputs against `@scure/btc-signer`.

## 3. Mutation testing

Mutation testing changes the code on purpose (flips a comparison, deletes a line) and checks that some test fails. A change no test notices marks behaviour nothing checks. EntropyLab runs StrykerJS periodically on security modules and adds tests for what survives:

- The first pilot is written up in [Mutation_Testing_Pilot.md](Mutation_Testing_Pilot.md).
- `src/js/bip39.js`: the mutation score went from 65.3% to 93.5% after #1019 (2026-10-21; most remaining survivors have no observable effect).
- Follow-up passes cover `journal.js` (#1033) and `wallet-export.js`, with `bip352.js` next.

## 4. In the browser

- **Browser suite** (`npm run test:browser`): the built page is driven headless, including the memory-residue checks. CI runs it in Firefox on every pull request (the "Firefox integration suite" job); locally it also runs in Chrome/Chromium when one is installed.
- **Memory-residue audit:** whether secrets survive in process memory after use and after End Session. See [Residue_Audit.md](Residue_Audit.md).
- **Adversarial nightly:** a scheduled workflow (`.github/workflows/jev-adversarial.yml`, daily at 05:37 UTC) builds the page fresh and runs adversarial scenarios against it.

## 5. Builds you can check

- **Reproducible:** `entropylab.html` rebuilds byte for byte, and CI checks it from two different source paths. See [Reproductions.md](Reproductions.md) and the README's "Verifying the download".
- **Attested and timestamped:** releases carry a Sigstore build attestation, signed checksums and an OpenTimestamps proof.
- **Pinned toolchain:** CI actions are pinned to commit SHAs, and a test fails if one is not.

## 6. Review and red-teaming

Every change is reviewed by more than its author:

- **Independent reviews.** One AI model writes a fix. Several others that did not write it review it (DeepSeek V4.1, Kimi K3, GLM 5.3, Muse Spark and Nemotron 3 Ultra take turns), and each review names the model that wrote it.
- **A red-team gate.** DeepSeek V4.1 audits every pull request adversarially before the final decision.
- **Proof before belief.** A reported bug counts only after an executed probe shows it, and two rounds of judging (one with the real `app.js` call sites) agree it is a defect and not behaviour the BIPs require. Model findings are often confidently wrong; this filter exists because of that.
- **Final check.** Claude Opus coordinates and checks each change against the BIPs and the actual code before it merges. Bug fixes merge only with green CI, at least three approvals from models that did not write the change, and no unresolved blocker from the red-team gate. Features wait for the maintainer.
- **The ledger.** Every audit, finding, refutation and fix is recorded in [audits/README.md](audits/README.md). Earlier audits are in [Adversarial_Audit.md](Adversarial_Audit.md).

Reviews and decisions are posted on each pull request, so the trail is public.

## What this does not claim

Testing finds bugs; it cannot prove there are none. EntropyLab is a calculator for checking and learning, not a replacement for a hardware wallet or a reviewed signing device. Use it offline, verify what it shows against a second tool, and see [SECURITY.md](../SECURITY.md) for how to report a vulnerability.
