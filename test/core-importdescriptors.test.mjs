// Tests for src/js/core-importdescriptors.js — watch-only Bitcoin Core
// importdescriptors JSON. Calculator export, not a generator.
// Run with: node --test test/core-importdescriptors.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { NETWORK, TEST_NETWORK, p2pkh, p2sh, p2tr, p2wpkh } from "@scure/btc-signer";
import { BITCOIND, CHAIN_FIXTURES, withChainNode } from "./bitcoind-harness.mjs";
import {
  CORE_IMPORT_RANGE_END,
  assertMatchingWatchDescriptors,
  buildImportDescriptorsJson,
  canonicalizeWatchDescriptor,
  coreImportDescriptorsFilename,
  descriptorChecksum,
  stripDescriptorChecksum,
} from "../src/js/core-importdescriptors.js";
import { b58checkDecode, b58checkEncode, descriptorChecksum as harnessChecksum } from "./wallet-export-harness.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const codec = { decode: b58checkDecode, encode: b58checkEncode };

const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = HDKey.fromMasterSeed(seed);
const fingerprint = master.fingerprint.toString(16).padStart(8, "0");
const nodeA = master.derive("m/48'/0'/0'/2'");
const nodeB = master.derive("m/48'/0'/1'/2'");
const nodeC = master.derive("m/48'/0'/2'/2'");
const keyA = `[${fingerprint}/48h/0h/0h/2h]${nodeA.publicExtendedKey}`;
const keyB = `[${fingerprint}/48h/0h/1h/2h]${nodeB.publicExtendedKey}`;
const keyC = `[${fingerprint}/48h/0h/2h/2h]${nodeC.publicExtendedKey}`;
const receiveBody = `wsh(sortedmulti(2,${keyA}/0/*,${keyB}/0/*,${keyC}/0/*))`;
const changeBody = `wsh(sortedmulti(2,${keyA}/1/*,${keyB}/1/*,${keyC}/1/*))`;
const receive = `${receiveBody}#${descriptorChecksum(receiveBody)}`;
const change = `${changeBody}#${descriptorChecksum(changeBody)}`;

const parse = (json) => JSON.parse(json);

// Exercise the application adapter with independently derived public fixtures.
function keyExportHarness() {
  const source = read("src/js/app.js");
  const context = vm.createContext({ buildImportDescriptorsJson, hodlBase58Check: codec,
    hodlWalletDatBirthday: "genesis", hodlAccountId: "bip84", hodlWalletResult: null });
  for (const name of ["hodlMsigCoreImportCodec", "hodlMsigDisplayedAddressEnd", "hodlCoreImportDescriptorsWallet", "hodlCoreImportDescriptorsJson"]) {
    const match = source.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
    assert.ok(match, `application export adapter ${name} exists`);
    vm.runInContext(match[0], context);
  }
  return context;
}

test("Key Station exports only the selected public account with the existing birthday and range rules", () => {
  const ui = keyExportHarness();
  const accounts = [44, 49, 84, 86].map((purpose) => {
    const node = master.derive(`m/${purpose}'/0'/0'`);
    const wrap = body => purpose === 49 ? `sh(wpkh(${body}))` : `${purpose === 44 ? "pkh" : purpose === 86 ? "tr" : "wpkh"}(${body})`;
    const descriptor = branch => {
      const body = wrap(`[${fingerprint}/${purpose}h/0h/0h]${node.publicExtendedKey}/${branch}/*`);
      return `${body}#${harnessChecksum(body)}`;
    };
    return { def: { id: `bip${purpose}` }, receiveDescriptor: descriptor(0), changeDescriptor: descriptor(1),
      addressBranches: [{ branch: 0, rows: [{ index: 5000 }] }, { branch: 1, rows: [{ index: 5002 }] }],
      get privateNode() { throw new Error("private material read"); } };
  });
  ui.hodlWalletResult = { kind: "hd", accounts, get seed() { throw new Error("seed read"); } };
  for (const account of accounts) for (const birthday of ["genesis", "now"]) {
    ui.hodlAccountId = account.def.id;
    ui.hodlWalletDatBirthday = birthday;
    ui.hodlRevealPrivate = true;
    assert.deepEqual(parse(ui.hodlCoreImportDescriptorsJson("calc")), [false, true].map(internal => ({
      desc: internal ? account.changeDescriptor : account.receiveDescriptor,
      active: true, internal, timestamp: birthday === "now" ? "now" : 0, range: [0, 6002],
    })));
  }
  ui.hodlAccountId = "stale-account";
  assert.equal(parse(ui.hodlCoreImportDescriptorsJson("calc"))[0].desc, accounts[2].receiveDescriptor, "fallback matches the displayed account");
  accounts[2].receiveDescriptor = `wpkh(${master.privateExtendedKey}/0/*)`;
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /private key/);
  ui.hodlWalletResult = null;
  assert.equal(ui.hodlCoreImportDescriptorsJson("calc"), "");
  ui.hodlWalletResult = { kind: "single" };
  assert.equal(ui.hodlCoreImportDescriptorsJson("calc"), "");
});

test("checksum matches the independent Core reference", () => {
  assert.equal(descriptorChecksum(receiveBody), harnessChecksum(receiveBody));
});

test("Key Station handles imported watch-only keys and never reuses a previous wallet's export", () => {
  const ui = keyExportHarness();
  const makeAccount = (node) => {
    const descriptor = branch => {
      const body = `wpkh(${node.publicExtendedKey}/${branch}/*)`;
      return `${body}#${harnessChecksum(body)}`;
    };
    return { def: { id: "bip84" }, receiveDescriptor: descriptor(0), changeDescriptor: descriptor(1), receive: [{ index: 0 }] };
  };
  const first = makeAccount(master.derive("m/84'/0'/0'"));
  const second = makeAccount(master.derive("m/84'/0'/1'"));
  // An imported zpub carries the same public payload as its Core xpub.
  const xpub = master.derive("m/84'/0'/0'").publicExtendedKey;
  const raw = b58checkDecode(xpub);
  raw.set([0x04, 0xb2, 0x47, 0x46]);
  const zpub = b58checkEncode(raw);
  const imported = { ...first };
  for (const name of ["receiveDescriptor", "changeDescriptor"]) {
    const body = stripDescriptorChecksum(first[name]).replace(xpub, zpub);
    imported[name] = `${body}#${harnessChecksum(body)}`;
  }
  ui.hodlWalletResult = { kind: "hd", accounts: [imported] };
  const beforeSwitch = parse(ui.hodlCoreImportDescriptorsJson("calc"));
  assert.deepEqual(beforeSwitch.map(entry => entry.desc), [first.receiveDescriptor, first.changeDescriptor]);
  ui.hodlWalletResult = { kind: "hd", accounts: [second] };
  assert.equal(parse(ui.hodlCoreImportDescriptorsJson("calc"))[0].desc, second.receiveDescriptor);
  assert.equal(ui.hodlCoreImportDescriptorsJson("msig"), "", "a stale multisig control cannot export the active key");
  second.receive[0].index = 998999;
  assert.deepEqual(parse(ui.hodlCoreImportDescriptorsJson("calc"))[0].range, [0, 999999]);
  second.receive[0].index = 999000;
  assert.throws(() => ui.hodlCoreImportDescriptorsJson("calc"), /importdescriptors refuses a range span/);
  ui.hodlWalletResult = { kind: "msig", receiveDescriptor: receive, changeDescriptor: change };
  assert.equal(ui.hodlCoreImportDescriptorsJson("calc"), "", "a stale key control cannot export the active multisig");
  assert.equal(parse(ui.hodlCoreImportDescriptorsJson("msig"))[0].desc, receive);
});

test("JSON.parse of the export is an array of length 2", () => {
  const entries = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(entries.length, 2);
});

test("receive is external, change is internal, both active, default range matches wallet.dat", () => {
  const walletSrc = read("src/js/wallet-export.js");
  const range = walletSrc.match(/const RANGE_END = (\d+)/);
  assert.equal(CORE_IMPORT_RANGE_END, Number(range[1]));
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(external.internal, false);
  assert.equal(internal.internal, true);
  assert.equal(external.active, true);
  assert.equal(internal.active, true);
  // No displayed-window number handed over: the range keeps Core's default
  // lookahead, ending at 0 + RANGE_END, exactly as wallet-export.js's
  // branchRangeFromRows reports a wallet it was given no rows for.
  assert.deepEqual(external.range, [0, CORE_IMPORT_RANGE_END]);
  assert.deepEqual(internal.range, [0, CORE_IMPORT_RANGE_END]);
});

test("the import range runs past the displayed address window like the wallet.dat export (audit B7b)", () => {
  // The wallet.dat side pins this arithmetic outright (wallet-export.test.mjs
  // "descriptor ranges cover displayed addresses plus a recovery gap"): rows
  // indexed 5000..5002 are watched through 5002 + 1000 = 6002, start pinned
  // to 0 so a fresh Core wallet's first getnewaddress is receive index 0.
  // The msig screen can display address windows up to 2^31-1; an export that
  // still said [0, 1000] would leave every shown address above 1000 unwatched.
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, rangeEnd: 5002 }));
  assert.deepEqual(external.range, [0, 6002]);
  assert.deepEqual(internal.range, [0, 6002]);
  // A window ending at 0 is exactly Core's default range.
  const [zero] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, rangeEnd: 0 }));
  assert.deepEqual(zero.range, [0, CORE_IMPORT_RANGE_END]);
  // The deepest windows (up to the last unhardened BIP32 child index) are
  // refused outright: Core's own import bound — a range span under
  // 1,000,000 — is tighter than the index bound, so [0, 2^31-1] would be
  // JSON the online node rejects. The Core-bound test below pins the exact
  // refusal boundary (999,000) against a port of ParseDescriptorRange.
});

test("a displayed window the export cannot cover is refused (audit B7b)", () => {
  // Core can watch at most 0..2^31-1; deeper or malformed window ends must
  // fail loudly instead of shipping an import that misses displayed rows.
  for (const rangeEnd of [-1, 0.5, Number.NaN, "5002", 2147483648, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER]) {
    assert.throws(
      () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, rangeEnd }),
      /a whole number from 0 to 2,147,483,647/,
    );
  }
});

// Bitcoin Core's own import bound (ParseDescriptorRange, src/rpc/util.cpp,
// applied by importdescriptors): a range whose span reaches 1,000,000 is
// refused at import with "Range is too large". The range start is pinned at
// 0, so a displayed end of 999,000 would export [0, 1000000] — JSON Core
// rejects on the online node. Refuse those ends at build time (#861 review).
// coreRangeError is a port of Core's check, the independent oracle.
const coreRangeError = ([low, high]) =>
  low < 0 ? "Range should be greater or equal than 0"
  : Math.floor(high / 2 ** 31) !== 0 ? "End of range is too high"
  : low > high ? "Range specified as [begin,end] must not have begin after end"
  : high - low >= 1000000 ? "Range is too large"
  : null;
test("a window Core's importdescriptors would refuse at import is refused at export (audit B7b)", () => {
  for (const rangeEnd of [5002, 998998, 998999]) {
    const [entry] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, rangeEnd }));
    assert.equal(coreRangeError(entry.range), null, `shown end ${rangeEnd} produces a range Core accepts`);
  }
  for (const rangeEnd of [999000, 5000000, 2147482647, 2147483647]) {
    assert.throws(
      () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, rangeEnd }),
      /importdescriptors refuses a range span/,
      `shown end ${rangeEnd} must be refused, not exported as JSON Core rejects`,
    );
  }
});

test("default timestamp is number 0; now mode is the string now", () => {
  const genesis = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(genesis[0].timestamp, 0);
  assert.equal(typeof genesis[0].timestamp, "number");
  const created = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, timestamp: "now" }));
  assert.equal(created[0].timestamp, "now");
  assert.equal(created[1].timestamp, "now");
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change, timestamp: 1710000000 }),
    /timestamp must be 0 or "now"/,
  );
});

test("desc strings include a matching BIP-380 checksum", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  for (const entry of [external, internal]) {
    const hash = entry.desc.lastIndexOf("#");
    assert.ok(hash > 0);
    assert.equal(entry.desc.slice(hash + 1), descriptorChecksum(entry.desc.slice(0, hash)));
  }
});

test("bodies are the msig receive and change descriptors with origins kept", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(stripDescriptorChecksum(external.desc), receiveBody);
  assert.equal(stripDescriptorChecksum(internal.desc), changeBody);
  assert.match(external.desc, new RegExp(`\\[${fingerprint}/48h/0h/0h/2h\\]`));
  assert.match(external.desc, /sortedmulti\(2,/);
});

test("the JSON never contains xprv-family keys, a mnemonic, or a seed", () => {
  const json = buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change });
  assert.doesNotMatch(json, /[xyztuvYZUV]prv/);
  assert.doesNotMatch(json, /abandon/);
  assert.doesNotMatch(json, /mnemonic|passphrase|seed phrase/i);
});

test("receive and change only differ by /0/* vs /1/*", () => {
  const [external, internal] = parse(buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: change }));
  assert.equal(
    stripDescriptorChecksum(external.desc).replaceAll("/0/*", "/1/*"),
    stripDescriptorChecksum(internal.desc),
  );
  assertMatchingWatchDescriptors(external.desc, internal.desc);
});

test("a receive-only wallet still exports one external descriptor", () => {
  const entries = parse(buildImportDescriptorsJson({ receiveDescriptor: receive }));
  assert.equal(entries.length, 1);
  assert.equal(entries[0].internal, false);
  assert.equal(entries[0].desc, receive);
});

test("SLIP-132 Zpub is rewritten to xpub when the codec is supplied", () => {
  const zpub = (() => {
    const raw = b58checkDecode(nodeA.publicExtendedKey);
    raw[0] = 0x02; raw[1] = 0xaa; raw[2] = 0x7e; raw[3] = 0xd3;
    return b58checkEncode(raw);
  })();
  assert.match(zpub, /^Zpub/);
  const slipBody = `wsh(sortedmulti(2,[${fingerprint}/48h/0h/0h/2h]${zpub}/0/*,${keyB}/0/*))`;
  const slip = `${slipBody}#${descriptorChecksum(slipBody)}`;
  assert.throws(() => canonicalizeWatchDescriptor(slip), /SLIP-132|Base58Check codec/);
  const canonical = canonicalizeWatchDescriptor(slip, codec);
  assert.match(canonical, /xpub/);
  assert.doesNotMatch(canonical, /Zpub/);
  const json = buildImportDescriptorsJson({ receiveDescriptor: slip, decode: codec.decode, encode: codec.encode });
  assert.match(json, /xpub/);
  assert.doesNotMatch(json, /Zpub/);
});

test("an extended private key is refused", () => {
  const xprv = nodeA.privateExtendedKey;
  const body = `wsh(sortedmulti(1,[${fingerprint}/48h/0h/0h/2h]${xprv}/0/*))`;
  const descriptor = `${body}#${descriptorChecksum(body)}`;
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: descriptor, changeDescriptor: change }),
    /extended private key/,
  );
});

test("capital SLIP-132 multisig private keys are refused", () => {
  // Yprv, Zprv (mainnet), Uprv, Vprv (testnet) — the private counterparts of
  // the capital public prefixes this module rewrites.
  for (const version of [0x0295b005, 0x02aa7a99, 0x024285b5, 0x02575048]) {
    const raw = b58checkDecode(nodeA.privateExtendedKey);
    raw[0] = version >>> 24 & 255; raw[1] = version >>> 16 & 255; raw[2] = version >>> 8 & 255; raw[3] = version & 255;
    const key = b58checkEncode(raw);
    assert.match(key, /^[YZUV]prv/);
    const body = `wsh(sortedmulti(1,${key}/0/*))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    assert.throws(() => buildImportDescriptorsJson({ receiveDescriptor: descriptor }), /extended private key/);
  }
});

test("mismatched receive/change keys are refused", () => {
  const other = `wsh(sortedmulti(2,${keyA}/1/*,${keyB}/1/*))`;
  const otherDesc = `${other}#${descriptorChecksum(other)}`;
  assert.throws(
    () => buildImportDescriptorsJson({ receiveDescriptor: receive, changeDescriptor: otherDesc }),
    /different keys/,
  );
});

test("missing descriptors and a bad checksum are refused", () => {
  assert.throws(() => buildImportDescriptorsJson({}), /No watch-only descriptors/);
  const corrupted = receive.slice(0, -1) + (receive.endsWith("0") ? "1" : "0");
  assert.throws(() => buildImportDescriptorsJson({ receiveDescriptor: corrupted }), /checksum does not match/);
});

test("filename includes the m-of-n policy when present", () => {
  assert.equal(coreImportDescriptorsFilename({ m: 3, n: 7 }), "entropylab-msig-3of7-importdescriptors.json");
  assert.equal(coreImportDescriptorsFilename({}), "entropylab-importdescriptors.json");
});

test("the builder never talks to the network", () => {
  const source = read("src/js/core-importdescriptors.js");
  assert.doesNotMatch(source, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
});

test("MS Station result markup renders every documented export; no new workspace tab", () => {
  const app = read("src/js/app.js");
  const shell = read("src/shell.html");
  // Audit B7a: README.md/llms.txt promise the msig wallet.dat, the watch-only
  // policy sheet (print + save) and the BIP 388 policy (copy + save); every
  // one of those controls must appear in the markup hodlShowMsig renders, and
  // hodlShowMsig must interpolate each builder, not a copy of it.
  assert.match(app, /id="\$\{prefix\}-copy-importdescriptors"/);
  assert.match(app, /id="\$\{prefix\}-save-importdescriptors"/);
  assert.match(app, /id="msig-download-wallet-dat"/);
  assert.match(app, /id="msig-print-policy-sheet"/);
  assert.match(app, /id="msig-save-policy-sheet"/);
  assert.match(app, /id="msig-copy-bip388"/);
  assert.match(app, /id="msig-save-bip388"/);
  assert.match(app, /hodlT\("Copy Core importdescriptors"\)/);
  assert.match(app, /hodlT\("Save Core Watch-only JSON"\)/);
  assert.match(app, /buildImportDescriptorsJson/);
  assert.match(app, /hodlCoreImportDescriptorsButtons\("msig"\)/);
  const showStart = app.indexOf("function hodlShowMsig(");
  const show = app.slice(showStart, app.indexOf("\nvar ", showStart));
  assert.match(show, /\$\{hodlMsigCoreImportDescriptorsMarkup\(\)\}/);
  assert.match(show, /\$\{hodlMsigPolicySheetMarkup\(\)\}/);
  assert.match(show, /\$\{hodlMsigBip388Markup\(\)\}/);
  assert.doesNotMatch(shell, /msig-copy-importdescriptors|msig-save-importdescriptors/);
  assert.doesNotMatch(shell, /id="workspace-tabs"[\s\S]{0,2000}importdescriptors/);
  assert.match(shell, /id="workspace-tabs"/);
});

test("wallet.dat export accepts watch-only msig and still ignores private material", () => {
  const source = read("src/js/wallet-export.js");
  assert.match(source, /kind === "msig"/);
  assert.match(source, /multiKey: true/);
  assert.match(source, /privateDescriptor: null/);
});

// Core is the consumer of this JSON. Independently derived scure addresses
// check both branches, including index 0 when the displayed window starts at 2.
for (const network of Object.keys(CHAIN_FIXTURES)) {
  test(`Bitcoin Core imports Key Station JSON on ${network}`, { skip: !BITCOIND, timeout: 120000 }, async () => {
    const ui = keyExportHarness(), mainnet = network === "mainnet";
    const net = mainnet ? NETWORK : { ...TEST_NETWORK, bech32: network === "regtest" ? "bcrt" : "tb" };
    const versions = mainnet ? undefined : { public: 0x043587cf, private: 0x04358394 };
    await withChainNode(network, (cli) => {
      const rpc = (...args) => JSON.parse(cli(args).stdout);
      for (const purpose of [44, 49, 84, 86]) {
        const node = HDKey.fromMasterSeed(seed, versions).derive(`m/${purpose}'/${mainnet ? 0 : 1}'/0'`);
        const descriptor = branch => {
          const key = `${node.publicExtendedKey}/${branch}/*`;
          const body = purpose === 49 ? `sh(wpkh(${key}))` : `${purpose === 44 ? "pkh" : purpose === 86 ? "tr" : "wpkh"}(${key})`;
          return `${body}#${harnessChecksum(body)}`;
        };
        const expected = (branch, index) => {
          const key = node.deriveChild(branch).deriveChild(index).publicKey;
          return (purpose === 44 ? p2pkh(key, net) : purpose === 49 ? p2sh(p2wpkh(key, net), net) : purpose === 86 ? p2tr(key.slice(1), undefined, net) : p2wpkh(key, net)).address;
        };
        ui.hodlAccountId = `bip${purpose}`;
        ui.hodlRevealPrivate = true;
        ui.hodlWalletResult = { kind: "hd", accounts: [{ def: { id: ui.hodlAccountId },
          receiveDescriptor: descriptor(0), changeDescriptor: descriptor(1), receive: [{ index: 2 }], change: [{ index: 2 }],
          get privateNode() { throw new Error("private material read"); } }] };
        for (const birthday of ["genesis", "now"]) {
          ui.hodlWalletDatBirthday = birthday;
          const name = `key-${purpose}-${birthday}`, wallet = `-rpcwallet=${name}`;
          rpc("-named", "createwallet", `wallet_name=${name}`, "disable_private_keys=true", "blank=true");
          assert.ok(rpc(wallet, "importdescriptors", ui.hodlCoreImportDescriptorsJson("calc")).every(entry => entry.success));
          const stored = rpc(wallet, "listdescriptors").descriptors;
          assert.equal(stored.length, 2);
          assert.equal(rpc(wallet, "getwalletinfo").private_keys_enabled, false);
          for (const entry of stored) {
            assert.deepEqual(entry.range, [0, 1002]);
            // Core v31.1 rpc/backup.cpp clamps 0 to 1 and resolves "now"
            // to the current chain tip's median time, not the wall clock.
            assert.equal(entry.timestamp, birthday === "genesis" ? 1 : rpc("getblockchaininfo").mediantime);
            assert.equal(rpc("getdescriptorinfo", entry.desc).hasprivatekeys, false);
            assert.deepEqual(rpc("deriveaddresses", entry.desc, "[2,2]"), [expected(entry.internal ? 1 : 0, 2)]);
          }
          const type = { 44: "legacy", 49: "p2sh-segwit", 84: "bech32", 86: "bech32m" }[purpose];
          assert.equal(cli([wallet, "getnewaddress", "", type]).stdout.trim(), expected(0, 0));
          assert.equal(cli([wallet, "getrawchangeaddress", type]).stdout.trim(), expected(1, 0));
        }
      }
    });
  });
}
