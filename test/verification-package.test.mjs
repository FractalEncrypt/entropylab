import test from "node:test";
import assert from "node:assert/strict";

import {
  buildVerificationPackage,
  verificationPackageFilename,
} from "../src/js/verification-package.js";
import { hashesReady } from "../src/js/hashes.js";

// base58.js runs in the WASM module.
await hashesReady;

// BIP-84 test vector: account 0 of "abandon … about" in both serialisations,
// so the SLIP-132 rewrite has an expected value that does not come from the
// code under test.
const BIP84_XPUB = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
const BIP84_ZPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

// Bitcoin Core doc/descriptors.md example, checksum included.
const CORE_DESCRIPTOR_BODY = "wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)";
const CORE_DESCRIPTOR_CHECKSUM = "cjjspncu";

// BIP-84 first receive and first change address.
const RECEIVE_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const CHANGE_ADDRESS = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";

const PSBT_BASE64 = "cHNidP8BAH0CAAAAAA==";
const WALLET_DAT_SHA256 = "0123456789abcdef".repeat(4);

const FULL_INPUT = {
  network: "mainnet",
  masterFingerprint: "d34db33f",
  descriptors: [`wpkh([d34db33f/84h/0h/0h]${BIP84_XPUB}/0/*)`],
  xpubs: [BIP84_XPUB],
  receiveAddresses: [{ index: 0, address: RECEIVE_ADDRESS }],
  changeAddresses: [{ index: 0, address: CHANGE_ADDRESS }],
  psbtBase64: PSBT_BASE64,
  walletDatSha256: WALLET_DAT_SHA256,
};

test("round-trips a full package with the documented keys in order", () => {
  const json = buildVerificationPackage(FULL_INPUT);
  assert.ok(json.endsWith("\n"), "the package ends with a newline");
  assert.ok(json.includes('\n  "schema": "entropylab-verification/1",\n'), "pretty-printed with two spaces");
  const parsed = JSON.parse(json);
  assert.deepEqual(Object.keys(parsed), [
    "schema",
    "network",
    "masterFingerprint",
    "descriptors",
    "xpubs",
    "receiveAddresses",
    "changeAddresses",
    "psbt",
    "walletDatSha256",
  ]);
  assert.equal(parsed.schema, "entropylab-verification/1");
  assert.equal(parsed.network, "main");
  assert.equal(parsed.masterFingerprint, "d34db33f");
  assert.equal(parsed.descriptors.length, 1);
  assert.ok(parsed.descriptors[0].startsWith(`wpkh([d34db33f/84h/0h/0h]${BIP84_XPUB}/0/*)#`));
  assert.match(parsed.descriptors[0], /#[a-z0-9]{8}$/);
  assert.deepEqual(parsed.xpubs, [BIP84_XPUB]);
  assert.deepEqual(parsed.receiveAddresses, [{ index: 0, address: RECEIVE_ADDRESS }]);
  assert.deepEqual(parsed.changeAddresses, [{ index: 0, address: CHANGE_ADDRESS }]);
  assert.equal(parsed.psbt, PSBT_BASE64);
  assert.equal(parsed.walletDatSha256, WALLET_DAT_SHA256);
});

const NETWORK_CASES = [
  ["mainnet", "main"],
  ["testnet", "test"],
  ["testnet3", "test"],
  ["testnet4", "test"],
  ["signet", "signet"],
  ["regtest", "regtest"],
];

for (const [entropylabName, expected] of NETWORK_CASES) {
  test(`maps the ${entropylabName} network to ${expected}`, () => {
    const parsed = JSON.parse(buildVerificationPackage({
      network: entropylabName,
      receiveAddresses: [{ index: 0, address: RECEIVE_ADDRESS }],
    }));
    assert.equal(parsed.network, expected);
  });
}

test("refuses an unknown network", () => {
  assert.throws(
    () => buildVerificationPackage({
      network: "liquid",
      receiveAddresses: [{ index: 0, address: RECEIVE_ADDRESS }],
    }),
    { message: /^network:/ },
  );
});

test("appends a missing descriptor checksum", () => {
  const parsed = JSON.parse(buildVerificationPackage({
    network: "mainnet",
    descriptors: [CORE_DESCRIPTOR_BODY],
  }));
  assert.deepEqual(parsed.descriptors, [`${CORE_DESCRIPTOR_BODY}#${CORE_DESCRIPTOR_CHECKSUM}`]);
});

test("refuses a descriptor whose checksum does not match", () => {
  assert.throws(
    () => buildVerificationPackage({
      network: "mainnet",
      descriptors: [`${CORE_DESCRIPTOR_BODY}#cjjspncv`],
    }),
    { message: /^checksum:/ },
  );
});

test("rewrites a SLIP-132 zpub descriptor as xpub", () => {
  const parsed = JSON.parse(buildVerificationPackage({
    network: "mainnet",
    descriptors: [`wpkh([d34db33f/84h/0h/0h]${BIP84_ZPUB}/0/*)`],
  }));
  assert.equal(parsed.descriptors.length, 1);
  assert.ok(parsed.descriptors[0].includes(BIP84_XPUB), "the zpub is rewritten as the matching xpub");
  assert.equal(parsed.descriptors[0].includes("zpub"), false);
  assert.match(parsed.descriptors[0], /#[a-z0-9]{8}$/);
});

const PRIVATE_FORMS = {
  "an extended private key": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
  "a capital Zprv": "ZprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5",
  "a WIF": "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
  "a twelve word mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
};

const PLACEMENTS = {
  descriptor: (material) => ({ descriptors: [material] }),
  xpub: (material) => ({ xpubs: [material] }),
  address: (material) => ({ receiveAddresses: [{ index: 0, address: material }] }),
  psbt: (material) => ({ psbtBase64: material }),
};

for (const [formName, material] of Object.entries(PRIVATE_FORMS)) {
  for (const [placeName, place] of Object.entries(PLACEMENTS)) {
    test(`refuses ${formName} in the ${placeName} field`, () => {
      assert.throws(
        () => buildVerificationPackage({ network: "mainnet", ...place(material) }),
        (error) => {
          assert.match(error.message, /^private:/);
          assert.equal(error.message.includes(material), false, "the refusal must not echo the material");
          return true;
        },
      );
    });
  }
}

test("refuses a package with nothing to verify", () => {
  assert.throws(
    () => buildVerificationPackage({ network: "mainnet" }),
    { message: /^empty:/ },
  );
  assert.throws(
    () => buildVerificationPackage({ network: "mainnet", descriptors: [], receiveAddresses: [], changeAddresses: [] }),
    { message: /^empty:/ },
  );
});

test("the same input produces byte-identical output", () => {
  const first = buildVerificationPackage(FULL_INPUT);
  const second = buildVerificationPackage(JSON.parse(JSON.stringify(FULL_INPUT)));
  assert.equal(first, second);
});

test("sanitises the filename label", () => {
  assert.equal(verificationPackageFilename("Cold Card"), "entropylab-verification-coldcard.json");
  assert.equal(verificationPackageFilename("../../etc/passwd"), "entropylab-verification-etcpasswd.json");
  assert.equal(verificationPackageFilename("my-wallet-2"), "entropylab-verification-my-wallet-2.json");
  assert.equal(verificationPackageFilename(""), "entropylab-verification-wallet.json");
  assert.equal(verificationPackageFilename(undefined), "entropylab-verification-wallet.json");
});
