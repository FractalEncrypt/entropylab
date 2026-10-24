// Public-only verification package for independent Bitcoin Core checks.
//
// EntropyLab hands an external verifier (portlandhodl/wasm-bitcoin-tools) a
// small, versioned JSON document holding only public output: descriptors,
// extended public keys, addresses, a PSBT and a wallet.dat digest. Nothing
// secret may cross that boundary, so every string in the input is scanned for
// private key material before anything is emitted. Pure: no I/O, no clock,
// same input → same bytes.

import { base58checkDecode, base58checkEncode } from "./base58.js";
import { wordlist } from "./bip39-english.js";
import { canonicalizeWatchDescriptor, descriptorChecksum } from "./core-importdescriptors.js";

const SCHEMA = "entropylab-verification/1";

const NETWORKS = new Map([
  ["mainnet", "main"],
  ["testnet", "test"],
  ["testnet3", "test"],
  ["testnet4", "test"],
  ["signet", "signet"],
  ["regtest", "regtest"],
]);

// Base58Check lives here so the module stays pure and dependency-free. Its
// only job is rewriting a SLIP-132 version field; the descriptor checksum
// still pins the rest of the string.
const BASE58_RUN = /[1-9A-HJ-NP-Za-km-z]+/g;
const EXTENDED_PRIVATE_PREFIX = /^(?:[xyztuv]prv|[YZUV]prv)/;
const WIF_PREFIXES = "5KL9c";
const WORD_RUN = /[A-Za-z]+/g;
const BIP39_WORDS = new Set(wordlist);

// Base58Check through the repo's own codec (base58.js, WASM-backed), the
// same one the app passes to canonicalizeWatchDescriptor; no hand-written
// hashing here.
const BASE58CHECK = { decode: base58checkDecode, encode: base58checkEncode };

// A key or WIF is a whole base58 token, never a slice of a longer one: an
// xpub is 111 characters and would otherwise contain 51-character windows
// starting with 5/K/L/9/c by chance.
function containsExtendedPrivateKey(text) {
  for (const match of text.matchAll(BASE58_RUN)) {
    if (match[0].length >= 94 && EXTENDED_PRIVATE_PREFIX.test(match[0])) return true;
  }
  return false;
}

function containsWif(text) {
  for (const match of text.matchAll(BASE58_RUN)) {
    const token = match[0];
    if ((token.length === 51 || token.length === 52) && WIF_PREFIXES.includes(token[0])) return true;
  }
  return false;
}

function containsMnemonicRun(text) {
  let run = 0;
  for (const match of text.matchAll(WORD_RUN)) {
    if (BIP39_WORDS.has(match[0].toLowerCase())) {
      run += 1;
      if (run >= 12) return true;
    } else {
      run = 0;
    }
  }
  return false;
}

function collectStrings(value, out) {
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      out.push(key);
      collectStrings(item, out);
    }
  }
}

// The refusal never repeats the material: the message is fixed text.
function assertPublicOnly(input) {
  const strings = [];
  collectStrings(input, strings);
  for (const text of strings) {
    if (containsExtendedPrivateKey(text) || containsWif(text) || containsMnemonicRun(text)) {
      throw new Error("private: the verification package is public-only and must not carry private key material.");
    }
  }
}

function mapNetwork(network) {
  const mapped = typeof network === "string" ? NETWORKS.get(network) : undefined;
  if (!mapped) throw new Error("network: unsupported network for a verification package.");
  return mapped;
}

function optionalHex(value, length, label) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`${label}: expected ${length} lowercase hex characters.`);
  }
  return value;
}

function normalizeDescriptor(descriptor) {
  if (typeof descriptor !== "string") throw new Error("descriptor: each descriptor must be a string.");
  const text = descriptor.trim();
  if (!text) throw new Error("descriptor: descriptor is empty.");
  const hash = text.lastIndexOf("#");
  if (hash >= 0) {
    let expected;
    try {
      expected = descriptorChecksum(text.slice(0, hash));
    } catch (error) {
      throw new Error(`descriptor: ${error.message}`);
    }
    if (expected !== text.slice(hash + 1)) throw new Error("checksum: descriptor checksum does not match.");
  }
  try {
    return canonicalizeWatchDescriptor(text, BASE58CHECK, "Descriptor");
  } catch (error) {
    throw new Error(`descriptor: ${error.message}`);
  }
}

function normalizeDescriptors(descriptors) {
  if (descriptors === undefined || descriptors === null) return [];
  if (!Array.isArray(descriptors)) throw new Error("descriptor: descriptors must be an array.");
  return descriptors.map(normalizeDescriptor);
}

function normalizeXpubs(xpubs) {
  if (xpubs === undefined || xpubs === null) return [];
  if (!Array.isArray(xpubs)) throw new Error("xpub: xpubs must be an array.");
  return xpubs.map((xpub) => {
    if (typeof xpub !== "string" || !xpub.trim()) throw new Error("xpub: each extended public key must be a non-empty string.");
    return xpub.trim();
  });
}

function normalizeAddresses(entries, label) {
  if (entries === undefined || entries === null) return [];
  if (!Array.isArray(entries)) throw new Error(`${label}: must be an array.`);
  const addresses = [];
  let previous = -1;
  for (const entry of entries) {
    if (!entry || typeof entry !== "object") throw new Error(`${label}: each entry needs an index and an address.`);
    if (!Number.isSafeInteger(entry.index) || entry.index < 0) throw new Error(`${label}: index must be a non-negative whole number.`);
    if (entry.index <= previous) throw new Error(`${label}: indexes must ascend without duplicates.`);
    previous = entry.index;
    if (typeof entry.address !== "string" || !entry.address.trim()) throw new Error(`${label}: address must be a non-empty string.`);
    addresses.push({ index: entry.index, address: entry.address.trim() });
  }
  return addresses;
}

function normalizePsbt(psbtBase64) {
  if (psbtBase64 === undefined || psbtBase64 === null) return null;
  const text = typeof psbtBase64 === "string" ? psbtBase64.trim() : "";
  if (!text.startsWith("cHNidP8")) throw new Error("psbt: expected base64 PSBT data beginning with cHNidP8.");
  return text;
}

export function buildVerificationPackage(input) {
  const source = input && typeof input === "object" ? input : {};
  assertPublicOnly(source);
  const network = mapNetwork(source.network);
  const masterFingerprint = optionalHex(source.masterFingerprint, 8, "masterFingerprint");
  const walletDatSha256 = optionalHex(source.walletDatSha256, 64, "walletDatSha256");
  const descriptors = normalizeDescriptors(source.descriptors);
  const xpubs = normalizeXpubs(source.xpubs);
  const receiveAddresses = normalizeAddresses(source.receiveAddresses, "receiveAddresses");
  const changeAddresses = normalizeAddresses(source.changeAddresses, "changeAddresses");
  const psbt = normalizePsbt(source.psbtBase64);
  if (!descriptors.length && !receiveAddresses.length && !changeAddresses.length) {
    throw new Error("empty: a verification package needs at least one descriptor or one address.");
  }
  return `${JSON.stringify({
    schema: SCHEMA,
    network,
    masterFingerprint,
    descriptors,
    xpubs,
    receiveAddresses,
    changeAddresses,
    psbt,
    walletDatSha256,
  }, null, 2)}\n`;
}

export function verificationPackageFilename(label) {
  const cleaned = String(label ?? "").toLowerCase().replace(/[^a-z0-9-]/g, "");
  return `entropylab-verification-${cleaned || "wallet"}.json`;
}
