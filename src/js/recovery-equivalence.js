// Wallet Recovery Equivalence Verification (issue #171).
//
// compareRecoveryArtifacts() answers one narrow question: do the supplied
// recovery artifacts (seed/mnemonic, xpub, SLIP-132 key, descriptor,
// address) describe the same key derivation and output policy?
//
// Security reasoning:
// - Verification only. Never generates entropy, never signs, never touches
//   the network. It composes the repo's existing, already-tested primitives
//   (HDKey, descriptorDerive, base58check, bip39) as black boxes and adds
//   no new cryptography.
// - Fail closed: unsupported descriptor templates, malformed keys, and
//   artifact subsets that share no checkable claim produce explicit
//   "insufficient" outcomes with a named failing step, never a silent pass.
// - A user pasting a seed here extends the same trust they already place
//   in EntropyLab's other workspaces; nothing new is persisted or exposed.
//
// Scope (v1): single-signature templates — pkh, wpkh, sh(wpkh), tr — with
// one extended public key and an optional [fingerprint/path] key origin.
// Multisig (wsh/multi/sortedmulti, Ypub/Zpub), miniscript, combo(), and
// raw-hex-key-only descriptors are reported UNSUPPORTED, not INVALID.

import { HDKey } from "./hdkey.js";
import { mnemonicToSeedSync, validateMnemonic } from "./bip39.js";
import { addressFor, descriptorDerive } from "./addresses.js";
import { base58checkDecode, base58checkEncode } from "./base58.js";
import { descriptorChecksum } from "./core-importdescriptors.js";

const BITCOIN_TESTNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

// SLIP-132 single-signature prefixes → the script type they claim. Uppercase
// Ypub/Zpub/Upub/Vpub are multisig and outside v1 scope.
const SLIP132_SCRIPT_TYPE = {
  zpub: "p2wpkh",
  ypub: "p2sh-p2wpkh",
  vpub: "p2wpkh",
  upub: "p2sh-p2wpkh",
};

// Version word for each recognized extended-public-key prefix. The version
// word is also the key's network claim: tpub/upub/vpub are testnet.
const EXTENDED_PUB_VERSIONS = {
  xpub: 0x0488b21e,
  ypub: 0x049d7cb2,
  zpub: 0x04b24746,
  tpub: 0x043587cf,
  upub: 0x044a5262,
  vpub: 0x045f1cf6,
};

const EXTENDED_PUB_RE =
  /(?:xpub|tpub|ypub|upub|zpub|vpub|Ypub|Zpub|Upub|Vpub)[1-9A-HJ-NP-Za-km-z]{90,}/g;
const ORIGIN_RE = /\[([0-9a-fA-F]{8})((?:\/[0-9]+['hH]?)*)\]/;

// Single-signature descriptor templates v1 understands, mapped to the script
// type addressFor() expects. sh(...) is only supported when it wraps wpkh.
const TEMPLATE_SCRIPT_TYPE = {
  pkh: "p2pkh",
  wpkh: "p2wpkh",
  "sh(wpkh)": "p2sh-p2wpkh",
  tr: "p2tr",
};

function hexSeedBytes(seedHex) {
  if (!/^[0-9a-fA-F]+$/.test(seedHex) || seedHex.length % 2 !== 0) return null;
  const out = new Uint8Array(seedHex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(seedHex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// Normalize any extended public key to the Core form of its own network
// (xpub on mainnet, tpub on testnet) by swapping the 4-byte version word;
// the remaining 74 bytes are untouched. This is a pure re-encoding of the
// same key material — SLIP-132 changes presentation, not the key.
function toCoreExtendedPub(key, version) {
  let body;
  try {
    body = base58checkDecode(key);
  } catch {
    return null;
  }
  try {
    if (body.length !== 78) return null;
    if (body[45] === 0) return null; // never echo private material back out
    const view = new DataView(body.buffer, body.byteOffset);
    view.setUint32(0, version, false);
    return base58checkEncode(body);
  } catch {
    return null;
  } finally {
    body.fill(0);
  }
}

function networkOfPrefix(prefix) {
  return prefix === "tpub" || prefix === "upub" || prefix === "vpub" ? "testnet" : "mainnet";
}

// The Core version word for a key's own network: xpub on mainnet, tpub on
// testnet. SLIP-132 prefixes only change presentation, not the network.
function coreVersionFor(prefix) {
  return networkOfPrefix(prefix) === "testnet" ? BITCOIN_TESTNET_VERSIONS.public : 0x0488b21e;
}

function versionsForNetwork(network) {
  return network === "mainnet" ? undefined : BITCOIN_TESTNET_VERSIONS;
}

// The argument of the descriptor's single key function, e.g. the
// "[fpr/path]xpub/0/*" inside wpkh(...) or sh(wpkh(...)).
function keyArgumentOf(text, fn) {
  const marker = fn === "sh(wpkh)" ? "wpkh(" : fn + "(";
  const open = text.indexOf(marker);
  if (open < 0) return null;
  const start = open + marker.length;
  let depth = 1;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return text.slice(start, i);
    }
  }
  return null;
}

// v1 only understands an account-level origin: purpose'/coin'/account', all
// three hardened. Anything else is a named Support failure, not a guess.
function isAccountPath(path) {
  const match = /^\/(\d+)'\/(\d+)'\/(\d+)'$/.exec(path);
  if (!match) return false;
  return match.slice(1).every((n) => Number(n) <= 2147483647);
}

// Parse a single-signature descriptor into its claims. Returns { error } when
// the template, checksum, key shape or origin is outside v1 scope; the caller
// turns that into a named Support failure.
function parseDescriptorClaims(descriptor) {
  const text = String(descriptor ?? "").trim();
  const hash = text.lastIndexOf("#");
  let body = text;
  if (hash >= 0) {
    const checksum = text.slice(hash + 1);
    body = text.slice(0, hash);
    let expected;
    try {
      expected = descriptorChecksum(body);
    } catch {
      return { error: "descriptor checksum could not be computed" };
    }
    if (checksum.length !== 8 || expected !== checksum) {
      return { error: "descriptor checksum does not match its body" };
    }
  }
  const fnMatch = body.match(/^([a-z]+)\(/);
  if (!fnMatch) return { error: "descriptor template outside v1 scope (pkh/wpkh/sh(wpkh)/tr, single extended key)" };
  let fn = fnMatch[1];
  if (fn === "sh") {
    if (/^sh\(wpkh\(/.test(body)) fn = "sh(wpkh)";
    else return { error: "descriptor template outside v1 scope (pkh/wpkh/sh(wpkh)/tr, single extended key)" };
  }
  const scriptType = TEMPLATE_SCRIPT_TYPE[fn];
  if (!scriptType) return { error: "descriptor template outside v1 scope (pkh/wpkh/sh(wpkh)/tr, single extended key)" };

  const arg = keyArgumentOf(body, fn);
  if (arg == null) return { error: "descriptor key argument could not be read" };
  const keyMatches = arg.match(EXTENDED_PUB_RE) ?? [];
  if (keyMatches.length === 0) return { error: "descriptor key is not a single extended public key" };
  if (keyMatches.length > 1) return { error: "descriptor carries more than one extended key (single-sig v1 scope)" };
  const key = keyMatches[0];
  const prefix = key.slice(0, 4);
  if (/^[YZUV]pub$/.test(prefix)) {
    return { error: "multisig SLIP-132 (Ypub/Zpub/Upub/Vpub) is outside v1 single-sig scope" };
  }
  if (EXTENDED_PUB_VERSIONS[prefix] == null) return { error: "extended key prefix is not recognized" };
  const coreXpub = toCoreExtendedPub(key, coreVersionFor(prefix));
  if (!coreXpub) return { error: "descriptor key is not a recognized public extended key" };

  const originMatch = arg.match(ORIGIN_RE);
  let originFingerprint = null;
  let originPath = null;
  if (originMatch) {
    originFingerprint = originMatch[1].toLowerCase();
    // HDKey.derive wants 'h'/'H' normalized to "'".
    originPath = originMatch[2].replace(/[hH]/g, "'");
    if (!isAccountPath(originPath)) {
      return { error: "descriptor origin is not an account-level path (purpose'/coin'/account')" };
    }
  } else if (arg.includes("[")) {
    return { error: "descriptor origin could not be parsed" };
  }
  return {
    scriptType,
    coreXpub,
    keyPrefix: prefix,
    keyNetwork: networkOfPrefix(prefix),
    originFingerprint,
    originPath,
  };
}

function stepOk(name) {
  return { name, ok: true };
}
function stepFail(name, detail) {
  return { name, ok: false, detail };
}

// Derive the canonical claims a seed/mnemonic makes about a wallet, using the
// descriptor's origin path when one is available (otherwise BIP-84 account 0).
function claimsFromSeed(master, descriptorClaims) {
  const fingerprintHex = master.fingerprint.toString(16).padStart(8, "0");
  const path = descriptorClaims?.originPath ?? "/84'/0'/0'";
  const account = master.derive("m" + path);
  return { fingerprintHex, account };
}

/**
 * Compare two or more recovery artifacts and report whether they describe
 * the same key derivation and output policy.
 *
 * @param {object} artifacts - subset of { seed, mnemonic, xpub, slip132, descriptor, address }
 * @param {object} [opts] - { network = "mainnet", receiveIndex = 0 }
 * @returns {{ steps: Array<{name: string, ok: boolean, detail?: string}>,
 *             verdict: "consistent" | "inconsistent" | "insufficient",
 *             mismatchAt?: string }}
 */
export function compareRecoveryArtifacts(artifacts, opts) {
  const { network = "mainnet", receiveIndex = 0 } = opts ?? {};
  const steps = [];

  const supplied = {};
  for (const key of ["seed", "mnemonic", "xpub", "slip132", "descriptor", "address"]) {
    const value = artifacts?.[key];
    if (value != null && String(value).trim() !== "") supplied[key] = String(value).trim();
  }
  if (Object.keys(supplied).length < 2) {
    return { steps, verdict: "insufficient" };
  }

  // ---- Descriptor claims (parse once; several comparisons reuse them).
  let descriptorClaims = null;
  let descriptorAddress = null;
  if (supplied.descriptor) {
    let parsed;
    try {
      parsed = parseDescriptorClaims(supplied.descriptor);
    } catch (err) {
      parsed = { error: `descriptor could not be parsed: ${err.message}` };
    }
    if (parsed.error) {
      steps.push(stepFail("Support", parsed.error));
    } else {
      descriptorClaims = parsed;
      try {
        descriptorAddress = descriptorDerive(supplied.descriptor, receiveIndex, descriptorClaims.keyNetwork).address;
      } catch (err) {
        steps.push(stepFail("Support", `descriptor does not derive at index ${receiveIndex}: ${err.message}`));
        descriptorClaims = null;
      }
    }
  }

  // ---- Every supplied key becomes a claim, so none can be shadowed.
  const keyClaims = [];
  const addKeyClaim = (source, keyText, scriptTypeClaim) => {
    const prefix = keyText.slice(0, 4);
    if (/^[YZUV]pub$/.test(prefix)) {
      // Ypub/Zpub/Upub/Vpub are multisig SLIP-132 prefixes. v1 is single-sig
      // only; misinterpreting one as a single-sig key would be worse than
      // refusing it, so fail closed with a named step.
      steps.push(stepFail("Support", "multisig SLIP-132 (Ypub/Zpub/Upub/Vpub) is outside v1 single-sig scope"));
      return;
    }
    if (EXTENDED_PUB_VERSIONS[prefix] == null) {
      steps.push(stepFail("Support", `${source} is not a recognized public extended key`));
      return;
    }
    const keyNetwork = networkOfPrefix(prefix);
    const coreXpub = toCoreExtendedPub(keyText, coreVersionFor(prefix));
    if (!coreXpub) {
      steps.push(stepFail("Support", `${source} is not a recognized public extended key`));
      return;
    }
    try {
      HDKey.fromExtendedKey(coreXpub, versionsForNetwork(keyNetwork));
    } catch (err) {
      steps.push(stepFail("Support", `${source} does not parse: ${err.message}`));
      return;
    }
    keyClaims.push({ source, coreXpub, network: keyNetwork, scriptTypeClaim });
  };

  if (supplied.xpub) addKeyClaim("xpub", supplied.xpub, null);
  if (supplied.slip132) {
    addKeyClaim("slip132", supplied.slip132, SLIP132_SCRIPT_TYPE[supplied.slip132.slice(0, 4)] ?? null);
  }
  if (descriptorClaims) {
    keyClaims.push({
      source: "descriptor",
      coreXpub: descriptorClaims.coreXpub,
      network: descriptorClaims.keyNetwork,
      scriptTypeClaim: SLIP132_SCRIPT_TYPE[descriptorClaims.keyPrefix] ?? null,
    });
  }

  // ---- Seed / mnemonic side: master fingerprint + account key. The
  // descriptor's key network decides the version words, so a testnet
  // descriptor is compared against testnet-derived keys.
  const seedNetwork = descriptorClaims?.keyNetwork ?? network;
  const versions = versionsForNetwork(seedNetwork);
  const seedClaimsList = [];
  const addSeedClaim = (source, master) => {
    const claims = claimsFromSeed(master, descriptorClaims);
    seedClaimsList.push({ source, ...claims });
    keyClaims.push({
      source,
      coreXpub: claims.account.neutered().publicExtendedKey,
      network: seedNetwork,
      scriptTypeClaim: null,
    });
  };

  if (supplied.mnemonic) {
    let valid = false;
    try {
      valid = validateMnemonic(supplied.mnemonic);
    } catch {
      valid = false;
    }
    if (!valid) {
      steps.push(stepFail("Support", "mnemonic fails BIP-39 checksum"));
    } else {
      let seedBytes = null;
      try {
        seedBytes = mnemonicToSeedSync(supplied.mnemonic);
        addSeedClaim("mnemonic", HDKey.fromMasterSeed(seedBytes, versions));
      } catch (err) {
        steps.push(stepFail("Support", `mnemonic could not be derived: ${err.message}`));
      } finally {
        if (seedBytes) seedBytes.fill(0);
      }
    }
  }
  if (supplied.seed) {
    const seedBytes = hexSeedBytes(supplied.seed);
    if (!seedBytes) {
      steps.push(stepFail("Support", "seed must be lowercase/uppercase hex, even length"));
    } else {
      try {
        addSeedClaim("seed", HDKey.fromMasterSeed(seedBytes, versions));
      } catch (err) {
        steps.push(stepFail("Support", `seed could not be derived: ${err.message}`));
      } finally {
        seedBytes.fill(0);
      }
    }
  }

  // ---- Pairwise key comparisons: every supplied key against every other.
  for (let i = 0; i < keyClaims.length; i++) {
    for (let j = i + 1; j < keyClaims.length; j++) {
      const a = keyClaims[i];
      const b = keyClaims[j];
      if (a.network !== b.network) {
        steps.push(stepFail("Network", `${a.source} is ${a.network}, ${b.source} is ${b.network}`));
      } else if (a.coreXpub !== b.coreXpub) {
        steps.push(stepFail("Account key", `${a.source} and ${b.source} derive different account keys`));
      } else {
        steps.push(stepOk("Account key"));
      }
    }
  }

  if (descriptorClaims?.originFingerprint) {
    for (const claim of seedClaimsList) {
      if (claim.fingerprintHex === descriptorClaims.originFingerprint) {
        steps.push(stepOk("Master fingerprint"));
      } else {
        steps.push(stepFail("Master fingerprint", `${claim.source} derives ${claim.fingerprintHex}, descriptor origin claims ${descriptorClaims.originFingerprint}`));
      }
    }
  }

  // ---- Script-type claims: each SLIP-132 prefix claims a script type, and
  // the descriptor template claims one. Any disagreement is a mismatch.
  const scriptClaims = [];
  for (const claim of keyClaims) {
    if (claim.scriptTypeClaim) scriptClaims.push({ source: claim.source, scriptType: claim.scriptTypeClaim });
  }
  if (descriptorClaims) scriptClaims.push({ source: "descriptor template", scriptType: descriptorClaims.scriptType });
  for (let i = 0; i < scriptClaims.length; i++) {
    for (let j = i + 1; j < scriptClaims.length; j++) {
      if (scriptClaims[i].scriptType === scriptClaims[j].scriptType) {
        steps.push(stepOk("Script type"));
      } else {
        steps.push(stepFail("Script type", `${scriptClaims[i].source} claims ${scriptClaims[i].scriptType}, ${scriptClaims[j].source} claims ${scriptClaims[j].scriptType}`));
      }
    }
  }

  // Address comparisons: descriptor side and (when possible) seed side.
  if (supplied.address && descriptorAddress) {
    if (supplied.address === descriptorAddress) steps.push(stepOk("Receive address"));
    else steps.push(stepFail("Receive address", `descriptor derives ${descriptorAddress}, supplied ${supplied.address}`));
  } else if (descriptorAddress && descriptorClaims) {
    // Cross-check the seed against the descriptor at the receive index.
    // This catches path/script confusion (e.g. same key under pkh vs wpkh)
    // even when the account-key comparison happens to match.
    for (const claim of seedClaimsList) {
      let seedAddress = null;
      try {
        const child = claim.account.derive(`m/0/${receiveIndex}`);
        seedAddress = addressFor(descriptorClaims.scriptType, child.publicKey, seedNetwork);
      } catch (err) {
        steps.push(stepFail("Support", `seed side does not derive at index ${receiveIndex}: ${err.message}`));
        continue;
      }
      if (seedAddress === descriptorAddress) steps.push(stepOk("Receive address"));
      else steps.push(stepFail("Receive address", `seed side derives ${seedAddress}, descriptor derives ${descriptorAddress}`));
    }
  }

  // A supplied artifact that could not be checked is never a pass.
  if (steps.some((s) => s.name === "Support" && !s.ok)) {
    return { steps, verdict: "inconsistent", mismatchAt: "Support" };
  }
  const comparable = steps.filter((s) => s.name !== "Support");
  if (comparable.length === 0) {
    // Two+ artifacts were supplied but none share a checkable claim.
    return { steps, verdict: "insufficient" };
  }
  const firstFailure = comparable.find((s) => !s.ok);
  if (firstFailure) {
    return { steps, verdict: "inconsistent", mismatchAt: firstFailure.name };
  }
  return { steps, verdict: "consistent" };
}

