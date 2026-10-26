// Lightning node identity tool for EntropyLab: derives the node pubkey a
// Lightning implementation would announce from a user-supplied seed phrase.
//
// Two seed schemes, two derivations:
//
// * aezeed (LND). The 24-word cipher seed deciphers (aezeed.js) to 16 bytes
//   of entropy that LND feeds DIRECTLY to BIP32 as the master seed (no BIP39
//   PBKDF2). The node identity key sits at m/1017'/coinType'/6'/0/0
//   (BIP43 purpose 1017, key family 6 = node key; coin type 0 on mainnet,
//   1 on testnet), per lnd/keychain/derivation.go.
//
// * BIP-39 (LDK, ldk-node convention). ldk-node turns the mnemonic into the
//   standard 64-byte BIP39 seed, takes the BIP32 master key's own 32-byte
//   private key, and hands that to LDK's KeysManager, which re-seeds a
//   second BIP32 master from it and derives the node secret at m/0'
//   (hardened), per ldk-node/src/builder.rs and rust-lightning's
//   sign::KeysManager. The result is network-independent.
//
// Deterministic transformations of user input only: nothing here generates
// entropy, and derived key material stays in page memory until wiped.
import { HDKey, HARDENED_OFFSET } from "./hdkey.js";
import { mnemonicToSeedSync, validateMnemonic } from "./bip39.js";
import { aezeedDecode, BITCOIN_GENESIS_TIMESTAMP } from "./aezeed.js";
import { wordlist as bip39English } from "./bip39-english.js";
import { hex } from "./coders.js";
import { t, tHtml as hodlT } from "./i18n.js";
import { privateCopyButtonHtml } from "./private-data.js";
import { publicFieldHtml, publicValueHtml } from "./public-data.js";

// ── Derivations (DOM-free, unit-tested directly) ────────────────────────────

// The aezeed internal (key-derivation) version this tool understands: LND
// writes version 0 and rejects anything else; guggero's cryptography-toolkit
// also emits version 1. Deriving a node key from an unknown internal version
// would print a key no Lightning implementation would ever use.
export const isKnownInternalVersion = (version) => version === 0 || version === 1;

// LND: the aezeed entropy is the BIP32 seed; node key at
// m/1017'/coinType'/6'/0/0. Returns the compressed pubkey hex, the path, and
// the root xprv (what chantools showrootkey prints; importable into wallets).
export const deriveLndNode = (entropy16, coinType) => {
  if (!(entropy16 instanceof Uint8Array) || entropy16.length !== 16) {
    throw new Error("aezeed entropy must be 16 bytes.");
  }
  if (coinType !== 0 && coinType !== 1) throw new Error("Coin type must be 0 (mainnet) or 1 (testnet).");
  const path = `m/1017'/${coinType}'/6'/0/0`;
  const master = HDKey.fromMasterSeed(entropy16);
  let node = null;
  try {
    node = master.derive(path);
    return { nodePubKey: hex.encode(node.publicKey), path, rootXprv: master.privateExtendedKey };
  } finally {
    if (node) node.wipePrivateData();
    master.wipePrivateData();
  }
};

// A BIP39 passphrase is UTF-8 text: a lone surrogate would silently encode
// as U+FFFD and derive a wallet that is not the one the user typed (the
// calculator's BIP39 path refuses the same, #1015). JS strings are UTF-16,
// so the check is a scan for unpaired surrogates.
const isWellFormedUtf16 = (text) => {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
};

// LDK (ldk-node): BIP39 seed -> master xprv -> its raw private key re-seeds
// a second master -> node secret at m/0'. The root xprv returned is the
// first-stage master (the on-chain wallet root ldk-node uses).
export const deriveLdkNode = (mnemonic, passphrase = "") => {
  if (!isWellFormedUtf16(passphrase)) {
    // The wrong side was the message: the guard fired, but its fallback text
    // ("not well-formed Unicode") dropped the actionable word the key and
    // the refusal tests carry — "surrogate", an invisible pasted character
    // the user must retype rather than paste.
    throw Object.assign(new Error("The passphrase contains an unpaired surrogate."), {
      key: "The passphrase contains an unpaired surrogate, which cannot be encoded as UTF-8. Retype the passphrase instead of pasting it.",
      code: "passphrase-utf8",
    });
  }
  const seed64 = mnemonicToSeedSync(mnemonic, passphrase);
  let master1 = null, master2 = null, node = null, key32 = null;
  try {
    master1 = HDKey.fromMasterSeed(seed64);
    key32 = master1.privateKey;
    master2 = HDKey.fromMasterSeed(key32);
    node = master2.deriveChild(0 + HARDENED_OFFSET);
    return { nodePubKey: hex.encode(node.publicKey), path: "m/0'", rootXprv: master1.privateExtendedKey };
  } finally {
    seed64.fill(0);
    if (key32) key32.fill(0);
    if (node) node.wipePrivateData();
    if (master2) master2.wipePrivateData();
    if (master1) master1.wipePrivateData();
  }
};

// ── Core Lightning hsm_secret (type 2) ──────────────────────────────────────

// CLN fixes coin type 0' on every network (hsm-secret.js); the network only
// changes the extended-key version bytes and the bech32 address prefix.
const CLN_NETWORKS = {
  bitcoin: { private: 0x0488ade4, public: 0x0488b21e, hrp: "bc" },
  testnet: { private: 0x04358394, public: 0x043587cf, hrp: "tb" },
};

const hodlHash160 = (bytes) => {
  if (typeof hodlHashes.hash160 === "function") return hodlHashes.hash160(bytes);
  if (typeof hodlHashes.ripemd160 === "function") return hodlHashes.ripemd160(hodlHashes.sha256(bytes));
  throw new Error("hash160 is unavailable.");
};

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

const hodlLnBech32Polymod = (values) => {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) checksum ^= BECH32_GENERATOR[i];
  }
  return checksum;
};

const hodlLnConvertBits = (bytes, from, to, pad) => {
  let accumulator = 0;
  let bits = 0;
  const out = [];
  const maxValue = (1 << to) - 1;
  for (const byte of bytes) {
    accumulator = (accumulator << from) | byte;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((accumulator >> bits) & maxValue);
    }
  }
  if (pad && bits > 0) out.push((accumulator << (to - bits)) & maxValue);
  return out;
};

const hodlLnBech32Encode = (hrp, data) => {
  const expanded = [];
  for (const char of hrp) expanded.push(char.charCodeAt(0) >> 5);
  expanded.push(0);
  for (const char of hrp) expanded.push(char.charCodeAt(0) & 31);
  const values = [...expanded, ...data, 0, 0, 0, 0, 0, 0];
  const mod = hodlLnBech32Polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...data, ...checksum].map((value) => BECH32_CHARSET[value]).join("")}`;
};

const hodlLnP2wpkhAddress = (publicKey, hrp) => hodlLnBech32Encode(hrp, [0, ...hodlLnConvertBits(hodlHash160(publicKey), 8, 5, true)]);

// The BIP86 account xprv and the first ten native-segwit receive addresses.
// deriveClnNode returns the node id and the descriptors; the xprv and the
// addresses are derived here from the same seed, then every buffer is wiped.
const hodlLnDeriveClnAccount = (phrase, network) => {
  const params = Object.hasOwn(CLN_NETWORKS, network) ? CLN_NETWORKS[network] : null;
  if (!params) throw Object.assign(new Error("Unknown network."), { key: "Unknown network.", code: "hsm-secret-network" });
  const seed = mnemonicToSeedSync(phrase, "");
  let master = null;
  let account = null;
  let chain = null;
  try {
    master = HDKey.fromMasterSeed(seed, { private: params.private, public: params.public });
    account = master.derive("m/86'/0'/0'");
    const xprv = account.privateExtendedKey;
    chain = account.deriveChild(0);
    const addresses = [];
    for (let index = 0; index < 10; index++) {
      const child = chain.deriveChild(index);
      try {
        addresses.push(hodlLnP2wpkhAddress(child.publicKey, params.hrp));
      } finally {
        child.wipePrivateData();
      }
    }
    return { xprv, addresses };
  } finally {
    seed.fill(0);
    if (chain) chain.wipePrivateData();
    if (account) account.wipePrivateData();
    if (master) master.wipePrivateData();
  }
};

// ── Tool wiring (markup in src/shell.html, #ln-card) ────────────────────────

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let hodlLnLast = null; // last successful derivation, kept for the reveal toggle
let hodlLnHsmMnemonic = null; // the type-2 words read from a chosen hsm_secret file
let hodlLnReveal = false;
let hodlLnJournalLog = () => {};
let hodlLnCopyIcon = () => "";

// A 24-word seed phrase is a few hundred characters; past this bound the
// text is a mispaste (a whole file, not a phrase), refused before any
// normalizing or deriving.
const LN_SEED_MAX_LENGTH = 4096;

export function hodlLnWipeMem() {
  if (hodlLnLast) {
    if (hodlLnLast.entropy) hodlLnLast.entropy.fill(0);
    if (hodlLnLast.salt) hodlLnLast.salt.fill(0);
    // The xprv and pubkey strings are immutable JS values; dropping the
    // references is the best effort available (same limit as the other
    // tools' extended-key display).
  }
  hodlLnLast = null;
  hodlLnReveal = false;
};

export function hodlLnWipeMem() {
  hodlLnClearResult();
  hodlLnHsmMnemonic = null;
}

const hodlLnFormat = () => (document.getElementById("ln-format")?.value === "bip39" ? "bip39" : "aezeed");
const hodlLnCoinType = () => (document.getElementById("ln-network")?.value === "testnet" ? 1 : 0);
const hodlLnNetworkName = () => (document.getElementById("ln-network")?.value === "testnet" ? "testnet" : "bitcoin");

const hodlLnNormalize = (text) => String(text || "").trim().toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter(Boolean);

const hodlLnBirthdayIso = (timestamp) => new Date(timestamp * 1000).toISOString().slice(0, 10);

const hodlLnPrivateField = (id, label, value) => `<div class="private-field is-revealed" data-private-field><p class="label copy-field-label">${escapeHtml(label)}${privateCopyButtonHtml(hodlLnCopyIcon)}</p><p class="psbt-kv" id="${id}" data-private-value data-i18n-skip translate="no">${escapeHtml(value)}</p></div>`;

function hodlLnValidateBip39(words) {
  if (words.length === 0) throw Object.assign(new Error("Type or paste your seed phrase."), { key: "Type or paste your seed phrase." });
  if (![12, 15, 18, 21, 24].includes(words.length)) {
    throw Object.assign(new Error("A seed phrase is 12, 15, 18, 21, or 24 words. You entered {n}."), { key: "A seed phrase is 12, 15, 18, 21, or 24 words. You entered {n}.", vars: { n: words.length } });
  }
  const unknown = words.map((word, index) => ({ word, index })).filter(({ word }) => !bip39English.includes(word));
  if (unknown.length > 0) {
    throw Object.assign(new Error("Unknown word"), { key: "Word {n} (“{word}”) is not on the BIP39 English list.", vars: { n: unknown[0].index + 1, word: unknown[0].word } });
  }
  const phrase = words.join(" ");
  if (!validateMnemonic(phrase)) {
    throw Object.assign(new Error("Bad checksum"), { key: "The BIP39 checksum does not match. A word is likely mistyped, missing, or swapped." });
  }
  return phrase;
}

function hodlLnRender() {
  const output = document.getElementById("ln-out");
  if (!output) return;
  if (!hodlLnLast) {
    output.innerHTML = "";
    return;
  }
  const r = hodlLnLast;
  const secrets = hodlLnReveal;
  const aezeed = r.format === "aezeed";
  const cln = r.format === "cln-hsm";
  const implementation = cln ? "Core Lightning" : aezeed ? "LND" : "LDK (ldk-node)";
  // Every translated string is computed ahead of the template with the
  // helper for its sink (AGENTS.md): hodlT for HTML element content, t for
  // the labels hodlLnPrivateField escapes itself.
  const nodeKeyLabel = hodlT("{implementation} node identity public key", { implementation });
  const pathLabel = cln ? hodlT("On-chain account path") : hodlT("Identity key path");
  const networkName = cln
    ? (r.network === "testnet" ? t("testnet") : t("mainnet"))
    : aezeed ? (r.coinType === 1 ? t("testnet") : t("mainnet")) : "";
  const pathNote = cln
    ? ` · ${escapeHtml(networkName)}`
    : aezeed
      ? ` · ${hodlT("coin type {coinType} ({network})", { coinType: r.coinType, network: networkName })}`
      : ` · ${hodlT("the LDK node identity does not depend on the network")}`;
  const detailNote = cln
    ? ""
    : aezeed
      ? `<p class="muted">${hodlT("Internal (key-derivation) version {v} · wallet birthday day {days} ({date} UTC, day 0 = Bitcoin genesis). Rescans from the birthday recover on-chain funds; channel funds need the node's channel backup.", { v: r.internalVersion, days: r.birthdayDays, date: hodlLnBirthdayIso(r.birthdayTimestamp) })}</p>`
      : `<p class="muted">${hodlT("Derived the ldk-node way: BIP39 seed → master key → its private key re-seeds a second BIP32 tree → node secret at")} <code>m/0'</code>.</p>`;
  const revealLabel = cln
    ? hodlT("Reveal the account private key (xprv)")
    : aezeed ? hodlT("Reveal the root private key and decoded entropy") : hodlT("Reveal the root private key");
  const entropyLabel = t("Decoded entropy (the BIP32 master seed)");
  const saltLabel = t("Salt");
  const rootXprvLabel = cln ? t("BIP86 account private key (xprv)") : t("BIP32 root private key (xprv)");
  const privateNote = cln
    ? hodlT("The account xprv can spend the node's on-chain wallet. Reveal it only while this file runs offline on an air-gapped computer.")
    : hodlT("The root xprv can spend the node's on-chain wallet. Reveal it only while this file runs offline on an air-gapped computer.");
  const hiddenNote = hodlT("Private material stays hidden until you reveal it.");
  const clnDetails = cln ? `
      <p class="label">${hodlT("Watch-only descriptors")}</p>
      <ul class="ln-descriptors">${r.descriptors.map((descriptor) => `<li>${publicValueHtml(descriptor, { clipboard: true })}</li>`).join("")}</ul>
      <p class="label">${hodlT("First 10 receive addresses")}</p>
      <ul class="ln-addresses">${r.addresses.map((address, index) => `<li><span class="muted">${index}</span> ${publicValueHtml(address, { clipboard: true })}</li>`).join("")}</ul>` : "";
  output.innerHTML = `
    <div class="ln-result">
      ${cln ? `<p class="muted" data-ln-note="single-key">${hodlT("Single key. This is not a channel backup.")}</p>` : ""}
      ${publicFieldHtml(nodeKeyLabel, r.nodePubKey, { id: "ln-node-pubkey", copyIcon: hodlLnCopyIcon })}
      <p class="muted">${pathLabel} ${publicValueHtml(r.path, { clipboard: false })}${pathNote}</p>
      ${detailNote}
      ${clnDetails}
      <label class="choice"><input type="checkbox" id="ln-reveal" data-private-reveal ${secrets ? "checked" : ""}> <span>${revealLabel}</span></label>
      ${secrets ? `
        ${aezeed ? `${hodlLnPrivateField("ln-entropy", entropyLabel, hex.encode(r.entropy))}
        ${hodlLnPrivateField("ln-salt", saltLabel, hex.encode(r.salt))}` : ""}
        ${hodlLnPrivateField("ln-root-xprv", rootXprvLabel, r.rootXprv)}
        <p class="muted">${privateNote}</p>` : `<p class="muted">${hiddenNote}</p>`}
    </div>`;
  // The switch reads its own state, not event.target: the conceal-on-leave
  // sweep unticks every switch by replaying a change through this handler.
  // Set the checked property on every render instead of trusting the markup
  // attribute to seed it: the sweep reads the property (and skips a switch
  // whose property is unset), so a re-created switch must always carry a
  // boolean state.
  const revealToggle = document.getElementById("ln-reveal");
  if (revealToggle) {
    revealToggle.checked = hodlLnReveal;
    revealToggle.addEventListener("change", () => {
      hodlLnReveal = revealToggle.checked;
      hodlLnRender();
    });
  }
}

function hodlRunLn() {
  const error = document.getElementById("ln-error");
  const session = document.getElementById("ln-session");
  error.textContent = "";
  hodlLnWipeMem();
  const format = hodlLnFormat();
  try {
    const text = String(document.getElementById("ln-seed").value || "");
    if (text.length > LN_SEED_MAX_LENGTH) {
      throw Object.assign(new Error("Seed text too long."), {
        key: "That seed text is too long ({n} characters). No seed phrase is longer than {max} characters.",
        vars: { n: text.length, max: LN_SEED_MAX_LENGTH },
        code: "seed-too-long",
      });
    }
    const words = hodlLnNormalize(text);
    const passphrase = document.getElementById("ln-pass").value;
    if (format === "aezeed") {
      const decoded = aezeedDecode(words, passphrase);
      const coinType = hodlLnCoinType();
      try {
        if (!isKnownInternalVersion(decoded.internalVersion)) {
          throw Object.assign(new Error("Unsupported internal version"), {
            key: "This cipher seed uses internal (key-derivation) version {v}, which no current Lightning implementation understands. Refusing to derive from it.",
            vars: { v: decoded.internalVersion },
            code: "internal-version",
          });
        }
        const derived = deriveLndNode(decoded.entropy, coinType);
        hodlLnLast = { format, coinType, ...decoded, ...derived };
      } catch (exception) {
        decoded.entropy.fill(0);
        decoded.salt.fill(0);
        throw exception;
      }
    } else if (format === "cln-hsm") {
      if (passphrase !== "") {
        throw Object.assign(new Error("No passphrase is needed for a type 2 hsm_secret."), {
          key: "No passphrase is needed for a type 2 hsm_secret.",
          code: "hsm-secret-passphrase-not-needed",
        });
      }
      const phrase = words.length > 0 ? readClnMnemonic(text) : hodlLnHsmMnemonic;
      if (!phrase) {
        throw Object.assign(new Error("Type or paste the 12 words, or choose the hsm_secret file."), {
          key: "Type or paste the 12 words, or choose the hsm_secret file.",
          code: "hsm-secret-missing",
        });
      }
      const network = hodlLnNetworkName();
      const derived = deriveClnNode(phrase, network);
      const account = hodlLnDeriveClnAccount(phrase, network);
      hodlLnLast = { format, network, path: "m/86'/0'/0'", nodePubKey: derived.nodeId, descriptors: derived.descriptors, xpub: derived.xpub, rootXprv: account.xprv, addresses: account.addresses };
    } else {
      const phrase = hodlLnValidateBip39(words);
      const derived = deriveLdkNode(phrase, passphrase);
      hodlLnLast = { format, ...derived };
    }
    hodlLnRender();
    session.textContent = t("Node key derived. Decoded key material stays in page memory until you clear it.");
    hodlLnJournalLog("derive", `${format} ${hodlLnLast.nodePubKey.slice(0, 8)}`, "ln");
  } catch (exception) {
    hodlLnWipeMem();
    hodlLnRender();
    // Keyed errors (aezeed.js taxonomy, the validations above) format and
    // translate through t(); anything else shows its raw message.
    error.textContent = exception && typeof exception.key === "string"
      ? t(exception.key, exception.vars)
      : exception instanceof Error ? exception.message : String(exception);
    error.dataset.code = exception && typeof exception.code === "string" ? exception.code : "";
    hodlLnJournalLog("derive-error", format, "ln");
  }
}

function hodlLnSyncFormat() {
  const format = hodlLnFormat();
  const network = document.getElementById("ln-network-field");
  if (network) network.hidden = format === "bip39";
  const upload = document.getElementById("ln-hsm-upload");
  if (upload) upload.hidden = format !== "cln-hsm";
  const note = document.getElementById("ln-seed-help");
  if (note) {
    if (format === "aezeed") note.textContent = t("The 24-word cipher seed LND printed at wallet creation.");
    else if (format === "bip39") note.textContent = t("A 12 to 24 word BIP-39 seed phrase, as used by ldk-node.");
    else note.textContent = t("The 12 words lightning-hsmtool getsecret prints, or choose the hsm_secret file.");
  }
}


// Reads the chosen hsm_secret, refuses every non-type-2 shape with a keyed
// error, and zeroes the bytes and resets the input in a finally block.
async function hodlLnReadHsmFile() {
  const input = document.getElementById("ln-hsm-file");
  const error = document.getElementById("ln-error");
  const session = document.getElementById("ln-session");
  if (!input) return;
  const file = input.files && input.files[0];
  if (!file) return;
  let bytes = null;
  try {
    bytes = new Uint8Array(await file.arrayBuffer());
    const type = detectHsmSecretType(bytes);
    if (type === HSM_SECRET_MNEMONIC_WITH_PASS) {
      throw Object.assign(new Error("This hsm_secret needs a passphrase; only type 2 (no passphrase) is supported."), {
        key: "This hsm_secret needs a passphrase; only type 2 (no passphrase) is supported.",
        code: "hsm-secret-passphrase",
      });
    }
    if (type === HSM_SECRET_PLAIN) {
      throw Object.assign(new Error("This is a legacy 32-byte hsm_secret, not a mnemonic secret."), {
        key: "This is a legacy 32-byte hsm_secret, not a mnemonic secret.",
        code: "hsm-secret-plain",
      });
    }
    if (type === HSM_SECRET_ENCRYPTED) {
      throw Object.assign(new Error("This encrypted legacy hsm_secret is not supported."), {
        key: "This encrypted legacy hsm_secret is not supported.",
        code: "hsm-secret-encrypted",
      });
    }
    if (type === HSM_SECRET_INVALID) {
      throw Object.assign(new Error("This hsm_secret is truncated."), {
        key: "This hsm_secret is truncated.",
        code: "hsm-secret-truncated",
      });
    }
    hodlLnClearResult();
    hodlLnHsmMnemonic = readClnMnemonic(bytes);
    // The file is the most recent entry: drop any typed words so Derive
    // cannot silently use them instead of the file the status line names.
    const seed = document.getElementById("ln-seed");
    if (seed) seed.value = "";
    if (error) {
      error.textContent = "";
      error.dataset.code = "";
    }
    if (session) session.textContent = t("hsm_secret read. Press Derive.");
    hodlLnRender();
  } catch (exception) {
    hodlLnClearResult();
    hodlLnHsmMnemonic = null;
    hodlLnRender();
    if (error) {
      error.textContent = exception && typeof exception.key === "string"
        ? t(exception.key, exception.vars)
        : exception instanceof Error ? exception.message : String(exception);
      error.dataset.code = exception && typeof exception.code === "string" ? exception.code : "";
    }
    hodlLnJournalLog("hsm-file-error", exception && typeof exception.code === "string" ? exception.code : "unknown", "ln");
  } finally {
    if (bytes) bytes.fill(0);
    input.value = "";
  }
}

// Wires the Lightning card. `journalLog` is the app's hodlJournalLog; the
// module takes it as an option instead of importing app.js (same shape as
// initPsbtEditor's options object).
export function hodlInitLn({ journalLog, copyIcon = () => "" } = {}) {
  const go = document.getElementById("ln-go");
  if (!go) return;
  if (typeof journalLog === "function") hodlLnJournalLog = journalLog;
  hodlLnCopyIcon = copyIcon;
  go.onclick = hodlRunLn;
  document.getElementById("ln-wipe").onclick = () => {
    hodlLnWipeMem();
    for (const id of ["ln-seed", "ln-pass", "ln-hsm-file"]) {
      const field = document.getElementById(id);
      if (field) field.value = "";
    }
    document.getElementById("ln-out").innerHTML = "";
    document.getElementById("ln-error").textContent = "";
    document.getElementById("ln-error").dataset.code = "";
    document.getElementById("ln-session").textContent = t("Accessible fields were cleared (best effort).");
  };
  for (const id of ["ln-format", "ln-network"]) {
    document.getElementById(id)?.addEventListener("change", () => {
      // A stale result next to a flipped select is how a correct seed looks
      // wrong (a mainnet pubkey beside "Testnet"): wipe and re-render on any
      // format or network change.
      hodlLnWipeMem();
      hodlLnRender();
      hodlLnSyncFormat();
    });
  }
  document.getElementById("ln-session").textContent = t("No node key derived. Enter a seed phrase and derive.");
  hodlLnSyncFormat();
}
