// Policy layer on top of comparePsbtDocs() for the PSBT Signer Audit.
//
// The engine is DOM-free, deterministic and pure: it reads two PSBT
// inspection documents (the same shape psbtInspectDoc produces) plus caller
// facts about signature verification, nonce history, anti-exfil and wallet
// ownership. It never parses PSBT bytes, never verifies cryptography and
// never decides UI wording. It fails closed: anything unverified is critical.
import { comparePsbtDocs } from "./psbt-diff.js";

const UTXO_FIELDS = new Set(["PSBT_IN_WITNESS_UTXO", "PSBT_IN_NON_WITNESS_UTXO"]);
const SIG_FIELDS = new Set(["PSBT_IN_PARTIAL_SIG", "PSBT_IN_TAP_KEY_SIG", "PSBT_IN_TAP_SCRIPT_SIG"]);
const FINAL_FIELDS = new Set(["PSBT_IN_FINAL_SCRIPTSIG", "PSBT_IN_FINAL_SCRIPTWITNESS"]);
const MUSIG2_FIELDS = new Set([
  "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS",
  "PSBT_IN_MUSIG2_PUB_NONCE",
  "PSBT_IN_MUSIG2_PARTIAL_SIG",
]);
const DERIVATION_FIELDS = new Set([
  "PSBT_IN_BIP32_DERIVATION",
  "PSBT_IN_TAP_BIP32_DERIVATION",
  "PSBT_OUT_BIP32_DERIVATION",
  "PSBT_OUT_TAP_BIP32_DERIVATION",
]);
const PROPRIETARY = new Set(["PSBT_IN_PROPRIETARY", "PSBT_OUT_PROPRIETARY", "PSBT_GLOBAL_PROPRIETARY"]);
// BIP-174 fields a finalizer may clear (everything standard except UTXO
// 0x00/0x01, proprietary 0xfc and unknown types), by key type byte.
const FINALIZER_CLEARABLE_TYPES = new Set([
  "02", "03", "04", "05", "06", "09", "0a", "0b", "0c", "0d",
  "13", "14", "15", "16", "17", "18", "1a", "1b", "1c",
]);

export const SIGNER_AUDIT_CODES = Object.freeze([
  "DOC_UNDECODABLE",
  "TX_REORDERED",
  "TX_INPUT_CHANGED",
  "TX_OUTPUT_CHANGED",
  "TX_VERSION_CHANGED",
  "TX_LOCKTIME_CHANGED",
  "UTXO_DECLARATION_CHANGED",
  "UNEXPECTED_SIGNER",
  "SIGNATURE_CHANGED",
  "SIGNATURE_REMOVED",
  "SIGNATURE_MALFORMED",
  "SIGNATURE_INVALID",
  "SIGNATURE_UNVERIFIED",
  "SIGHASH_WEAK",
  "SIGHASH_MISMATCH",
  "SIGHASH_UNDEFINED",
  "SIGHASH_DECLARATION_CHANGED",
  "FINALIZATION_INVALID",
  "FIELD_REMOVED",
  "FINGERPRINT_MISMATCH",
  "METADATA_REMOVED",
  "CHANGE_NOT_FROM_WALLET",
  "NONCE_REUSE",
  "NONCE_CROSS_KEY",
  "ANTIEXFIL_FAILED",
  "METADATA_CHANGED",
  "SIGHASH_DECLARATION_ADDED",
  "SIGNER_UNKNOWN",
  "MUSIG2_MATERIAL_ADDED",
  "METADATA_ADDED",
  "SIGHASH_DECLARATION_INVALID",
  "CHANGE_UNVERIFIED",
  "NONCE_REUSE_POSSIBLE",
  "NONCE_COVERAGE_INCOMPLETE",
  "ORIGIN_INCONSISTENT",
  "SIGNATURE_ADDED",
  "FINALIZED",
  "METADATA_ENRICHMENT",
  "CHANGE_VERIFIED",
]);

const isObject = (value) => value !== null && typeof value === "object";
const lower = (value) => String(value ?? "").toLowerCase();
const keyType = (key) => lower(key).slice(0, 2);
// psbtInspectDoc serialises u64 sat amounts as decimal strings; the audit
// reports them as numbers so evidence reads like the spec's literals.
const numeric = (value) => (typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value);
const finding = (code, severity, scope, index, field, evidence) => ({ code, severity, scope, index, field, evidence });

const isPairArray = (pairs) => Array.isArray(pairs) && pairs.every(isObject);
const structurallyComplete = (doc) => isObject(doc)
  && isObject(doc.tx)
  && Array.isArray(doc.tx.inputs)
  && doc.tx.inputs.every(isObject)
  && Array.isArray(doc.tx.outputs)
  && doc.tx.outputs.every(isObject)
  && Array.isArray(doc.inputs)
  && doc.inputs.every(isPairArray)
  && Array.isArray(doc.outputs)
  && doc.outputs.every(isPairArray)
  && Array.isArray(doc.globals)
  && doc.globals.every(isObject);

const unknownChecks = () => ({
  transactionBody: "unknown",
  utxoDeclarations: "unknown",
  signatures: "unknown",
  sighashPolicy: "unknown",
  signerKeys: "unknown",
  metadata: "unknown",
  nonceReuse: "unknown",
  antiExfil: "unknown",
  changeOutputs: "unknown",
});

const mapPairs = (doc, scope, index) => {
  if (scope === "global") return doc.globals ?? [];
  if (scope === "input-map") return doc.inputs?.[index] ?? [];
  if (scope === "output-map") return doc.outputs?.[index] ?? [];
  return [];
};

const findPair = (doc, scope, index, key, ordinal) => {
  const pairs = mapPairs(doc, scope, index).filter((pair) => pair.key === key);
  if (ordinal === undefined || ordinal === null) return pairs[0] ?? null;
  return pairs[ordinal] ?? null;
};

const pairForChange = (doc, change, side) => {
  const ordinal = side === "before" ? change.beforeOrdinal : change.afterOrdinal;
  return findPair(doc, change.scope, change.index, change.key, ordinal);
};

const utxoValues = (pair) => {
  if (!pair?.decoded) return {};
  if (pair.name === "PSBT_IN_WITNESS_UTXO") {
    return { value: numeric(pair.decoded.value), scriptPubKey: pair.decoded.scriptPubKey };
  }
  if (pair.name === "PSBT_IN_NON_WITNESS_UTXO") {
    return { value: numeric(pair.decoded.prevout?.value), scriptPubKey: pair.decoded.prevout?.scriptPubKey };
  }
  return {};
};

const parseLittleEndian32 = (value) => {
  const hex = lower(value);
  if (!/^[0-9a-f]{8}$/.test(hex)) return null;
  const bytes = hex.match(/../g).reverse().join("");
  return parseInt(bytes, 16);
};

const sighashPairs = (doc, index) => (doc.inputs?.[index] ?? []).filter((pair) => pair.name === "PSBT_IN_SIGHASH_TYPE");

const declaredSighash = (doc, index) => {
  const pairs = sighashPairs(doc, index);
  for (const pair of pairs) {
    if (pair.decoded && !pair.decodeError && typeof pair.decoded.sighashType === "number") {
      return pair.decoded.sighashType;
    }
  }
  for (const pair of pairs) {
    const parsed = parseLittleEndian32(pair.value);
    if (parsed !== null) return parsed;
  }
  return null;
};

const taprootish = (doc, index) => (doc.inputs?.[index] ?? []).some((pair) => {
  const type = parseInt(keyType(pair.key), 16);
  return type >= 0x13 && type <= 0x18;
});

const definedSighash = (value, tap) => {
  if (value === 0x01 || value === 0x02 || value === 0x03 || value === 0x81 || value === 0x82 || value === 0x83) return true;
  return tap && value === 0x00;
};

const weakSighash = (value) => (value & 0x80) !== 0 || (value & 0x7f) === 0x02 || (value & 0x7f) === 0x03;
const fullCommitment = (value, tap) => value === 0x01 || (tap && value === 0x00);

const declaredPolicy = (doc, index) => {
  if (sighashPairs(doc, index).length === 0) return { value: null, invalid: false };
  const value = declaredSighash(doc, index);
  if (value === null) return { value: null, invalid: true };
  if (!definedSighash(value, taprootish(doc, index))) return { value, invalid: true };
  return { value, invalid: false };
};

const detectReorder = (before, after, keyOf) => {
  if (before.length !== after.length) return null;
  const left = before.map(keyOf);
  const right = after.map(keyOf);
  const sorted = (values) => values.slice().sort().join("\u0000");
  if (sorted(left) !== sorted(right)) return null;
  const used = new Set();
  const order = [];
  for (const key of right) {
    const at = left.findIndex((candidate, index) => !used.has(index) && candidate === key);
    if (at === -1) return null;
    used.add(at);
    order.push(at);
  }
  if (order.every((value, index) => value === index)) return null;
  return { order };
};

const computeChangeFindings = (afterDoc, wallet) => {
  const findings = [];
  const verified = new Set();
  if (!wallet) return { findings, verified };
  const fingerprints = Array.isArray(wallet.fingerprints) ? wallet.fingerprints.map(lower) : [];
  const scripts = Array.isArray(wallet.scriptPubKeys) ? wallet.scriptPubKeys.map(lower) : [];
  const scriptSet = new Set(scripts);
  const outputs = afterDoc.tx?.outputs ?? [];
  if (fingerprints.length > 0) {
    for (let index = 0; index < outputs.length; index++) {
      const pairs = afterDoc.outputs?.[index] ?? [];
      const derivation = pairs.find((pair) => (pair.name === "PSBT_OUT_BIP32_DERIVATION" || pair.name === "PSBT_OUT_TAP_BIP32_DERIVATION")
        && pair.decoded && !pair.decodeError
        && fingerprints.includes(lower(pair.decoded.fingerprint)));
      if (!derivation) continue;
      const scriptPubKey = lower(outputs[index].scriptPubKey);
      const fingerprint = lower(derivation.decoded.fingerprint);
      if (scripts.length > 0) {
        if (scriptSet.has(scriptPubKey)) {
          findings.push(finding("CHANGE_VERIFIED", "info", "output", index, null, { index, scriptPubKey, fingerprint }));
          verified.add(index);
        } else {
          findings.push(finding("CHANGE_NOT_FROM_WALLET", "critical", "output", index, null, { index, scriptPubKey, fingerprint }));
        }
      } else {
        findings.push(finding("CHANGE_UNVERIFIED", "warning", "output", index, null, { index, scriptPubKey, fingerprint }));
      }
    }
  } else if (scripts.length > 0) {
    for (let index = 0; index < outputs.length; index++) {
      const scriptPubKey = lower(outputs[index].scriptPubKey);
      if (scriptSet.has(scriptPubKey)) {
        findings.push(finding("CHANGE_VERIFIED", "info", "output", index, null, { index, scriptPubKey, fingerprint: null }));
        verified.add(index);
      }
    }
  }
  return { findings, verified };
};

const expectedKeysFor = (doc, index) => {
  const keys = new Set();
  for (const pair of doc.inputs?.[index] ?? []) {
    if (pair.decodeError) continue;
    if (pair.name === "PSBT_IN_BIP32_DERIVATION" && pair.decoded?.pubkey) keys.add(lower(pair.decoded.pubkey));
    if ((pair.name === "PSBT_IN_TAP_BIP32_DERIVATION" || pair.name === "PSBT_IN_TAP_INTERNAL_KEY") && pair.decoded?.xonly) {
      keys.add(lower(pair.decoded.xonly));
    }
    if (pair.name === "PSBT_IN_PARTIAL_SIG") keys.add(lower(pair.key).slice(2));
    if (pair.name === "PSBT_IN_TAP_SCRIPT_SIG") keys.add(lower(pair.key).slice(2, 66));
  }
  return keys;
};

const hasTaprootMaterial = (doc, index) => (doc.inputs?.[index] ?? []).some((pair) => (
  pair.name === "PSBT_IN_TAP_INTERNAL_KEY" || pair.name === "PSBT_IN_TAP_BIP32_DERIVATION"
));

const pubkeyForEvent = (event) => {
  if (event.name === "PSBT_IN_TAP_KEY_SIG") return null;
  if (event.name === "PSBT_IN_TAP_SCRIPT_SIG") {
    return lower(event.pair?.decoded?.xonly ?? lower(event.key).slice(2, 66));
  }
  return lower(event.pair?.decoded?.pubkey ?? lower(event.key).slice(2));
};

const parseAppendedSighash = (event) => {
  const pair = event.pair;
  if (!pair || pair.decodeError || !pair.decoded) return { malformed: true, decodeError: pair?.decodeError };
  const value = lower(event.value);
  if (!/^[0-9a-f]*$/.test(value) || value.length % 2 !== 0) return { malformed: true };
  const bytes = value.length / 2;
  if (event.name === "PSBT_IN_PARTIAL_SIG") {
    if (bytes < 9) return { malformed: true };
    return { appended: parseInt(value.slice(-2), 16), tap: false };
  }
  if (event.name === "PSBT_IN_TAP_KEY_SIG" || event.name === "PSBT_IN_TAP_SCRIPT_SIG") {
    if (bytes === 64) return { appended: 0, tap: true };
    if (bytes === 65) {
      const appended = parseInt(value.slice(-2), 16);
      if (appended === 0x00) return { malformed: true };
      return { appended, tap: true };
    }
    return { malformed: true };
  }
  return { malformed: true };
};

const samePubkey = (a, b) => {
  if (a === null || a === undefined || b === null || b === undefined) return (a ?? null) === (b ?? null);
  return lower(a) === lower(b);
};

export function auditSigner(beforeDoc, afterDoc, options = {}) {
  if (!isObject(beforeDoc) || !isObject(afterDoc)) {
    throw new TypeError("Both PSBT inspection documents are required.");
  }

  const findings = [];

  for (const [side, doc] of [["before", beforeDoc], ["after", afterDoc]]) {
    if (!structurallyComplete(doc)) {
      findings.push(finding("DOC_UNDECODABLE", "critical", null, null, null, { side, reason: "malformed_document" }));
      return { verdict: "fail", equal: false, checks: unknownChecks(), findings, stats: null, diff: null };
    }
  }

  for (const [side, doc] of [["before", beforeDoc], ["after", afterDoc]]) {
    if (doc.rustBitcoinError) {
      findings.push(finding("DOC_UNDECODABLE", "critical", null, null, null, { side, reason: "rust_bitcoin_error" }));
    }
    if (doc.txSanityError) {
      findings.push(finding("DOC_UNDECODABLE", "critical", null, null, null, { side, reason: "tx_sanity_error" }));
    }
    if (doc.sanitize?.duplicateKeys?.state === "problem") {
      findings.push(finding("DOC_UNDECODABLE", "critical", null, null, null, { side, reason: "duplicate_keys" }));
    }
  }

  const diff = comparePsbtDocs(beforeDoc, afterDoc);

  const reorderedInputs = detectReorder(
    beforeDoc.tx.inputs,
    afterDoc.tx.inputs,
    (input) => JSON.stringify([input.txid, input.vout, input.scriptSig, input.sequence]),
  );
  const reorderedOutputs = detectReorder(
    beforeDoc.tx.outputs,
    afterDoc.tx.outputs,
    (output) => JSON.stringify([output.value, output.scriptPubKey]),
  );
  if (reorderedInputs) {
    findings.push(finding("TX_REORDERED", "critical", "transaction", null, null, { dimension: "inputs", order: reorderedInputs.order }));
  }
  if (reorderedOutputs) {
    findings.push(finding("TX_REORDERED", "critical", "transaction", null, null, { dimension: "outputs", order: reorderedOutputs.order }));
  }
  const suppressed = (change) => (
    (reorderedInputs && (change.scope === "input" || change.scope === "input-map"))
    || (reorderedOutputs && (change.scope === "output" || change.scope === "output-map"))
  );
  const activeChanges = diff.changes.filter((change) => !suppressed(change));

  const changeResult = computeChangeFindings(afterDoc, options.wallet);
  const verifiedChangeOutputs = changeResult.verified;

  // Pre-pass: pubkeys of every new signature, so the enrichment allowlist can
  // be decided while the phase-C walk keeps its emission order.
  const newSigPubkeys = new Map();
  const newTaprootSigInputs = new Set();
  for (const change of activeChanges) {
    if (change.scope !== "input-map" || change.kind !== "added" || !SIG_FIELDS.has(change.name)) continue;
    const index = change.index;
    if (!newSigPubkeys.has(index)) newSigPubkeys.set(index, new Set());
    const set = newSigPubkeys.get(index);
    if (change.name === "PSBT_IN_TAP_KEY_SIG") {
      newTaprootSigInputs.add(index);
      for (const pair of afterDoc.inputs?.[index] ?? []) {
        if ((pair.name === "PSBT_IN_TAP_INTERNAL_KEY" || pair.name === "PSBT_IN_TAP_BIP32_DERIVATION") && pair.decoded?.xonly) {
          set.add(lower(pair.decoded.xonly));
        }
      }
    } else {
      if (change.name === "PSBT_IN_TAP_SCRIPT_SIG") newTaprootSigInputs.add(index);
      const pair = pairForChange(afterDoc, change, "after");
      const pubkey = change.name === "PSBT_IN_TAP_SCRIPT_SIG"
        ? lower(pair?.decoded?.xonly ?? lower(change.key).slice(2, 66))
        : lower(pair?.decoded?.pubkey ?? lower(change.key).slice(2));
      if (pubkey) set.add(pubkey);
    }
  }

  // Pre-pass: finalization candidates and the removals they may explain.
  const beforeHasFinal = (index) => (beforeDoc.inputs?.[index] ?? []).some((pair) => FINAL_FIELDS.has(pair.name));
  const finalizationCandidates = new Set();
  const addedFinalFieldsByInput = new Map();
  const removedFieldsByInput = new Map();
  for (const change of activeChanges) {
    if (change.scope !== "input-map") continue;
    if (change.kind === "removed") {
      if (!removedFieldsByInput.has(change.index)) removedFieldsByInput.set(change.index, []);
      removedFieldsByInput.get(change.index).push(change.name);
    }
    if (change.kind === "added" && FINAL_FIELDS.has(change.name) && !beforeHasFinal(change.index)) {
      finalizationCandidates.add(change.index);
      if (!addedFinalFieldsByInput.has(change.index)) addedFinalFieldsByInput.set(change.index, []);
      addedFinalFieldsByInput.get(change.index).push(change.name);
    }
  }

  const newSigEvents = [];
  const finalizationEmitted = new Set();
  const weakAsRequested = { value: false };
  const declaredInvalidEmitted = new Set();
  const declaredUndefinedEmitted = new Set();

  const emitDeclaredUndefined = (index, value) => {
    if (declaredUndefinedEmitted.has(index)) return;
    declaredUndefinedEmitted.add(index);
    findings.push(finding("SIGHASH_UNDEFINED", "critical", "input-map", index, null, { index, source: "declared", value }));
  };

  const emitFinalization = (index) => {
    if (finalizationEmitted.has(index)) return;
    finalizationEmitted.add(index);
    const removedFields = removedFieldsByInput.get(index) ?? [];
    const finalFields = addedFinalFieldsByInput.get(index) ?? [];
    const entries = (options.verification?.signatures ?? []).filter((entry) => entry.index === index && FINAL_FIELDS.has(entry.name));
    const covered = finalFields.every((name) => entries.some((entry) => entry.name === name));
    const verified = covered && entries.length > 0 && entries.every((entry) => entry.valid === true);
    if (verified) {
      findings.push(finding("FINALIZED", "info", "input-map", index, null, { index, finalFields, removedFields, signatures: entries.length }));
      return;
    }
    let reason = "no_signatures";
    if (entries.some((entry) => entry.valid === false)) reason = "signature_invalid";
    else if (entries.some((entry) => entry.valid === null)) reason = "unverified";
    findings.push(finding("FINALIZATION_INVALID", "critical", "input-map", index, null, { index, reason, removedFields }));
  };

  const isEnrichment = (change, afterPair) => {
    if (change.name === "PSBT_GLOBAL_XPUB") return true;
    if (change.scope === "input-map") {
      if (change.name === "PSBT_IN_BIP32_DERIVATION" || change.name === "PSBT_IN_TAP_BIP32_DERIVATION") {
        const pubkey = lower(afterPair?.decoded?.pubkey ?? afterPair?.decoded?.xonly ?? "");
        return newSigPubkeys.get(change.index)?.has(pubkey) ?? false;
      }
      if (change.name === "PSBT_IN_TAP_INTERNAL_KEY") {
        return newTaprootSigInputs.has(change.index);
      }
    }
    if (change.scope === "output-map") {
      if (change.name === "PSBT_OUT_BIP32_DERIVATION" || change.name === "PSBT_OUT_TAP_BIP32_DERIVATION" || change.name === "PSBT_OUT_TAP_INTERNAL_KEY") {
        return verifiedChangeOutputs.has(change.index);
      }
    }
    return false;
  };

  for (const change of activeChanges) {
    const { scope, index, name, kind } = change;

    if (change.category === "transaction") {
      let code = null;
      if (scope === "transaction") {
        if (change.field === "version") code = "TX_VERSION_CHANGED";
        else if (change.field === "locktime") code = "TX_LOCKTIME_CHANGED";
      } else if (scope === "input") {
        code = "TX_INPUT_CHANGED";
      } else if (scope === "output") {
        code = "TX_OUTPUT_CHANGED";
      }
      if (code) {
        findings.push(finding(code, "critical", scope, index, change.field ?? null, {
          index: index ?? undefined,
          field: change.field ?? undefined,
          kind,
          before: change.before,
          after: change.after,
        }));
      }
      continue;
    }

    if (scope === "input-map" && UTXO_FIELDS.has(name)) {
      const beforePair = pairForChange(beforeDoc, change, "before");
      const afterPair = pairForChange(afterDoc, change, "after");
      const beforeValues = utxoValues(beforePair);
      const afterValues = utxoValues(afterPair);
      findings.push(finding("UTXO_DECLARATION_CHANGED", "critical", "input-map", index, null, {
        index,
        name,
        kind,
        ...(beforeValues.value !== undefined ? { beforeValue: beforeValues.value } : {}),
        ...(afterValues.value !== undefined ? { afterValue: afterValues.value } : {}),
        ...(beforeValues.scriptPubKey !== undefined ? { beforeScriptPubKey: beforeValues.scriptPubKey } : {}),
        ...(afterValues.scriptPubKey !== undefined ? { afterScriptPubKey: afterValues.scriptPubKey } : {}),
      }));
      continue;
    }

    if (name === "PSBT_IN_SIGHASH_TYPE") {
      if (kind === "added") {
        const value = parseLittleEndian32(change.after);
        const tap = taprootish(afterDoc, index);
        if (value === null || !definedSighash(value, tap)) {
          emitDeclaredUndefined(index, value);
        } else if (fullCommitment(value, tap)) {
          findings.push(finding("SIGHASH_DECLARATION_ADDED", "info", "input-map", index, null, { index, value }));
        } else if (weakSighash(value)) {
          findings.push(finding("SIGHASH_DECLARATION_ADDED", "warning", "input-map", index, null, { index, value }));
        }
      } else if (kind === "changed") {
        findings.push(finding("SIGHASH_DECLARATION_CHANGED", "critical", "input-map", index, null, {
          index,
          before: change.before,
          after: change.after,
        }));
      } else if (kind === "removed") {
        if (finalizationCandidates.has(index) && FINALIZER_CLEARABLE_TYPES.has(keyType(change.key))) continue;
        findings.push(finding("SIGHASH_DECLARATION_CHANGED", "critical", "input-map", index, null, {
          index,
          before: change.before,
        }));
      }
      continue;
    }

    if (FINAL_FIELDS.has(name)) {
      if (kind === "added" && !beforeHasFinal(index)) {
        emitFinalization(index);
      } else if (kind === "added" || kind === "changed") {
        findings.push(finding("SIGNATURE_CHANGED", "critical", "input-map", index, null, { index, name }));
      } else if (kind === "removed") {
        findings.push(finding("SIGNATURE_REMOVED", "critical", "input-map", index, null, { index, name }));
      }
      continue;
    }

    if (SIG_FIELDS.has(name)) {
      if (kind === "added") {
        newSigEvents.push({
          index,
          name,
          key: change.key,
          value: change.after,
          pair: pairForChange(afterDoc, change, "after"),
        });
      } else if (kind === "changed") {
        findings.push(finding("SIGNATURE_CHANGED", "critical", "input-map", index, null, { index, name }));
      } else if (kind === "removed") {
        if (finalizationCandidates.has(index) && FINALIZER_CLEARABLE_TYPES.has(keyType(change.key))) continue;
        findings.push(finding("SIGNATURE_REMOVED", "critical", "input-map", index, null, { index, name }));
      }
      continue;
    }

    if (MUSIG2_FIELDS.has(name)) {
      if (kind === "added") {
        findings.push(finding("MUSIG2_MATERIAL_ADDED", "warning", "input-map", index, null, { index, name }));
      } else if (kind === "changed") {
        findings.push(finding("SIGNATURE_CHANGED", "critical", "input-map", index, null, { index, name }));
      } else if (kind === "removed") {
        if (finalizationCandidates.has(index) && FINALIZER_CLEARABLE_TYPES.has(keyType(change.key))) continue;
        findings.push(finding("SIGNATURE_REMOVED", "critical", "input-map", index, null, { index, name }));
      }
      continue;
    }

    if (DERIVATION_FIELDS.has(name) && kind === "changed") {
      const beforePair = pairForChange(beforeDoc, change, "before");
      const afterPair = pairForChange(afterDoc, change, "after");
      if (beforePair?.decoded && afterPair?.decoded && !beforePair.decodeError && !afterPair.decodeError) {
        const fingerprintBefore = lower(beforePair.decoded.fingerprint);
        const fingerprintAfter = lower(afterPair.decoded.fingerprint);
        const pathBefore = beforePair.decoded.path;
        const pathAfter = afterPair.decoded.path;
        if (fingerprintBefore !== fingerprintAfter || pathBefore !== pathAfter) {
          const pubkey = lower(beforePair.decoded.pubkey ?? beforePair.decoded.xonly ?? afterPair.decoded.pubkey ?? afterPair.decoded.xonly ?? "");
          findings.push(finding("FINGERPRINT_MISMATCH", "critical", scope, index, null, {
            scope,
            index,
            name,
            pubkey,
            ...(fingerprintBefore !== fingerprintAfter ? { fingerprintBefore, fingerprintAfter } : {}),
            ...(pathBefore !== pathAfter ? { pathBefore, pathAfter } : {}),
          }));
          continue;
        }
      }
    }

    if (scope === "input-map" && kind === "removed"
      && finalizationCandidates.has(index)
      && FINALIZER_CLEARABLE_TYPES.has(keyType(change.key))
      && !UTXO_FIELDS.has(name)
      && !FINAL_FIELDS.has(name)
      && !PROPRIETARY.has(name)
      && name !== null) {
      continue;
    }

    if (scope === "input-map" && kind === "removed") {
      findings.push(finding("FIELD_REMOVED", "critical", "input-map", index, null, { index, key: change.key, name }));
      continue;
    }

    if (kind === "added") {
      const afterPair = pairForChange(afterDoc, change, "after");
      if (isEnrichment(change, afterPair)) {
        findings.push(finding("METADATA_ENRICHMENT", "info", scope, index, null, { scope, index, key: change.key, name }));
      } else {
        findings.push(finding("METADATA_ADDED", "warning", scope, index, null, { scope, index, key: change.key, name }));
      }
    } else if (kind === "changed") {
      const severity = PROPRIETARY.has(name) || name === null ? "warning" : "critical";
      findings.push(finding("METADATA_CHANGED", severity, scope, index, null, {
        scope,
        index,
        key: change.key,
        name,
        before: change.before,
        after: change.after,
      }));
    } else if (kind === "removed") {
      findings.push(finding("METADATA_REMOVED", "critical", scope, index, null, { scope, index, key: change.key, name }));
    }
  }

  // Phase D — signer identity of new signatures.
  const unknownPubkeysByInput = new Map();
  for (const event of newSigEvents) {
    const pubkey = pubkeyForEvent(event);
    if (event.name === "PSBT_IN_TAP_KEY_SIG") {
      if (!hasTaprootMaterial(beforeDoc, event.index)) {
        if (!unknownPubkeysByInput.has(event.index)) unknownPubkeysByInput.set(event.index, []);
        unknownPubkeysByInput.get(event.index).push(pubkey);
        continue;
      }
      const added = finding("SIGNATURE_ADDED", "info", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        pubkey,
        sighashAppended: null,
      });
      findings.push(added);
      event.identityFinding = added;
      continue;
    }
    const expected = expectedKeysFor(beforeDoc, event.index);
    if (expected.size === 0) {
      if (!unknownPubkeysByInput.has(event.index)) unknownPubkeysByInput.set(event.index, []);
      unknownPubkeysByInput.get(event.index).push(pubkey);
      continue;
    }
    if (!expected.has(pubkey)) {
      findings.push(finding("UNEXPECTED_SIGNER", "critical", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        pubkey,
        expectedKeys: [...expected],
      }));
      continue;
    }
    const added = finding("SIGNATURE_ADDED", "info", "input-map", event.index, null, {
      index: event.index,
      name: event.name,
      pubkey,
      sighashAppended: null,
    });
    findings.push(added);
    event.identityFinding = added;
  }
  for (const [index, pubkeys] of unknownPubkeysByInput) {
    findings.push(finding("SIGNER_UNKNOWN", "warning", "input-map", index, null, { index, pubkeys }));
  }

  // Phase E — sighash evaluation of new signatures.
  for (const event of newSigEvents) {
    const parsed = parseAppendedSighash(event);
    if (parsed.malformed) {
      findings.push(finding("SIGNATURE_MALFORMED", "critical", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        ...(parsed.decodeError ? { decodeError: parsed.decodeError } : {}),
      }));
      event.malformed = true;
      continue;
    }
    const appended = parsed.appended;
    const tap = parsed.tap;
    if (event.identityFinding) event.identityFinding.evidence.sighashAppended = appended;

    if (!definedSighash(appended, tap)) {
      findings.push(finding("SIGHASH_UNDEFINED", "critical", "input-map", event.index, null, {
        index: event.index,
        source: "appended",
        value: appended,
      }));
      continue;
    }

    const beforePolicy = declaredPolicy(beforeDoc, event.index);
    let expected = null;
    if (beforePolicy.invalid) {
      if (!declaredInvalidEmitted.has(event.index)) {
        declaredInvalidEmitted.add(event.index);
        findings.push(finding("SIGHASH_DECLARATION_INVALID", "warning", "input-map", event.index, null, { index: event.index }));
      }
    } else {
      expected = beforePolicy.value;
    }

    const afterPolicy = declaredPolicy(afterDoc, event.index);
    if (afterPolicy.invalid && afterPolicy.value !== null) {
      emitDeclaredUndefined(event.index, afterPolicy.value);
    }

    if (expected !== null && appended !== expected) {
      findings.push(finding("SIGHASH_MISMATCH", "critical", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        pubkey: pubkeyForEvent(event),
        appended,
        declared: expected,
        source: "original",
      }));
    } else if (afterPolicy.value !== null && appended !== afterPolicy.value) {
      findings.push(finding("SIGHASH_MISMATCH", "critical", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        pubkey: pubkeyForEvent(event),
        appended,
        declared: afterPolicy.value,
        source: "returned",
      }));
    }

    if (weakSighash(appended) && appended !== expected) {
      findings.push(finding("SIGHASH_WEAK", "critical", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        pubkey: pubkeyForEvent(event),
        appended,
      }));
    } else if (weakSighash(appended) && appended === expected) {
      weakAsRequested.value = true;
    }
  }

  // Phase F — signature verification (fail closed).
  for (const event of newSigEvents) {
    if (event.malformed) continue;
    const pubkey = pubkeyForEvent(event);
    const verification = options.verification;
    if (!verification) {
      findings.push(finding("SIGNATURE_UNVERIFIED", "critical", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        pubkey,
        reason: "verification_unavailable",
      }));
      continue;
    }
    const entry = (verification.signatures ?? []).find((candidate) => (
      candidate.index === event.index
      && candidate.name === event.name
      && samePubkey(candidate.pubkey, pubkey)
    ));
    if (!entry || entry.valid === null) {
      findings.push(finding("SIGNATURE_UNVERIFIED", "critical", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        pubkey,
        reason: verification.complete === false ? "budget_exhausted" : "not_checked",
      }));
    } else if (entry.valid === false) {
      findings.push(finding("SIGNATURE_INVALID", "critical", "input-map", event.index, null, {
        index: event.index,
        name: event.name,
        pubkey,
      }));
    }
  }

  // Phase G — change / wallet verification.
  findings.push(...changeResult.findings);

  // Phase H — origin consistency.
  const origin = afterDoc.sanitize?.xpubDerivesChild;
  if (origin?.state === "problem") {
    for (const item of origin.findings ?? []) {
      findings.push(finding("ORIGIN_INCONSISTENT", "warning", item.scope ?? null, item.index ?? null, item.name ?? null, {
        scope: item.scope,
        index: item.index,
        name: item.name,
        fingerprint: item.fingerprint,
        reason: item.reason,
      }));
    }
  }

  // Phase I — nonce.
  const nonceStatus = options.nonce?.status;
  if (nonceStatus === "reuse") findings.push(finding("NONCE_REUSE", "critical", null, null, null, {}));
  else if (nonceStatus === "cross-key") findings.push(finding("NONCE_CROSS_KEY", "critical", null, null, null, {}));
  else if (nonceStatus === "possible") findings.push(finding("NONCE_REUSE_POSSIBLE", "warning", null, null, null, {}));
  else if (nonceStatus === "incomplete") findings.push(finding("NONCE_COVERAGE_INCOMPLETE", "warning", null, null, null, {}));

  // Phase J — anti-exfil.
  if (options.antiExfil?.status === "failed") {
    findings.push(finding("ANTIEXFIL_FAILED", "critical", null, null, null, { signer: options.antiExfil.signer ?? null }));
  }

  const has = (code, severity) => findings.some((f) => f.code === code && (severity === undefined || f.severity === severity));

  const transactionBody = has("TX_REORDERED")
    ? "reordered"
    : findings.some((f) => f.code.startsWith("TX_") && f.code !== "TX_REORDERED")
      ? "changed"
      : "unchanged";
  const utxoDeclarations = has("UTXO_DECLARATION_CHANGED") ? "changed" : "unchanged";

  let signatures = "none_added";
  if (has("SIGNATURE_CHANGED") || has("SIGNATURE_REMOVED")) signatures = "removed_or_changed";
  else if (has("SIGNATURE_INVALID")) signatures = "invalid";
  else if (has("SIGNATURE_UNVERIFIED") || has("SIGNATURE_MALFORMED")) signatures = "unverified";
  else if (newSigEvents.length > 0 || has("FINALIZED")) signatures = "valid";

  let sighashPolicy = "none";
  if (has("SIGHASH_UNDEFINED")) sighashPolicy = "undefined";
  else if (has("SIGHASH_MISMATCH")) sighashPolicy = "mismatch";
  else if (has("SIGHASH_WEAK")) sighashPolicy = "weak";
  else if (weakAsRequested.value) sighashPolicy = "weak_as_requested";
  else if (newSigEvents.length > 0) sighashPolicy = "full_commitment";

  let signerKeys = "no_new_signatures";
  if (has("UNEXPECTED_SIGNER")) signerKeys = "unexpected";
  else if (has("SIGNER_UNKNOWN")) signerKeys = "unknown";
  else if (has("SIGNATURE_ADDED")) signerKeys = "match";

  let metadata = "unchanged";
  if (findings.some((f) => f.severity === "critical" && (f.code === "METADATA_CHANGED" || f.code === "METADATA_REMOVED" || f.code === "FINGERPRINT_MISMATCH"))) {
    metadata = "mutated";
  } else if (has("METADATA_ADDED") || has("METADATA_ENRICHMENT")) {
    metadata = "additions";
  }

  let nonceReuse = "not_checked";
  if (nonceStatus === "clean") nonceReuse = "none_found";
  else if (nonceStatus === "reuse") nonceReuse = "reuse";
  else if (nonceStatus === "cross-key") nonceReuse = "cross_key";
  else if (nonceStatus === "possible") nonceReuse = "possible";
  else if (nonceStatus === "incomplete") nonceReuse = "incomplete";

  let antiExfil = "not_available";
  if (options.antiExfil?.status === "verified") antiExfil = "verified";
  else if (options.antiExfil?.status === "failed") antiExfil = "failed";

  let changeOutputs = "not_checked";
  if (has("CHANGE_NOT_FROM_WALLET")) changeOutputs = "not_from_wallet";
  else if (has("CHANGE_UNVERIFIED")) changeOutputs = "unverified";
  else if (has("CHANGE_VERIFIED")) changeOutputs = "verified";
  else if (options.wallet) changeOutputs = "none_presented";

  const verdict = findings.some((f) => f.severity === "critical") ? "fail" : "pass";
  const stats = {
    inputs: afterDoc.tx.inputs.length,
    outputs: afterDoc.tx.outputs.length,
    newSignatures: newSigEvents.length,
    feeBefore: beforeDoc.fee?.known ? numeric(beforeDoc.fee.sats) : null,
    feeAfter: afterDoc.fee?.known ? numeric(afterDoc.fee.sats) : null,
  };

  return {
    verdict,
    equal: diff.equal,
    checks: {
      transactionBody,
      utxoDeclarations,
      signatures,
      sighashPolicy,
      signerKeys,
      metadata,
      nonceReuse,
      antiExfil,
      changeOutputs,
    },
    findings,
    stats,
    diff,
  };
}
