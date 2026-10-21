// Shared fuzz harness: deterministic PRNG, env-driven seed/iteration/only
// selection, replayable failures, and a ddmin-style shrinker.
export const mulberry32 = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

const envInt = (name, fallback) => {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  if (raw.trim() === "") throw new Error(`${name} must be a non-negative integer, got ${raw}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer, got ${raw}`);
  return value;
};

export const fuzzEnv = (prefix, { defaultSeed, defaultIterations }) => {
  const seed = envInt(`${prefix}_SEED`, defaultSeed);
  const iterations = envInt(`${prefix}_ITERATIONS`, defaultIterations);
  const only = envInt(`${prefix}_ONLY`, null);
  return { seed, iterations, only };
};

const shellQuote = (value) => `'${value.replace(/'/g, "'\\''")}'`;
const replayCommand = (prefix, seed, i) => {
  const file = process.argv[1] ?? "test/unknown.test.mjs";
  return `${prefix}_SEED=${seed} ${prefix}_ONLY=${i} node --test ${shellQuote(file)}`;
};

export const runCases = (prefix, opts, caseAt) => {
  const { seed, iterations, only } = fuzzEnv(prefix, opts);
  if (only !== null && only >= iterations) {
    throw new Error(`${prefix}_ONLY=${only} is out of range for ${iterations} iterations`);
  }
  const rand = mulberry32(seed);
  const results = [];
  const last = only === null ? iterations - 1 : only;
  for (let i = 0; i <= last; i++) {
    try {
      const result = caseAt(i, rand);
      if (only === null || i === only) results.push(result);
    } catch (error) {
      if (error && typeof error === "object" && typeof error.message === "string") {
        error.message += `\nReplay: ${replayCommand(prefix, seed, i)}`;
      }
      throw error;
    }
  }
  return results;
};

const size = (value) => JSON.stringify(value).length;
const clone = (value) => JSON.parse(JSON.stringify(value));
const getAt = (root, path) => path.reduce((node, key) => node[key], root);
const setAt = (root, path, value) => {
  if (path.length === 0) return value;
  const parent = getAt(root, path.slice(0, -1));
  parent[path[path.length - 1]] = value;
  return root;
};

const collectReductions = (node, path, root, out) => {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const candidate = clone(root);
      getAt(candidate, path).splice(i, 1);
      out.push(candidate);
    }
    node.forEach((child, i) => collectReductions(child, [...path, i], root, out));
    return;
  }
  if (typeof node === "string") {
    const variants = ["", node.slice(0, Math.floor(node.length / 2)), node.slice(Math.floor(node.length / 2)), node.slice(0, -1), node.slice(1)];
    for (const variant of variants) {
      if (variant === node) continue;
      const candidate = clone(root);
      out.push(setAt(candidate, path, variant));
    }
    return;
  }
  if (node && typeof node === "object") {
    for (const key of Object.keys(node)) {
      const candidate = clone(root);
      delete getAt(candidate, path)[key];
      out.push(candidate);
    }
    for (const key of Object.keys(node)) {
      collectReductions(node[key], [...path, key], root, out);
    }
    return;
  }
  for (const empty of [0, "", null]) {
    if (node === empty) continue;
    const candidate = clone(root);
    out.push(setAt(candidate, path, empty));
  }
};

export const shrink = (caseObj, predicate) => {
  let current = clone(caseObj);
  let changed = true;
  while (changed) {
    changed = false;
    const candidates = [];
    collectReductions(current, [], current, candidates);
    for (const candidate of candidates) {
      if (size(candidate) < size(current) && predicate(candidate)) {
        current = candidate;
        changed = true;
        break;
      }
    }
  }
  return current;
};
