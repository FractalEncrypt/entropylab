import { test } from "node:test";
import assert from "node:assert/strict";
import { fuzzEnv, mulberry32, runCases, shrink } from "./fuzz-kit.mjs";

const withEnv = (prefix, vars, fn) => {
  const saved = {};
  for (const [key, value] of Object.entries(vars)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return fn();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
};

test("same seed and iteration count yield the identical case sequence", () => {
  const prefix = "FUZZ_KIT_SEQ";
  withEnv(prefix, {
    [`${prefix}_SEED`]: "12345",
    [`${prefix}_ITERATIONS`]: "7",
    [`${prefix}_ONLY`]: undefined,
  }, () => {
    const run = () => runCases(prefix, { defaultSeed: 1, defaultIterations: 3 }, (i, rand) => ({ i, value: rand() }));
    const first = run();
    const second = run();
    assert.deepEqual(second, first);
    assert.equal(first.length, 7);
    assert.deepEqual(first.map((c) => c.i), [0, 1, 2, 3, 4, 5, 6]);
  });
});

test("_ONLY=n replays exactly case n and the printed replay command reproduces the failure", () => {
  const prefix = "FUZZ_KIT_ONLY";
  const testName = "only replay test";
  const opts = { defaultSeed: 1, defaultIterations: 3, testName };
  withEnv(prefix, {
    [`${prefix}_SEED`]: "999",
    [`${prefix}_ITERATIONS`]: "10",
    [`${prefix}_ONLY`]: undefined,
  }, () => {
    const full = runCases(prefix, opts, (i, rand) => ({ i, value: rand() }));
    const n = 4;
    process.env[`${prefix}_ONLY`] = String(n);
    const only = runCases(prefix, opts, (i, rand) => ({ i, value: rand() }));
    assert.equal(only.length, 1);
    assert.deepEqual(only[0], full[n]);

    let error;
    try {
      runCases(prefix, opts, (i) => {
        if (i === n) throw new Error(`synthetic failure at ${i}`);
        return i;
      });
    } catch (caught) {
      error = caught;
    }
    assert.ok(error);
    assert.match(error.message, new RegExp(`synthetic failure at ${n}`));
    const replayLine = error.message.split("\n").find((line) => line.startsWith("Replay: "));
    assert.ok(replayLine, "the error must carry a replay command");
    assert.ok(replayLine.includes(`${prefix}_SEED=999`), "the replay command must pin the seed");
    assert.ok(replayLine.includes(`${prefix}_ITERATIONS=10`), "the replay command must pin the non-default iteration count");
    assert.ok(replayLine.includes(`${prefix}_ONLY=${n}`), "the replay command must pin the failing case");
    assert.ok(replayLine.includes(`--test-name-pattern '${testName}'`), "the replay command must name the failing test");

    // Parse the env assignments from the replay command and run them.
    const envPart = replayLine.slice("Replay: ".length).split(" node --test")[0];
    const assignments = [...envPart.matchAll(/([A-Z0-9_]+)=(\d+)/g)];
    assert.ok(assignments.length >= 3, "the replay command must set seed, iterations, and only");
    const saved = {};
    for (const key of Object.keys(process.env)) {
      if (key.startsWith(`${prefix}_`)) {
        saved[key] = process.env[key];
        delete process.env[key];
      }
    }
    try {
      for (const [, key, value] of assignments) process.env[key] = value;
      let replayError;
      try {
        runCases(prefix, opts, (i) => {
          if (i === n) throw new Error(`synthetic failure at ${i}`);
          return i;
        });
      } catch (caught) {
        replayError = caught;
      }
      assert.ok(replayError, "the replay must fail");
      assert.match(replayError.message, new RegExp(`synthetic failure at ${n}`));
    } finally {
      for (const key of Object.keys(process.env)) {
        if (key.startsWith(`${prefix}_`)) delete process.env[key];
      }
      Object.assign(process.env, saved);
    }
  });
});

test("runCases shrinks a failing case and keeps the original in the message", () => {
  const prefix = "FUZZ_KIT_SHRINK_RUN";
  const testName = "shrink run test";
  const originalCase = { a: [1, 2, 3, 4], b: "hello world", c: 42 };
  const caseAt = () => {
    const error = new Error("synthetic shrink failure");
    error.case = originalCase;
    error.check = (candidate) => {
      if (Array.isArray(candidate.a) && candidate.a.includes(3) && typeof candidate.b === "string" && candidate.b.includes("hello") && candidate.c === 42) {
        throw new Error("still fails");
      }
      return false;
    };
    throw error;
  };
  withEnv(prefix, {
    [`${prefix}_SEED`]: "1",
    [`${prefix}_ITERATIONS`]: "1",
    [`${prefix}_ONLY`]: undefined,
  }, () => {
    let error;
    try {
      runCases(prefix, { defaultSeed: 1, defaultIterations: 1, testName }, caseAt);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error);
    assert.match(error.message, /Original case: /);
    assert.match(error.message, /Shrunk case: /);
    const shrunkLine = error.message.split("\n").find((line) => line.startsWith("Shrunk case: "));
    const shrunk = JSON.parse(shrunkLine.slice("Shrunk case: ".length));
    assert.ok(JSON.stringify(shrunk).length < JSON.stringify(originalCase).length);
    assert.deepEqual(shrunk.a, [3]);
    assert.equal(shrunk.b, "hello");
    assert.equal(shrunk.c, 42);
  });
});

test("shrink strictly reduces size while preserving the failing assertion", () => {
  const original = { a: [1, 2, 3, 4], b: "hello world", c: 42, d: { e: "xyz", f: [5, 6] } };
  const predicate = (candidate) =>
    Array.isArray(candidate.a) && candidate.a.includes(3) &&
    typeof candidate.b === "string" && candidate.b.includes("hello") &&
    candidate.c === 42;
  const shrunk = shrink(original, predicate);
  assert.ok(predicate(shrunk));
  assert.ok(JSON.stringify(shrunk).length < JSON.stringify(original).length);
  assert.deepEqual(shrunk.a, [3]);
  assert.equal(shrunk.b, "hello");
  assert.equal(shrunk.c, 42);
  assert.equal(shrunk.d, undefined);
});

test("shrink treats a throwing predicate as still failing", () => {
  const original = { a: 1, b: 2 };
  const shrunk = shrink(original, (candidate) => {
    if (candidate.a === undefined) throw new Error("boom");
    return false;
  });
  assert.deepEqual(shrunk, {});
});

test("zero overhead when all cases pass", () => {
  const prefix = "FUZZ_KIT_PASS";
  withEnv(prefix, {
    [`${prefix}_SEED`]: "1",
    [`${prefix}_ITERATIONS`]: "5",
    [`${prefix}_ONLY`]: undefined,
  }, () => {
    let calls = 0;
    const results = runCases(prefix, { defaultSeed: 1, defaultIterations: 3 }, (i, rand) => {
      calls += 1;
      return { i, value: rand() };
    });
    assert.equal(calls, 5);
    assert.equal(results.length, 5);
    assert.deepEqual(results.map((r) => r.i), [0, 1, 2, 3, 4]);
  });
});

test("mulberry32 is deterministic", () => {
  const a = mulberry32(42);
  const b = mulberry32(42);
  assert.deepEqual([a(), a(), a()], [b(), b(), b()]);
});

test("fuzzEnv defaults and overrides", () => {
  const prefix = "FUZZ_KIT_ENV";
  withEnv(prefix, {
    [`${prefix}_SEED`]: undefined,
    [`${prefix}_ITERATIONS`]: undefined,
    [`${prefix}_ONLY`]: undefined,
  }, () => {
    assert.deepEqual(fuzzEnv(prefix, { defaultSeed: 7, defaultIterations: 9 }), { seed: 7, iterations: 9, only: null });
  });
  withEnv(prefix, {
    [`${prefix}_SEED`]: "16",
    [`${prefix}_ITERATIONS`]: "3",
    [`${prefix}_ONLY`]: "1",
  }, () => {
    assert.deepEqual(fuzzEnv(prefix, { defaultSeed: 7, defaultIterations: 9 }), { seed: 16, iterations: 3, only: 1 });
  });
});

test("fuzzEnv refuses malformed seed, iteration and only values", () => {
  const prefix = "FUZZ_KIT_BAD_ENV";
  const malformed = ["-1", "1.5", "abc", "  ", "0x10", "1e3", "+1", " 1", "1 ", String(Number.MAX_SAFE_INTEGER + 1)];
  for (const key of ["SEED", "ITERATIONS", "ONLY"]) {
    for (const value of malformed) {
      withEnv(prefix, {
        [`${prefix}_SEED`]: undefined,
        [`${prefix}_ITERATIONS`]: undefined,
        [`${prefix}_ONLY`]: undefined,
        [`${prefix}_${key}`]: value,
      }, () => {
        assert.throws(
          () => fuzzEnv(prefix, { defaultSeed: 1, defaultIterations: 1 }),
          new RegExp(`${prefix}_${key} must be a non-negative decimal integer`),
        );
      });
    }
  }
});

test("fuzzEnv refuses seeds that do not fit 32 bits", () => {
  const prefix = "FUZZ_KIT_SEED32";
  withEnv(prefix, {
    [`${prefix}_SEED`]: "4294967296",
    [`${prefix}_ITERATIONS`]: "1",
    [`${prefix}_ONLY`]: undefined,
  }, () => {
    assert.throws(
      () => fuzzEnv(prefix, { defaultSeed: 1, defaultIterations: 1 }),
      new RegExp(`${prefix}_SEED must be a non-negative decimal integer no greater than 4294967295`),
    );
  });
  withEnv(prefix, {
    [`${prefix}_SEED`]: "4294967295",
    [`${prefix}_ITERATIONS`]: "1",
    [`${prefix}_ONLY`]: undefined,
  }, () => {
    assert.equal(fuzzEnv(prefix, { defaultSeed: 1, defaultIterations: 1 }).seed, 4294967295);
  });
});

test("runCases refuses an out-of-range _ONLY", () => {
  const prefix = "FUZZ_KIT_ONLY_RANGE";
  withEnv(prefix, {
    [`${prefix}_SEED`]: "1",
    [`${prefix}_ITERATIONS`]: "3",
    [`${prefix}_ONLY`]: "3",
  }, () => {
    assert.throws(
      () => runCases(prefix, { defaultSeed: 1, defaultIterations: 3 }, () => {
        throw new Error("case should not run");
      }),
      new RegExp(`${prefix}_ONLY=3 is out of range`),
    );
  });
  withEnv(prefix, {
    [`${prefix}_SEED`]: "1",
    [`${prefix}_ITERATIONS`]: "0",
    [`${prefix}_ONLY`]: "0",
  }, () => {
    assert.throws(
      () => runCases(prefix, { defaultSeed: 1, defaultIterations: 0 }, () => {
        throw new Error("case should not run");
      }),
      new RegExp(`${prefix}_ONLY=0 is out of range`),
    );
  });
});

test("replay command quotes the test path", () => {
  const prefix = "FUZZ_KIT_REPLAY";
  const originalArgv1 = process.argv[1];
  process.argv[1] = "/tmp/a b/test.mjs";
  try {
    withEnv(prefix, {
      [`${prefix}_SEED`]: "1",
      [`${prefix}_ITERATIONS`]: "1",
      [`${prefix}_ONLY`]: undefined,
    }, () => {
      let error;
      try {
        runCases(prefix, { defaultSeed: 1, defaultIterations: 1 }, () => {
          throw new Error("boom");
        });
      } catch (caught) {
        error = caught;
      }
      assert.ok(error);
      assert.ok(error.message.includes("node --test '/tmp/a b/test.mjs'"));
    });
  } finally {
    process.argv[1] = originalArgv1;
  }
});

test("shrink reduces root-level scalar cases", () => {
  assert.equal(shrink("aaaaaaaa", (s) => typeof s === "string" && s.startsWith("aa")), "aa");
  assert.equal(shrink(42, (n) => typeof n === "number" && n >= 0), 0);
  assert.equal(shrink(true, (v) => v === true || v === 0), 0);
  assert.equal(shrink(null, (v) => v === null || v === 0), 0);
});
