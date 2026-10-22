// Audit SC-2: the timestamp, OTS upgrade and release-asset jobs install the
// OpenTimestamps client from PyPI. Pinning only the top-level package left its
// eight dependencies floating and nothing hash-checked, in jobs that also hold
// the release-push token. The install must take exactly the locked wheels or
// fail, and no step that runs the client may see the push token. A textual
// guard cannot parse YAML, but it fails the moment any of these lines move.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(root, path), "utf8");
const lockPath = ".github/ots-requirements.txt";
const workflows = readdirSync(join(root, ".github/workflows"))
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => ({ name, text: read(`.github/workflows/${name}`) }));

const jobBlock = (workflow, name) =>
  workflow.match(new RegExp(`^  ${name}:\\n[\\s\\S]*?(?=^  [a-z0-9_-]+:\\n|(?![\\s\\S]))`, "m"))?.[0] ?? "";
const steps = (job) => job.split(/^ {6}- /m).slice(1);

// Each top-level job under `jobs:` as { job, block }.
const jobsOf = (text) => {
  const body = text.split(/^jobs:\n/m)[1] ?? "";
  return [...body.matchAll(/^ {2}([a-z0-9_-]+):\n([\s\S]*?)(?=^ {2}[a-z0-9_-]+:\n|(?![\s\S]))/gm)].map(
    ([, job, block]) => ({ job, block }),
  );
};

// The two workflows that push a proof (the OTS client runs in a third,
// release-assets.yml, whose job holds no secret; see the guard below).
const otsWorkflows = ["ci-cd.yml", "ots-upgrade.yml"].map((name) => ({
  name,
  text: read(`.github/workflows/${name}`),
}));

// A job "runs the OTS client" when it creates the venv, invokes the binary or
// installs the wheels.
const runsOtsClient = (block) => /\$RUNNER_TEMP\/ots|\$OTS\b|\bpip3?"? install\b/.test(block);

// opentimestamps-client 0.7.2's dependency closure, from the requires_dist
// metadata PyPI publishes for it and for each dependency in turn.
const closure = [
  "opentimestamps-client",
  "opentimestamps",
  "python-bitcoinlib",
  "pycryptodomex",
  "GitPython",
  "gitdb",
  "smmap",
  "PySocks",
  "appdirs",
];

const lockEntries = () =>
  read(lockPath)
    .replace(/\\\n\s*/g, " ")
    .split("\n")
    .filter((line) => line.trim() && !line.trim().startsWith("#"));

test("the OTS lock pins every package of the client's closure by version and wheel hash", () => {
  const entries = lockEntries();
  const names = [];
  for (const entry of entries) {
    const match = entry.match(/^([A-Za-z0-9._-]+)==([0-9][0-9A-Za-z.]*)((?: +--hash=sha256:[0-9a-f]{64})+)\s*$/);
    assert.ok(match, `${entry} must be name==version with sha256 hashes and nothing else`);
    names.push(match[1].toLowerCase());
  }
  assert.ok(entries.some((entry) => entry.startsWith("opentimestamps-client==0.7.2 ")), "the client stays at 0.7.2");
  assert.deepEqual([...names].sort(), closure.map((name) => name.toLowerCase()).sort(), "the lock is exactly the closure");
});

test("every pip install in CI takes only the hash-locked OTS wheels", () => {
  let installs = 0;
  for (const { name, text } of workflows) {
    for (const [line] of text.matchAll(/^.*\bpip3?"? install\b.*$/gm)) {
      installs += 1;
      for (const flag of ["--require-hashes", "--no-deps", "--only-binary :all:", `-r "$GITHUB_WORKSPACE/${lockPath}"`]) {
        assert.ok(line.includes(flag), `${name}: ${line.trim()} lacks ${flag}`);
      }
      assert.doesNotMatch(line, /==/, `${name}: pins belong in ${lockPath}, not on the command line`);
    }
  }
  assert.equal(installs, 3, "the timestamp, upgrade and release-asset jobs each install the client once");
});

// The old guard checked that the push was a later *step* of the same job. A
// step boundary is not isolation: the client can write .git/hooks/pre-push or
// leave a background process in the workspace the push token later enters.
// The client and the token must live in different jobs on different runners.
// Every workflow, not only the two that push a proof: release-assets.yml runs
// the client too, and so would any workflow added later.
test("no job that installs or runs the OTS client can reach a secret or the release environment", () => {
  const clientJobs = [];
  for (const { name, text } of workflows) {
    for (const { job, block } of jobsOf(text).filter(({ block }) => runsOtsClient(block))) {
      clientJobs.push(`${name}:${job}`);
      assert.doesNotMatch(block, /^ {4}environment:/m, `${name}:${job} runs the OTS client and must not hold an environment`);
      assert.doesNotMatch(block, /secrets\./, `${name}:${job} runs the OTS client and must not read a secret`);
      assert.doesNotMatch(block, /PUSH_TOKEN/, `${name}:${job} runs the OTS client and must not hold the push token`);
    }
  }
  assert.deepEqual(
    clientJobs.sort(),
    ["ci-cd.yml:timestamp", "ots-upgrade.yml:upgrade", "release-assets.yml:check"],
    "the timestamp, upgrade and release-asset jobs are the only ones that run the client",
  );
});

test("no job that holds the push token or the release environment runs the OTS client", () => {
  for (const { name, text } of otsWorkflows) {
    const jobs = jobsOf(text).filter(({ block }) => /PUSH_TOKEN|^ {4}environment: release$/m.test(block));
    assert.ok(jobs.length > 0, `${name} has a job that pushes the proof`);
    for (const { job, block } of jobs) {
      assert.doesNotMatch(
        block,
        /\$RUNNER_TEMP\/ots|\$OTS\b|\bpip3?"? install\b/,
        `${name}:${job} holds the push token and must not install or run the OTS client`,
      );
    }
  }
});

test("the push job validates the proof and pushes with hooks disabled and an explicit refspec", () => {
  for (const [file, job] of [
    ["ci-cd.yml", "timestamp-push"],
    ["ots-upgrade.yml", "upgrade-push"],
  ]) {
    const block = jobBlock(read(`.github/workflows/${file}`), job);
    assert.ok(block, `${file}:${job} exists`);
    const all = steps(block);
    const checkout = all.find((step) => step.includes("actions/checkout@"));
    assert.match(checkout, /persist-credentials: false/, `${file}:${job} must not leave GITHUB_TOKEN in .git/config`);
    const validate = all.find((step) => step.includes("stat -c %s"));
    assert.ok(validate, `${file}:${job} validates the proof size`);
    assert.match(validate, /65536/, "the size limit is enforced");
    assert.match(
      validate,
      /004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108/,
      "the 31-byte magic, major version 1 and the SHA-256 op tag are pinned",
    );
    assert.match(validate, /head -c 33/, "the header is read");
    assert.match(validate, /head -c 65/, "the digest is read");
    assert.match(validate, /tail -c 32/, "the digest is the 32 bytes after the header");
    // The push job checks rock out after the OTS job finished: the proof must
    // cover the HTML rock carries now, not only the digest the run expected.
    assert.match(validate, /sha256sum entropylab\.html/, `${file}:${job} compares the proof with rock's entropylab.html`);
    const commit = all.find((step) => step.includes("git commit"));
    assert.ok(commit, `${file}:${job} commits the proof`);
    assert.ok(all.indexOf(validate) < all.indexOf(commit), "validation runs before the commit");
    assert.match(commit, /git add entropylab\.html\.ots\n/, "only the proof is staged");
    assert.match(commit, /rev-list --count origin\/rock\.\.HEAD/, "exactly one commit may be ahead of rock");
    assert.match(commit, /diff --name-only origin\/rock\.\.HEAD/, "that commit may change only the proof");
    const push = all.find((step) => step.includes("push origin HEAD:rock"));
    assert.ok(push, `${file}:${job} pushes the explicit refspec HEAD:rock`);
    assert.ok(all.indexOf(commit) < all.indexOf(push), "the push comes after the checked commit");
    // "Already on rock" exits 0 without a commit; the push must not run then.
    assert.match(commit, /^ {8}id: proof$/m, `${file}:${job} names the commit step`);
    assert.ok(
      commit.lastIndexOf('echo "committed=true" >> "$GITHUB_OUTPUT"') > commit.lastIndexOf("diff --name-only origin/rock..HEAD"),
      "committed=true is set only after the one-commit and proof-only checks",
    );
    assert.match(push, /^ {8}if: steps\.proof\.outputs\.committed == 'true'$/m, `${file}:${job} pushes only after a checked commit`);
    assert.match(push, /core\.hooksPath=\/dev\/null/, "hooks are disabled for the push");
    assert.match(push, /^ {8}env:\n {10}PUSH_TOKEN: \$\{\{ secrets\.RELEASE_PUSH_TOKEN \}\}$/m, "the token arrives through env, not inlined into the script");
    assert.doesNotMatch(push.split(/\n {8}run: /)[1] ?? "", /\$\{\{/, "the push script has no expression substitution");
    assert.equal(all.filter((step) => step.includes("secrets.RELEASE_PUSH_TOKEN")).length, 1, `${file}:${job} reads the token in exactly one step`);
  }
});

test("the upgrade job binds the committed proof to rock's entropylab.html digest (audit L8)", () => {
  // ots-upgrade upgrades and republishes whatever proof sits on rock. Without
  // a digest check, a proof left on rock for bytes the tree no longer carries
  // (an admin push, a reverted stamp commit) would be upgraded into a full
  // Bitcoin attestation of the wrong artifact; only release-assets.yml would
  // notice, at release time. The stamp job already compares digests the same
  // way before deciding to re-stamp (ci-cd.yml, timestamp job).
  const block = jobBlock(read(".github/workflows/ots-upgrade.yml"), "upgrade");
  assert.ok(block, "ots-upgrade.yml:upgrade exists");
  const upgrade = steps(block).find((step) => step.includes('"$OTS" upgrade'));
  assert.ok(upgrade, "the upgrade step exists");
  assert.match(upgrade, /sha256sum entropylab\.html/, "the checkout's HTML digest must be computed");
  assert.match(upgrade, /"\$OTS" info entropylab\.html\.ots/, "the committed proof's digest must be read");
  assert.match(upgrade, /if \[ "\$EXISTING" != "\$ACTUAL" \]/, "a digest mismatch must be refused before any upgrade");
});

test("the upgrade push refuses a proof with fewer Bitcoin attestations than the committed one", () => {
  // DeepSeek's red-team of #1047 (OTS-2): the untrusted client could hand
  // back a fresh pending proof for the same digest, which passes the header
  // and digest checks and would replace a completed Bitcoin attestation.
  const block = jobBlock(read(".github/workflows/ots-upgrade.yml"), "upgrade-push");
  const all = steps(block);
  const validate = all.find((step) => step.includes("stat -c %s"));
  assert.match(validate, /grep -o ' 05 88 96 0d 73 d7 19 01'/, "the BitcoinBlockHeaderAttestation tag is counted byte-aligned");
  assert.match(validate, /NEW=\$\(attestations "\$PROOF"\)/, "the uploaded proof's attestations are counted");
  assert.match(validate, /OLD=\$\(attestations entropylab\.html\.ots\)/, "the committed proof's attestations are counted");
  assert.match(validate, /if \[ "\$NEW" -lt "\$OLD" \]; then\n\s+echo "::error::[^"]*"\n\s+exit 1/, "fewer attestations fail the job");
  assert.ok(all.indexOf(validate) < all.findIndex((step) => step.includes("git commit")), "before the commit");
});

test("the attestation counter counts Bitcoin attestations exactly, run as the workflow runs it", (t) => {
  // The function is taken from ots-upgrade.yml itself and fed each proof on
  // stdin, so the test exercises the shipped shell, not a copy.
  const validate = steps(jobBlock(read(".github/workflows/ots-upgrade.yml"), "upgrade-push")).find((step) => step.includes("stat -c %s"));
  const fn = validate.split("\n").map((line) => line.trim()).find((line) => line.startsWith("attestations() {"));
  assert.ok(fn, "the counter is defined in the validation step");
  const count = (bytes) => {
    const run = spawnSync("bash", ["-c", `set -euo pipefail\n${fn}\nattestations -`], { input: Buffer.from(bytes) });
    if (run.error?.code === "ENOENT") return null;
    assert.equal(run.status, 0, String(run.stderr));
    return Number(String(run.stdout).trim());
  };
  const BTC = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
  const PENDING = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
  const header = [0x00, ...Buffer.from("OpenTimestamps"), 0x00, 0x00, ...Buffer.from("Proof"), 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94, 0x01, 0x08, ...new Array(32).fill(0x11)];
  const none = count([...header, 0x00, ...PENDING, 0x05]);
  if (none === null) return t.skip("bash is not available");
  assert.equal(none, 0, "a pending-only proof has no Bitcoin attestation");
  assert.equal(count([...header, 0x00, ...BTC, 0x02, 0x01, 0x02, 0x00, ...BTC, 0x01, 0x07, 0x00, ...BTC, 0x01, 0x09]), 3, "three attestations, as in the upgraded proof of 27362f2");
  assert.equal(count([...header, 0x50, 0x58, 0x89, 0x60, 0xd7, 0x3d, 0x71, 0x90, 0x10]), 0, "a lookalike shifted by half a byte is not counted");
  assert.equal(count([...new Array(44).fill(0), ...BTC]), 1, "a tag split across od's 16-byte lines is counted");
});
