// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Integration coverage for the git helpers, against throwaway repositories.
// The interesting behaviour is fail-closed resolution and path handling, none of
// which can be exercised without a real repository.

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("child_process");
const { mkdtempSync, rmSync, writeFileSync, mkdirSync } = require("fs");
const { tmpdir } = require("os");
const { join } = require("path");
const {
  listFilesAtCommit,
  readFileAtCommit,
  repoRelativeGitPath,
  resolveBaseCommit,
  toGitPath,
} = require("../lib/git-base");

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

// Build a repository with two commits and return its path.
function scratchRepo(setup) {
  const dir = mkdtempSync(join(tmpdir(), "git-base-test-"));
  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["config", "user.email", "test@example.com"]);
  git(dir, ["config", "user.name", "Test"]);
  setup(dir);
  return dir;
}

function commitAll(dir, message) {
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-q", "-m", message]);
}

test("toGitPath normalises Windows separators", () => {
  assert.equal(toGitPath("schemas\\dev\\a.json"), "schemas/dev/a.json");
  assert.equal(toGitPath("schemas/dev/a.json"), "schemas/dev/a.json");
  assert.equal(toGitPath("./a.json"), "a.json");
});

test("toGitPath rejects non-string paths", () => {
  for (const path of [null, undefined, 42, ["schemas", "a.json"], {}]) {
    assert.throws(() => toGitPath(path), TypeError);
  }
});

test("readFileAtCommit reads a file using either separator", () => {
  const dir = scratchRepo((d) => {
    mkdirSync(join(d, "schemas", "dev"), { recursive: true });
    writeFileSync(join(d, "schemas", "dev", "a.json"), '{"v":1}\n');
    commitAll(d, "add");
  });
  try {
    // A Windows caller naturally produces backslashes; without normalisation the
    // literal comparison against ls-tree output misses and the file reads as
    // absent, which a gate cannot distinguish from "genuinely deleted".
    assert.equal(readFileAtCommit(dir, "HEAD", "schemas\\dev\\a.json"), '{"v":1}\n');
    assert.equal(readFileAtCommit(dir, "HEAD", "schemas/dev/a.json"), '{"v":1}\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readFileAtCommit finds a path that git would C-quote", () => {
  const dir = scratchRepo((d) => {
    writeFileSync(join(d, "sch\u00e9ma.json"), "{}\n");
    commitAll(d, "add");
  });
  try {
    // Without -z, git renders this name as "sch\303\251ma.json" and the literal
    // membership check fails open.
    assert.equal(readFileAtCommit(dir, "HEAD", "sch\u00e9ma.json"), "{}\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readFileAtCommit returns null for a genuinely absent file", () => {
  const dir = scratchRepo((d) => {
    writeFileSync(join(d, "a.json"), "{}\n");
    commitAll(d, "add");
  });
  try {
    assert.equal(readFileAtCommit(dir, "HEAD", "missing.json"), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readFileAtCommit handles output larger than Node's default buffer", () => {
  const content = "x".repeat(2 * 1024 * 1024);
  const dir = scratchRepo((d) => {
    writeFileSync(join(d, "large.txt"), content);
    commitAll(d, "add");
  });
  try {
    assert.equal(readFileAtCommit(dir, "HEAD", "large.txt"), content);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("listFilesAtCommit lists tracked files under a directory", () => {
  const dir = scratchRepo((d) => {
    mkdirSync(join(d, "schemas"), { recursive: true });
    writeFileSync(join(d, "schemas", "a.json"), "{}\n");
    writeFileSync(join(d, "schemas", "b.json"), "{}\n");
    commitAll(d, "add");
  });
  try {
    const files = listFilesAtCommit(dir, "HEAD", "schemas").sort();
    assert.deepEqual(files, ["schemas/a.json", "schemas/b.json"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("listFilesAtCommit lists the repository root", () => {
  const dir = scratchRepo((d) => {
    mkdirSync(join(d, "schemas"), { recursive: true });
    writeFileSync(join(d, "root.json"), "{}\n");
    writeFileSync(join(d, "schemas", "nested.json"), "{}\n");
    commitAll(d, "add");
  });
  try {
    assert.deepEqual(listFilesAtCommit(dir, "HEAD", dir).sort(), [
      "root.json",
      "schemas/nested.json",
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("listFilesAtCommit treats pathspec magic as a literal filename", () => {
  const dir = scratchRepo((d) => {
    writeFileSync(join(d, "a.txt"), "ordinary\n");
    writeFileSync(join(d, "[ab].txt"), "magic-looking\n");
    commitAll(d, "add");
  });
  try {
    assert.deepEqual(
      listFilesAtCommit(dir, "HEAD", "[ab].txt"),
      ["[ab].txt"]
    );
    assert.equal(
      readFileAtCommit(dir, "HEAD", "[ab].txt"),
      "magic-looking\n"
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resolveBaseCommit honours an explicit base ref", () => {
  const dir = scratchRepo((d) => {
    writeFileSync(join(d, "a.txt"), "one\n");
    commitAll(d, "first");
    // Tag the first commit under a name the resolver's fallback would never
    // choose, so this asserts the injected ref was actually used rather than
    // passing by coincidence when the fallback lands on the same commit.
    git(d, ["branch", "injected-base"]);
    writeFileSync(join(d, "a.txt"), "two\n");
    commitAll(d, "second");
  });
  try {
    const first = git(dir, ["rev-parse", "injected-base"]);
    const base = resolveBaseCommit(dir, {
      argv: [],
      env: { MXC_VERSIONING_BASE_REF: "injected-base" },
    });
    assert.equal(base.ref, "injected-base");
    assert.equal(base.commit, first);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resolveBaseCommit takes its options as a single object", () => {
  // The options are `{ argv, env }`; passing them positionally silently falls
  // back to `process.argv` / `process.env`, which reads whatever the ambient
  // job happens to set and makes these tests depend on their environment.
  const dir = scratchRepo((d) => {
    writeFileSync(join(d, "a.txt"), "one\n");
    commitAll(d, "first");
    git(d, ["branch", "injected-base"]);
    writeFileSync(join(d, "a.txt"), "two\n");
    commitAll(d, "second");
  });
  try {
    // An ambient value must not win over the injected one.
    const previous = process.env.MXC_VERSIONING_BASE_REF;
    process.env.MXC_VERSIONING_BASE_REF = "origin/definitely-not-here";
    try {
      const base = resolveBaseCommit(dir, {
        argv: [],
        env: { MXC_VERSIONING_BASE_REF: "injected-base" },
      });
      assert.equal(base.ref, "injected-base");
    } finally {
      if (previous === undefined) delete process.env.MXC_VERSIONING_BASE_REF;
      else process.env.MXC_VERSIONING_BASE_REF = previous;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resolveBaseCommit fails closed in CI when the base ref is unavailable", () => {
  const dir = scratchRepo((d) => {
    writeFileSync(join(d, "a.txt"), "one\n");
    commitAll(d, "first");
  });
  try {
    // A shallow clone or a missing fetch must be an error, not a silent skip
    // that reports success while checking nothing.
    assert.throws(
      () =>
        resolveBaseCommit(dir, {
          argv: [],
          env: {
            GITHUB_ACTIONS: "true",
            MXC_VERSIONING_BASE_REF: "origin/does-not-exist",
          },
        }),
      /does-not-exist/
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resolveBaseCommit requires an explicit base ref under GitHub Actions", () => {
  const dir = scratchRepo((d) => {
    writeFileSync(join(d, "a.txt"), "one\n");
    commitAll(d, "first");
  });
  try {
    assert.throws(
      () =>
        resolveBaseCommit(dir, {
          argv: [],
          env: { GITHUB_ACTIONS: "true" },
        }),
      /MXC_VERSIONING_BASE_REF is required in GitHub Actions/
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("toGitPath collapses non-canonical spellings", () => {
  // These are all meaningful to the filesystem but never appear in git's own
  // output, so comparing them literally would make an existing file look absent.
  assert.equal(toGitPath("schemas//dev/a.json"), "schemas/dev/a.json");
  assert.equal(toGitPath("././a.json"), "a.json");
  assert.equal(toGitPath("schemas/../a.json"), "a.json");
  assert.equal(toGitPath("schemas/dev/../dev/a.json"), "schemas/dev/a.json");
  // A `..` with nothing to pop can never name a tracked file.
  assert.throws(() => toGitPath("../a.json"), /escapes the repository root/);
});

test("readFileAtCommit accepts the natural absolute call shape", () => {
  // `path.join(repoRoot, ...)` is what a caller naturally writes, and it yields
  // an absolute path that matches no ls-tree entry. Returning null there would
  // be read as "absent at the base", so a gate would skip its own check.
  const dir = scratchRepo((d) => {
    mkdirSync(join(d, "schemas", "dev"), { recursive: true });
    writeFileSync(join(d, "schemas", "dev", "a.json"), '{"v":1}\n');
    commitAll(d, "first");
  });
  try {
    const expected = '{"v":1}\n';
    for (const path of [
      "schemas/dev/a.json",
      "schemas\\dev\\a.json",
      join(dir, "schemas", "dev", "a.json"),
      "schemas//dev/a.json",
      "./schemas/dev/../dev/a.json",
    ]) {
      assert.equal(
        readFileAtCommit(dir, "HEAD", path),
        expected,
        `should read ${path}`
      );
    }
    // A genuinely absent file is still null, so the signal keeps its meaning.
    assert.equal(readFileAtCommit(dir, "HEAD", "schemas/dev/missing.json"), null);
    // A path that cannot name a file in this repository is refused outright
    // rather than reported as absent.
    assert.throws(
      () => readFileAtCommit(dir, "HEAD", join(tmpdir(), "elsewhere.json")),
      /outside the repository root/
    );
    assert.throws(
      () => readFileAtCommit(dir, "HEAD", "../elsewhere.json"),
      /escapes the repository root/
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test(
  "repoRelativeGitPath compares Windows absolute paths case-insensitively",
  { skip: process.platform !== "win32" },
  () => {
    const dir = scratchRepo((d) => {
      mkdirSync(join(d, "schemas"), { recursive: true });
      writeFileSync(join(d, "schemas", "a.json"), "{}\n");
      commitAll(d, "add");
    });
    try {
      assert.equal(
        repoRelativeGitPath(dir.toUpperCase(), join(dir, "schemas", "a.json")),
        "schemas/a.json"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
);
