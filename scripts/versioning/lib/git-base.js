// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { execFileSync, spawnSync } = require("child_process");

function argumentValue(argv, name) {
  const index = argv.indexOf(name);
  if (index < 0) return null;
  if (!argv[index + 1]) throw new Error(`${name} requires a ref`);
  return argv[index + 1];
}

function requestedBaseRef(argv = process.argv.slice(2), env = process.env) {
  const fromArgs = argumentValue(argv, "--base-ref");
  if (fromArgs) return fromArgs;
  if (env.MXC_VERSIONING_BASE_REF) return env.MXC_VERSIONING_BASE_REF;
  if (env.GITHUB_ACTIONS) {
    throw new Error(
      "MXC_VERSIONING_BASE_REF is required in GitHub Actions; refusing to skip history checks"
    );
  }
  return null;
}

function git(repoRoot, args, { trim = true } = {}) {
  const output = execFileSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return trim ? output.trimEnd() : output;
}

function refExists(repoRoot, ref) {
  return (
    spawnSync("git", ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], {
      cwd: repoRoot,
      stdio: "ignore",
    }).status === 0
  );
}

function resolveBaseCommit(
  repoRoot,
  { argv = process.argv.slice(2), env = process.env } = {}
) {
  let ref = requestedBaseRef(argv, env);
  if (ref) {
    if (!refExists(repoRoot, ref)) {
      throw new Error(`versioning base ref "${ref}" is unavailable`);
    }
  } else {
    ref = ["origin/main", "HEAD^"].find((candidate) =>
      refExists(repoRoot, candidate)
    );
    if (!ref) {
      throw new Error(
        "could not resolve a versioning base; pass --base-ref <ref> or set MXC_VERSIONING_BASE_REF"
      );
    }
  }

  let commit;
  try {
    commit = git(repoRoot, ["merge-base", "HEAD", ref]);
  } catch (error) {
    throw new Error(
      `could not compute merge-base between HEAD and "${ref}": ${error.message}`
    );
  }
  if (!commit) throw new Error(`empty merge-base for HEAD and "${ref}"`);
  return { ref, commit };
}

function listFilesAtCommit(repoRoot, commit, path) {
  const output = git(repoRoot, [
    "ls-tree",
    "-r",
    "--name-only",
    commit,
    "--",
    path,
  ]);
  return output ? output.split(/\r?\n/).filter(Boolean) : [];
}

function readFileAtCommit(repoRoot, commit, path) {
  if (!listFilesAtCommit(repoRoot, commit, path).includes(path)) return null;
  return git(repoRoot, ["show", `${commit}:${path}`], { trim: false });
}

module.exports = {
  listFilesAtCommit,
  readFileAtCommit,
  requestedBaseRef,
  resolveBaseCommit,
};
