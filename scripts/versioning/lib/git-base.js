// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const { execFileSync, spawnSync } = require("child_process");
const { isAbsolute, resolve } = require("path");

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
    maxBuffer: Infinity,
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

// Git speaks repository-relative paths with forward slashes. Callers on Windows
// naturally produce backslashes (path.join), which would never match `ls-tree`
// output and would make an existing file look absent.
//
// Non-canonical spellings fail the same way: `.` and `..` segments and doubled
// slashes are all meaningful to the filesystem but never appear in git's own
// output, so they are collapsed here rather than compared literally.
function toGitPath(path) {
  if (typeof path !== "string") {
    throw new TypeError(`path must be a string, got ${typeof path}`);
  }
  const text = path.split("\\").join("/");
  const segments = [];
  for (const segment of text.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      // A `..` with nothing to pop escapes the repository root, so it can never
      // name a tracked file. Throw rather than silently normalising it away,
      // which would make an out-of-tree path read as an in-tree one.
      if (segments.length === 0) {
        throw new Error(`path "${path}" escapes the repository root`);
      }
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return segments.join("/");
}

// Reduces a caller's path to the repository-relative form git expects. The
// natural call shape is `path.join(repoRoot, ...)`, which yields an absolute
// path that matches no `ls-tree` entry, so an absolute path inside the
// repository is rebased onto its root and one outside it is refused.
//
// Refusing is the point: returning a value that simply fails to match would be
// reported as "the file is not present at that commit", and a gate reading that
// as "newly added, nothing to compare" would pass without checking anything.
function repoRelativeGitPath(repoRoot, path) {
  const normalized = toGitPath(path);
  const root = toGitPath(resolve(repoRoot));
  if (!isAbsolute(path.split("\\").join("/")) && !hasDriveLetter(normalized)) {
    return normalized;
  }
  const caseInsensitive = process.platform === "win32" || hasDriveLetter(root);
  const comparablePath = caseInsensitive ? normalized.toLowerCase() : normalized;
  const comparableRoot = caseInsensitive ? root.toLowerCase() : root;
  if (comparablePath === comparableRoot) return "";
  const prefix = `${comparableRoot}/`;
  if (!comparablePath.startsWith(prefix)) {
    throw new Error(
      `path "${path}" is outside the repository root "${repoRoot}"`
    );
  }
  return normalized.slice(root.length + 1);
}

function hasDriveLetter(path) {
  return /^[A-Za-z]:\//.test(path);
}

function listFilesAtCommit(repoRoot, commit, path) {
  // `-z` gives NUL-delimited, unquoted names. Without it git C-quotes any path
  // containing non-ASCII bytes, quotes, backslashes or control characters, and
  // the literal comparison below would silently miss it.
  const gitPath = repoRelativeGitPath(repoRoot, path);
  const output = git(
    repoRoot,
    ["ls-tree", "-r", "-z", "--name-only", commit, "--", gitPath],
    { trim: false }
  );
  return output ? output.split("\0").filter(Boolean) : [];
}

/// Returns the file's content at `commit`, or `null` when the file does not
/// exist there. Throws when git itself fails, or when the path cannot name a
/// file in this repository at all, so neither a lookup error nor a malformed
/// path is ever mistaken for an absent file.
function readFileAtCommit(repoRoot, commit, path) {
  const gitPath = repoRelativeGitPath(repoRoot, path);
  if (!listFilesAtCommit(repoRoot, commit, gitPath).includes(gitPath)) {
    return null;
  }
  return git(repoRoot, ["show", `${commit}:${gitPath}`], { trim: false });
}

module.exports = {
  listFilesAtCommit,
  readFileAtCommit,
  repoRelativeGitPath,
  requestedBaseRef,
  resolveBaseCommit,
  toGitPath,
};
