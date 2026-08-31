// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Reads the two lists in `src/ffi/mxc_ffi/build.rs` that have to agree: the
// sources csbindgen is told to read, and the sources declared as
// `cargo:rerun-if-changed`. Only text cargo acts on counts, so the reader walks
// Rust's lexical structure once and keeps code and string literals apart:
// a directive written inside a comment never reaches cargo, and one quoted
// inside a string literal is data, not a call.

const PLACEHOLDER = "\u0000";

function isIdentChar(c) {
  return c !== undefined && /\p{ID_Continue}/u.test(c);
}

// Rust reuses `'` for both char literals and lifetimes, so `&'a str` must not
// open a literal that swallows the rest of the file. Only an escape, or a
// single character followed by a closing quote, is a literal.
function charLiteralEnd(text, i) {
  if (text[i + 1] === "\\") {
    for (let j = i + 3; j < text.length && j < i + 12; j++) {
      if (text[j] === "'") return j + 1;
    }
    return -1;
  }
  return text[i + 2] === "'" ? i + 3 : -1;
}

// A raw string is `r`, optionally preceded by `b` or `c`, then N hashes, then a
// quote, and it ends at the first quote followed by the same N hashes.
function rawStringStart(text, i) {
  let j = i;
  if (text[j] === "b" || text[j] === "c") j++;
  if (text[j] !== "r") return null;
  j++;
  let hashes = 0;
  while (text[j] === "#") {
    hashes++;
    j++;
  }
  return text[j] === '"' ? { bodyStart: j + 1, hashes } : null;
}

/**
 * Splits `build.rs` text into a code view and the string literals it contains.
 *
 * The code view has every comment removed and every string literal replaced by
 * a NUL-delimited index, so a pattern matched against it is matched against
 * code alone. Newlines inside comments are preserved so line structure holds.
 */
function tokenize(text) {
  const strings = [];
  let code = "";
  let i = 0;

  while (i < text.length) {
    const c = text[i];

    if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }

    if (c === "/" && text[i + 1] === "*") {
      let depth = 1;
      i += 2;
      while (i < text.length && depth > 0) {
        if (text[i] === "/" && text[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (text[i] === "*" && text[i + 1] === "/") {
          depth--;
          i += 2;
        } else {
          if (text[i] === "\n") code += "\n";
          i++;
        }
      }
      continue;
    }

    const raw = !isIdentChar(text[i - 1]) ? rawStringStart(text, i) : null;
    if (raw) {
      const close = '"' + "#".repeat(raw.hashes);
      const end = text.indexOf(close, raw.bodyStart);
      const bodyEnd = end === -1 ? text.length : end;
      code += `${PLACEHOLDER}${strings.length}${PLACEHOLDER}`;
      strings.push(text.slice(raw.bodyStart, bodyEnd));
      i = end === -1 ? text.length : end + close.length;
      continue;
    }

    if (c === '"') {
      let j = i + 1;
      let value = "";
      while (j < text.length && text[j] !== '"') {
        if (text[j] === "\\") {
          value += text.slice(j, j + 2);
          j += 2;
          continue;
        }
        value += text[j];
        j++;
      }
      code += `${PLACEHOLDER}${strings.length}${PLACEHOLDER}`;
      strings.push(value);
      i = j + 1;
      continue;
    }

    if (c === "'") {
      const end = charLiteralEnd(text, i);
      if (end !== -1) {
        i = end;
        continue;
      }
    }

    code += c;
    i++;
  }

  return { code, strings };
}

const RERUN_CALL = new RegExp(
  `(^|[^\\p{ID_Continue}])println!\\s*\\(\\s*${PLACEHOLDER}(\\d+)${PLACEHOLDER}`,
  "gu"
);
const RERUN_PREFIX = /^cargo::?rerun-if-changed=(.+)$/;
const CSBINDGEN_CALL = /\.input_extern_file\s*\(/g;
const PLACEHOLDER_REF = new RegExp(`${PLACEHOLDER}(\\d+)${PLACEHOLDER}`, "g");

/**
 * Scans `build.rs` text for the csbindgen inputs and the `rerun-if-changed`
 * declarations.
 *
 * `unparseable` holds the opening text of any `.input_extern_file(...)` call
 * whose argument is not a plain string literal, so a live but unrecognised
 * input is reported rather than skipped.
 */
function scanBuildRs(text) {
  const { code, strings } = tokenize(text);

  const declaredInputs = [];
  for (const match of code.matchAll(RERUN_CALL)) {
    const value = strings[Number(match[2])];
    const directive = RERUN_PREFIX.exec(value);
    // A formatted argument names no path this check could compare.
    if (directive && !/[{}]/.test(directive[1])) {
      declaredInputs.push(directive[1].trim());
    }
  }

  // Enumerate every call site, then read each one — rather than matching only
  // the shape we expect. A pattern that skips what it cannot read would let an
  // unrecognised-but-live input pass unnoticed while the literal calls keep the
  // zero-call guard quiet.
  const csbindgenInputs = [];
  const unparseable = [];
  for (const site of code.matchAll(CSBINDGEN_CALL)) {
    const rest = code.slice(site.index + site[0].length);
    const literal = rest.match(
      new RegExp(`^\\s*${PLACEHOLDER}(\\d+)${PLACEHOLDER}\\s*,?\\s*\\)`)
    );
    if (literal) {
      csbindgenInputs.push(strings[Number(literal[1])]);
    } else {
      const shown = rest
        .split("\n")[0]
        .replace(PLACEHOLDER_REF, (_, n) => `"${strings[Number(n)]}"`);
      unparseable.push(shown.trim().slice(0, 60));
    }
  }

  return { csbindgenInputs, unparseable, declaredInputs };
}

module.exports = { scanBuildRs };
