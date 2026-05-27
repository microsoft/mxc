// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for turning a CLI argv vector back into the single `commandLine`
//! string stored on `CodexRequest`.
//!
//! `script_code` on `CodexRequest` is a single `String`, so when the
//! driver collects trailing CLI args we must serialise them as if the
//! user had written the same value in `process.commandLine`. The direct
//! Windows path uses `CommandLineToArgvW`-compatible quoting; shell-backed
//! paths use the target shell's quoting rules so argv data does not become
//! shell syntax.

use std::error::Error;
use std::fmt;

/// Command-line parser that will consume the rendered command string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandLineContext {
    /// The rendered string is passed directly to a Windows process-creation API.
    WindowsCreateProcess,
    /// The rendered string is appended after `cmd.exe /c`.
    WindowsCommandProcessor,
    /// The rendered string is passed to a POSIX shell as `/bin/sh -c`.
    PosixShell,
}

/// Error returned when argv cannot be safely represented in the requested
/// command-line context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLineError {
    message: String,
}

impl CommandLineError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CommandLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CommandLineError {}

/// Join an argv slice into a command-line string for the parser represented by
/// `context`.
pub fn cmdline_from_argv_for_context(
    argv: &[String],
    context: CommandLineContext,
) -> Result<String, CommandLineError> {
    validate_argv(argv)?;

    let mut out = String::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        match context {
            CommandLineContext::WindowsCreateProcess => {
                append_windows_create_process(&mut out, arg)
            }
            CommandLineContext::WindowsCommandProcessor => append_windows_cmd(&mut out, arg)?,
            CommandLineContext::PosixShell => append_posix_shell(&mut out, arg),
        }
    }
    Ok(out)
}

/// Join an argv slice into a single command-line string using the
/// `CommandLineToArgvW` quoting rules. Tokens with no whitespace or
/// quote characters are emitted verbatim; everything else is wrapped
/// in double quotes with backslash/quote escaping.
pub fn cmdline_from_argv(argv: &[String]) -> String {
    let mut out = String::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        append_windows_create_process(&mut out, arg);
    }
    out
}

fn validate_argv(argv: &[String]) -> Result<(), CommandLineError> {
    if argv.iter().any(|arg| arg.contains('\0')) {
        return Err(CommandLineError::new(
            "CLI command arguments must not contain null bytes",
        ));
    }
    Ok(())
}

fn append_windows_create_process(out: &mut String, arg: &str) {
    append_windows_quoted(out, arg, needs_windows_create_process_quotes);
}

fn append_windows_cmd(out: &mut String, arg: &str) -> Result<(), CommandLineError> {
    if arg.contains('%') || arg.contains('!') {
        return Err(CommandLineError::new(
            "CLI command arguments for cmd.exe-backed sandboxes must not contain '%' or '!'",
        ));
    }
    append_windows_quoted(out, arg, needs_windows_cmd_quotes);
    Ok(())
}

fn append_windows_quoted(out: &mut String, arg: &str, needs_quoting: fn(&str) -> bool) {
    if !needs_quoting(arg) {
        out.push_str(arg);
        return;
    }

    append_quoted_windows_arg(out, arg);
}

fn needs_windows_create_process_quotes(arg: &str) -> bool {
    arg.is_empty()
        || arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '\n' || c == '\x0b' || c == '"')
}

fn needs_windows_cmd_quotes(arg: &str) -> bool {
    needs_windows_create_process_quotes(arg)
        || arg
            .chars()
            .any(|c| matches!(c, '&' | '|' | '<' | '>' | '^' | '(' | ')'))
}

fn append_quoted_windows_arg(out: &mut String, arg: &str) {
    out.push('"');
    let mut backslashes: usize = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Double every preceding backslash, then escape the quote.
                for _ in 0..backslashes * 2 + 1 {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Trailing backslashes inside a quoted block must be doubled so the
    // closing quote isn't escaped.
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('"');
}

fn append_posix_shell(out: &mut String, arg: &str) {
    if is_posix_shell_safe_unquoted(arg) {
        out.push_str(arg);
        return;
    }

    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
}

fn is_posix_shell_safe_unquoted(arg: &str) -> bool {
    !arg.is_empty()
        && arg.bytes().all(|b| {
            matches!(
                b,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'_'
                    | b'@'
                    | b'%'
                    | b'+'
                    | b'='
                    | b':'
                    | b','
                    | b'.'
                    | b'/'
                    | b'-'
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|t| (*t).to_string()).collect()
    }

    #[test]
    fn empty_argv_produces_empty_string() {
        assert_eq!(cmdline_from_argv(&[]), "");
    }

    #[test]
    fn plain_tokens_join_with_single_space() {
        assert_eq!(cmdline_from_argv(&s(&["py", "foo.py"])), "py foo.py");
    }

    #[test]
    fn token_with_space_is_quoted() {
        assert_eq!(
            cmdline_from_argv(&s(&["py", "hello world.py"])),
            "py \"hello world.py\""
        );
    }

    #[test]
    fn token_with_quote_escapes_the_quote() {
        assert_eq!(
            cmdline_from_argv(&s(&["py", "-c", "print(\"hi\")"])),
            "py -c \"print(\\\"hi\\\")\""
        );
    }

    #[test]
    fn empty_token_is_emitted_as_empty_quoted_pair() {
        assert_eq!(cmdline_from_argv(&s(&["py", ""])), "py \"\"");
    }

    #[test]
    fn trailing_backslashes_inside_quotes_are_doubled() {
        // Path "C:\foo bar\" must serialise so the runtime parser sees
        // a single trailing backslash, not an escaped closing quote.
        assert_eq!(
            cmdline_from_argv(&s(&["echo", "C:\\foo bar\\"])),
            "echo \"C:\\foo bar\\\\\""
        );
    }

    #[test]
    fn backslashes_not_before_quote_are_not_doubled() {
        assert_eq!(
            cmdline_from_argv(&s(&["echo", "a\\b c"])),
            "echo \"a\\b c\""
        );
    }

    #[test]
    fn windows_create_process_context_matches_legacy_helper() {
        let argv = s(&["py", "hello world.py", "safe&whoami"]);

        assert_eq!(
            cmdline_from_argv_for_context(&argv, CommandLineContext::WindowsCreateProcess).unwrap(),
            cmdline_from_argv(&argv)
        );
    }

    #[test]
    fn windows_cmd_context_quotes_metacharacters() {
        assert_eq!(
            cmdline_from_argv_for_context(
                &s(&["echo", "safe&whoami"]),
                CommandLineContext::WindowsCommandProcessor
            )
            .unwrap(),
            "echo \"safe&whoami\""
        );
    }

    #[test]
    fn windows_cmd_context_rejects_percent_and_bang_expansion() {
        let percent_err = cmdline_from_argv_for_context(
            &s(&["echo", "%PATH%"]),
            CommandLineContext::WindowsCommandProcessor,
        )
        .unwrap_err();
        let bang_err = cmdline_from_argv_for_context(
            &s(&["echo", "!PATH!"]),
            CommandLineContext::WindowsCommandProcessor,
        )
        .unwrap_err();

        assert!(percent_err.to_string().contains("must not contain"));
        assert!(bang_err.to_string().contains("must not contain"));
    }

    #[test]
    fn posix_shell_context_single_quotes_shell_metacharacters() {
        assert_eq!(
            cmdline_from_argv_for_context(
                &s(&["echo", "safe&whoami"]),
                CommandLineContext::PosixShell
            )
            .unwrap(),
            "echo 'safe&whoami'"
        );
    }

    #[test]
    fn posix_shell_context_escapes_single_quotes() {
        assert_eq!(
            cmdline_from_argv_for_context(&s(&["echo", "can't"]), CommandLineContext::PosixShell)
                .unwrap(),
            "echo 'can'\\''t'"
        );
    }

    #[test]
    fn context_renderer_rejects_null_bytes() {
        let err = cmdline_from_argv_for_context(
            &["echo\0hidden".to_string()],
            CommandLineContext::WindowsCreateProcess,
        )
        .unwrap_err();

        assert!(err.to_string().contains("null bytes"));
    }
}
