// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TraceLogging ETW event emission for MXC telemetry.
//!
//! Event-specific data types and emission functions. The actual ETW
//! write is delegated to the `mxc_telemetry` crate, which adds
//! common fields automatically.

/// Bounded set of failure categories for error classification.
/// Prevents free-form strings that could contain PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    ConfigError,
    PolicyError,
    ProcessError,
    Timeout,
    InitError,
    Unknown,
}

impl FailureReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConfigError => "config_error",
            Self::PolicyError => "policy_error",
            Self::ProcessError => "process_error",
            Self::Timeout => "timeout",
            Self::InitError => "init_error",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Sanitize an error message by stripping potential PII (file paths, usernames).
pub fn sanitize_error_message(msg: &str) -> String {
    let mut sanitized = String::with_capacity(msg.len());
    let mut chars = msg.chars().peekable();

    while let Some(c) = chars.next() {
        // Detect UNC paths: \\server\share\...
        // These can leak internal hostnames, share names, and usernames.
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == '\\' {
                    sanitized.push_str("<path>");
                    for ch in chars.by_ref() {
                        if ch.is_whitespace() || ch == '\'' || ch == '"' {
                            sanitized.push(ch);
                            break;
                        }
                    }
                    continue;
                }
            }
        }

        // Detect URL credentials: scheme://user:pass@host
        // Strip everything between :// and @ to prevent credential leaks.
        if c == ':' {
            let upcoming: String = chars.clone().take(2).collect();
            if upcoming == "//" {
                // We already pushed chars up to ':', now look for user:pass@
                sanitized.push(c); // ':'
                chars.next(); // first '/'
                chars.next(); // second '/'
                sanitized.push_str("//");
                // Collect until whitespace/quote/end to inspect for '@'
                let mut url_rest = String::new();
                for ch in chars.by_ref() {
                    if ch.is_whitespace() || ch == '\'' || ch == '"' {
                        // Check if we collected credentials (text before '@')
                        if let Some(at_pos) = url_rest.find('@') {
                            sanitized.push_str("<credentials>@");
                            sanitized.push_str(&url_rest[at_pos + 1..]);
                        } else {
                            sanitized.push_str(&url_rest);
                        }
                        sanitized.push(ch);
                        url_rest.clear();
                        break;
                    }
                    url_rest.push(ch);
                }
                // Handle end-of-string (no trailing whitespace/quote)
                if !url_rest.is_empty() {
                    if let Some(at_pos) = url_rest.find('@') {
                        sanitized.push_str("<credentials>@");
                        sanitized.push_str(&url_rest[at_pos + 1..]);
                    } else {
                        sanitized.push_str(&url_rest);
                    }
                }
                continue;
            }
        }

        // Detect Windows paths: letter followed by :\
        if c.is_ascii_alphabetic() {
            if let Some(&next) = chars.peek() {
                if next == ':' {
                    // Peek further for backslash
                    let rest: String = chars.clone().take(2).collect();
                    if rest.starts_with(":\\") {
                        sanitized.push_str("<path>");
                        // Skip until whitespace or quote
                        for ch in chars.by_ref() {
                            if ch.is_whitespace() || ch == '\'' || ch == '"' {
                                sanitized.push(ch);
                                break;
                            }
                        }
                        continue;
                    }
                }
            }
            sanitized.push(c);
            continue;
        }

        // Detect Unix paths: /home/, /tmp/, /var/, /usr/, /etc/, /root/, /mnt/, /opt/, /Users/
        if c == '/' {
            let prefixes = [
                "home/", "tmp/", "var/", "usr/", "etc/", "root/", "mnt/", "opt/", "Users/",
            ];
            let upcoming: String = chars.clone().take(6).collect();
            if prefixes.iter().any(|p| upcoming.starts_with(p)) {
                sanitized.push_str("<path>");
                // Skip until whitespace or quote
                for ch in chars.by_ref() {
                    if ch.is_whitespace() || ch == '\'' || ch == '"' {
                        sanitized.push(ch);
                        break;
                    }
                }
                continue;
            }
        }

        sanitized.push(c);
    }

    // Cap output at 256 characters total, respecting UTF-8 char boundaries
    // to avoid panics from `String::truncate` on multi-byte characters.
    // Reserve 3 bytes for the "..." suffix so the total never exceeds 256.
    const MAX_LEN: usize = 256;
    const SUFFIX: &str = "...";
    if sanitized.len() > MAX_LEN {
        let limit = MAX_LEN - SUFFIX.len(); // 253
        let mut truncate_at = limit;
        while !sanitized.is_char_boundary(truncate_at) {
            truncate_at -= 1;
        }
        sanitized.truncate(truncate_at);
        sanitized.push_str(SUFFIX);
    }

    sanitized
}

/// Data for an MXC.Execution ETW event.
pub struct ExecutionEvent<'a> {
    pub backend: &'a str,
    pub exit_code: i32,
    pub outcome: &'a str,
    pub duration_ms: u64,
    pub failure_reason: Option<FailureReason>,
}

/// Log an MXC.Execution ETW event.
///
/// Delegates to the `mxc_telemetry` provider which adds common fields
/// (Version, Channel, IsDebugging, UTCReplace_AppSessionGuid).
pub fn log_execution(event: &ExecutionEvent<'_>) {
    let failure_str = event.failure_reason.map(|r| r.as_str()).unwrap_or("");

    mxc_telemetry::log_execution(
        event.backend,
        event.exit_code,
        event.outcome,
        event.duration_ms,
        failure_str,
    );
}

/// Log an MXC.Error ETW event.
///
/// Delegates to the `mxc_telemetry` provider which adds common fields.
pub fn log_error(backend: &str, error_type: FailureReason, error_message: &str) {
    let sanitized = sanitize_error_message(error_message);

    mxc_telemetry::log_error(backend, error_type.as_str(), &sanitized);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_reason_as_str() {
        assert_eq!(FailureReason::ConfigError.as_str(), "config_error");
        assert_eq!(FailureReason::PolicyError.as_str(), "policy_error");
        assert_eq!(FailureReason::ProcessError.as_str(), "process_error");
        assert_eq!(FailureReason::Timeout.as_str(), "timeout");
        assert_eq!(FailureReason::InitError.as_str(), "init_error");
        assert_eq!(FailureReason::Unknown.as_str(), "unknown");
    }

    #[test]
    fn sanitize_strips_windows_paths() {
        let msg = "Failed to read C:\\Users\\alice\\secret\\config.json";
        let result = sanitize_error_message(msg);
        assert!(!result.contains("alice"));
        assert!(!result.contains("secret"));
        assert!(result.contains("<path>"));
    }

    #[test]
    fn sanitize_strips_unix_paths() {
        let msg = "Cannot open /home/bob/project/data.txt";
        let result = sanitize_error_message(msg);
        assert!(!result.contains("bob"));
        assert!(result.contains("<path>"));
    }

    #[test]
    fn sanitize_strips_macos_users_paths() {
        let msg = "Cannot open /Users/alice/Library/config.plist";
        let result = sanitize_error_message(msg);
        assert!(!result.contains("alice"));
        assert!(!result.contains("Library"));
        assert!(result.contains("<path>"));
    }

    #[test]
    fn sanitize_truncates_long_messages() {
        let long_msg = "x".repeat(500);
        let result = sanitize_error_message(&long_msg);
        assert!(result.len() < 300);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn sanitize_preserves_safe_messages() {
        let msg = "Firewall rule creation failed";
        assert_eq!(sanitize_error_message(msg), msg);
    }

    #[test]
    fn sanitize_strips_unc_paths() {
        let msg = r"Access denied to \\fileserver\users$\alice\config.json";
        let result = sanitize_error_message(msg);
        assert!(!result.contains("fileserver"));
        assert!(!result.contains("alice"));
        assert!(result.contains("<path>"));
    }

    #[test]
    fn sanitize_strips_unc_paths_at_end() {
        let msg = r"Failed: \\CORPDC01\share\internal";
        let result = sanitize_error_message(msg);
        assert!(!result.contains("CORPDC01"));
        assert!(!result.contains("internal"));
        assert!(result.contains("<path>"));
    }

    #[test]
    fn sanitize_strips_url_credentials() {
        let msg = "Connection to http://admin:s3cret@proxy.corp.net:8080/api failed";
        let result = sanitize_error_message(msg);
        assert!(!result.contains("admin"));
        assert!(!result.contains("s3cret"));
        assert!(result.contains("<credentials>@"));
        assert!(result.contains("proxy.corp.net"));
    }

    #[test]
    fn sanitize_preserves_url_without_credentials() {
        let msg = "GET https://example.com/api/v1 returned 404";
        let result = sanitize_error_message(msg);
        assert!(result.contains("example.com/api/v1"));
        assert!(!result.contains("<credentials>"));
    }
}
