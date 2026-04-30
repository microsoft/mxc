// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TraceLogging ETW event emission for MXC telemetry.

use tracelogging as tlg;

use super::MXC_PROVIDER;

/// Bounded set of failure categories for error classification.
/// Prevents free-form strings that could contain PII.
#[derive(Debug, Clone, Copy)]
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

/// Sanitize an error message by stripping potential PII (file paths, usernames).
pub fn sanitize_error_message(msg: &str) -> String {
    let mut sanitized = String::with_capacity(msg.len());
    let mut chars = msg.chars().peekable();

    while let Some(c) = chars.next() {
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

        // Detect Unix paths: /home/, /tmp/, /var/, /usr/, /etc/, /root/, /mnt/, /opt/
        if c == '/' {
            let prefixes = [
                "home/", "tmp/", "var/", "usr/", "etc/", "root/", "mnt/", "opt/",
            ];
            let upcoming: String = chars.clone().take(5).collect();
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

    // Truncate to a reasonable length
    if sanitized.len() > 256 {
        sanitized.truncate(256);
        sanitized.push_str("...");
    }

    sanitized
}

/// Data for an MXC.Execution ETW event.
pub struct ExecutionEvent<'a> {
    pub backend: &'a str,
    pub exit_code: i32,
    pub outcome: &'a str,
    pub duration_ms: u64,
    pub init_duration_ms: u64,
    pub version: &'a str,
    pub failure_reason: Option<FailureReason>,
}

/// Log an MXC.Execution ETW event.
pub fn log_execution(event: &ExecutionEvent<'_>) {
    let failure_str = event.failure_reason.map(|r| r.as_str()).unwrap_or("");

    tlg::write_event!(
        MXC_PROVIDER,
        "MXC.Execution",
        level(Informational),
        keyword(0x1),
        str8("mxc.backend", event.backend),
        i32("mxc.exit_code", &event.exit_code),
        str8("mxc.outcome", event.outcome),
        u64("mxc.duration_ms", &event.duration_ms),
        u64("mxc.init_duration_ms", &event.init_duration_ms),
        str8("mxc.version", event.version),
        str8("mxc.failure_reason", failure_str),
    );
}

/// Log an MXC.Error ETW event.
pub fn log_error(backend: &str, error_type: FailureReason, error_message: &str, version: &str) {
    let sanitized = sanitize_error_message(error_message);

    tlg::write_event!(
        MXC_PROVIDER,
        "MXC.Error",
        level(Warning),
        keyword(0x2),
        str8("mxc.backend", backend),
        str8("mxc.error_type", error_type.as_str()),
        str8("mxc.error_message", &sanitized),
        str8("mxc.version", version),
    );
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
}
