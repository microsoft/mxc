// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::config_deserialize::escape_diagnostic_text;
use crate::models::{
    ContainmentBackend, WorkingDirectoryCompatibility, WorkingDirectoryScope, WorkingDirectoryStyle,
};

pub(crate) fn validate_working_directory(
    value: &str,
    containment: &ContainmentBackend,
    scope: WorkingDirectoryScope,
    compatibility: WorkingDirectoryCompatibility,
) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }

    if value.contains('\0') {
        return Err(format!(
            "Invalid configuration at `process.cwd`: value '{}' must not contain null bytes",
            escape_diagnostic_text(value)
        ));
    }

    let style = style_for(containment, scope);

    if compatibility == WorkingDirectoryCompatibility::LegacyRelativeAllowed
        && !matches!(style, Some(WorkingDirectoryStyle::WslcLocalDrive))
    {
        if matches!(style, Some(WorkingDirectoryStyle::RootedWindows))
            && is_windows_current_drive_rooted(value)
        {
            return Err(format!(
                "Invalid configuration at `process.cwd`: value '{}' is rooted on the \
                 launching process's current drive and is not a portable relative Windows path",
                escape_diagnostic_text(value)
            ));
        }
        return Ok(());
    }

    let Some(style) = style else {
        return Ok(());
    };
    if matches_style(value, style) {
        return Ok(());
    }

    Err(format!(
        "Invalid configuration at `process.cwd`: value '{}' must be {} for the {} backend. \
         Relative or target-incompatible working directories depend on the target's ambient \
         working-directory state",
        escape_diagnostic_text(value),
        accepted_form(style),
        containment.wire_name()
    ))
}

pub(crate) const fn style_for(
    containment: &ContainmentBackend,
    scope: WorkingDirectoryScope,
) -> Option<WorkingDirectoryStyle> {
    match (containment, scope) {
        (
            ContainmentBackend::ProcessContainer
            | ContainmentBackend::WindowsSandbox
            | ContainmentBackend::IsolationSession,
            WorkingDirectoryScope::OneShot | WorkingDirectoryScope::Exec,
        ) => Some(WorkingDirectoryStyle::RootedWindows),
        (
            ContainmentBackend::Bubblewrap | ContainmentBackend::Lxc | ContainmentBackend::Seatbelt,
            WorkingDirectoryScope::OneShot | WorkingDirectoryScope::Exec,
        ) => Some(WorkingDirectoryStyle::AbsolutePosix),
        (ContainmentBackend::Wslc, WorkingDirectoryScope::OneShot) => {
            Some(WorkingDirectoryStyle::WslcLocalDrive)
        }
        (ContainmentBackend::Wslc, WorkingDirectoryScope::Exec) => {
            Some(WorkingDirectoryStyle::AbsolutePosix)
        }
        (
            ContainmentBackend::Vm | ContainmentBackend::MicroVm | ContainmentBackend::Hyperlight,
            WorkingDirectoryScope::OneShot | WorkingDirectoryScope::Exec,
        ) => None,
    }
}

fn matches_style(value: &str, style: WorkingDirectoryStyle) -> bool {
    match style {
        WorkingDirectoryStyle::RootedWindows => is_rooted_windows_path(value),
        WorkingDirectoryStyle::AbsolutePosix => is_absolute_posix_path(value),
        WorkingDirectoryStyle::WslcLocalDrive => is_wslc_mappable_windows_path(value),
    }
}

/// Whether `value` is an exact rooted local Windows drive path.
///
/// This predicate is host-independent and deliberately rejects surrounding
/// whitespace, interior NULs, UNC paths, and device namespaces.
pub fn is_rooted_local_windows_drive_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && value.trim() == value
        && !value.contains('\0')
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && is_windows_separator(bytes[2])
}

fn is_rooted_windows_path(value: &str) -> bool {
    value.trim() == value
        && !value.contains('\0')
        && (is_rooted_local_windows_drive_path(value) || is_windows_remote_or_device_path(value))
}

/// Whether `value` is an absolute POSIX path representable as a C string.
pub fn is_absolute_posix_path(value: &str) -> bool {
    value.starts_with('/') && !value.contains('\0')
}

/// Whether one-shot WSLc can map `value` under `/mnt/<drive>` without changing
/// which host path it names.
///
/// Windows clamps `..` at a drive root, while Linux would let `/mnt/c/..`
/// escape to `/mnt`. Reject parent components instead of silently normalizing
/// the caller's explicit cwd.
pub fn is_wslc_mappable_windows_path(value: &str) -> bool {
    is_rooted_local_windows_drive_path(value)
        && !value[3..]
            .split(['\\', '/'])
            .any(|component| component == "..")
}

fn is_windows_remote_or_device_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3 && is_windows_separator(bytes[0]) && is_windows_separator(bytes[1])
}

fn is_windows_current_drive_rooted(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes
        .first()
        .is_some_and(|value| is_windows_separator(*value))
        && bytes
            .get(1)
            .is_none_or(|value| !is_windows_separator(*value))
}

const fn is_windows_separator(value: u8) -> bool {
    matches!(value, b'\\' | b'/')
}

const fn accepted_form(style: WorkingDirectoryStyle) -> &'static str {
    match style {
        WorkingDirectoryStyle::RootedWindows => {
            "a rooted Windows path such as `C:\\work` or `\\\\server\\share`"
        }
        WorkingDirectoryStyle::AbsolutePosix => {
            "an absolute POSIX path beginning with `/`, such as `/work`"
        }
        WorkingDirectoryStyle::WslcLocalDrive => {
            "a rooted local Windows drive path such as `C:\\work` that maps under `/mnt/<drive>`"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rooted_windows_classification_is_host_independent() {
        for accepted in [
            r"C:\work",
            "d:/work",
            r"\\server\share",
            "//server/share",
            r"\\?\C:\work",
            r"\\.\C:\work",
        ] {
            assert!(matches_style(
                accepted,
                WorkingDirectoryStyle::RootedWindows
            ));
        }
        for rejected in [
            "",
            "work",
            r"C:work",
            r"\work",
            "/work",
            r"\\",
            " C:\\work",
            "C:\\work ",
        ] {
            assert!(
                !matches_style(rejected, WorkingDirectoryStyle::RootedWindows),
                "{rejected}"
            );
        }
    }

    #[test]
    fn posix_classification_requires_a_leading_slash() {
        for accepted in ["/", "/work", "/work ", "//server/share"] {
            assert!(matches_style(
                accepted,
                WorkingDirectoryStyle::AbsolutePosix
            ));
        }
        for rejected in ["", "work", "~/work", "~", " /work", r"C:\work"] {
            assert!(
                !matches_style(rejected, WorkingDirectoryStyle::AbsolutePosix),
                "{rejected}"
            );
        }
    }

    #[test]
    fn wslc_one_shot_accepts_only_mappable_windows_paths() {
        for accepted in [r"C:\work", "d:/work"] {
            assert!(validate_working_directory(
                accepted,
                &ContainmentBackend::Wslc,
                WorkingDirectoryScope::OneShot,
                WorkingDirectoryCompatibility::AbsoluteRequired,
            )
            .is_ok());
        }
        for rejected in [
            "/work",
            "work",
            r"C:work",
            r"\\server\share\work",
            r"C:\..\Windows",
            r"C:\work\..\other",
        ] {
            assert!(validate_working_directory(
                rejected,
                &ContainmentBackend::Wslc,
                WorkingDirectoryScope::OneShot,
                WorkingDirectoryCompatibility::AbsoluteRequired,
            )
            .is_err());
        }
    }

    #[test]
    fn backend_scope_table_covers_every_containment_variant() {
        use ContainmentBackend::{
            Bubblewrap, Hyperlight, IsolationSession, Lxc, MicroVm, ProcessContainer, Seatbelt, Vm,
            WindowsSandbox, Wslc,
        };

        for backend in [ProcessContainer, WindowsSandbox, IsolationSession] {
            for scope in [WorkingDirectoryScope::OneShot, WorkingDirectoryScope::Exec] {
                assert_eq!(
                    style_for(&backend, scope),
                    Some(WorkingDirectoryStyle::RootedWindows),
                    "{backend:?} {scope:?}"
                );
                assert!(validate_working_directory(
                    r"C:\work",
                    &backend,
                    scope,
                    WorkingDirectoryCompatibility::AbsoluteRequired,
                )
                .is_ok());
            }
        }

        for backend in [Bubblewrap, Lxc, Seatbelt] {
            for scope in [WorkingDirectoryScope::OneShot, WorkingDirectoryScope::Exec] {
                assert_eq!(
                    style_for(&backend, scope),
                    Some(WorkingDirectoryStyle::AbsolutePosix),
                    "{backend:?} {scope:?}"
                );
                assert!(validate_working_directory(
                    "/work",
                    &backend,
                    scope,
                    WorkingDirectoryCompatibility::AbsoluteRequired,
                )
                .is_ok());
            }
        }

        assert_eq!(
            style_for(&Wslc, WorkingDirectoryScope::OneShot),
            Some(WorkingDirectoryStyle::WslcLocalDrive)
        );
        assert_eq!(
            style_for(&Wslc, WorkingDirectoryScope::Exec),
            Some(WorkingDirectoryStyle::AbsolutePosix)
        );

        for backend in [Vm, MicroVm, Hyperlight] {
            for scope in [WorkingDirectoryScope::OneShot, WorkingDirectoryScope::Exec] {
                assert_eq!(style_for(&backend, scope), None, "{backend:?} {scope:?}");
            }
        }
    }

    #[test]
    fn legacy_compatibility_bypasses_only_relative_path_validation() {
        assert!(validate_working_directory(
            "relative",
            &ContainmentBackend::ProcessContainer,
            WorkingDirectoryScope::OneShot,
            WorkingDirectoryCompatibility::LegacyRelativeAllowed,
        )
        .is_ok());
        assert!(validate_working_directory(
            r"C:work",
            &ContainmentBackend::ProcessContainer,
            WorkingDirectoryScope::OneShot,
            WorkingDirectoryCompatibility::LegacyRelativeAllowed,
        )
        .is_ok());
        assert!(validate_working_directory(
            "bad\0path",
            &ContainmentBackend::ProcessContainer,
            WorkingDirectoryScope::OneShot,
            WorkingDirectoryCompatibility::LegacyRelativeAllowed,
        )
        .is_err());
        for rooted in [r"\\server\share", r"\\?\C:\work", r"\\.\C:\work"] {
            assert!(validate_working_directory(
                rooted,
                &ContainmentBackend::ProcessContainer,
                WorkingDirectoryScope::OneShot,
                WorkingDirectoryCompatibility::LegacyRelativeAllowed,
            )
            .is_ok());
        }
        for rooted in [r"\work", "/work"] {
            assert!(validate_working_directory(
                rooted,
                &ContainmentBackend::ProcessContainer,
                WorkingDirectoryScope::OneShot,
                WorkingDirectoryCompatibility::LegacyRelativeAllowed,
            )
            .is_err());
        }
    }

    #[test]
    fn legacy_compatibility_does_not_bypass_wslc_mapping() {
        assert!(validate_working_directory(
            r"C:\work",
            &ContainmentBackend::Wslc,
            WorkingDirectoryScope::OneShot,
            WorkingDirectoryCompatibility::LegacyRelativeAllowed,
        )
        .is_ok());
        for rejected in ["relative", "/work"] {
            assert!(validate_working_directory(
                rejected,
                &ContainmentBackend::Wslc,
                WorkingDirectoryScope::OneShot,
                WorkingDirectoryCompatibility::LegacyRelativeAllowed,
            )
            .is_err());
        }
    }

    #[test]
    fn diagnostic_escapes_control_and_format_characters() {
        let error = validate_working_directory(
            "relative\n\u{202e}spoof",
            &ContainmentBackend::Lxc,
            WorkingDirectoryScope::OneShot,
            WorkingDirectoryCompatibility::AbsoluteRequired,
        )
        .unwrap_err();
        assert!(error.contains("process.cwd"));
        assert!(error.contains(r"\n"));
        assert!(error.contains(r"\u{202e}"));
        assert!(!error.contains('\n'));
        assert!(!error.contains('\u{202e}'));
    }
}
