// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Learning-mode UI violation vocabulary.
//!
//! Event 27 reports a category and detail value. UI-operation details use the
//! `JOB_OBJECT_UILIMIT_*` constants from winnt.h; keeping the mapping here gives
//! the actionable ETL analyzer one source of truth for both block and allow
//! traces.

/// The workload attempted an operation requiring the Win32k GUI subsystem.
pub(crate) const CONVERT_TO_GUI: u32 = 1;

/// The workload attempted an operation blocked by a Job UI limit.
pub(crate) const UI_OPERATION: u32 = 2;

const UI_LIMIT_NAMES: &[(u32, &str)] = &[
    (0x0001, "Handles"),
    (0x0002, "ReadClipboard"),
    (0x0004, "WriteClipboard"),
    (0x0008, "SystemParameters"),
    (0x0010, "DisplaySettings"),
    (0x0020, "GlobalAtoms"),
    (0x0040, "Desktop"),
    (0x0080, "ExitWindows"),
    (0x0100, "IME"),
    (0x0200, "Injection"),
];

/// Returns the actionable denial resource for an Event 27 category/detail pair.
///
/// Category zero means no violation and is omitted. Unknown nonzero categories
/// remain diagnostic so a new OS category is visible without being mistaken
/// for a known policy relaxation.
pub(crate) fn resource_name(category: u32, detail: u32) -> Option<String> {
    Some(match category {
        0 => return None,
        CONVERT_TO_GUI => "ConvertToGui".to_string(),
        UI_OPERATION => ui_operation_name(detail)
            .map(str::to_string)
            .unwrap_or_else(|| format!("UiOperation({detail})")),
        _ => format!("Category({category})/Detail({detail})"),
    })
}

fn ui_operation_name(value: u32) -> Option<&'static str> {
    UI_LIMIT_NAMES
        .iter()
        .find_map(|(flag, name)| (*flag == value).then_some(*name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_job_ui_limit_has_a_actionable_resource_name() {
        let expected = [
            (0x0001, "Handles"),
            (0x0002, "ReadClipboard"),
            (0x0004, "WriteClipboard"),
            (0x0008, "SystemParameters"),
            (0x0010, "DisplaySettings"),
            (0x0020, "GlobalAtoms"),
            (0x0040, "Desktop"),
            (0x0080, "ExitWindows"),
            (0x0100, "IME"),
            (0x0200, "Injection"),
        ];

        for (detail, name) in expected {
            assert_eq!(resource_name(UI_OPERATION, detail).as_deref(), Some(name));
        }
    }

    #[test]
    fn unknown_values_remain_diagnostic() {
        assert_eq!(
            resource_name(UI_OPERATION, 0x400).as_deref(),
            Some("UiOperation(1024)")
        );
        assert_eq!(
            resource_name(99, 7).as_deref(),
            Some("Category(99)/Detail(7)")
        );
    }

    #[test]
    fn category_none_is_not_a_denial() {
        assert_eq!(resource_name(0, 0), None);
    }
}
