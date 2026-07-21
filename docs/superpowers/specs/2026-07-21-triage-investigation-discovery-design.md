# Triage Investigation Discovery Design

## Purpose

Make the maintainer-only `/investigate` command discoverable at the point where
an issue has been successfully routed by automatic triage.

## Behavior

When the Issue Triage workflow applies at least one allowed area label or
assigns at least one owner, its existing public triage comment will append:

> **Maintainers:** Comment `/investigate` to check whether this issue or bug is
> valid against the most current code. Copilot will also produce a report with
> the changes that will be needed. For a small, unambiguous documentation or
> test fix, it may also create one draft PR.

The callout will not appear when triage cannot confidently route the issue and
leaves `Needs-Triage` in place.

## Scope and Safety

This changes only the explanatory content of the Issue Triage comment. It does
not change the triage trigger, roles, label or assignment rules, safe outputs,
or the `/investigate` workflow's permissions and limits.

