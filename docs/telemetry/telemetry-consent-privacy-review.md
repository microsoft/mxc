# Telemetry consent privacy review package

**Status:** Approval pending. Privacy/legal approval is a merge/release gate
for consent resource version 1; this document does not record approval.

## Product and purpose

Microsoft eXecution Container (MXC) is a sandboxed code-execution system.
Optional diagnostic data is used to understand product usage, diagnose bounded
failure categories, and improve reliability.

## Canonical disclosure

Review the exact version 1 `en-US` title, body, action labels, and privacy link
in [`telemetry-consent-design.md`](telemetry-consent-design.md#canonical-consent-resource).
All EXE and SDK surfaces receive that Rust-owned resource and must render every
field verbatim.

## Data sent

- MXC version and channel
- Containment backend
- Run outcome and exit code
- Run duration
- Bounded failure category
- Lifecycle phase
- Random app-session and sandbox-lifecycle correlation identifiers

## Data explicitly excluded

- Command text
- File paths
- Environment variables
- Standard input or output
- Usernames
- Credentials
- Free-form error messages

## Controls

- Collection is Windows-only.
- Telemetry is off unless each run explicitly requests it.
- No consent request, No, dismissal, missing response, malformed state, or any
  error means no collection.
- Only an explicit Yes returned from the presenter invocation that received the
  current canonical resource creates a grant.
- Users can withdraw through MXC telemetry consent controls at any time.
- Administrative policy is a deny-only ceiling and cannot opt a user in.
- Consent and policy are rechecked immediately before every event.
- Legacy or unknown-version grants require explicit re-consent.

## Persistence and retention boundary

MXC stores the user's local decision, prompt resource version, locale, MXC
version, source, and update timestamp in the per-user consent file. This local
record is not telemetry payload. Service-side diagnostic-data retention and
access controls must be confirmed by the receiving Microsoft telemetry system
owner as part of approval.

## Reviewer decisions required

1. Approve or revise resource version 1 wording.
2. Confirm the listed included/excluded data categories.
3. Confirm the Microsoft Privacy Statement link is sufficient.
4. Confirm service-side retention, access, regional, and deletion requirements.
5. Confirm whether additional locale or accessibility requirements apply at
   initial stable release.

Any material wording or collected-field change after approval requires a new
resource version and explicit re-consent.
