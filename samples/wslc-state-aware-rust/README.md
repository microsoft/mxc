# WSLC State-Aware Rust API Sketch

`src\main.rs` is a design-meeting sketch of the desired Rust API. It is not
intended to compile against the current PR.

The sketch shows:

- `provision` taking typed settings and returning a typed result containing
  `sandbox_id`.
- The schema version appearing only during provision.
- `start`, `stop`, and `deprovision` taking only the sandbox ID.
- `exec_attached` taking a command string and typed execution options.
- Automatic cleanup after provisioning.

`src\main-as-pr.rs` preserves the version that reflects the API currently
implemented by PR #1219.
