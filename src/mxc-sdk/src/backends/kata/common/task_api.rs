// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The containerd shim v2 Task API (`containerd.task.v2.Task`).
//!
//! Only the messages and calls the Kata backend uses are defined. Field
//! numbers come from containerd's `api/runtime/task/v2/shim.proto`,
//! `api/types/mount.proto`, and Kata's `runtimeoptions.proto`.

use std::time::Duration;

use crate::kata_common::protobuf::{DecodeError, Decoder, Encoder};
use crate::kata_common::ttrpc::{CallError, Client};

/// The service name the shim registers.
pub(crate) const TASK_SERVICE: &str = "containerd.task.v2.Task";

/// `Any.type_url` for the runtime options message. The shim reads only the
/// value, but containerd always sets a type URL.
const RUNTIME_OPTIONS_TYPE_URL: &str = "type.googleapis.com/runtimeoptions.v1.Options";

/// `Any.type_url` containerd uses for the OCI process of an exec request.
const OCI_PROCESS_TYPE_URL: &str = "types.containerd.io/opencontainers/runtime-spec/1/Process";

/// SIGKILL, the only signal the backend sends.
pub(crate) const SIGKILL: u32 = 9;

/// How long a call that creates or starts the sandbox may take. Booting a VM
/// on a loaded host is slow, so this is generous.
const BOOT_TIMEOUT: Duration = Duration::from_secs(180);
/// How long the other calls may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// `google.protobuf.Any`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Any {
    pub(crate) type_url: String,
    pub(crate) value: Vec<u8>,
}

impl Any {
    fn encode(&self) -> Encoder {
        let mut e = Encoder::new();
        e.string(1, &self.type_url).bytes(2, &self.value);
        e
    }
}

/// `containerd.types.Mount`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mount {
    pub(crate) kind: String,
    pub(crate) source: String,
    pub(crate) options: Vec<String>,
}

impl Mount {
    fn encode(&self) -> Encoder {
        let mut e = Encoder::new();
        e.string(1, &self.kind).string(2, &self.source);
        for option in &self.options {
            e.repeated_string(4, option);
        }
        e
    }
}

/// `runtimeoptions.v1.Options`: tells the shim which Kata configuration file
/// to load, and so which hypervisor to run.
pub(crate) fn runtime_options(config_path: &str) -> Any {
    let mut e = Encoder::new();
    e.string(2, config_path);
    Any {
        type_url: RUNTIME_OPTIONS_TYPE_URL.to_string(),
        value: e.finish(),
    }
}

/// The OCI process an exec request runs, as the JSON containerd sends.
pub(crate) fn oci_process(json: Vec<u8>) -> Any {
    Any {
        type_url: OCI_PROCESS_TYPE_URL.to_string(),
        value: json,
    }
}

/// Paths of the FIFOs the shim opens for a process's standard streams. An
/// empty path means the stream is not connected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StdioPaths {
    pub(crate) stdin: String,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// `CreateTaskRequest`.
#[derive(Debug, Clone)]
pub(crate) struct CreateRequest {
    pub(crate) id: String,
    pub(crate) bundle: String,
    pub(crate) rootfs: Vec<Mount>,
    pub(crate) stdio: StdioPaths,
    pub(crate) options: Option<Any>,
}

impl CreateRequest {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.string(1, &self.id).string(2, &self.bundle);
        for mount in &self.rootfs {
            e.message(3, &mount.encode());
        }
        e.string(5, &self.stdio.stdin)
            .string(6, &self.stdio.stdout)
            .string(7, &self.stdio.stderr);
        if let Some(options) = &self.options {
            e.message(10, &options.encode());
        }
        e.finish()
    }
}

/// `ExecProcessRequest`.
#[derive(Debug, Clone)]
pub(crate) struct ExecRequest {
    pub(crate) id: String,
    pub(crate) exec_id: String,
    pub(crate) stdio: StdioPaths,
    pub(crate) spec: Any,
}

impl ExecRequest {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.string(1, &self.id)
            .string(2, &self.exec_id)
            .string(4, &self.stdio.stdin)
            .string(5, &self.stdio.stdout)
            .string(6, &self.stdio.stderr)
            .message(7, &self.spec.encode());
        e.finish()
    }
}

/// Encodes a request that names a task and optionally one of its processes:
/// `StartRequest`, `DeleteRequest`, `WaitRequest`, `StateRequest`.
fn process_ref(id: &str, exec_id: &str) -> Vec<u8> {
    let mut e = Encoder::new();
    e.string(1, id).string(2, exec_id);
    e.finish()
}

fn kill_request(id: &str, exec_id: &str, signal: u32, all: bool) -> Vec<u8> {
    let mut e = Encoder::new();
    e.string(1, id)
        .string(2, exec_id)
        .uint(3, u64::from(signal))
        .boolean(4, all);
    e.finish()
}

fn close_io_request(id: &str, exec_id: &str, stdin: bool) -> Vec<u8> {
    let mut e = Encoder::new();
    e.string(1, id).string(2, exec_id).boolean(3, stdin);
    e.finish()
}

fn shutdown_request(id: &str, now: bool) -> Vec<u8> {
    let mut e = Encoder::new();
    e.string(1, id).boolean(2, now);
    e.finish()
}

/// A decoded `Timestamp` is not needed; replies are reduced to the fields the
/// backend reads.
fn first_varint(buf: &[u8], number: u32) -> Result<u64, DecodeError> {
    for field in Decoder::new(buf) {
        let field = field?;
        if field.number == number {
            return field.varint();
        }
    }
    Ok(0)
}

/// What `Delete` reports about a process that has been removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeleteReply {
    pub(crate) pid: u32,
    pub(crate) exit_status: u32,
}

/// Typed calls to one shim.
#[derive(Debug, Clone)]
pub(crate) struct TaskClient {
    client: Client,
}

impl TaskClient {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }

    fn call(
        &self,
        method: &str,
        payload: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, CallError> {
        self.client.call(TASK_SERVICE, method, payload, timeout)
    }

    /// Creates the task. This is when the shim boots the VM and creates the
    /// container; the init process does not run until [`TaskClient::start`].
    pub(crate) fn create(&self, request: &CreateRequest) -> Result<u32, CallError> {
        let reply = self.call("Create", &request.encode(), Some(BOOT_TIMEOUT))?;
        Ok(first_varint(&reply, 1)? as u32)
    }

    /// Starts the init process (empty `exec_id`) or a prepared exec process.
    pub(crate) fn start(&self, id: &str, exec_id: &str) -> Result<u32, CallError> {
        let reply = self.call("Start", &process_ref(id, exec_id), Some(BOOT_TIMEOUT))?;
        Ok(first_varint(&reply, 1)? as u32)
    }

    /// Prepares an extra process in a running task. Call [`TaskClient::start`]
    /// with the same `exec_id` to run it.
    pub(crate) fn exec(&self, request: &ExecRequest) -> Result<(), CallError> {
        self.call("Exec", &request.encode(), Some(CALL_TIMEOUT))
            .map(drop)
    }

    /// Blocks until the process exits and returns its exit status. A process
    /// killed by signal N reports 128 + N.
    pub(crate) fn wait(&self, id: &str, exec_id: &str) -> Result<u32, CallError> {
        let reply = self.call("Wait", &process_ref(id, exec_id), None)?;
        Ok(first_varint(&reply, 1)? as u32)
    }

    pub(crate) fn kill(
        &self,
        id: &str,
        exec_id: &str,
        signal: u32,
        all: bool,
    ) -> Result<(), CallError> {
        self.call(
            "Kill",
            &kill_request(id, exec_id, signal, all),
            Some(CALL_TIMEOUT),
        )
        .map(drop)
    }

    /// Tells the shim to stop forwarding stdin, which delivers EOF to the
    /// process. The shim does not do this when the stdin FIFO is closed.
    pub(crate) fn close_stdin(&self, id: &str, exec_id: &str) -> Result<(), CallError> {
        self.call(
            "CloseIO",
            &close_io_request(id, exec_id, true),
            Some(CALL_TIMEOUT),
        )
        .map(drop)
    }

    /// Removes a stopped process or task.
    pub(crate) fn delete(&self, id: &str, exec_id: &str) -> Result<DeleteReply, CallError> {
        let reply = self.call("Delete", &process_ref(id, exec_id), Some(CALL_TIMEOUT))?;
        let mut out = DeleteReply {
            pid: 0,
            exit_status: 0,
        };
        for field in Decoder::new(&reply) {
            let field = field?;
            match field.number {
                1 => out.pid = field.varint()? as u32,
                2 => out.exit_status = field.varint()? as u32,
                _ => {}
            }
        }
        Ok(out)
    }

    /// Asks the shim to exit. With `now` it stops the VM without waiting for
    /// containers to finish.
    pub(crate) fn shutdown(&self, id: &str, now: bool) -> Result<(), CallError> {
        self.call("Shutdown", &shutdown_request(id, now), Some(CALL_TIMEOUT))
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // The expected bytes below were produced by `buf convert` from containerd's
    // own `shim.proto` and `mount.proto`, so they check the field numbers
    // against the protocol definition rather than against this encoder.

    /// `CreateTaskRequest{id:"abc", bundle:"/run/x/bundle",
    /// rootfs:[{type:"overlay", source:"overlay", options:["lowerdir=/a",
    /// "upperdir=/b"]}], stdin:"/run/i", stdout:"/run/o", stderr:"/run/e",
    /// options:Any{type_url:"t", value:"\n\x03foo"}}`
    const GOLDEN_CREATE: &str = "0a03616263120d2f72756e2f782f62756e646c65\
        1a2c0a076f7665726c617912076f7665726c6179220b6c6f7765726469723d2f61\
        220b75707065726469723d2f622a062f72756e2f6932062f72756e2f6f3a062f72756e2f65\
        520a0a017412050a03666f6f";

    #[test]
    fn create_matches_the_reference_encoding() {
        let request = CreateRequest {
            id: "abc".into(),
            bundle: "/run/x/bundle".into(),
            rootfs: vec![Mount {
                kind: "overlay".into(),
                source: "overlay".into(),
                options: vec!["lowerdir=/a".into(), "upperdir=/b".into()],
            }],
            stdio: StdioPaths {
                stdin: "/run/i".into(),
                stdout: "/run/o".into(),
                stderr: "/run/e".into(),
            },
            options: Some(Any {
                type_url: "t".into(),
                value: b"\n\x03foo".to_vec(),
            }),
        };
        assert_eq!(request.encode(), unhex(GOLDEN_CREATE));
    }

    /// `ExecProcessRequest{id:"abc", exec_id:"e1", stdin:"/i", stdout:"/o",
    /// stderr:"/e", spec:Any{type_url:"u", value:"{}"}}`
    const GOLDEN_EXEC: &str = "0a036162631202653122022f692a022f6f32022f653a070a017512027b7d";

    #[test]
    fn exec_matches_the_reference_encoding() {
        let request = ExecRequest {
            id: "abc".into(),
            exec_id: "e1".into(),
            stdio: StdioPaths {
                stdin: "/i".into(),
                stdout: "/o".into(),
                stderr: "/e".into(),
            },
            spec: Any {
                type_url: "u".into(),
                value: b"{}".to_vec(),
            },
        };
        assert_eq!(request.encode(), unhex(GOLDEN_EXEC));
    }

    #[test]
    fn small_requests_match_the_reference_encoding() {
        // KillRequest{id:"abc", exec_id:"e1", signal:9, all:true}
        assert_eq!(
            kill_request("abc", "e1", 9, true),
            unhex("0a036162631202653118092001")
        );
        // CloseIORequest{id:"abc", exec_id:"e1", stdin:true}
        assert_eq!(
            close_io_request("abc", "e1", true),
            unhex("0a03616263120265311801")
        );
        // ShutdownRequest{id:"abc", now:true}
        assert_eq!(shutdown_request("abc", true), unhex("0a036162631001"));
        // WaitRequest for the init process omits the empty exec id.
        assert_eq!(process_ref("abc", ""), unhex("0a03616263"));
    }

    #[test]
    fn runtime_options_carry_the_config_path_in_field_two() {
        // runtimeoptions.v1.Options{config_path:"/c.toml"}
        let any = runtime_options("/c.toml");
        assert_eq!(any.value, unhex("12072f632e746f6d6c"));
        assert!(any.type_url.ends_with("runtimeoptions.v1.Options"));
    }

    #[test]
    fn replies_are_decoded_from_the_reference_encoding() {
        // WaitResponse{exit_status:137, exited_at:{seconds:1700000000, nanos:5}}
        assert_eq!(
            first_varint(&unhex("08890112080880e2cfaa061005"), 1).unwrap(),
            137
        );
        // CreateTaskResponse{pid:1234}
        assert_eq!(first_varint(&unhex("08d209"), 1).unwrap(), 1234);
        // An empty reply decodes as the proto3 default.
        assert_eq!(first_varint(&[], 1).unwrap(), 0);
    }

    #[test]
    fn unknown_reply_fields_are_skipped() {
        // field 7 (string) then field 1 varint
        let reply = unhex("3a03616263 0807");
        assert_eq!(first_varint(&reply, 1).unwrap(), 7);
    }
}
