// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::{Arc, Mutex};

use aci_edge_sandboxes::{
    Backend, Capabilities, DeprovisionResult, Error, ExecControl, ExecIo, ExecOutcome, ExecRequest,
    ProvisionRequest, ProvisionResult, SandboxId, SandboxSpec, StartResult, StopResult,
};

#[derive(Debug, Clone, Default)]
pub(super) struct Fixture {
    pub events: Arc<Mutex<Vec<&'static str>>>,
    pub fail: Option<&'static str>,
    pub stop_fails: bool,
    pub deprovision_fails: bool,
    pub outcome: Option<ExecOutcome>,
    pub capabilities: Option<Capabilities>,
    pub image: Arc<Mutex<Option<aci_edge_sandboxes::ImageSource>>>,
    pub stdin_piped: Arc<Mutex<Option<bool>>>,
    pub require_stdin_eof: bool,
    pub stdin_reader: Arc<Mutex<Option<aci_edge_sandboxes::InputSource>>>,
    pub stdin_closer: Arc<Mutex<Option<aci_edge_sandboxes::InputCloser>>>,
    pub stop_gate: Option<Arc<CleanupGate>>,
}

#[derive(Debug, Default)]
pub(super) struct CleanupGate {
    pub entered: std::sync::atomic::AtomicBool,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
}

impl CleanupGate {
    pub fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }

    fn wait(&self) {
        self.entered
            .store(true, std::sync::atomic::Ordering::Release);
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
    }
}

impl Fixture {
    pub fn event(&self, stage: &'static str) -> aci_edge_sandboxes::Result<()> {
        self.events.lock().unwrap().push(stage);
        if self.fail == Some(stage) {
            Err(Error::backend_error(format!("injected {stage} failure")))
        } else {
            Ok(())
        }
    }

    pub fn id() -> SandboxId {
        SandboxId::from_token("0123456789abcdef0123456789abcdef").unwrap()
    }

    pub fn supported_capabilities() -> Capabilities {
        let mut capabilities = Capabilities::new("nvx-test");
        capabilities.exec.command_line = true;
        capabilities.exec.stdin = true;
        capabilities.exec.cancel = true;
        capabilities.exec.cwd = true;
        capabilities.exec.env = true;
        capabilities.exec.max_timeout_ms = Some(3_600_000);
        capabilities.spec.image_reference = true;
        capabilities
    }
}

impl Backend for Fixture {
    fn name(&self) -> &str {
        "nvx-test"
    }

    fn capabilities(&self) -> Capabilities {
        self.capabilities
            .clone()
            .unwrap_or_else(Self::supported_capabilities)
    }

    fn probe(&self) -> aci_edge_sandboxes::Result<()> {
        self.event("probe")
    }

    fn validate_provision_with(
        &self,
        _request: &ProvisionRequest,
        _spec: &SandboxSpec,
    ) -> aci_edge_sandboxes::Result<()> {
        self.event("validate_provision")
    }

    fn validate_exec(&self, _request: &ExecRequest) -> aci_edge_sandboxes::Result<()> {
        self.event("validate_exec")
    }

    fn provision(&self, request: &ProvisionRequest) -> aci_edge_sandboxes::Result<ProvisionResult> {
        self.provision_with(request, &SandboxSpec::new())
    }

    fn provision_with(
        &self,
        _request: &ProvisionRequest,
        spec: &SandboxSpec,
    ) -> aci_edge_sandboxes::Result<ProvisionResult> {
        *self.image.lock().unwrap() = spec.image.clone();
        self.event("provision")?;
        Ok(ProvisionResult {
            sandbox_id: Self::id(),
            metadata: None,
        })
    }

    fn start(&self, _id: &SandboxId) -> aci_edge_sandboxes::Result<StartResult> {
        self.event("start")?;
        Ok(StartResult::default())
    }

    fn exec(
        &self,
        _id: &SandboxId,
        _request: &ExecRequest,
        mut io: ExecIo,
    ) -> aci_edge_sandboxes::Result<Box<dyn ExecControl>> {
        *self.stdin_piped.lock().unwrap() = Some(io.stdin.is_some());
        self.event("exec")?;
        io.stdout.write(b"out").unwrap();
        io.stderr.write(b"err").unwrap();
        if self.require_stdin_eof {
            *self.stdin_closer.lock().unwrap() =
                io.stdin.as_ref().map(|stdin| stdin.close_handle());
            *self.stdin_reader.lock().unwrap() = io.stdin.take();
        }
        drop(io);
        Ok(Box::new(self.clone()))
    }

    fn stop(&self, _id: &SandboxId) -> aci_edge_sandboxes::Result<StopResult> {
        self.event("stop")?;
        if let Some(gate) = &self.stop_gate {
            gate.wait();
        }
        if self.stop_fails {
            Err(Error::backend_error("injected stop failure"))
        } else {
            Ok(StopResult::default())
        }
    }

    fn deprovision(&self, _id: &SandboxId) -> aci_edge_sandboxes::Result<DeprovisionResult> {
        self.event("deprovision")?;
        if self.deprovision_fails {
            Err(Error::backend_error("injected deprovision failure"))
        } else {
            Ok(DeprovisionResult::default())
        }
    }
}

impl ExecControl for Fixture {
    fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
        self.event("wait")?;
        if let Some(mut stdin) = self.stdin_reader.lock().unwrap().take() {
            use std::io::Read;
            let mut input = Vec::new();
            stdin
                .read_to_end(&mut input)
                .map_err(|error| Error::backend_error(format!("stdin read failed: {error}")))?;
        }
        Ok(self.outcome.unwrap_or(ExecOutcome::Exited(7)))
    }

    fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
        self.event("cancel")?;
        if let Some(closer) = self.stdin_closer.lock().unwrap().as_ref() {
            closer.close();
        }
        Ok(())
    }
}
