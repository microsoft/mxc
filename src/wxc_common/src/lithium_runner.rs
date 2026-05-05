// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `LithiumScriptRunner` — delegates sandbox execution to the remote Lithium service.
//!
//! The Lithium API (see the OpenAPI spec at `docs/lithium-api.yaml`) manages
//! sandboxes remotely: a `POST` to `/partners/{partnerId}/pools/{poolId}/sandboxes`
//! checks out a sandbox and returns its `sandboxId`, `toolUri`, lifecycle state,
//! etc. A matching `DELETE` terminates it.
//!
//! Workload execution assumes the sandbox image exposes an in-VM HTTP command
//! runner — see `examples/install_nginx_sandbox.sh` (the test image used by
//! `examples/15_lithium_agent_fleet.json`), which publishes a runner at
//! `http://<sandbox>/8003/run` accepting `{command, timeout}` JSON and
//! returning `{returncode, stdout, stderr}`. The endpoint path is configurable
//! via `LithiumConfig::command_runner_path`.
//!
//! The bearer token required by the service is read from the environment
//! variable named by `LithiumConfig::management_token_env_var` (default
//! `MXC_LITHIUM_MANAGEMENT_TOKEN`) — never from the JSON config.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::logger::Logger;
use crate::models::{CodexRequest, LithiumConfig, ScriptResponse};
use crate::script_runner::ScriptRunner;

/// Total HTTP attempts (initial call + retries) for transient 503 responses.
const RETRY_MAX_ATTEMPTS: u32 = 3;
/// Backoff for the first retry. Doubles on each subsequent retry.
const RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// Subset of the Lithium `CheckoutResponse` schema that we care about.
///
/// The real response has many more fields (`tags`, `volumes`, `owner`, ...);
/// we only deserialize what the runner needs for execution, logging, and
/// teardown. `ports[]` carries the server-set `proxyUri` for each port we
/// reserved in the checkout — this is the address we POST workloads to.
#[derive(Debug, Deserialize, Serialize)]
struct CheckoutResponse {
    #[serde(rename = "sandboxId")]
    sandbox_id: String,
    #[serde(rename = "poolId")]
    pool_id: String,
    #[serde(rename = "sandboxName")]
    sandbox_name: String,
    state: String,
    #[serde(rename = "toolUri")]
    tool_uri: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    #[serde(default)]
    ports: Vec<CheckoutPort>,
}

/// One entry in `CheckoutResponse.ports[]`. We only need `port` (to match
/// against our reservation) and `proxyUri` (to POST workloads to). Other
/// fields (policy, allow, protocol) round-trip through the response but the
/// runner doesn't act on them.
#[derive(Debug, Deserialize, Serialize)]
struct CheckoutPort {
    port: u16,
    #[serde(rename = "proxyUri")]
    proxy_uri: Option<String>,
}

/// Runner that drives a sandbox through the Lithium HTTP API.
pub struct LithiumScriptRunner {
    config: LithiumConfig,
}

impl LithiumScriptRunner {
    pub fn new(config: &LithiumConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Validate that the required config fields are populated.
    fn validate(&self) -> Result<(), String> {
        let required = [
            ("apiEndpoint", &self.config.api_endpoint),
            ("partnerId", &self.config.partner_id),
            ("poolId", &self.config.pool_id),
            ("imageId", &self.config.image_id),
            ("shapeName", &self.config.shape_name),
        ];
        for (name, value) in required {
            if value.is_empty() {
                return Err(format!(
                    "experimental.lithium.{} is required but was empty",
                    name
                ));
            }
        }
        if !(1..=86400).contains(&self.config.max_idle_in_seconds) {
            return Err("experimental.lithium.maxIdleInSeconds must be 1..=86400".to_string());
        }
        if !(1..=86400).contains(&self.config.max_lifetime_in_seconds) {
            return Err("experimental.lithium.maxLifetimeInSeconds must be 1..=86400".to_string());
        }
        Ok(())
    }

    /// Read the bearer token from the configured environment variable.
    fn load_token(&self) -> Result<String, String> {
        let var = &self.config.management_token_env_var;
        match std::env::var(var) {
            Ok(v) if !v.is_empty() => Ok(v),
            Ok(_) => Err(format!("environment variable '{}' is empty", var)),
            Err(_) => Err(format!(
                "environment variable '{}' is not set (required for Lithium bearer auth)",
                var
            )),
        }
    }

    /// Read the bearer token used to authenticate against the in-sandbox
    /// proxy host (audience differs from the management API in `test`; same
    /// as management in `int`). Falls back to the management token when the
    /// proxy env var is unset, with a logger note so a single-audience
    /// environment continues to work transparently.
    fn load_proxy_token(&self, fallback: &str, logger: &mut Logger) -> String {
        let var = &self.config.proxy_token_env_var;
        match std::env::var(var) {
            Ok(v) if !v.is_empty() => {
                logger.log_line(&format!(
                    "proxy auth: using token from {} (length {})",
                    var,
                    v.len()
                ));
                v
            }
            _ => {
                logger.log_line(&format!(
                    "proxy auth: env {} not set; falling back to management token. \
                     This works for environments where the proxy and management API share an AAD audience (e.g. 'int'), \
                     but the 'test' environment expects a separate NodeProxy token (api://w365a-svc-nodeproxy-test/.default).",
                    var
                ));
                fallback.to_string()
            }
        }
    }

    fn build_agent(&self) -> ureq::Agent {
        let timeout = Duration::from_millis(self.config.request_timeout_ms as u64);
        ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .build()
    }

    /// Agent for the in-sandbox command-runner call. Uses a longer read
    /// timeout because the call blocks until the user's command finishes.
    fn build_workload_agent(&self) -> ureq::Agent {
        let connect_timeout = Duration::from_millis(self.config.request_timeout_ms as u64);
        let read_timeout = Duration::from_millis(self.config.command_runner_timeout_ms as u64);
        ureq::AgentBuilder::new()
            .timeout_connect(connect_timeout)
            .timeout_read(read_timeout)
            .timeout_write(connect_timeout)
            .build()
    }

    /// Construct the URL for the in-sandbox command-runner endpoint by joining
    /// the trimmed `tool_uri` with the configured runner path. Both halves are
    /// trimmed/normalized so we don't emit `//` or drop the leading `/`.
    fn command_runner_url(&self, tool_uri: &str) -> String {
        let base = tool_uri.trim_end_matches('/');
        let path = if self.config.command_runner_path.starts_with('/') {
            self.config.command_runner_path.clone()
        } else {
            format!("/{}", self.config.command_runner_path)
        };
        format!("{}{}", base, path)
    }

    /// Build the JSON body POSTed to the in-sandbox command runner.
    fn build_run_body(&self, request: &CodexRequest) -> serde_json::Value {
        let mut body = json!({ "command": request.script_code });
        // The user's per-script timeout is in seconds; pass it through if
        // non-zero so the runner can enforce it locally and respond with a
        // 504 instead of letting the HTTP read time out.
        if request.script_timeout > 0 {
            body["timeout"] = json!(request.script_timeout);
        }
        if !request.working_directory.is_empty() {
            body["cwd"] = json!(request.working_directory);
        }
        body
    }

    fn sandboxes_url(&self) -> String {
        format!(
            "{}/partners/{}/pools/{}/sandboxes",
            self.config.api_endpoint.trim_end_matches('/'),
            self.config.partner_id,
            self.config.pool_id,
        )
    }

    fn sandbox_url(&self, sandbox_id: &str) -> String {
        format!("{}/{}", self.sandboxes_url(), sandbox_id)
    }

    /// Build the `CheckoutRequest` body per the OpenAPI spec.
    fn build_checkout_body(&self, request: &CodexRequest) -> serde_json::Value {
        let sandbox_name = if request.container_id.is_empty() {
            // The service treats sandboxName as an idempotency key (max 64 chars).
            format!("mxc-{}", uuid_like_suffix())
        } else {
            request.container_id.clone()
        };

        let mut body = json!({
            "sandboxName": sandbox_name,
            "imageId": self.config.image_id,
            "shapeName": self.config.shape_name,
            "policies": {
                "maxIdleInSeconds": self.config.max_idle_in_seconds,
                "maxLifetimeInSeconds": self.config.max_lifetime_in_seconds,
            },
        });

        if !self.config.ports.is_empty() {
            body["ports"] = serde_json::to_value(&self.config.ports).unwrap_or_else(|_| json!([]));
        }

        // Carry the requested command line as a tag so it appears alongside
        // the sandbox in the Lithium console (the runner executes it via the
        // in-sandbox command-runner, separately, after checkout returns).
        if !request.script_code.is_empty() {
            body["tags"] = json!({ "commandLine": request.script_code });
        }

        body
    }

    fn checkout(
        &self,
        agent: &ureq::Agent,
        token: &str,
        request: &CodexRequest,
        logger: &mut Logger,
    ) -> Result<CheckoutResponse, String> {
        let url = self.sandboxes_url();
        let body = self.build_checkout_body(request);
        logger.log_line(&format!(
            "POST {} (api-version={}, body={})",
            url,
            self.config.api_version,
            truncate_for_log(&body.to_string(), 1024)
        ));

        let response = with_retry_on_503(RETRY_MAX_ATTEMPTS, RETRY_INITIAL_BACKOFF, || {
            agent
                .post(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .set("api-version", &self.config.api_version)
                .set("Content-Type", "application/json")
                .send_json(body.clone())
                .map_err(Box::new)
        })
        .map_err(|e| format!("POST {} failed: {}", url, format_ureq_err_detailed(*e)))?;

        let status = response.status();
        if status != 201 {
            let body = response.into_string().unwrap_or_default();
            return Err(format!(
                "unexpected status {} from POST {} (expected 201): {}",
                status,
                url,
                truncate_for_log(&body, 1024)
            ));
        }
        // Read the body once so we can include it in a parse error if needed.
        let body_text = response
            .into_string()
            .map_err(|e| format!("read CheckoutResponse body: {}", e))?;
        let parsed: CheckoutResponse = serde_json::from_str(&body_text).map_err(|e| {
            format!(
                "parse CheckoutResponse ({}): {}",
                e,
                truncate_for_log(&body_text, 1024)
            )
        })?;

        // Surface the bits the runner cares about (and that operators ask
        // about when execution fails): sandbox id, state, and per-port proxy
        // URIs. Visible with --debug; not logged in the error path.
        let ports_summary: Vec<String> = parsed
            .ports
            .iter()
            .map(|p| {
                format!(
                    "{}=>{}",
                    p.port,
                    p.proxy_uri.as_deref().unwrap_or("<no proxyUri>")
                )
            })
            .collect();
        logger.log_line(&format!(
            "checkout: sandboxId={} state={} ports=[{}] toolUri={}",
            parsed.sandbox_id,
            parsed.state,
            ports_summary.join(", "),
            parsed.tool_uri.as_deref().unwrap_or("<none>")
        ));

        Ok(parsed)
    }

    fn terminate(&self, agent: &ureq::Agent, token: &str, sandbox_id: &str, logger: &mut Logger) {
        let url = self.sandbox_url(sandbox_id);
        logger.log_line(&format!("DELETE {}", url));

        let result = with_retry_on_503(RETRY_MAX_ATTEMPTS, RETRY_INITIAL_BACKOFF, || {
            agent
                .delete(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .set("api-version", &self.config.api_version)
                .call()
                .map_err(Box::new)
        });
        match result {
            Ok(resp) => {
                logger.log_line(&format!("DELETE succeeded: status {}", resp.status()));
            }
            Err(e) => {
                // Teardown failure is logged but does not flip the exit code —
                // the remote service enforces its own retention TTL.
                logger.log_line(&format!("DELETE failed: {}", short_ureq_err(&e)));
            }
        }
    }

    /// Execute `request.script_code` inside the checked-out sandbox via its
    /// HTTP command-runner endpoint and return stdout/stderr/exit code.
    fn run_workload(
        &self,
        request: &CodexRequest,
        token: &str,
        checkout: &CheckoutResponse,
        logger: &mut Logger,
    ) -> ScriptResponse {
        if request.script_code.is_empty() {
            logger.log_line("process.commandLine is empty — nothing to execute");
            return ScriptResponse {
                exit_code: 0,
                standard_out: String::new(),
                standard_err: String::new(),
                error_message: String::new(),
            };
        }

        // Pick which reserved port we POST through. The example reserves a
        // single HTTPS port (8443); for multi-port configs the first entry
        // wins. Operators wanting different routing should reorder ports.
        let target_port = match self.config.ports.first() {
            Some(p) => p.port,
            None => {
                return ScriptResponse::error(
                    "Lithium config has no ports[] reservations; cannot reach the in-sandbox command runner. Add a port (e.g. {\"port\":8443,\"policy\":\"Owner\",\"protocol\":\"Https\"}).",
                );
            }
        };

        let proxy_uri = match checkout
            .ports
            .iter()
            .find(|p| p.port == target_port)
            .and_then(|p| p.proxy_uri.as_deref())
        {
            Some(uri) if !uri.is_empty() => uri.to_string(),
            _ => {
                return ScriptResponse::error(&format!(
                    "Lithium checkout response did not include a proxyUri for port {}; cannot reach the in-sandbox command runner",
                    target_port
                ));
            }
        };

        let url = self.command_runner_url(&proxy_uri);
        let body = self.build_run_body(request);
        logger.log_line(&format!(
            "command-runner: target_port={} proxy_uri={} url={} body={}",
            target_port,
            proxy_uri,
            url,
            truncate_for_log(&body.to_string(), 1024)
        ));

        let agent = self.build_workload_agent();
        let response = match with_retry_on_503(RETRY_MAX_ATTEMPTS, RETRY_INITIAL_BACKOFF, || {
            agent
                .post(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .set("Content-Type", "application/json")
                .send_json(body.clone())
                .map_err(Box::new)
        }) {
            Ok(resp) => resp,
            Err(e) => {
                return ScriptResponse::error(&format!(
                    "command-runner POST {} failed: {}",
                    url,
                    format_ureq_err_detailed(*e)
                ));
            }
        };

        let status = response.status();
        // Read the body once so we can include it in a parse-error message.
        let body_text = match response.into_string() {
            Ok(s) => s,
            Err(e) => {
                return ScriptResponse::error(&format!(
                    "command-runner read body failed (HTTP {}): {}",
                    status, e
                ));
            }
        };
        let parsed: Result<RunResponse, _> = serde_json::from_str(&body_text);
        match parsed {
            Ok(r) => {
                logger.log_line(&format!(
                    "command-runner returned status={} runner_status={:?} returncode={:?} stdout_len={} stderr_len={}",
                    status,
                    r.status,
                    r.returncode,
                    r.stdout.as_ref().map(|s| s.len()).unwrap_or(0),
                    r.stderr.as_ref().map(|s| s.len()).unwrap_or(0)
                ));
                let exit_code = r.returncode.unwrap_or(match status {
                    200 => 0,
                    504 => 124, // GNU `timeout` convention
                    _ => -1,
                });
                ScriptResponse {
                    exit_code,
                    standard_out: r.stdout.unwrap_or_default(),
                    standard_err: r.stderr.unwrap_or_default(),
                    error_message: if status == 200 {
                        String::new()
                    } else {
                        r.message
                            .unwrap_or_else(|| format!("command-runner HTTP {}", status))
                    },
                }
            }
            Err(e) => ScriptResponse::error(&format!(
                "could not parse command-runner response (HTTP {}): {}: body={}",
                status,
                e,
                truncate_for_log(&body_text, 1024)
            )),
        }
    }
}

/// Shape of the JSON returned by the in-sandbox command runner. Every field
/// is optional — the runner emits different keys for `completed`, `timeout`,
/// and `error` outcomes.
#[derive(Debug, Deserialize)]
struct RunResponse {
    status: Option<String>,
    returncode: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    message: Option<String>,
}

impl ScriptRunner for LithiumScriptRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        if let Err(e) = self.validate() {
            return ScriptResponse::error(&e);
        }

        let token = match self.load_token() {
            Ok(t) => t,
            Err(e) => return ScriptResponse::error(&e),
        };

        let agent = self.build_agent();

        let checkout = match self.checkout(&agent, &token, request, logger) {
            Ok(c) => c,
            Err(e) => return ScriptResponse::error(&format!("Lithium checkout failed: {}", e)),
        };
        logger.log_line(&format!("Lithium sandbox created: {}", checkout.sandbox_id));

        let proxy_token = self.load_proxy_token(&token, logger);
        let response = self.run_workload(request, &proxy_token, &checkout, logger);

        if request.lifecycle.destroy_on_exit {
            self.terminate(&agent, &token, &checkout.sandbox_id, logger);
        } else {
            logger.log_line(&format!(
                "lifecycle.destroyOnExit is false — leaving sandbox {} running",
                checkout.sandbox_id
            ));
        }

        response
    }
}

/// Shorten a `ureq::Error` for logging. `ureq::Error::Status` carries the
/// response body which can be large and noisy in logs.
fn short_ureq_err(err: &ureq::Error) -> String {
    match err {
        ureq::Error::Status(code, _) => format!("HTTP {}", code),
        ureq::Error::Transport(t) => format!("transport: {}", t),
    }
}

/// Format a `ureq::Error` for inclusion in user-facing error messages.
/// Inlines the response body for `Status` errors (truncated at 1 KiB) — the
/// body is usually where the actionable diagnostic lives. Consumes the error
/// because reading the body consumes the response.
fn format_ureq_err_detailed(err: ureq::Error) -> String {
    match err {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            let body_for_msg = if body.is_empty() {
                "<empty body>".to_string()
            } else if body.len() > 1024 {
                format!(
                    "{}... [truncated, {} bytes total]",
                    &body[..1024],
                    body.len()
                )
            } else {
                body
            };
            format!("HTTP {}: {}", code, body_for_msg)
        }
        ureq::Error::Transport(t) => format!("transport: {}", t),
    }
}

/// Truncate a string for inclusion in a log/error message. Used when we want
/// to surface a response body but keep messages bounded.
fn truncate_for_log(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}... [truncated, {} bytes total]", &s[..max], s.len())
    }
}

/// Run `f`, retrying on HTTP 503 responses with exponential backoff. Other
/// statuses (including 2xx success and other 4xx/5xx errors) are returned
/// immediately. Transport errors are also returned immediately — connection
/// failures usually mean the host is down or unreachable, not transiently
/// overloaded, so retrying them tends to mask configuration mistakes.
fn with_retry_on_503<T, F>(
    max_attempts: u32,
    initial_backoff: Duration,
    mut f: F,
) -> Result<T, Box<ureq::Error>>
where
    F: FnMut() -> Result<T, Box<ureq::Error>>,
{
    let attempts = max_attempts.max(1);
    for attempt in 0..attempts {
        match f() {
            Err(boxed)
                if attempt + 1 < attempts
                    && matches!(boxed.as_ref(), ureq::Error::Status(503, _)) =>
            {
                let multiplier = 1u32 << attempt.min(5);
                std::thread::sleep(initial_backoff.saturating_mul(multiplier));
                continue;
            }
            other => return other,
        }
    }
    unreachable!("retry loop must exit via the `other` arm on the final attempt")
}

/// Generate a short suffix for use as a fallback `sandboxName` when the
/// caller did not provide `containerId`. This is not a UUID — it just needs
/// to be unique enough within the bounds of the `sandboxName` idempotency
/// key. Derived from the current time in nanoseconds.
fn uuid_like_suffix() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::LifecycleConfig;

    fn sample_config() -> LithiumConfig {
        LithiumConfig {
            api_endpoint: "https://lithium.example.com".to_string(),
            partner_id: "contoso".to_string(),
            pool_id: "pool-a".to_string(),
            image_id: "hello-world:latest".to_string(),
            shape_name: "2c4g".to_string(),
            max_idle_in_seconds: 300,
            max_lifetime_in_seconds: 3600,
            api_version: "1.0".to_string(),
            management_token_env_var: "MXC_LITHIUM_MANAGEMENT_TOKEN_TEST".to_string(),
            proxy_token_env_var: "MXC_LITHIUM_PROXY_TOKEN_TEST".to_string(),
            request_timeout_ms: 30_000,
            command_runner_path: "/8003/run".to_string(),
            command_runner_timeout_ms: 600_000,
            ports: Vec::new(),
        }
    }

    #[test]
    fn validate_rejects_missing_required_fields() {
        let mut config = sample_config();
        config.image_id = String::new();
        let runner = LithiumScriptRunner::new(&config);
        let err = runner.validate().unwrap_err();
        assert!(err.contains("imageId"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_out_of_range_idle() {
        let mut config = sample_config();
        config.max_idle_in_seconds = 0;
        let runner = LithiumScriptRunner::new(&config);
        assert!(runner.validate().is_err());
    }

    #[test]
    fn validate_accepts_populated_config() {
        let runner = LithiumScriptRunner::new(&sample_config());
        assert!(runner.validate().is_ok());
    }

    #[test]
    fn sandboxes_url_strips_trailing_slash() {
        let mut config = sample_config();
        config.api_endpoint = "https://lithium.example.com/".to_string();
        let runner = LithiumScriptRunner::new(&config);
        assert_eq!(
            runner.sandboxes_url(),
            "https://lithium.example.com/partners/contoso/pools/pool-a/sandboxes"
        );
    }

    #[test]
    fn sandbox_url_appends_id() {
        let runner = LithiumScriptRunner::new(&sample_config());
        assert_eq!(
            runner.sandbox_url("sb-123"),
            "https://lithium.example.com/partners/contoso/pools/pool-a/sandboxes/sb-123"
        );
    }

    #[test]
    fn checkout_body_uses_container_id_as_sandbox_name() {
        let runner = LithiumScriptRunner::new(&sample_config());
        let request = CodexRequest {
            container_id: "my-container".to_string(),
            script_code: "echo hello".to_string(),
            lifecycle: LifecycleConfig::default(),
            ..Default::default()
        };

        let body = runner.build_checkout_body(&request);
        assert_eq!(body["sandboxName"], "my-container");
        assert_eq!(body["imageId"], "hello-world:latest");
        assert_eq!(body["shapeName"], "2c4g");
        assert_eq!(body["policies"]["maxIdleInSeconds"], 300);
        assert_eq!(body["tags"]["commandLine"], "echo hello");
    }

    #[test]
    fn checkout_body_includes_ports_when_configured() {
        use crate::models::LithiumPortMapping;
        let mut config = sample_config();
        config.ports = vec![LithiumPortMapping {
            port: 8443,
            policy: "Owner".to_string(),
            protocol: "Https".to_string(),
        }];
        let runner = LithiumScriptRunner::new(&config);
        let body = runner.build_checkout_body(&CodexRequest::default());
        let ports = body.get("ports").expect("ports field present");
        assert!(ports.is_array());
        let entry = &ports[0];
        assert_eq!(entry["port"], 8443);
        assert_eq!(entry["policy"], "Owner");
        assert_eq!(entry["protocol"], "Https");
    }

    #[test]
    fn checkout_body_omits_ports_when_empty() {
        let runner = LithiumScriptRunner::new(&sample_config());
        let body = runner.build_checkout_body(&CodexRequest::default());
        assert!(
            body.get("ports").is_none(),
            "expected no ports field; got: {}",
            body
        );
    }

    #[test]
    fn checkout_body_synthesizes_sandbox_name_when_missing() {
        let runner = LithiumScriptRunner::new(&sample_config());
        let request = CodexRequest::default();
        let body = runner.build_checkout_body(&request);
        let name = body["sandboxName"].as_str().unwrap();
        assert!(name.starts_with("mxc-"));
    }

    #[test]
    fn command_runner_url_joins_tool_uri_and_path() {
        let runner = LithiumScriptRunner::new(&sample_config());
        assert_eq!(
            runner.command_runner_url("http://sb-1.example/"),
            "http://sb-1.example/8003/run"
        );
        assert_eq!(
            runner.command_runner_url("http://sb-1.example"),
            "http://sb-1.example/8003/run"
        );
    }

    #[test]
    fn command_runner_url_matches_real_lithium_proxy_uri_shape() {
        // Verbatim shape from a live Lithium CheckoutResponse: bare URL, no
        // trailing slash, host encodes the sandbox ID and an internal port
        // (which differs from the user-reserved port — that's a Lithium
        // convention, not something we have to translate).
        let runner = LithiumScriptRunner::new(&sample_config());
        let proxy_uri = "https://08fa8c079e3834a992812e82efb7f2c303--8080.sandboxproxy.northcentralus-rc1.us.test.w365lith.azure-test.net";
        assert_eq!(
            runner.command_runner_url(proxy_uri),
            "https://08fa8c079e3834a992812e82efb7f2c303--8080.sandboxproxy.northcentralus-rc1.us.test.w365lith.azure-test.net/8003/run"
        );
    }

    #[test]
    fn command_runner_url_normalizes_missing_leading_slash_in_path() {
        let mut config = sample_config();
        config.command_runner_path = "cmd/run".to_string();
        let runner = LithiumScriptRunner::new(&config);
        assert_eq!(
            runner.command_runner_url("http://sb-1.example"),
            "http://sb-1.example/cmd/run"
        );
    }

    #[test]
    fn build_run_body_carries_command_timeout_and_cwd() {
        let runner = LithiumScriptRunner::new(&sample_config());
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            script_timeout: 45,
            working_directory: "/work".to_string(),
            ..Default::default()
        };
        let body = runner.build_run_body(&request);
        assert_eq!(body["command"], "echo hi");
        assert_eq!(body["timeout"], 45);
        assert_eq!(body["cwd"], "/work");
    }

    #[test]
    fn build_run_body_omits_zero_timeout_and_empty_cwd() {
        let runner = LithiumScriptRunner::new(&sample_config());
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        let body = runner.build_run_body(&request);
        assert_eq!(body["command"], "echo hi");
        assert!(body.get("timeout").is_none() || body["timeout"].is_null());
        assert!(body.get("cwd").is_none() || body["cwd"].is_null());
    }

    fn config_with_port(port: u16) -> LithiumConfig {
        use crate::models::LithiumPortMapping;
        let mut config = sample_config();
        config.ports = vec![LithiumPortMapping {
            port,
            policy: "Owner".to_string(),
            protocol: "Https".to_string(),
        }];
        config
    }

    #[test]
    fn run_workload_returns_error_when_no_ports_configured() {
        let runner = LithiumScriptRunner::new(&sample_config());
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        let checkout = CheckoutResponse {
            sandbox_id: "sb-1".to_string(),
            pool_id: "pool-a".to_string(),
            sandbox_name: "name".to_string(),
            state: "ready".to_string(),
            tool_uri: None,
            expires_at: None,
            ports: Vec::new(),
        };
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        let response = runner.run_workload(&request, "tok", &checkout, &mut logger);
        assert_eq!(response.exit_code, -1);
        assert!(
            response.standard_err.contains("ports[]"),
            "got: {}",
            response.standard_err
        );
    }

    #[test]
    fn run_workload_returns_error_when_proxy_uri_missing_for_port() {
        let runner = LithiumScriptRunner::new(&config_with_port(8443));
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        let checkout = CheckoutResponse {
            sandbox_id: "sb-1".to_string(),
            pool_id: "pool-a".to_string(),
            sandbox_name: "name".to_string(),
            state: "ready".to_string(),
            tool_uri: None,
            expires_at: None,
            // Response has a different port reserved — none for 8443.
            ports: vec![CheckoutPort {
                port: 80,
                proxy_uri: Some("http://other.example".to_string()),
            }],
        };
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        let response = runner.run_workload(&request, "tok", &checkout, &mut logger);
        assert_eq!(response.exit_code, -1);
        assert!(
            response.standard_err.contains("proxyUri") && response.standard_err.contains("8443"),
            "got: {}",
            response.standard_err
        );
    }

    #[test]
    fn run_workload_skips_http_when_command_empty() {
        let runner = LithiumScriptRunner::new(&config_with_port(8443));
        let request = CodexRequest::default();
        let checkout = CheckoutResponse {
            sandbox_id: "sb-1".to_string(),
            pool_id: "pool-a".to_string(),
            sandbox_name: "name".to_string(),
            state: "ready".to_string(),
            tool_uri: None,
            expires_at: None,
            ports: vec![CheckoutPort {
                port: 8443,
                proxy_uri: Some("http://127.0.0.1:1".to_string()),
            }],
        };
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        let response = runner.run_workload(&request, "tok", &checkout, &mut logger);
        assert_eq!(response.exit_code, 0);
        assert!(response.standard_out.is_empty());
        assert!(response.standard_err.is_empty());
    }

    /// Read an HTTP request from the socket far enough that the client can
    /// finish sending it, then write `response` and shut down the write side
    /// gracefully. Without the explicit `shutdown(Write)`, on Windows
    /// `TcpStream::drop` can RST the connection if the receive buffer still
    /// has unread bytes (the request body), which surfaces as
    /// "An existing connection was forcibly closed by the remote host".
    fn serve_one(mut sock: std::net::TcpStream, response: &[u8]) {
        use std::io::{Read, Write};
        let mut buf = [0u8; 4096];
        let mut total = 0usize;
        let mut content_length: Option<usize> = None;
        let mut header_end: Option<usize> = None;
        loop {
            let n = sock.read(&mut buf[total..]).unwrap_or(0);
            if n == 0 {
                break;
            }
            total += n;
            if header_end.is_none() {
                if let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(idx + 4);
                    let headers = std::str::from_utf8(&buf[..idx]).unwrap_or("");
                    for line in headers.split("\r\n") {
                        if let Some(rest) = line
                            .strip_prefix("Content-Length: ")
                            .or_else(|| line.strip_prefix("content-length: "))
                        {
                            content_length = rest.trim().parse().ok();
                        }
                    }
                }
            }
            if let (Some(end), Some(len)) = (header_end, content_length) {
                if total >= end + len {
                    break;
                }
            } else if header_end.is_some() && content_length.is_none() {
                break;
            }
            if total == buf.len() {
                break;
            }
        }
        let _ = sock.write_all(response);
        let _ = sock.shutdown(std::net::Shutdown::Write);
        // Drain any remaining data from the client so the kernel sends FIN
        // rather than RST when the socket drops.
        let _ = sock.read(&mut buf);
    }

    /// End-to-end test of the run_workload happy path: spin up a tiny
    /// single-shot HTTP server that mimics the in-sandbox command runner,
    /// point the runner at it, and verify the response is parsed.
    #[test]
    fn run_workload_parses_command_runner_response() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept");
            let body = r#"{"status":"completed","returncode":0,"stdout":"Agent online\nAgent workload complete\n","stderr":"","duration_seconds":5.0}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            serve_one(sock, response.as_bytes());
        });

        let mut config = config_with_port(8443);
        // Path-only routing for the test server.
        config.command_runner_path = "/run".to_string();
        // Keep timeouts short so a regression doesn't hang the suite.
        config.request_timeout_ms = 5_000;
        config.command_runner_timeout_ms = 5_000;
        let runner = LithiumScriptRunner::new(&config);

        let request = CodexRequest {
            script_code: "echo 'Agent online' && sleep 5 && echo 'Agent workload complete'"
                .to_string(),
            ..Default::default()
        };
        let checkout = CheckoutResponse {
            sandbox_id: "sb-1".to_string(),
            pool_id: "pool-a".to_string(),
            sandbox_name: "name".to_string(),
            state: "ready".to_string(),
            tool_uri: None,
            expires_at: None,
            ports: vec![CheckoutPort {
                port: 8443,
                proxy_uri: Some(format!("http://{}", addr)),
            }],
        };
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        let response = runner.run_workload(&request, "tok", &checkout, &mut logger);
        server.join().expect("server thread");

        assert_eq!(response.exit_code, 0);
        assert!(response.standard_out.contains("Agent online"));
        assert!(response.standard_out.contains("Agent workload complete"));
        assert!(response.standard_err.is_empty());
        assert!(response.error_message.is_empty());
    }

    // ---- retry helper unit tests --------------------------------------

    fn fake_response(status: u16) -> ureq::Response {
        ureq::Response::new(status, "Test", "{}").expect("synthesize ureq response")
    }

    #[test]
    fn retry_helper_returns_first_success_immediately() {
        let calls = std::cell::RefCell::new(0u32);
        let result: Result<ureq::Response, Box<ureq::Error>> =
            with_retry_on_503(3, Duration::ZERO, || {
                *calls.borrow_mut() += 1;
                Ok(fake_response(200))
            });
        assert_eq!(*calls.borrow(), 1);
        assert_eq!(result.unwrap().status(), 200);
    }

    #[test]
    fn retry_helper_retries_on_503_then_succeeds() {
        let calls = std::cell::RefCell::new(0u32);
        let result: Result<ureq::Response, Box<ureq::Error>> =
            with_retry_on_503(3, Duration::ZERO, || {
                let mut n = calls.borrow_mut();
                *n += 1;
                if *n < 3 {
                    Err(Box::new(ureq::Error::Status(503, fake_response(503))))
                } else {
                    Ok(fake_response(200))
                }
            });
        assert_eq!(*calls.borrow(), 3);
        assert_eq!(result.unwrap().status(), 200);
    }

    #[test]
    fn retry_helper_gives_up_after_max_attempts() {
        let calls = std::cell::RefCell::new(0u32);
        let result: Result<ureq::Response, Box<ureq::Error>> =
            with_retry_on_503(3, Duration::ZERO, || {
                *calls.borrow_mut() += 1;
                Err(Box::new(ureq::Error::Status(503, fake_response(503))))
            });
        assert_eq!(*calls.borrow(), 3);
        match result {
            Err(e) if matches!(*e, ureq::Error::Status(503, _)) => {}
            other => panic!("expected 503 after exhausting retries, got {:?}", other),
        }
    }

    #[test]
    fn retry_helper_does_not_retry_other_status_codes() {
        for status in [400u16, 401, 404, 500, 502, 504] {
            let calls = std::cell::RefCell::new(0u32);
            let result: Result<ureq::Response, Box<ureq::Error>> =
                with_retry_on_503(3, Duration::ZERO, || {
                    *calls.borrow_mut() += 1;
                    Err(Box::new(ureq::Error::Status(status, fake_response(status))))
                });
            assert_eq!(*calls.borrow(), 1, "should not retry on HTTP {}", status);
            match result {
                Err(e) if matches!(*e, ureq::Error::Status(s, _) if s == status) => {}
                other => panic!("expected HTTP {}, got {:?}", status, other),
            }
        }
    }

    #[test]
    fn retry_helper_max_attempts_zero_runs_once() {
        let calls = std::cell::RefCell::new(0u32);
        let _: Result<ureq::Response, Box<ureq::Error>> =
            with_retry_on_503(0, Duration::ZERO, || {
                *calls.borrow_mut() += 1;
                Ok(fake_response(200))
            });
        assert_eq!(*calls.borrow(), 1);
    }

    /// End-to-end: TCP listener returns 503 on the first connection and a
    /// valid runner response on the second. Verifies `run_workload` retries
    /// and returns the success body.
    #[test]
    fn run_workload_retries_503_from_command_runner() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (sock, _) = listener.accept().expect("accept");
                let n = counter_clone.fetch_add(1, Ordering::SeqCst);
                let response = if n == 0 {
                    let body = r#"{"status":"unavailable"}"#;
                    format!(
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    let body =
                        r#"{"status":"completed","returncode":0,"stdout":"ok\n","stderr":""}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                serve_one(sock, response.as_bytes());
            }
        });

        let mut config = config_with_port(8443);
        config.command_runner_path = "/run".to_string();
        config.request_timeout_ms = 5_000;
        config.command_runner_timeout_ms = 5_000;
        let runner = LithiumScriptRunner::new(&config);

        let request = CodexRequest {
            script_code: "echo ok".to_string(),
            ..Default::default()
        };
        let checkout = CheckoutResponse {
            sandbox_id: "sb-1".to_string(),
            pool_id: "pool-a".to_string(),
            sandbox_name: "name".to_string(),
            state: "ready".to_string(),
            tool_uri: None,
            expires_at: None,
            ports: vec![CheckoutPort {
                port: 8443,
                proxy_uri: Some(format!("http://{}", addr)),
            }],
        };

        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        let response = runner.run_workload(&request, "tok", &checkout, &mut logger);
        server.join().expect("server thread");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "expected exactly one retry"
        );
        assert_eq!(response.exit_code, 0);
        assert!(response.standard_out.contains("ok"));
        assert!(response.error_message.is_empty());
    }

    #[test]
    fn load_token_errors_when_env_var_missing() {
        let mut config = sample_config();
        config.management_token_env_var =
            "MXC_LITHIUM_MANAGEMENT_TOKEN_DEFINITELY_UNSET_1234".to_string();
        // Ensure the var is not set.
        std::env::remove_var(&config.management_token_env_var);
        let runner = LithiumScriptRunner::new(&config);
        let err = runner.load_token().unwrap_err();
        assert!(err.contains("not set"));
    }
}
