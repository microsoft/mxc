// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `LithiumScriptRunner` — delegates sandbox execution to the remote Lithium service.
//!
//! The Lithium API (see the OpenAPI spec at `docs/lithium-api.yaml`) manages
//! sandboxes remotely: a `POST` to `/partners/{partnerId}/pools/{poolId}/sandboxes`
//! checks out a sandbox and returns its `sandboxId`, `toolUri`, lifecycle state,
//! etc. A matching `DELETE` terminates it.
//!
//! This runner currently implements only the checkout/teardown lifecycle. The
//! sandbox tool API (which would actually execute `process.commandLine` inside
//! the remote sandbox) is not yet specified; once it is, the `run_workload`
//! step below will be filled in (likely via SSH to the address carried by the
//! checkout response).
//!
//! The bearer token required by the service is read from the environment
//! variable named by `LithiumConfig::token_env_var` (default
//! `MXC_LITHIUM_TOKEN`) — never from the JSON config.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::logger::Logger;
use crate::models::{CodexRequest, LithiumConfig, ScriptResponse};
use crate::script_runner::ScriptRunner;

/// Subset of the Lithium `CheckoutResponse` schema that we care about.
///
/// The real response has many more fields (`ports`, `tags`, `volumes`, ...);
/// we only deserialize what the runner needs for logging and teardown.
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
        let var = &self.config.token_env_var;
        match std::env::var(var) {
            Ok(v) if !v.is_empty() => Ok(v),
            Ok(_) => Err(format!("environment variable '{}' is empty", var)),
            Err(_) => Err(format!(
                "environment variable '{}' is not set (required for Lithium bearer auth)",
                var
            )),
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

        // Carry the requested command line as a tag. The tool-API execution
        // path is not yet implemented; this preserves the caller's intent for
        // when the service can consume it.
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
        logger.log_line(&format!("POST {}", url));

        let response = agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("api-version", &self.config.api_version)
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| format!("POST {}: {}", url, short_ureq_err(&e)))?;

        let status = response.status();
        if status != 201 {
            return Err(format!(
                "unexpected status {} from POST {} (expected 201)",
                status, url
            ));
        }
        response
            .into_json::<CheckoutResponse>()
            .map_err(|e| format!("parse CheckoutResponse: {}", e))
    }

    fn terminate(&self, agent: &ureq::Agent, token: &str, sandbox_id: &str, logger: &mut Logger) {
        let url = self.sandbox_url(sandbox_id);
        logger.log_line(&format!("DELETE {}", url));

        match agent
            .delete(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("api-version", &self.config.api_version)
            .call()
        {
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

    /// Placeholder for the sandbox tool-API workload execution step.
    ///
    /// Once the tool API is specified (likely SSH to an address carried by
    /// the checkout response), this method will connect, run
    /// `request.script_code`, and capture stdout/stderr/exit code.
    fn run_workload(
        &self,
        _agent: &ureq::Agent,
        _token: &str,
        checkout: &CheckoutResponse,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let mut out = String::new();
        out.push_str(&format!("sandboxId:   {}\n", checkout.sandbox_id));
        out.push_str(&format!("poolId:      {}\n", checkout.pool_id));
        out.push_str(&format!("sandboxName: {}\n", checkout.sandbox_name));
        out.push_str(&format!("state:       {}\n", checkout.state));
        if let Some(uri) = &checkout.tool_uri {
            out.push_str(&format!("toolUri:     {}\n", uri));
        }
        if let Some(exp) = &checkout.expires_at {
            out.push_str(&format!("expiresAt:   {}\n", exp));
        }
        logger.log_line(
            "Lithium workload execution is not yet implemented — sandbox checked out only.",
        );

        ScriptResponse {
            exit_code: 0,
            standard_out: out,
            standard_err: String::new(),
            error_message: String::new(),
        }
    }
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

        let response = self.run_workload(&agent, &token, &checkout, logger);

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
            token_env_var: "MXC_LITHIUM_TOKEN_TEST".to_string(),
            request_timeout_ms: 30_000,
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
    fn checkout_body_synthesizes_sandbox_name_when_missing() {
        let runner = LithiumScriptRunner::new(&sample_config());
        let request = CodexRequest::default();
        let body = runner.build_checkout_body(&request);
        let name = body["sandboxName"].as_str().unwrap();
        assert!(name.starts_with("mxc-"));
    }

    #[test]
    fn load_token_errors_when_env_var_missing() {
        let mut config = sample_config();
        config.token_env_var = "MXC_LITHIUM_TOKEN_DEFINITELY_UNSET_1234".to_string();
        // Ensure the var is not set.
        std::env::remove_var(&config.token_env_var);
        let runner = LithiumScriptRunner::new(&config);
        let err = runner.load_token().unwrap_err();
        assert!(err.contains("not set"));
    }
}
