// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Repository-local, pinned wrapper around Diplomat's binding generator.

use std::collections::HashMap;
use std::env;
use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

use diplomat_tool::{config::Config, DocsUrlGenerator};

fn main() -> Result<()> {
    let mut arguments = env::args_os();
    let executable = arguments.next().unwrap_or_default();
    let language = argument(&mut arguments, "target language")?;
    let bindings_output = PathBuf::from(argument(&mut arguments, "output directory")?);
    if language != "c" && language != "dotnet" {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "unsupported target language {:?}; expected \"c\" or \"dotnet\"",
                language
            ),
        ));
    }
    let prototype_output = if language == "dotnet" {
        Some(PathBuf::from(argument(
            &mut arguments,
            ".NET prototype output directory",
        )?))
    } else {
        None
    };
    if arguments.next().is_some() {
        return Err(usage(&executable));
    }

    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .ok_or_else(|| Error::other("unable to locate the Rust workspace root"))?;
    let entry = src_root.join(r"ffi\mxc_ffi\src\diplomat.rs");
    let config_path = src_root.join(r"ffi\mxc_ffi\diplomat.toml");

    let mut config = Config::default();
    config.read_file(&config_path).map_err(Error::other)?;
    let docs_url_generator = DocsUrlGenerator::with_base_urls(None, HashMap::new());
    diplomat_tool::gen(
        &entry,
        &language,
        &bindings_output,
        &docs_url_generator,
        config,
        false,
    )?;

    if let Some(prototype_output) = prototype_output {
        generate_dotnet_prototype(&bindings_output, &prototype_output)?;
    }

    Ok(())
}

/// Emit the public prototype facade from Diplomat's generated static API.
///
/// The facade intentionally reads `MxcDiplomat.cs` instead of maintaining a
/// second operation list. A changed bridge signature either flows through to
/// the public wrapper or causes generation to fail before consumers compile.
fn generate_dotnet_prototype(bindings_output: &Path, prototype_output: &Path) -> Result<()> {
    let generated_api = bindings_output.join("MxcDiplomat.cs");
    let source = std::fs::read_to_string(&generated_api)?;
    let static_methods = parse_public_static_methods(&source)?;
    let facade = render_dotnet_prototype(&static_methods)?;

    std::fs::create_dir_all(prototype_output)?;
    std::fs::write(prototype_output.join("MxcDiplomatPrototype.g.cs"), facade)?;

    let stream_types = [
        "MxcDiplomatSandbox",
        "MxcDiplomatInputStream",
        "MxcDiplomatOutputStream",
    ];
    let instance_methods = stream_types
        .iter()
        .map(|type_name| {
            let source = std::fs::read_to_string(bindings_output.join(format!("{type_name}.cs")))?;
            let methods = parse_public_instance_methods(&source)?;
            Ok(methods
                .into_iter()
                .map(|method| (type_name.to_string(), method))
                .collect::<Vec<_>>())
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let extensions = render_dotnet_async_extensions(&instance_methods)?;
    std::fs::write(
        prototype_output.join("MxcDiplomatPrototypeExtensions.g.cs"),
        extensions,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicStaticMethod {
    return_type: String,
    name: String,
    parameters: String,
    arguments: String,
}

fn parse_public_static_methods(source: &str) -> Result<Vec<PublicStaticMethod>> {
    const PREFIX: &str = "public static ";

    let methods = source
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix(PREFIX))
        .map(parse_public_method_signature)
        .collect::<Result<Vec<_>>>()?;

    if methods.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Diplomat generated MxcDiplomat.cs contains no public static methods",
        ));
    }
    if !methods.iter().any(|method| method.name == "Run") {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Diplomat generated MxcDiplomat.cs contains no public static Run method",
        ));
    }
    Ok(methods)
}

fn parse_public_instance_methods(source: &str) -> Result<Vec<PublicStaticMethod>> {
    const PREFIX: &str = "public ";

    source
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix(PREFIX))
        .filter(|signature| !signature.starts_with("static "))
        .filter(|signature| signature.contains('('))
        .map(parse_public_method_signature)
        .collect()
}

fn parse_public_method_signature(signature: &str) -> Result<PublicStaticMethod> {
    let signature = signature.trim_end();
    let (name_and_return, parameters) = signature.split_once('(').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("could not parse generated static method signature: {signature}"),
        )
    })?;
    let parameters = parameters.strip_suffix(')').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("could not parse generated static method parameters: {signature}"),
        )
    })?;
    let (return_type, name) = name_and_return.rsplit_once(' ').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("could not parse generated static method name: {signature}"),
        )
    })?;

    let arguments = if parameters.trim().is_empty() {
        String::new()
    } else {
        parameters
            .split(',')
            .map(|parameter| {
                parameter
                    .split('=')
                    .next()
                    .and_then(|parameter| parameter.split_whitespace().last())
                    .ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "could not parse parameter in generated static method: {signature}"
                            ),
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?
            .join(", ")
    };

    Ok(PublicStaticMethod {
        return_type: return_type.trim().to_string(),
        name: name.trim().to_string(),
        parameters: parameters.trim().to_string(),
        arguments,
    })
}

fn render_dotnet_prototype(methods: &[PublicStaticMethod]) -> Result<String> {
    let mut output = String::from(
        "// <auto-generated/> by mxc_diplomat_codegen from Diplomat's MxcDiplomat.cs\n\
         // Do not edit: run scripts/generate-diplomat-bindings.ps1 instead.\n\n\
         using System.Threading;\n\
         using System.Threading.Tasks;\n\
         using Microsoft.Mxc.Diplomat;\n\n\
         namespace Microsoft.Mxc.Diplomat.Prototype;\n\n\
         /// <summary>Public convenience surface over the generated Diplomat binding.</summary>\n\
         public static class MxcDiplomatPrototype\n\
         {\n",
    );

    for method in methods {
        output.push_str(&format!(
            "    /// <inheritdoc cref=\"MxcDiplomat.{name}\" />\n\
             \x20   public static {return_type} {name}({parameters}) =>\n\
             \x20       MxcDiplomat.{name}({arguments});\n\n",
            name = method.name,
            return_type = method.return_type,
            parameters = method.parameters,
            arguments = method.arguments,
        ));
    }

    for method in methods.iter().filter(|method| method.takes_request_json()) {
        let async_name = format!("{}Async", method.name);
        if methods.iter().any(|candidate| candidate.name == async_name) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "generated static method {} conflicts with public async facade name {async_name}",
                    method.name
                ),
            ));
        }
        output.push_str(&render_async_static_method(method, &async_name));
    }
    output.push_str("}\n");

    Ok(output)
}

fn render_dotnet_async_extensions(methods: &[(String, PublicStaticMethod)]) -> Result<String> {
    let mut output = String::from(
        "// <auto-generated/> by mxc_diplomat_codegen from Diplomat's opaque classes\n\
         // Do not edit: run scripts/generate-diplomat-bindings.ps1 instead.\n\n\
         using System.Threading;\n\
         using System.Threading.Tasks;\n\
         using Microsoft.Mxc.Diplomat;\n\n\
         namespace Microsoft.Mxc.Diplomat.Prototype;\n\n\
         /// <summary>Task-based convenience methods for generated mutable handles.</summary>\n\
         public static class MxcDiplomatPrototypeExtensions\n\
         {\n",
    );

    for (owner, method) in methods
        .iter()
        .filter(|(_, method)| method.is_blocking_instance_method())
    {
        let async_name = format!("{}Async", method.name);
        let parameters = append_cancellation_token(&method.parameters);
        let invocation = if method.arguments.is_empty() {
            format!("value.{}()", method.name)
        } else {
            format!("value.{}({})", method.name, method.arguments)
        };
        let task_type = if method.return_type == "void" {
            "Task".to_string()
        } else {
            format!("Task<{}>", method.return_type)
        };
        output.push_str(&format!(
            "    /// <summary>Runs <c>{owner}.{name}</c> on a worker thread.</summary>\n\
             \x20   /// <remarks>Cancellation is honored before work starts; a running native call cannot be interrupted.</remarks>\n\
             \x20   public static {task_type} {async_name}(this {owner} value, {parameters}) =>\n\
             \x20       Task.Run(() => {invocation}, cancellationToken);\n\n",
            owner = owner,
            name = method.name,
            task_type = task_type,
            async_name = async_name,
            parameters = parameters,
            invocation = invocation,
        ));
    }
    output.push_str("}\n");
    Ok(output)
}

impl PublicStaticMethod {
    /// MXC bridge methods carrying request JSON can block in native code. This
    /// detects them from Diplomat's generated signature rather than maintaining
    /// a hand-written operation list.
    fn takes_request_json(&self) -> bool {
        self.parameters
            .split(',')
            .any(|parameter| parameter.trim_start().starts_with("string "))
    }

    /// Generate worker wrappers for the potentially blocking or I/O-bearing
    /// mutable-handle methods. `Take*`, `Try*`, and `Dispose` are immediate
    /// ownership/query operations and remain synchronous.
    fn is_blocking_instance_method(&self) -> bool {
        !self.name.starts_with("Take") && !self.name.starts_with("Try") && self.name != "Dispose"
    }
}

fn render_async_static_method(method: &PublicStaticMethod, async_name: &str) -> String {
    let parameters = append_cancellation_token(&method.parameters);
    format!(
        "    /// <summary>Runs the generated synchronous <c>MxcDiplomat.{name}</c> call on a worker thread.</summary>\n\
         \x20   /// <remarks>Cancellation is honored before work starts; a running native call cannot be interrupted.</remarks>\n\
         \x20   public static Task<{return_type}> {async_name}({parameters}) =>\n\
         \x20       Task.Run(() => MxcDiplomat.{name}({arguments}), cancellationToken);\n\n",
        name = method.name,
        return_type = method.return_type,
        async_name = async_name,
        parameters = parameters,
        arguments = method.arguments,
    )
}

fn append_cancellation_token(parameters: &str) -> String {
    if parameters.is_empty() {
        "CancellationToken cancellationToken = default".to_string()
    } else {
        format!("{parameters}, CancellationToken cancellationToken = default")
    }
}

fn argument(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<String> {
    arguments
        .next()
        .and_then(|argument| argument.into_string().ok())
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("missing {name}")))
}

fn usage(executable: &std::ffi::OsString) -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        format!(
            "usage: {} c <output-directory> | {} dotnet <bindings-output-directory> \
             <prototype-output-directory>",
            PathBuf::from(executable).display(),
            PathBuf::from(executable).display()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED_API: &str = r#"
public partial class MxcDiplomat
{
    public static MxcDiplomatVersion Version()
    {
    }

    public static MxcDiplomatDiscovery Discover()
    {
    }

    public static MxcDiplomatRunResult Run(string requestJson)
    {
    }

    public static MxcDiplomatStateAwareEnvelope Provision(string requestJson, bool dryRun, bool experimental)
    {
    }
}
"#;

    #[test]
    fn generated_static_methods_drive_the_public_facade() {
        let methods = parse_public_static_methods(GENERATED_API).expect("generated API parses");
        let facade = render_dotnet_prototype(&methods).expect("facade renders");

        assert!(facade.contains("MxcDiplomat.Version()"));
        assert!(facade.contains("MxcDiplomat.Discover()"));
        assert!(facade.contains("MxcDiplomat.Run(requestJson)"));
        assert!(facade.contains(
            "Task<MxcDiplomatRunResult> RunAsync(string requestJson, \
             CancellationToken cancellationToken = default)"
        ));
        assert!(facade.contains(
            "Task<MxcDiplomatStateAwareEnvelope> ProvisionAsync(string requestJson, bool dryRun, \
             bool experimental, CancellationToken cancellationToken = default)"
        ));
    }

    #[test]
    fn generated_api_without_run_is_rejected() {
        let error = parse_public_static_methods("public static MxcDiplomatVersion Version()")
            .expect_err("Run is required for the public async facade");

        assert!(error.to_string().contains("no public static Run method"));
    }

    #[test]
    fn blocking_handle_methods_drive_async_extensions() {
        let methods = vec![
            (
                "MxcDiplomatSandbox".to_string(),
                PublicStaticMethod {
                    return_type: "MxcDiplomatWaitResult".to_string(),
                    name: "Wait".to_string(),
                    parameters: String::new(),
                    arguments: String::new(),
                },
            ),
            (
                "MxcDiplomatSandbox".to_string(),
                PublicStaticMethod {
                    return_type: "MxcDiplomatPollResult".to_string(),
                    name: "TryWait".to_string(),
                    parameters: String::new(),
                    arguments: String::new(),
                },
            ),
            (
                "MxcDiplomatOutputStream".to_string(),
                PublicStaticMethod {
                    return_type: "ulong".to_string(),
                    name: "Read".to_string(),
                    parameters: "byte[] bytes".to_string(),
                    arguments: "bytes".to_string(),
                },
            ),
        ];

        let extensions = render_dotnet_async_extensions(&methods).expect("extensions render");

        assert!(extensions.contains(
            "Task<MxcDiplomatWaitResult> WaitAsync(this MxcDiplomatSandbox value, \
             CancellationToken cancellationToken = default)"
        ));
        assert!(extensions.contains(
            "Task<ulong> ReadAsync(this MxcDiplomatOutputStream value, byte[] bytes, \
             CancellationToken cancellationToken = default)"
        ));
        assert!(!extensions.contains("TryWaitAsync"));
    }
}
