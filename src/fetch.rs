// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use crate::{
    cli::CommonFlags,
    error::{Error, Result},
};
use clap::{Parser, Subcommand};
use log::{debug, info};
use regl::attesters::cca::utils::decode_cca_token;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum FetchCmd {
    /// Fetch evidence.
    Evidence(evidence::Args),

    /// Fetch endorsements.
    Endorsements(endorsements::Args),

    /// Fetch policies from the verification service.
    Policy(policy::Args),
}

pub fn cmd(command: FetchCmd) -> Result<()> {
    match command {
        FetchCmd::Evidence(args) => evidence::fetch(args),
        FetchCmd::Endorsements(args) => endorsements::fetch(args),
        FetchCmd::Policy(args) => policy::fetch(args),
    }
}

mod evidence {
    use super::*;
    use crate::evidence::{AttesterKind, generate_evidence, get_nonce};

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Regl attester backend to use for evidence generation.
        ///
        /// - `ratsd` (default) Connect to a RATSD daemon (required to pass the --ratsd-url argument)
        /// - `tsm`   Read from the Linux configfs-tsm interface (requires CCA hardware)
        /// - `sim`   Build a CCA token from default JSON claims & JWK (inside test/json/: cca-claims.json and iak.jwk)
        #[arg(short, long, value_enum, default_value_t = AttesterKind::Ratsd)]
        attester: AttesterKind,

        /// URL of the RATSD daemon to connect to. Required when --attester
        /// is set to `ratsd`. Defaults to `http://localhost:8895`.
        #[arg(long, value_parser = utils::validate_base_url)]
        ratsd_url: Option<String>,

        /// Path to ARM CCA claims file (JSON format) to build a simulated attester
        /// (i.e., when --attester is set to `sim`). Default to `test/json/cca-claims.json`.
        #[arg(long, value_parser = utils::validate_input_file_path)]
        sim_claims: Option<PathBuf>,

        /// Path to ARM CCA iak file (JWK format) to build a simulated attester
        /// (i.e., when --attester is set to `sim`). Default to `test/json/iak.jwk`.
        #[arg(long, value_parser = utils::validate_input_file_path)]
        sim_iak: Option<PathBuf>,

        /// Path to a text file containing nonce as raw bytes.
        #[arg(long, value_parser = utils::validate_input_file_path, conflicts_with_all = &["nonce_hex", "nonce_b64", "nonce_b64url"])]
        nonce_raw: Option<PathBuf>,

        /// A hex-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["nonce_raw", "nonce_b64", "nonce_b64url"])]
        nonce_hex: Option<String>,

        /// A base64-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["nonce_raw", "nonce_hex", "nonce_b64url"])]
        nonce_b64: Option<String>,

        /// A base64url-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["nonce_raw", "nonce_hex", "nonce_b64"])]
        nonce_b64url: Option<String>,

        /// Output file path. If not specified, the evidence will
        /// be saved to default `evidence.cbor` in the current working directory.
        #[arg(short, long, value_parser = utils::validate_output_path, default_value = "evidence.cbor")]
        output: PathBuf,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    pub fn fetch(args: Args) -> Result<()> {
        debug!("Fetch evidence");

        let Args {
            attester,
            ratsd_url,
            sim_claims,
            sim_iak,
            nonce_raw,
            nonce_hex,
            nonce_b64,
            nonce_b64url,
            output,
            ..
        } = args;
        debug!(
            "Loaded arguments: \n
            attester={attester:?}, \n
            ratsd_url={ratsd_url:?}, \n
            sim_claims={sim_claims:?}, \n
            sim_iak={sim_iak:?}, \n
            nonce_raw={nonce_raw:?}, \n
            nonce_hex={nonce_hex:?}, \n
            nonce_b64={nonce_b64:?}, \n
            nonce_b64url={nonce_b64url:?}, \n
            output={output:?}"
        );

        utils::check_output_file(&output, args.common.force)?;

        let nonce = get_nonce(nonce_raw, nonce_hex, nonce_b64, nonce_b64url)?;

        debug!("Generating attestation evidence using {attester:?} attester");
        let evidence = generate_evidence(
            &attester,
            ratsd_url.as_deref(),
            sim_claims.as_ref(),
            sim_iak.as_ref(),
            &nonce,
        )?;

        debug!("Pretty print: {}", args.common.pretty);
        let token = decode_cca_token(&evidence)?;
        let evidence_json = if args.common.pretty {
            serde_json::to_string_pretty(&token)?
        } else {
            serde_json::to_string(&token)?
        };
        info!("{evidence_json}");

        utils::write_output_to_file(&evidence, &output)?;
        info!("Evidence saved to: {:?}", output);

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use evidence::AttesterKind;

        #[test]
        fn test_fetch_evidence() {
            let temp_dir = tempfile::tempdir().unwrap();
            let output_path = temp_dir.path().join("test_evidence.cbor");

            let args = evidence::Args {
                attester: AttesterKind::Sim,
                ratsd_url: None,
                sim_claims: None,
                sim_iak: None,
                nonce_raw: None,
                nonce_hex: None,
                nonce_b64: None,
                nonce_b64url: None,
                output: output_path,
                common: CommonFlags {
                    pretty: true,
                    force: true,
                },
            };
            let result = evidence::fetch(args);
            assert!(result.is_ok());
        }
    }
}

mod endorsements {
    use super::*;
    use crate::coserv::{ResultType, get_reference_values, get_trust_anchor};

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Implementation ID (as per [rfc4648](https://datatracker.ietf.org/doc/html/rfc4648),
        /// base64 Standard or URL Safe encoding, padding optional). Use this to fetch reference values.
        #[arg(short = 'E', long, conflicts_with = "evidence")]
        impl_id: Option<String>,

        /// Instance ID (as per [rfc4648](https://datatracker.ietf.org/doc/html/rfc4648),
        /// base64 Standard or URL Safe encoding, padding optional). Use this to fetch trust anchors.
        #[arg(short = 'I', long, conflicts_with = "evidence")]
        inst_id: Option<String>,

        /// Path to an evidence file in CBOR format. Use this to extract
        /// impl-id and inst-id and then fetch endorsements.
        #[arg(short = 'e', long, value_parser=utils::validate_input_file_path, conflicts_with_all = &["impl_id", "inst_id"])]
        evidence: Option<PathBuf>,

        /// The base URL to a CoSERV service.
        /// Coserv service should support the result-type=collected.
        #[arg(short = 'S', long, value_parser = utils::validate_base_url)]
        coserv_server: String,

        /// The path to an X509 certificate to bootstrap TLS handshakes with the CoSERV service.
        #[arg(short = 't', long, value_parser = utils::validate_input_file_path)]
        ca_cert: Option<PathBuf>,

        /// The path to the directory where local coserv results will be cached.
        /// If not specified, no local caching is performed, and all CoSERV requests
        /// will go to the server.
        #[arg(short = 'l', long, value_parser = utils::validate_input_directory_path)]
        local_cache: Option<PathBuf>,

        /// The server MUST sign CoSERV results. The command fails
        /// if the server does not support signing.
        #[arg(long, default_value_t = false)]
        must_sign: bool,

        /// CoSERV Result type
        #[arg(short, long, default_value = "collected", ignore_case = true)]
        result_type: ResultType,

        /// Output file path for fetched trust anchor. If not specified, the trust anchor output will
        /// be saved to default `coserv_ta.cbor` in the current working directory.
        #[arg(long, value_parser = utils::validate_output_path, default_value = "coserv_ta.cbor")]
        output_ta: PathBuf,

        /// Output file path for fetched reference values. If not specified, the reference values will
        /// be saved to default `coserv_rv.cbor` in the current working directory.
        #[arg(long, value_parser = utils::validate_output_path, default_value = "coserv_rv.cbor")]
        output_rv: PathBuf,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    pub fn fetch(args: Args) -> Result<()> {
        debug!("Fetch endorsements");

        let Args {
            impl_id,
            inst_id,
            evidence,
            coserv_server,
            ca_cert,
            local_cache,
            must_sign,
            result_type,
            output_ta,
            output_rv,
            ..
        } = args;
        debug!(
            "Loaded arguments: \n
            impl_id={impl_id:?}, \n
            inst_id={inst_id:?}, \n
            evidence={evidence:?}, \n
            coserv_server={coserv_server}, \n
            ca_cert={ca_cert:?}, \n
            local_cache={local_cache:?}, \n
            must_sign={must_sign:?}, \n
            result_type={result_type:?}, \n
            output_ta={output_ta:?}, \n
            output_rv={output_rv:?}"
        );

        // Validate that selector to fetch endorsements is provided
        let has_selector = impl_id.is_some() || inst_id.is_some() || evidence.is_some();
        if !has_selector {
            return Err(Error::MissingField {
                object: "endorsements",
                field: "selector (--impl-id, --inst-id, or --evidence)",
            });
        }

        // get instance and implementation ids from input arguments or evidence

        let mut inst_id_bytes = Vec::new();
        let mut impl_id_bytes = Vec::new();

        if let Some(ref inst_id_str) = inst_id {
            inst_id_bytes = utils::decode_base64(inst_id_str)?;
            if inst_id_bytes.len() != 33 {
                return Err(Error::InvalidValue {
                    value: format!("got invalid inst_id length: {}", inst_id_bytes.len()),
                    expected: "33 bytes",
                });
            }
            debug!("got inst_id from arguments");
        }

        if let Some(ref impl_id_str) = impl_id {
            impl_id_bytes = utils::decode_base64(impl_id_str)?;
            if impl_id_bytes.len() != 32 {
                return Err(Error::InvalidValue {
                    value: format!("got invalid impl_id length: {}", impl_id_bytes.len()),
                    expected: "32 bytes",
                });
            }
            debug!("got impl_id from arguments");
        }

        if let Some(ref evidence_path_buf) = evidence {
            debug!("Evidence file provided. Extracting inst_id and impl_id from evidence.");
            let raw = fs::read(evidence_path_buf)?;
            let evidence = decode_cca_token(&raw)?;

            inst_id_bytes = evidence.platform.instance_id;
            if inst_id_bytes.len() != 33 {
                return Err(Error::InvalidValue {
                    value: format!("got invalid inst_id length: {}", inst_id_bytes.len()),
                    expected: "33 bytes",
                });
            }
            debug!("got inst_id from evidence");

            impl_id_bytes = evidence.platform.implementation_id;
            if impl_id_bytes.len() != 32 {
                return Err(Error::InvalidValue {
                    value: format!("got invalid impl_id length: {}", impl_id_bytes.len()),
                    expected: "32 bytes",
                });
            }
            debug!("got impl_id from evidence");
        }

        // performing the actual fetch from inst_id and impl_id

        if !inst_id_bytes.is_empty() {
            utils::check_output_file(&output_ta, args.common.force)?;

            debug!("Fetching trust anchors for inst_id");
            let result_ta = get_trust_anchor(
                inst_id_bytes,
                &coserv_server,
                ca_cert.as_ref(),
                local_cache.as_ref(),
                must_sign,
                &result_type,
            )?;

            debug!("Trust anchors: {:?}", result_ta);
            let result_ta_cbor = result_ta.to_cbor()?;

            utils::write_output_to_file(&result_ta_cbor, &output_ta)?;
            info!("Trust anchors saved to: {:?}", output_ta);
        }

        if !impl_id_bytes.is_empty() {
            utils::check_output_file(&output_rv, args.common.force)?;

            debug!("Fetching reference values for impl_id");
            let result_rv = get_reference_values(
                impl_id_bytes,
                &coserv_server,
                ca_cert.as_ref(),
                local_cache.as_ref(),
                must_sign,
                &result_type,
            )?;

            debug!("Reference values: {:?}", result_rv);
            let result_rv_cbor = result_rv.to_cbor()?;

            utils::write_output_to_file(&result_rv_cbor, &output_rv)?;
            info!("Reference values saved to: {:?}", output_rv);
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::coserv::{reference_value_query_from_impl_id, trust_anchor_query_from_inst_id};
        use base64::{Engine as _, engine::general_purpose};
        use coserv_rs::discovery::DiscoveryDocument;
        use regl::attesters::cca::utils::decode_cca_token;
        use std::fs;
        use tokio::runtime::Runtime;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        async fn start_mock_coserv_server() -> MockServer {
            let server = MockServer::start().await;

            let discovery_reply: DiscoveryDocument = serde_json::from_str(
                fs::read_to_string("test/json/coservdiscoverydoc.json")
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();

            Mock::given(method("GET"))
                .and(path("/.well-known/coserv-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(discovery_reply))
                .mount(&server)
                .await;

            let raw = fs::read("test/cbor/ccatoken.cbor").unwrap();
            let evidence = decode_cca_token(&raw).unwrap();

            let inst_id = evidence.platform.instance_id;

            let ta_query = trust_anchor_query_from_inst_id(inst_id, &ResultType::Collected)
                .unwrap()
                .to_b64_url()
                .unwrap();

            let ta_endpoint = format!("/endorsement-distribution/v1/coserv/{ta_query}");

            let ta_result = fs::read("test/cbor/ta_result.cbor").unwrap();

            Mock::given(method("GET"))
                .and(path(ta_endpoint))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(ta_result, "application/coserv+cbor"),
                )
                .mount(&server)
                .await;

            let impl_id = evidence.platform.implementation_id;

            let rv_query = reference_value_query_from_impl_id(impl_id, &ResultType::Collected)
                .unwrap()
                .to_b64_url()
                .unwrap();

            let rv_endpoint = format!("/endorsement-distribution/v1/coserv/{rv_query}");

            let rv_result = fs::read("test/cbor/rv_result.cbor").unwrap();

            Mock::given(method("GET"))
                .and(path(rv_endpoint))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(rv_result, "application/coserv+cbor"),
                )
                .mount(&server)
                .await;

            debug!("Mock server running at {}", server.uri());

            server
        }

        #[test]
        fn test_fetch_endorsements() {
            let server = Runtime::new()
                .unwrap()
                .block_on(async { start_mock_coserv_server().await });

            let raw = fs::read("test/cbor/ccatoken.cbor").unwrap();
            let evidence = decode_cca_token(&raw).unwrap();

            let inst_id_str = general_purpose::STANDARD.encode(evidence.platform.instance_id);

            let impl_id_str = general_purpose::STANDARD.encode(evidence.platform.implementation_id);

            let temp_dir = tempfile::tempdir().unwrap();
            let output_rv = temp_dir.path().join("test_rv_result.cbor");
            let output_ta = temp_dir.path().join("test_ta_result.cbor");

            let args = endorsements::Args {
                impl_id: Some(impl_id_str),
                inst_id: Some(inst_id_str),
                evidence: None,
                coserv_server: server.uri(),
                ca_cert: None,
                local_cache: None,
                must_sign: false,
                result_type: ResultType::Collected,
                output_rv,
                output_ta,
                common: CommonFlags {
                    pretty: false,
                    force: true,
                },
            };
            let result = endorsements::fetch(args);
            assert!(result.is_ok());
        }
    }
}

mod policy {
    use super::*;
    use crate::utils;
    use serde_json::json;
    use tokio::runtime::Runtime;
    use uuid::Uuid;
    use veraison_apiclient::{
        DiscoveryBuilder, ServiceState,
        auth::{Authenticator, BasicAuthenticator, Oauth2Authenticator},
        http::ConfigureHttp,
        management::{Policy, PolicyManagerBuilder},
    };

    #[derive(Debug, Clone, Default, Copy, clap::ValueEnum)]
    pub enum AuthMethod {
        #[default]
        Passthrough,
        Basic,
        Oauth2,
    }

    #[derive(Debug, Parser)]
    pub struct Args {
        /// The base URL of the management service.
        #[arg(short = 'S', long, value_parser = utils::validate_base_url)]
        management_server: String,

        /// The path to an X509 certificate to bootstrap TLS handshakes with the management service.
        #[arg(short = 't', long, value_parser = utils::validate_input_file_path)]
        ca_cert: Option<PathBuf>,

        /// Fetch a specific policy for the scheme by UUID. Conflicts with --active and --all.
        #[arg(long, conflicts_with_all = &["all"], value_parser = utils::validate_uuid)]
        policy_id: Option<Uuid>,

        /// Fetch all policies for the scheme. Conflicts with --active and --policy-id.
        #[arg(long, conflicts_with_all = &["policy_id"])]
        all: bool,

        /// The attestation scheme for the policy. Default is ARM_CCA.
        #[arg(short = 's', long, default_value = "ARM_CCA")]
        scheme: String,

        /// Authentication method to use for the management API. Can be one of:
        /// passthrough, basic, or oauth2. Default is passthrough.
        #[arg(long, value_enum, default_value_t = AuthMethod::Passthrough)]
        auth: AuthMethod,

        /// Username for basic auth or OAuth2 resource-owner credentials.
        #[arg(long)]
        username: Option<String>,

        /// Password for basic auth or OAuth2 resource-owner credentials.
        #[arg(long)]
        password: Option<String>,

        /// OAuth2 token endpoint URL.
        #[arg(long)]
        token_url: Option<String>,

        /// OAuth2 client ID.
        #[arg(long)]
        client_id: Option<String>,

        /// OAuth2 client secret.
        #[arg(long)]
        client_secret: Option<String>,

        /// With --active or --policy-id: output file path to save the fetched policy.
        /// If not specified, the policy will be saved to default `<policy-id>.rego`
        /// in the current working directory.
        #[arg(short = 'f', long, value_parser = utils::validate_output_path)]
        outputfile: Option<PathBuf>,

        /// With --all: output directory where each fetched policy is saved as <policy-id>.rego.
        /// If not specified, the policies will be saved to default `./policies` directory
        /// in the current working directory.
        #[arg(short = 'd', long, value_parser = utils::validate_output_path,  default_value = "./policies")]
        outputdir: PathBuf,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    /// Fetch policies from the verification service.
    pub fn fetch(args: Args) -> Result<()> {
        debug!("Fetch policy");

        let Args {
            management_server,
            ca_cert,
            policy_id,
            all,
            scheme,
            auth,
            username,
            password,
            token_url,
            client_id,
            client_secret,
            outputfile,
            outputdir,
            ..
        } = args;
        debug!(
            "Loaded arguments: \n
            management_server={management_server}, \n
            ca_cert={ca_cert:?}, \n
            policy_id={policy_id:?}, \n
            all={all}, \n
            scheme={scheme}, \n
            auth={auth:?}, \n
            outputfile={outputfile:?}, \n
            outputdir={outputdir:?}"
        );

        let runtime = Runtime::new()
            .map_err(|err| Error::custom(format!("failed to create tokio runtime: {err}")))?;

        runtime.block_on(async {
            let mut discovery_builder =
                DiscoveryBuilder::new().with_base_url(management_server.to_string());
            let mut runner_builder =
                PolicyManagerBuilder::new().with_base_url(management_server.to_string());

            if let Some(ca_cert) = &ca_cert {
                discovery_builder = discovery_builder.with_root_certificate(ca_cert.clone());
                runner_builder = runner_builder.with_root_certificate(ca_cert.clone());
            }

            let discoverer = discovery_builder.build()?;
            let management_api = discoverer.get_management_api().await?;

            // Currently Management Service State is hardcoded to READY,
            // but we check it anyway in case it changes in the future.
            match management_api.service_state() {
                ServiceState::Ready => {}
                state => {
                    return Err(Error::custom(format!(
                        "management service is not ready (state: {:?})",
                        state
                    )));
                }
            }

            match auth {
                AuthMethod::Passthrough => {
                    debug!("Using passthrough authentication for management API");
                }
                AuthMethod::Basic => {
                    debug!("Using basic authentication for management API");
                    let Some(username) = username else {
                        return Err(Error::custom("username is required for basic auth"));
                    };
                    let Some(password) = password else {
                        return Err(Error::custom("password is required for basic auth"));
                    };
                    let mut basic_auth = BasicAuthenticator::default();
                    basic_auth.configure(&json!({"username": username, "password": password}))?;
                    runner_builder = runner_builder.with_authenticator(basic_auth);
                }
                AuthMethod::Oauth2 => {
                    debug!("Using OAuth2 authentication for management API");
                    let Some(username) = username else {
                        return Err(Error::custom("username is required for oauth2 auth"));
                    };
                    let Some(password) = password else {
                        return Err(Error::custom("password is required for oauth2 auth"));
                    };
                    let Some(token_url) = token_url else {
                        return Err(Error::custom("token_url is required for oauth2 auth"));
                    };
                    let Some(client_id) = client_id else {
                        return Err(Error::custom("client_id is required for oauth2 auth"));
                    };
                    let Some(client_secret) = client_secret else {
                        return Err(Error::custom("client_secret is required for oauth2 auth"));
                    };
                    let mut oauth2_auth = Oauth2Authenticator::default();
                    oauth2_auth.configure(&json!({
                        "username": username,
                        "password": password,
                        "token_url": token_url,
                        "client_id": client_id,
                        "client_secret": client_secret,
                    }))?;
                    runner_builder = runner_builder.with_authenticator(oauth2_auth);
                }
            }

            let runner = runner_builder.build()?;

            if all {
                debug!("Fetching all policies for scheme: {scheme}");
                let Some(_) = management_api.get_api_endpoint("getPolicies") else {
                    return Err(Error::custom(
                        "endpoint to get policies is missing in management discovery document",
                    ));
                };

                let policies = runner.get_policies(&scheme, "").await?;
                info!("All policies for {scheme}: \n{policies:?}");

                for policy in policies {
                    let path = outputdir.join(format!("{}.rego", policy.uuid));
                    utils::check_output_file(&path, args.common.force)?;
                    validate_and_write_policy(&path, policy)?;
                }
                info!("Policies saved to: {:?}", outputdir);

                Ok(())
            } else if let Some(policy_id) = policy_id {
                debug!("Fetching policy {policy_id} for scheme: {scheme}");
                let Some(_) = management_api.get_api_endpoint("getPolicy") else {
                    return Err(Error::custom(
                        "endpoint to get policy is missing in management discovery document",
                    ));
                };

                let policy = runner.get_policy(&scheme, policy_id).await?;
                info!("Policy {policy_id} for {scheme}: \n{policy:?}");

                let outputfile =
                    outputfile.unwrap_or_else(|| PathBuf::from(format!("{}.rego", policy.uuid)));

                utils::check_output_file(&outputfile, args.common.force)?;
                validate_and_write_policy(&outputfile, policy)?;

                Ok(())
            } else {
                debug!("Fetching active policy for scheme: {scheme}");
                let Some(_) = management_api.get_api_endpoint("getActivePolicy") else {
                    return Err(Error::custom(
                        "endpoint to get active policy is missing in management discovery document",
                    ));
                };

                let policy = runner.get_active_policy(&scheme).await?;
                info!("Active policy for {scheme}: \n{policy:?}");

                let outputfile =
                    outputfile.unwrap_or_else(|| PathBuf::from(format!("{}.rego", policy.uuid)));

                utils::check_output_file(&outputfile, args.common.force)?;
                validate_and_write_policy(&outputfile, policy)?;

                Ok(())
            }
        })
    }

    // Validate that the policy rules are valid Rego source code and write them to the specified file.
    fn validate_and_write_policy(path: &PathBuf, policy: Policy) -> Result<()> {
        utils::validate_policy_rules(path, policy.rules.as_bytes())?;
        utils::write_output_to_file(&policy.rules, path)?;
        info!("Policy saved to: {:?}", path);
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };

        async fn start_mock_management_server(policy_id: Uuid) -> MockServer {
            let server = MockServer::start().await;
            let discovery_document = fs::read("test/json/managementdiscoverydoc.json").unwrap();
            let active_policy = serde_json::json!({
                "uuid": policy_id,
                "ctime": "2026-09-09T00:00:00Z",
                "name": "active-policy",
                "type": "opa",
                "rules": "package policy\n\nallow := true\n",
                "active": true
            });
            let policy_list = serde_json::json!([
                active_policy,
                {
                    "uuid": Uuid::new_v4(),
                    "ctime": "2026-09-10T00:00:00Z",
                    "name": "older-policy",
                    "type": "opa",
                    "rules": "package policy\n\nallow := false\n",
                    "active": false
                }
            ]);

            Mock::given(method("GET"))
                .and(path("/.well-known/veraison/management"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    discovery_document,
                    "application/vnd.veraison.discovery+json",
                ))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/management/v1/policy/ARM_CCA"))
                .and(header("accept", "application/vnd.veraison.policy+json"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/vnd.veraison.policy+json")
                        .set_body_raw(
                            active_policy.to_string(),
                            "application/vnd.veraison.policy+json",
                        ),
                )
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path(format!("/management/v1/policy/ARM_CCA/{policy_id}")))
                .and(header("accept", "application/vnd.veraison.policy+json"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/vnd.veraison.policy+json")
                        .set_body_raw(
                            active_policy.to_string(),
                            "application/vnd.veraison.policy+json",
                        ),
                )
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/management/v1/policies/ARM_CCA"))
                .and(header("accept", "application/vnd.veraison.policies+json"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/vnd.veraison.policies+json")
                        .set_body_raw(
                            policy_list.to_string(),
                            "application/vnd.veraison.policies+json",
                        ),
                )
                .mount(&server)
                .await;

            server
        }

        #[test]
        fn fetch_policy_actions_use_management_discovery_and_expected_endpoints() {
            let policy_id = Uuid::new_v4();
            let server = Runtime::new()
                .unwrap()
                .block_on(async { start_mock_management_server(policy_id).await });

            let temp_dir = tempfile::tempdir().unwrap();
            let output_path = temp_dir.path().join(format!("test_{}.rego", policy_id));

            let active_args = Args {
                management_server: server.uri(),
                ca_cert: None,
                policy_id: None,
                all: false,
                scheme: "ARM_CCA".into(),
                auth: AuthMethod::Passthrough,
                username: None,
                password: None,
                token_url: None,
                client_id: None,
                client_secret: None,
                outputfile: Some(output_path.clone()),
                outputdir: temp_dir.path().into(),
                common: CommonFlags {
                    pretty: false,
                    force: true,
                },
            };

            let by_id_args = Args {
                management_server: server.uri(),
                ca_cert: None,
                policy_id: Some(policy_id),
                all: false,
                scheme: "ARM_CCA".into(),
                auth: AuthMethod::Passthrough,
                username: None,
                password: None,
                token_url: None,
                client_id: None,
                client_secret: None,
                outputfile: Some(output_path.clone()),
                outputdir: temp_dir.path().into(),
                common: CommonFlags {
                    pretty: false,
                    force: true,
                },
            };

            let all_args = Args {
                management_server: server.uri(),
                ca_cert: None,
                policy_id: None,
                all: true,
                scheme: "ARM_CCA".into(),
                auth: AuthMethod::Passthrough,
                username: None,
                password: None,
                token_url: None,
                client_id: None,
                client_secret: None,
                outputfile: Some(output_path.clone()),
                outputdir: temp_dir.path().into(),
                common: CommonFlags {
                    pretty: false,
                    force: true,
                },
            };

            for args in [active_args, by_id_args, all_args] {
                assert!(policy::fetch(args).is_ok());
            }
        }
    }
}
