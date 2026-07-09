// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use crate::{
    cli::CommonFlags,
    error::{Error, Result},
};
use clap::{ArgGroup, Parser, Subcommand};
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

        /// URL of the RATSD daemon to connect to. Required when --attester is set to `ratsd`. Defaults to `http://localhost:8895`.
        #[arg(long, value_parser = utils::validate_base_url)]
        ratsd_url: Option<String>,

        /// Path to ARM CCA claims file (JSON format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/cca-claims.json`.
        #[arg(long, value_parser = utils::validate_input_file_path)]
        sim_claims: Option<PathBuf>,

        /// Path to ARM CCA iak file (JWK format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/iak.jwk`.
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
            "Loaded arguments: attester={attester:?}, ratsd_url={ratsd_url:?}, sim_claims={sim_claims:?}, sim_iak={sim_iak:?}, nonce_raw={nonce_raw:?}, nonce_hex={nonce_hex:?}, nonce_b64={nonce_b64:?}, nonce_b64url={nonce_b64url:?}, output={output:?}"
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
            let args = evidence::Args {
                attester: AttesterKind::Sim,
                ratsd_url: None,
                sim_claims: None,
                sim_iak: None,
                nonce_raw: None,
                nonce_hex: None,
                nonce_b64: None,
                nonce_b64url: None,
                output: std::path::PathBuf::from("test_evidence.cbor"),
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
        /// Implementation ID (as per [rfc4648](https://datatracker.ietf.org/doc/html/rfc4648), base64 Standard or URL Safe encoding, padding optional). Use this to fetch reference values.
        #[arg(short = 'E', long, conflicts_with = "evidence")]
        impl_id: Option<String>,

        /// Instance ID (as per [rfc4648](https://datatracker.ietf.org/doc/html/rfc4648), base64 Standard or URL Safe encoding, padding optional). Use this to fetch trust anchors.
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
            "Loaded arguments: impl_id={impl_id:?}, inst_id={inst_id:?}, evidence={evidence:?}, coserv_server={coserv_server}, ca_cert={ca_cert:?}, local_cache={local_cache:?}, must_sign={must_sign:?}, result_type={result_type:?}, output_ta={output_ta:?}, output_rv={output_rv:?}"
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

            let args = endorsements::Args {
                impl_id: Some(impl_id_str),
                inst_id: Some(inst_id_str),
                evidence: None,
                coserv_server: server.uri(),
                ca_cert: None,
                local_cache: None,
                must_sign: false,
                result_type: ResultType::Collected,
                output_rv: std::path::PathBuf::from("rv_result.cbor"),
                output_ta: std::path::PathBuf::from("ta_result.cbor"),
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

    #[derive(Debug, Parser)]
    #[command(group(
        ArgGroup::new("selector")
            .required(true)
            .args(["policy_id", "all"])
    ))]
    pub struct Args {
        /// The base URL of the management service.
        #[arg(short = 'S', long, value_parser = utils::validate_base_url)]
        management_server: String,

        /// The path to an X509 certificate to bootstrap TLS handshakes with the management service.
        #[arg(short = 't', long, value_parser = utils::validate_input_file_path)]
        ca_cert: Option<PathBuf>,

        /// Fetch a specific policy by ID. Conflicts with --all.
        #[arg(short = 'P', long, conflicts_with = "all")]
        policy_id: Option<String>,

        /// Fetch all policies. Conflicts with --policy-id. Used with --outputdir,
        /// each policy is saved as <outputdir>/<policy-id>.rego.
        #[arg(
            short = 'a',
            long,
            conflicts_with = "policy_id",
            default_value_t = false
        )]
        all: bool,

        /// With --policy-id: output file path to save the fetched policy. If not specified,
        /// the policy will be saved to default `<policy-id>.rego` in the current working directory.
        #[arg(short = 'f', long, value_parser = utils::validate_output_path, requires = "policy_id")]
        outputfile: Option<PathBuf>,

        /// With --all: output directory path where each policy is saved as <policy-id>.rego.
        #[arg(short = 'd', long, value_parser = utils::validate_output_path, requires = "all")]
        outputdir: Option<PathBuf>,

        // Common flags for all commands.
        #[command(flatten)]
        pub common: CommonFlags,
    }

    /// Fetch policies from the verification service.
    pub fn fetch(_args: Args) -> Result<()> {
        todo!()
    }
}
