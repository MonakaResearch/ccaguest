// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use clap::ValueEnum;
use log::debug;
use std::path::PathBuf;
use tokio::runtime::Runtime;

use coserv_rs::coserv::corim_rs::{
    ClassIdTypeChoice, ClassMapBuilder, InstanceIdTypeChoice, TaggedBytes, TaggedUeidType, UeidType,
};

use coserv_rs::{
    coserv::{
        ArtifactTypeChoice, Coserv, CoservBuilder, CoservEnvQueryBuilder, CoservProfile,
        EnvironmentSelectorMap, OpensslVerifier, ResultTypeChoice, StatefulClassBuilder,
        StatefulInstanceBuilder,
    },
    discovery::ResultVerificationKey,
};

use veraison_apiclient::{
    Discovery, DiscoveryBuilder,
    coserv::{QueryRunner, QueryRunnerBuilder},
    http::ConfigureHttp,
};

pub const DEFAULT_CCA_PROFILE: &str = "tag:arm.com,2025:endorsements/cca_platform#1.0.0";

#[derive(Debug, Clone, ValueEnum)]
pub enum ResultType {
    Collected,
    Source,
    Both,
}

impl From<&ResultType> for ResultTypeChoice {
    fn from(value: &ResultType) -> Self {
        match value {
            ResultType::Collected => ResultTypeChoice::CollectedArtifacts,
            ResultType::Source => ResultTypeChoice::SourceArtifacts,
            ResultType::Both => ResultTypeChoice::Both,
        }
    }
}

/// create trust anchor query and run it against the CoSERV service
pub fn get_trust_anchor(
    inst_id: Vec<u8>,
    coserv_service_base_url: &str,
    ca_cert: Option<&PathBuf>,
    cache: Option<&PathBuf>,
    must_sign: bool,
    result_type: &ResultType,
) -> Result<Coserv<'static>> {
    let ta_query = trust_anchor_query_from_inst_id(inst_id, result_type)?;

    run_discovery_and_query(
        &ta_query,
        coserv_service_base_url,
        ca_cert,
        cache,
        must_sign,
    )
}

/// create reference value query and run it against the CoSERV service
pub fn get_reference_values(
    impl_id: Vec<u8>,
    coserv_service_base_url: &str,
    ca_cert: Option<&PathBuf>,
    cache: Option<&PathBuf>,
    must_sign: bool,
    result_type: &ResultType,
) -> Result<Coserv<'static>> {
    let rv_query = reference_value_query_from_impl_id(impl_id, result_type)?;

    run_discovery_and_query(
        &rv_query,
        coserv_service_base_url,
        ca_cert,
        cache,
        must_sign,
    )
}

/// run discovery and query against the CoSERV service
fn run_discovery_and_query<'a>(
    query: &Coserv<'a>,
    coserv_service_base_url: &str,
    ca_cert: Option<&PathBuf>,
    cache: Option<&PathBuf>,
    must_sign: bool,
) -> Result<Coserv<'a>> {
    let rt = Runtime::new()
        .map_err(|e| Error::custom(format!("could not create tokio runtime: {e}")))?;

    rt.block_on(async {
        QueryClient::run_discovery(coserv_service_base_url, ca_cert, cache)
            .await?
            .run_query(query, must_sign)
            .await
    })
}

/// Create a CoSERV query from CCA instance ID
pub fn trust_anchor_query_from_inst_id<'a>(
    inst_id: Vec<u8>,
    result_type: &ResultType,
) -> Result<Coserv<'a>> {
    if inst_id.len() != 33 {
        return Err(Error::InvalidValue {
            value: format!("got invalid inst_id length: {}", inst_id.len()),
            expected: "33 bytes",
        });
    }
    let ueid = UeidType::new(inst_id.as_slice().into());
    let cca_instance_id = InstanceIdTypeChoice::Ueid(TaggedUeidType::new(ueid));
    let instances = vec![
        StatefulInstanceBuilder::new()
            .environment(cca_instance_id)
            .build()?,
    ];

    // create query map
    let ta_query = CoservEnvQueryBuilder::new()
        .artifact_type(ArtifactTypeChoice::TrustAnchors)
        .result_type(result_type.into())
        .environment_selector(EnvironmentSelectorMap::Instance(instances))
        .build()?;

    // create coserv map
    let ta_coserv = CoservBuilder::new()
        .profile(CoservProfile::Uri(DEFAULT_CCA_PROFILE.into()))
        .query(ta_query.into())
        .build()?;

    Ok(ta_coserv)
}

/// Create a CoSERV query from CCA implementation ID
pub fn reference_value_query_from_impl_id<'a>(
    impl_id: Vec<u8>,
    result_type: &ResultType,
) -> Result<Coserv<'a>> {
    if impl_id.len() != 32 {
        return Err(Error::InvalidValue {
            value: format!("got invalid impl_id length: {}", impl_id.len()),
            expected: "32 bytes",
        });
    }
    let id = ClassIdTypeChoice::Bytes(TaggedBytes::new(impl_id.as_slice().into()));
    let cca_class_map = ClassMapBuilder::new().class_id(id).build()?;

    let classes = vec![
        StatefulClassBuilder::new()
            .environment(cca_class_map)
            .build()?,
    ];

    // create query map
    let rv_query = CoservEnvQueryBuilder::new()
        .artifact_type(ArtifactTypeChoice::ReferenceValues)
        .result_type(result_type.into())
        .environment_selector(EnvironmentSelectorMap::Class(classes))
        .build()?;

    // create coserv map
    let rv_coserv = CoservBuilder::new()
        .profile(CoservProfile::Uri(DEFAULT_CCA_PROFILE.into()))
        .query(rv_query.into())
        .build()?;

    Ok(rv_coserv)
}

/// Convenient wrapper around the [QueryRunner] that also includes a signature verifier and any
/// other client-side state that might be needed.
pub struct QueryClient {
    query_runner: QueryRunner,
    verifier: Option<OpensslVerifier>,
}

impl QueryClient {
    async fn run_discovery(
        coserv_service_base_url: &str,
        ca_cert: Option<&PathBuf>,
        cache_path: Option<&PathBuf>,
    ) -> Result<QueryClient> {
        let mut discovery_builder =
            DiscoveryBuilder::new().with_base_url(coserv_service_base_url.to_string());

        let mut builder = QueryRunnerBuilder::new();

        if let Some(ca_cert) = ca_cert {
            discovery_builder = discovery_builder.with_root_certificate(ca_cert.clone());
            builder = builder.with_root_certificate(ca_cert.clone());
        }

        if let Some(cache_path) = cache_path {
            discovery_builder = discovery_builder.with_default_disk_cache(cache_path.clone());
            builder = builder.with_default_disk_cache(cache_path.clone());
        }

        let discoverer = discovery_builder.build()?;

        let discovery_doc = Discovery::get_coserv_discovery_document_json(&discoverer).await?;

        debug!(
            "discovered api endpoints: {:?}",
            discovery_doc.api_endpoints
        );

        // Extract the request-response API endpoint
        let endpoint = discovery_doc
            .api_endpoints
            .get("CoSERVRequestResponse")
            .ok_or_else(|| {
                Error::custom("missing key CoSERVRequestResponse in discovery document")
            })?;

        // remove trailing slash from base url to avoid multiple slashes in final coserv_request_response_url
        let coserv_url = coserv_service_base_url.trim_end_matches("/");
        let coserv_request_response_url = format!("{coserv_url}{endpoint}");
        debug!("url for coserv query is: {coserv_request_response_url}");

        builder = builder.with_request_response_url(coserv_request_response_url);

        let query_runner = builder.build()?;

        // Extract the verification key and make an OpenSslVerifier from it
        let verification_key = discovery_doc.result_verification_key;
        let verifier = match verification_key {
            ResultVerificationKey::Jose(jwk) => {
                if jwk.is_empty() {
                    // It is not valid for the server to supply an empty key array
                    // (Servers that do not support signed results should omit the key array field altogether)
                    return Err(Error::custom(
                        "the CoSERV server has returned an empty set of jwk verification keys",
                    ));
                } else if jwk.len() > 1 {
                    // It is valid for the server to return multiple keys.
                    // However, we can't support this due to https://github.com/veraison/coserv-rs/issues/10
                    // We want to catch this as a visible error case.
                    return Err(Error::custom(
                        "the CoSERV server has returned multiple verification keys, which is valid but not supported",
                    ));
                } else {
                    let jwk_str = jwk[0].to_string();
                    debug!("The JWK string for the verification key is {}", jwk_str);
                    let verifier = OpensslVerifier::from_jwk(&jwk_str)?;
                    Some(verifier)
                }
            }
            ResultVerificationKey::Cose(_) => {
                // We requested the discovery document as JSON, not CBOR, so this case should not be possible
                return Err(Error::custom(
                    "verification key should be a JWK in a JSON discovery document",
                ));
            }
            ResultVerificationKey::Undefined => {
                // This is valid, and means that the server does not support verification
                debug!("The CoSERV server does not support signed results.");
                None
            }
        };

        Ok(QueryClient {
            query_runner,
            verifier,
        })
    }

    async fn run_query<'a>(&self, query: &Coserv<'a>, must_sign: bool) -> Result<Coserv<'a>> {
        if must_sign && !self.supports_signing() {
            return Err(Error::custom(
                "CoSERV Service does not support signing, but --must-sign was specified",
            ));
        }

        let result = if must_sign {
            if let Some(verifier) = &self.verifier {
                self.query_runner
                    .execute_query_signed_extracted(query, verifier)
                    .await?
            } else {
                return Err(Error::custom(
                    "signed CoSERV result was requested, but not supported by the server",
                ));
            }
        } else {
            self.query_runner.execute_query_unsigned(query).await?
        };
        Ok(result)
    }

    fn supports_signing(&self) -> bool {
        self.verifier.is_some()
    }
}
