// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use clap::{Parser, Subcommand};
use log::debug;
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum SubmitCmd {
    /// Submit a policy to the verification service.
    Policy(policy::Args),
}

pub fn cmd(command: SubmitCmd) -> Result<()> {
    match command {
        SubmitCmd::Policy(args) => policy::submit(args),
    }
}

mod policy {
    use super::*;
    use crate::utils;
    use log::info;
    use std::fs;
    use tokio::runtime::Runtime;
    use uuid::Uuid;
    use veraison_apiclient::{
        DiscoveryBuilder, ServiceState,
        auth::{Authenticator, BasicAuthenticator, Oauth2Authenticator},
        http::ConfigureHttp,
        management::PolicyManagerBuilder,
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

        /// Create a new policy for the specified scheme. The policy will be
        /// activated unless --dont-activate (or -d) is specified.
        #[arg(long, conflicts_with_all = &["activate", "deactivate"])]
        new: bool,

        /// Activate an existing policy.
        #[arg(long, conflicts_with_all = &["new", "deactivate"])]
        activate: bool,

        /// Deactivate all policies for a scheme.
        #[arg(long, conflicts_with_all = &["new", "activate"])]
        deactivate: bool,

        /// The attestation scheme for the policy. Default is ARM_CCA.
        #[arg(short = 's', long, default_value = "ARM_CCA")]
        scheme: String,

        /// Path to the Rego policy file (.rego) to submit. Only applicable when --new is specified.
        #[arg(short = 'f', long, value_parser = utils::validate_input_file_path, requires = "new")]
        policy_file: Option<PathBuf>,

        /// Optional human-readable name for the policy. Only applicable when --new is specified.
        #[arg(short = 'n', long, requires = "new")]
        name: Option<String>,

        /// Don't activate the policy after creating it. Only applicable when --new is specified.
        #[arg(short = 'd', long, requires = "new")]
        dont_activate: bool,

        /// Policy UUID to activate. Only applicable when --activate is specified.
        #[arg(short = 'P', long, value_parser = utils::validate_uuid, requires = "activate")]
        policy_id: Option<Uuid>,

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
    }

    /// Submit a policy action to the management service.
    pub fn submit(args: Args) -> Result<()> {
        debug!("Submit policy");

        let Args {
            management_server,
            ca_cert,
            new,
            activate,
            deactivate,
            scheme,
            policy_file,
            name,
            dont_activate,
            policy_id,
            auth,
            username,
            password,
            token_url,
            client_id,
            client_secret,
            ..
        } = args;
        debug!(
            "Loaded arguments: \n
            management_server={management_server}, \n
            ca_cert={ca_cert:?}, \n
            new={new}, \n
            activate={activate}, \n
            deactivate={deactivate}, \n
            scheme={scheme}, \n
            policy_file={policy_file:?}, \n
            name={name:?}, \n
            dont_activate={dont_activate}, \n
            policy_id={policy_id:?}, \n
            auth={auth:?}"
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

            if new {
                debug!("Creating new policy for scheme: {scheme}");
                let Some(policy_file) = policy_file else {
                    return Err(Error::custom("policy file is required for --new action"));
                };

                let Some(_) = management_api.get_api_endpoint("createPolicy") else {
                    return Err(Error::custom(
                        "endpoint to create new policy is missing in management discovery document",
                    ));
                };

                // Validate that the policy file parses as valid Rego/Opa syntax before sending it.
                let rules = fs::read(&policy_file)?;
                utils::validate_policy_rules(&policy_file, &rules)?;

                let created = runner
                    .create_opa_policy(scheme.as_ref(), rules, name.as_deref().unwrap_or(""))
                    .await?;
                info!("created policy: \n{created:?}");

                // If the user has not specified --dont-activate (or -d), activate the policy after creation.
                if !dont_activate {
                    debug!("Activating policy {} for scheme: {scheme}", created.uuid);

                    let Some(_) = management_api.get_api_endpoint("activatePolicy") else {
                        return Err(Error::custom(
                            "endpoint to activate policy is missing in management discovery document",
                        ));
                    };

                    runner
                        .activate_policy(scheme.as_ref(), created.uuid)
                        .await?;
                    info!("activated policy: \n{created:?}");
                }
                Ok(())
            } else if activate {
                debug!("Activating policy {policy_id:?} for scheme: {scheme}");
                let Some(policy_id) = policy_id else {
                    return Err(Error::custom("policy id is required for --activate action"));
                };

                let Some(_) = management_api.get_api_endpoint("activatePolicy") else {
                    return Err(Error::custom(
                        "endpoint to activate policy is missing in management discovery document",
                    ));
                };

                runner.activate_policy(scheme.as_ref(), policy_id).await?;
                info!("activated policy: \n{policy_id:?}");
                Ok(())
            } else if deactivate {
                debug!("Deactivating all policies for scheme: {scheme}");
                let Some(_) = management_api.get_api_endpoint("deactivatePolicies") else {
                    return Err(Error::custom(
                        "endpoint to deactivate policy is missing in management discovery document",
                    ));
                };

                runner.deactivate_all_policies(scheme.as_ref()).await?;
                info!("deactivated all policy for {scheme:?}");
                Ok(())
            } else {
                Err(Error::custom(
                    "one of --new, --activate, or --deactivate must be specified",
                ))
            }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path, query_param},
        };

        fn policy_path_and_content() -> (PathBuf, String) {
            let path = PathBuf::from("test/policy/allow-all.rego");
            let content = fs::read_to_string(&path).unwrap();
            (path, content)
        }

        async fn start_mock_management_server(policy_id: Uuid) -> MockServer {
            let server = MockServer::start().await;
            let discovery_document = fs::read("test/json/managementdiscoverydoc.json").unwrap();
            let (_, policy_text) = policy_path_and_content();

            Mock::given(method("GET"))
                .and(path("/.well-known/veraison/management"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    discovery_document,
                    "application/vnd.veraison.discovery+json",
                ))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/management/v1/policy/ARM_CCA"))
                .and(query_param("name", "my-policy"))
                .and(header(
                    "content-type",
                    "application/vnd.veraison.policy.opa",
                ))
                .and(header("accept", "application/vnd.veraison.policy+json"))
                .and(wiremock::matchers::body_string(&policy_text))
                .respond_with(
                    ResponseTemplate::new(201)
                        .insert_header("content-type", "application/vnd.veraison.policy+json")
                        .set_body_raw(
                            serde_json::json!({
                                "uuid": policy_id,
                                "ctime": "2026-09-09T00:00:00Z",
                                "name": "my-policy",
                                "type": "opa",
                                "rules": policy_text,
                                "active": false
                            })
                            .to_string(),
                            "application/vnd.veraison.policy+json",
                        ),
                )
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path(format!(
                    "/management/v1/policy/ARM_CCA/{policy_id}/activate"
                )))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .and(path("/management/v1/policies/ARM_CCA/deactivate"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            debug!("Mock server running at {}", server.uri());

            server
        }

        #[test]
        fn test_policy_creation_activation_deactivation() {
            let policy_id = Uuid::new_v4();
            let server = Runtime::new()
                .unwrap()
                .block_on(async { start_mock_management_server(policy_id).await });
            let policy_file = PathBuf::from("test/policy/allow-all.rego");

            let create_args = Args {
                management_server: server.uri(),
                ca_cert: None,
                new: true,
                activate: false,
                deactivate: false,
                scheme: "ARM_CCA".into(),
                policy_file: Some(policy_file),
                name: Some("my-policy".into()),
                dont_activate: false,
                policy_id: None,
                auth: AuthMethod::Passthrough,
                username: None,
                password: None,
                token_url: None,
                client_id: None,
                client_secret: None,
            };

            let activate_args = Args {
                management_server: server.uri(),
                ca_cert: None,
                new: false,
                activate: true,
                deactivate: false,
                scheme: "ARM_CCA".into(),
                policy_file: None,
                name: None,
                dont_activate: false,
                policy_id: Some(policy_id),
                auth: AuthMethod::Passthrough,
                username: None,
                password: None,
                token_url: None,
                client_id: None,
                client_secret: None,
            };

            let deactivate_args = Args {
                management_server: server.uri(),
                ca_cert: None,
                new: false,
                activate: false,
                deactivate: true,
                scheme: "ARM_CCA".into(),
                policy_file: None,
                name: None,
                dont_activate: false,
                policy_id: None,
                auth: AuthMethod::Passthrough,
                username: None,
                password: None,
                token_url: None,
                client_id: None,
                client_secret: None,
            };

            for args in [create_args, activate_args, deactivate_args] {
                assert!(policy::submit(args).is_ok());
            }
        }

        #[test]
        fn test_policy_submission_with_invalid_rego() {
            let policy_id = Uuid::new_v4();
            let server = Runtime::new()
                .unwrap()
                .block_on(async { start_mock_management_server(policy_id).await });
            let invalid_file = PathBuf::from("test/policy/invalid.rego");

            let args = Args {
                management_server: server.uri(),
                ca_cert: None,
                new: true,
                activate: false,
                deactivate: false,
                scheme: "ARM_CCA".into(),
                policy_file: Some(invalid_file),
                name: Some("bad-policy".into()),
                dont_activate: false,
                policy_id: None,
                auth: AuthMethod::Passthrough,
                username: None,
                password: None,
                token_url: None,
                client_id: None,
                client_secret: None,
            };

            let result = policy::submit(args);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("invalid Rego policy")
            );
        }
    }
}
