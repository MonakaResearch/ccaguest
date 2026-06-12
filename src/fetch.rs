// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::{cli::CommonFlags, error::Result};
use clap::{ArgGroup, Parser, Subcommand};
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
    use crate::utils;

    #[derive(Debug, Parser)]
    pub struct Args {
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

        /// Common flags for all commands.
        #[command(flatten)]
        pub common: CommonFlags,
    }

    pub fn fetch(_args: Args) -> Result<()> {
        todo!()
    }
}

mod endorsements {
    use super::*;
    use crate::utils;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Implementation ID. Use this to fetch reference values.
        #[arg(short = 'E', long, conflicts_with = "evidence")]
        impl_id: Option<String>,

        /// Instance ID. Use this to fetch trust anchors.
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
        #[arg(short = 'l', long, value_parser = utils::validate_input_file_path)]
        local_cache: Option<PathBuf>,

        /// The server MUST sign CoSERV results. The command fails
        /// if the server does not support signing.
        #[arg(long, default_value_t = false)]
        must_sign: bool,

        /// CoSERV Result type: collected (default), source or both
        #[arg(short, long, default_value = "collected")]
        result_type: String,

        /// Output file path for fetched trust anchor. If not specified, the trust anchor output will
        /// be saved to default `coserv_ta.cbor` in the current working directory.
        #[arg(long, value_parser = utils::validate_output_path, default_value = "coserv_ta.cbor")]
        output_ta: PathBuf,

        /// Output file path for fetched reference values. If not specified, the reference values will
        /// be saved to default `coserv_rv.cbor` in the current working directory.
        #[arg(long, value_parser = utils::validate_output_path, default_value = "coserv_rv.cbor")]
        output_rv: PathBuf,

        /// Common flags for all commands.
        #[command(flatten)]
        pub common: CommonFlags,
    }

    pub fn fetch(_args: Args) -> Result<()> {
        todo!()
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

        /// Common flags for all commands.
        #[command(flatten)]
        pub common: CommonFlags,
    }

    /// Fetch policies from the verification service.
    pub fn fetch(_args: Args) -> Result<()> {
        todo!()
    }
}
