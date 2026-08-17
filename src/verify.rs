// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::{cli::CommonFlags, error::Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum VerifyCmd {
    /// Local verification.
    Local(local::Args),

    /// Remote verification.
    Remote(remote::Args),
}

pub fn cmd(command: VerifyCmd) -> Result<()> {
    match command {
        VerifyCmd::Local(args) => local::verify(args),
        VerifyCmd::Remote(args) => remote::verify(args),
    }
}

mod local {
    use super::*;
    use crate::utils;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Path to an evidence file in CBOR format. If not provided,
        /// a new evidence will be generated on the fly.
        /// If second option is used, a nonce can also be provided using a
        /// text file for raw nonce bytes or string for hex and base64-encoded nonce.
        ///  The argument for that includes the nonce's encoding
        /// (--nonce_<raw | hex | base64 | base64url>). If the nonce is not
        /// exactly 64B long, it is truncated/right padded with zero bytes,
        /// to make it 64B long.
        #[arg(short, long, value_parser=utils::validate_input_file_path,  conflicts_with_all = &["nonce_raw", "nonce_hex", "nonce_b64", "nonce_b64url"])]
        evidence: Option<PathBuf>,

        /// Path to a text file containing nonce as raw bytes.
        #[arg(long, value_parser = utils::validate_input_file_path, conflicts_with_all = &["evidence", "nonce_hex", "nonce_b64", "nonce_b64url"])]
        nonce_raw: Option<PathBuf>,

        /// A hex-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_b64", "nonce_b64url"])]
        nonce_hex: Option<String>,

        /// A base64-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_hex", "nonce_b64url"])]
        nonce_b64: Option<String>,

        /// A base64url-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_hex", "nonce_b64"])]
        nonce_b64url: Option<String>,

        /// Path to the reference values file. Must be a CoSERV results file in CBOR format.
        #[arg(short = 'R', long, value_parser = utils::validate_input_file_path)]
        reference_values: Option<PathBuf>,

        /// Path to the trust anchor file. Must be a CoSERV results file in CBOR format.
        #[arg(short = 'T', long, value_parser = utils::validate_input_file_path)]
        trust_anchor: Option<PathBuf>,

        /// The base URL to a CoSERV service if endorsements are not present locally.
        /// Coserv service should support the result-type=collected.
        #[arg(short = 'S', long, value_parser = utils::validate_base_url, required_unless_present_all = ["reference_values", "trust_anchor"])]
        coserv_server: Option<String>,

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

        /// Output file path for writing the attestation results. If not specified,
        /// the attestation results will be saved to default `ear.json` in the current working directory.
        #[arg(short, long, value_parser = utils::validate_output_path, default_value = "ear.json")]
        output: PathBuf,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    /// Verify an ARM-CCA based Confidential (Realm) VM using a local verifier.
    pub fn verify(_args: Args) -> Result<()> {
        todo!()
    }
}

mod remote {
    use super::*;
    use crate::utils;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// The base URL to a verification service.
        #[arg(short = 'S', long, value_parser = utils::validate_base_url)]
        verification_server: String,

        /// The path to an X509 certificate to bootstrap TLS handshakes with the verification service.
        #[arg(short = 't', long, value_parser = utils::validate_input_file_path)]
        ca_cert: Option<PathBuf>,

        /// Output file path for writing the attestation results. If not specified,
        /// the attestation results will be saved to default `ear.jwt` in the current working directory.
        #[arg(short, long, value_parser = utils::validate_output_path, default_value = "ear.jwt")]
        output: PathBuf,

        /// Optional policy ID to use for verification
        #[arg(short = 'P', long)]
        policy_id: Option<String>,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    /// Verify an ARM-CCA based Confidential (Realm) VM using a remote verifier.
    pub fn verify(_args: Args) -> Result<()> {
        todo!()
    }
}
