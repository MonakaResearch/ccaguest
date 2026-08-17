// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::{cli::CommonFlags, error::Result};
use clap::{Parser, Subcommand};
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

    #[derive(Debug, Parser)]
    pub struct Args {
        /// The base URL of the management service.
        #[arg(short = 'S', long, value_parser = utils::validate_base_url)]
        management_server: String,

        /// The path to an X509 certificate to bootstrap TLS handshakes with the management service.
        #[arg(short = 't', long, value_parser = utils::validate_input_file_path)]
        ca_cert: Option<PathBuf>,

        /// Policy ID to assign to the submitted policy.
        #[arg(short = 'P', long)]
        policy_id: String,

        /// Path to the Rego policy file (.rego).
        #[arg(short = 'f', long, value_parser = utils::validate_input_file_path)]
        policy_file: PathBuf,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    /// Submit a policy to the management service.
    pub fn submit(_args: Args) -> Result<()> {
        todo!()
    }
}
