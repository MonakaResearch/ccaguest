// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};

use crate::{display::DisplayCmd, fetch::FetchCmd, submit::SubmitCmd, verify::VerifyCmd};

#[derive(Debug, Clone, Args)]
pub struct CommonFlags {
    /// Pretty print the output.
    #[arg(short, long, default_value_t = false)]
    pub pretty: bool,

    /// Force write if output exists.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

/// Command-line tool for performing ARM CCA features: evidence generation, evidence verification,
/// endorsements & policy fetching, policy submission. It can also be used to
/// display evidence, ear and endorsements.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Display commands e.g., evidence, endorsements, ear
    #[command(subcommand)]
    Display(DisplayCmd),

    /// Fetch commands e.g., evidence, endorsements, policy
    #[command(subcommand)]
    Fetch(FetchCmd),

    /// Submit commands e.g., policy
    #[command(subcommand)]
    Submit(SubmitCmd),

    /// Verification-related commands e.g., remote, local
    #[command(subcommand)]
    Verify(VerifyCmd),
}
