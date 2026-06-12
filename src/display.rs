// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::{cli::CommonFlags, error::Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum DisplayCmd {
    /// Display evidence.
    Evidence(evidence::Args),

    /// Display endorsements.
    Endorsements(endorsements::Args),

    /// Display entity attestation results (EAR).
    Ear(ear::Args),
}

pub fn cmd(command: DisplayCmd) -> Result<()> {
    match command {
        DisplayCmd::Evidence(args) => evidence::display(args),
        DisplayCmd::Endorsements(args) => endorsements::display(args),
        DisplayCmd::Ear(args) => ear::display(args),
    }
}

mod evidence {
    use super::*;
    use crate::utils;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Path to the evidence file in CBOR format.
        #[arg(short, long, value_parser = utils::validate_input_file_path)]
        file: PathBuf,

        /// Common flags for all commands.
        #[command(flatten)]
        pub common: CommonFlags,
    }
    pub fn display(_args: Args) -> Result<()> {
        todo!()
    }
}

mod endorsements {
    use super::*;
    use crate::utils;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Path to the endorsements file in CBOR format.
        #[arg(short, long, value_parser = utils::validate_input_file_path)]
        file: PathBuf,

        /// Common flags for all commands.
        #[command(flatten)]
        pub common: CommonFlags,
    }
    pub fn display(_args: Args) -> Result<()> {
        todo!()
    }
}

mod ear {
    use super::*;
    use crate::utils;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Path to the EAR file in JWK format.
        #[arg(short, long, value_parser = utils::validate_input_file_path)]
        file: PathBuf,

        /// Common flags for all commands.
        #[command(flatten)]
        pub common: CommonFlags,
    }
    pub fn display(_args: Args) -> Result<()> {
        todo!()
    }
}
