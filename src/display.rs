// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cli::CommonFlags,
    error::{Error, Result},
};
use clap::{Parser, Subcommand};
use log::debug;
use std::fs;
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
    use regl::attesters::cca::utils::decode_cca_token;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Path to the evidence file in CBOR format.
        #[arg(short, long, value_parser = utils::validate_input_file_path)]
        file: PathBuf,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    pub fn display(args: Args) -> Result<()> {
        debug!("Displaying evidence file: {:?}", args.file);

        let raw = fs::read(args.file)?;
        let token = decode_cca_token(&raw)?;

        debug!("Pretty print: {}", args.common.pretty);
        let evidence_json = if args.common.pretty {
            serde_json::to_string_pretty(&token)?
        } else {
            serde_json::to_string(&token)?
        };

        println!("{evidence_json}");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_display_evidence() {
            let args = evidence::Args {
                file: "test/cbor/ccatoken.cbor".into(),
                common: CommonFlags {
                    pretty: true,
                    force: false,
                },
            };
            let result = evidence::display(args);
            assert!(result.is_ok());
        }
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

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
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

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    pub fn display(args: Args) -> Result<()> {
        debug!("Displaying EAR file: {:?}", args.file);

        let bytes = fs::read_to_string(&args.file)
            .map_err(|e| Error::Custom(format!("failed to read EAR file: {e}")))?;

        let parts: Vec<&str> = bytes.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidValue {
                value: bytes.to_string(),
                expected: "a JWK in the format of header.payload.signature",
            });
        }

        let payload = utils::decode_base64_url_nopad(parts[1])?;
        let ear_value: serde_json::Value = serde_json::from_slice(&payload)?;

        debug!("Pretty print: {}", args.common.pretty);
        let ear_json = if args.common.pretty {
            serde_json::to_string_pretty(&ear_value)?
        } else {
            serde_json::to_string(&ear_value)?
        };

        println!("{ear_json}");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_display_ear() {
            let args = ear::Args {
                file: "test/json/ear.jwk".into(),
                common: CommonFlags {
                    pretty: true,
                    force: false,
                },
            };
            let result = ear::display(args);
            assert!(result.is_ok());
        }
    }
}
