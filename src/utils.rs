// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use base64::{Engine as _, engine::general_purpose};
use log::debug;
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

/// Validates that an input file exists and is readable.
pub fn validate_input_file_path(path: &str) -> Result<PathBuf> {
    let path_buf = PathBuf::from(path);
    if path_buf.is_file() {
        Ok(path_buf)
    } else {
        Err(Error::custom(format!(
            "file '{}' not found",
            path_buf.display()
        )))
    }
}

/// Validates that an input directory exists and is readable.
pub fn validate_input_directory_path(path: &str) -> Result<PathBuf> {
    let path_buf = PathBuf::from(path);
    if path_buf.is_dir() {
        Ok(path_buf)
    } else {
        Err(Error::custom(format!(
            "directory '{}' not found",
            path_buf.display()
        )))
    }
}

/// validate_output_path will check if output path is valid.
pub fn validate_output_path(path: &str) -> Result<PathBuf> {
    if path.trim().is_empty() {
        return Err(Error::custom("output path is empty"));
    }
    let path_buf = PathBuf::from(path);
    Ok(path_buf)
}

/// validate_base_url will check if the provided URL is valid base URL.
pub fn validate_base_url(url: &str) -> Result<String> {
    let parsed_url = Url::parse(url)?;

    if parsed_url.cannot_be_a_base() {
        return Err(Error::RelativeUrlWithoutBase);
    }

    let scheme = parsed_url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(Error::IncorrectScheme {
            scheme: scheme.to_string(),
        });
    }

    Ok(url.to_string())
}

/// decode_base64_url_nopad will decode a base64url-encoded string (without padding) into bytes.
pub fn decode_base64_url_nopad(encoded: &str) -> Result<Vec<u8>> {
    Ok(general_purpose::URL_SAFE_NO_PAD.decode(encoded)?)
}

/// decode_base64_std_nopad will decode a Standard base64-encoded string (without padding) into bytes.
fn decode_base64_std_nopad(encoded: &str) -> Result<Vec<u8>> {
    Ok(general_purpose::STANDARD_NO_PAD.decode(encoded)?)
}

/// decode_base64 with decode_base64_url_nopad, if it fails then try decode_base64_std_nopad
pub fn decode_base64(encoded: &str) -> Result<Vec<u8>> {
    let encoded = encoded.trim_end_matches('=');
    match decode_base64_url_nopad(encoded) {
        Ok(decoded) => Ok(decoded),
        Err(_) => decode_base64_std_nopad(encoded),
    }
}

/// write given content to output file
pub fn write_output_to_file<C>(content: C, output: &Path) -> Result<()>
where
    C: AsRef<[u8]>,
{
    if let Some(parent) = output.parent()
        && !parent.is_dir()
        && !parent.is_empty()
    {
        fs::create_dir_all(parent)?;
        debug!("created parent directory: {:?}", parent);
    }
    fs::write(output, content)?;
    Ok(())
}

/// check if output file already exist and is allowed to overwrite
pub fn check_output_file(output: &Path, force: bool) -> Result<()> {
    if output.is_file() && !force {
        return Err(Error::custom(format!(
            "Output file '{:?}' already exists. Use --force to overwrite.",
            output
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_input_file_path() {
        let result = validate_input_file_path("test/json/iak.jwk");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_input_file_path() {
        let result = validate_input_file_path(".../abc.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_input_file_path_2() {
        let result = validate_input_file_path("docs");
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_input_directory_path() {
        let result = validate_input_directory_path("docs");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_input_directory_path() {
        let result = validate_input_directory_path("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_output_path() {
        let result = validate_output_path("");
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_base_url() {
        let result = validate_base_url("http://example.com/");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_base_url() {
        let result = validate_base_url("example.com/");
        assert!(result.is_err());
    }
}
