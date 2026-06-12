// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use std::path::PathBuf;
use url::Url;

/// Validates that an input file exists and is readable.
pub fn validate_input_file_path(path: &str) -> Result<PathBuf> {
    let path_buf = PathBuf::from(path);
    if path_buf.is_file() {
        Ok(path_buf)
    } else if path_buf.is_dir() {
        Err(Error::custom(format!(
            "'{}' is a directory, not a file",
            path_buf.display()
        )))
    } else {
        Err(Error::custom(format!(
            "file '{}' not found",
            path_buf.display()
        )))
    }
}

/// validate_output_path will check if output path is valid.
pub fn validate_output_path(path: &str) -> Result<PathBuf> {
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

    // this is needed because https://github.com/veraison/rust-apiclient/blob/main/src/lib.rs#L426C5-L439C13
    // directly joins base url with well known endpoint path, which can lead to double slashes in the final url
    // if base url ends with a slash. So we need to normalize the base url by removing trailing slashes from the path.
    // TO-DO: remove after issue https://github.com/veraison/rust-apiclient/issues/40 is resolved in OSS.
    let mut normalized = parsed_url;
    let path = normalized.path().to_string();
    let normalized_path = if path.is_empty() || path == "/" {
        String::new()
    } else {
        path.trim_end_matches('/').to_string()
    };
    normalized.set_path(&normalized_path);

    Ok(normalized.to_string())
}
