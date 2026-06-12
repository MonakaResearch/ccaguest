// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("relative URL without base is not allowed")]
    RelativeUrlWithoutBase,

    #[error("incorrect URL scheme: {scheme}")]
    IncorrectScheme { scheme: String },

    #[error("failed to parse url: {0}")]
    Url(#[from] url::ParseError),

    // -- custom --
    #[error("{0}")]
    Custom(String),
}

impl Error {
    pub fn custom<T>(val: T) -> Self
    where
        T: Display,
    {
        Error::Custom(val.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
