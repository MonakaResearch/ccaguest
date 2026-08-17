// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Display;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid value: {value}, expected {expected}")]
    InvalidValue {
        value: String,
        expected: &'static str,
    },

    #[error("missing mandatory field {object}.{field}")]
    MissingField {
        object: &'static str,
        field: &'static str,
    },

    #[error("relative URL without base is not allowed")]
    RelativeUrlWithoutBase,

    #[error("incorrect URL scheme: {scheme}")]
    IncorrectScheme { scheme: String },

    #[error("failed to parse url: {0}")]
    Url(#[from] url::ParseError),

    #[error("failed to decode base64url: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("regl error: {0}")]
    Regl(#[from] regl::attesters::cca::CcaError),

    #[error(transparent)]
    Apiclient(#[from] veraison_apiclient::Error),

    #[error(transparent)]
    Corim(#[from] coserv_rs::coserv::corim_rs::Error),

    #[error(transparent)]
    CorimError(#[from] coserv_rs::coserv::corim_rs::CorimError),

    #[error(transparent)]
    Coserv(#[from] coserv_rs::error::CoservError),

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
