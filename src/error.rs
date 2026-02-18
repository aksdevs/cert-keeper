use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("vault authentication failed: {0}")]
    VaultAuth(String),

    #[error("vault PKI request failed: {0}")]
    VaultPki(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("certificate parse error: {0}")]
    CertParse(String),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
