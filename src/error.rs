use thiserror::Error;

#[derive(Error, Debug)]
pub enum LockdownError {
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Safety check failed: {0}")]
    Safety(String),

    #[error("Master password error: {0}")]
    MasterPassword(String),

    #[error("{0}")]
    Other(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, LockdownError>;
