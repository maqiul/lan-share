use thiserror::Error;

#[derive(Error, Debug)]
pub enum LspError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Transfer error: {0}")]
    Transfer(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Invalid frame: {0}")]
    InvalidFrame(String),

    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Window full")]
    WindowFull,

    // v3.0 新增
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("Retransmission limit exceeded for stream {0}")]
    RetransmitLimitExceeded(u32),

    #[error("Delta sync error: {0}")]
    DeltaSync(String),

    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Flow control: zero window on stream {0}")]
    ZeroWindow(u32),

    #[error("Congestion: stream {0} in fast recovery")]
    FastRecovery(u32),
}

pub type Result<T> = std::result::Result<T, LspError>;
