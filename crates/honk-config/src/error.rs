use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Include error: {0}")]
    Include(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Unknown node protocol: {0}")]
    UnknownProtocol(String),

    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),
}
