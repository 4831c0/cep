#[derive(Debug, thiserror::Error)]
pub enum CepError {
    #[error("Structure hasn't been initialized properly before use")]
    StructUninitialized,
    #[error("Invalid key length")]
    InvalidKey,
    #[error("General encryption failure")]
    EncryptionFailure
}