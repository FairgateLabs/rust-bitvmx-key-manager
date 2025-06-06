use thiserror::Error;

#[derive(Error, Debug)]
pub enum Musig2SignerError {
    #[error("Storage error: {0}")]
    StorageError(#[from] storage_backend::error::StorageError),

    #[error("Aggregated public key not found")]
    AggregatedPubkeyNotFound,

    #[error("ID not found")]
    IdNotFound,

    #[error("Partial signature already exists")]
    PartialSignatureAlreadyExists,

    #[error("Incomplete number of partial signatures")]
    InvalidParticipantPartialSignatures,

    #[error("Invalid number of participant nonces")]
    InvalidParticipantNonces,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid number of participants")]
    InvalidNumberOfParticipants,

    #[error("Incomplete participant nonces")]
    IncompleteParticipantNonces,

    #[error("Invalid partial signature")]
    InvalidPartialSignature,

    #[error("Invalid final signature")]
    InvalidFinalSignature,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid signature length")]
    InvalidSignatureLength,

    #[error("Nonce seed error")]
    NonceSeedError,

    #[error("Failed to convert public key")]
    ConvertionPublicKeyError,

    #[error("Duplicated message")]
    DuplicatedMessage,

    #[error("Nonce already exists")]
    NonceAlreadyExists,

    #[error("Invalid message id")]
    InvalidMessageId,

    #[error("Nonces not generated")]
    NoncesNotGenerated,

    #[error("Can't rebuild tweak: {0}")]
    CantRebuildTweak(#[from] musig2::secp256k1::scalar::OutOfRangeError),

    #[error("Can´t reconstruct value: {0}")]
    CantReconstructValue(String),
}
