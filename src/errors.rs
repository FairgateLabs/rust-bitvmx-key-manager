use bitcoin::{hashes::FromSliceError, secp256k1};
use thiserror::Error;

use config as settings;

#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("Secure storage error")]
    SecureStorageError(#[from] SecureStorageError),

    #[error("Invalid private key: {0}")]
    PrivKeySliceError(#[from] bitcoin::key::FromWifError),

    #[error("Failed to create DerivationPath, Xpriv or ChildNumber: {0}")]
    Bip32Error(#[from] bitcoin::bip32::Error),

    #[error("Failed to create new Winternitz key")]
    WinternitzGenerationError(#[from] WinternitzError),

    #[error("Entry not found for public key")]
    EntryNotFound,
}

#[derive(Error, Debug)]
pub enum SecureStorageError {
    #[error("Failed to access secure storage")]
    StorageError(#[from] std::io::Error),

    #[error("Failed to decode data")]
    FailedToDecodeData(#[from] FromSliceError),

    #[error("Failed to decode private key")]
    FailedToDecodePrivateKey(#[from] secp256k1::Error),

    #[error("Failed to decode public key")]
    FailedToDecodePublicKey(#[from] bitcoin::key::FromSliceError),

    #[error("Failed to encrypt data")]
    FailedToEncryptData {
        error: cocoon::Error,
    },

    #[error("Failed to decrypt data")]
    FailedToDecryptData {
        error: cocoon::Error,
    },

    #[error("Failed to convert data to byte array")]
    CorruptedData
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Bad argument: {msg}")]
    BadArgument { msg: String },

    #[error("Unexpected error: {0}")]
    UnexpectedError(String),

    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    #[error("Invalid Winternitz Type: {0}")]
    InvalidWinternitzType(String),
    
    #[error("Invalid Configuration File: {0}")]
    InvalidConfigFile(String),

    #[error("Invalid Hex String: {0}")]
    InvalidHexString(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("while trying to build configuration")]
    ConfigFileError(#[from] settings::ConfigError),
}

#[derive(Error, Debug)]
pub enum WinternitzError {
    #[error("Index overflow: cannot generate more keys")]
    IndexOverflow,

    #[error("Hash size of {0} bytes does not match the size specified in the Winternitz type {1}")]
    HashSizeMissmatch(usize, String),

    #[error("Signature size of {0} bytes must be a multiple of the size specified in the Winternitz type {1}")]
    InvalidSignatureLength(usize, String),
}
