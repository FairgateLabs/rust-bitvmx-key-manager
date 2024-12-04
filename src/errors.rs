use bitcoin::{hashes::FromSliceError, key::ParsePublicKeyError, secp256k1};
use thiserror::Error;

use config as settings;

#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("Invalid private key: {0}")]
    FailedToParsePublicKey(#[from] ParsePublicKeyError),

    #[error("Invalid private key: {0}")]
    FailedToParsePrivateKey(#[from] bitcoin::key::FromWifError),

    #[error("Failed to create DerivationPath, Xpriv or ChildNumber: {0}")]
    Bip32Error(#[from] bitcoin::bip32::Error),

    #[error("Failed to create new Winternitz key")]
    WinternitzGenerationError(#[from] WinternitzError),

    #[error("Failed to tweak secret key")]
    FailedToTweakKey(#[from] secp256k1::Error),

    #[error("Failed to access secure storage")]
    KeyStorageError(#[from] KeyStoreError),

    #[error("Entry not found for public key")]
    EntryNotFound,
}

#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("Failed to access secure storage")]
    StorageError(#[from] std::io::Error),

    #[error("Failed to open secure storage")]
    OpenError,

    #[error("Failed to write secure storage")]
    WriteError(#[from] rocksdb::Error),

    #[error("Failed to read secure storage")]
    ReadError(rocksdb::Error),

    #[error("Failed to decode data")]
    FailedToDecodeData(#[from] FromSliceError),

    #[error("Failed to decode private key")]
    FailedToDecodePrivateKey(#[from] secp256k1::Error),

    #[error("Failed to decode public key")]
    FailedToDecodePublicKey(#[from] bitcoin::key::FromSliceError),

    #[error("Failed to encrypt data")]
    FailedToEncryptData { error: cocoon::Error },

    #[error("Failed to decrypt data")]
    FailedToDecryptData { error: cocoon::Error },

    #[error("Failed to load Winternitz seed from key store")]
    WinternitzSeedNotFound,

    #[error("Failed to load the BIP32 key derivation seed from key store")]
    KeyDerivationSeedNotFound,

    #[error("Failed to convert data to byte array")]
    CorruptedData,
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

    #[error("Winternitz seed is invalid")]
    InvalidWinternitzSeed,

    #[error("Key derivation seed is invalid")]
    InvalidKeyDerivationSeed,
}

#[derive(Error, Debug)]
pub enum WinternitzError {
    #[error("Index overflow: cannot generate more keys")]
    IndexOverflow,

    #[error("Hash size of {0} bytes does not match the size specified in the Winternitz type {1}")]
    HashSizeMissmatch(usize, String),

    #[error("Signature size of {0} bytes must be a multiple of the size specified in the Winternitz type {1}")]
    InvalidSignatureLength(usize, String),

    #[error("Public key size of {0} bytes must be a multiple of the size specified in the Winternitz type {1}")]
    InvalidPublicKeyLength(usize, String),

    #[error("Invalid Winternitz type {0}")]
    InvalidWinternitzType(String),

    #[error("Extra data in Winternitz Public Key missing {0}")]
    ExtraDataMissing(String),
}
