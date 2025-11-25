use bip39::Mnemonic;
use bitcoin::Network;
use config::KeyManagerConfig;
use errors::{ConfigError, KeyManagerError};
use key_manager::KeyManager;
use std::str::FromStr;
use storage_backend::storage_config::StorageConfig;

pub mod cli;
pub mod config;
pub mod errors;
pub mod key_manager;
pub mod key_store;
pub mod key_type;
pub mod musig2;
pub mod rsa;
pub mod tests;
pub mod verifier;
pub mod winternitz;

// Re-exports
pub use bitcoin;
pub use bitvmx_settings;
pub use storage_backend;

pub fn create_key_manager_from_config(
    key_manager_config: &KeyManagerConfig,
    storage_config: StorageConfig,
) -> Result<KeyManager, KeyManagerError> {
    let mnemonic = match &key_manager_config.mnemonic_sentence {
        Some(mnemonic_sentence) => Some(decode_key_derivation_seed(mnemonic_sentence)?),
        None => None,
    };

    let passphrase = match &key_manager_config.mnemonic_passphrase {
        Some(pass) => Some(pass.clone()),
        None => None,
    };

    let network =
        Network::from_str(&key_manager_config.network).map_err(|_| ConfigError::InvalidNetwork)?;

    let key_manager = KeyManager::new(network, mnemonic, passphrase, storage_config)?;

    Ok(key_manager)
}

fn decode_key_derivation_seed(mnemonic_sentence: &str) -> Result<Mnemonic, ConfigError> {
    Mnemonic::parse(mnemonic_sentence).map_err(|_| ConfigError::InvalidMnemonicSentence)
}
