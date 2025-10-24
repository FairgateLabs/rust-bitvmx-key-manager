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

pub fn create_key_manager_from_config(
    key_manager_config: &KeyManagerConfig,
    storage_config: StorageConfig,
) -> Result<KeyManager, KeyManagerError> {
    let key_derivation_seed = match &key_manager_config.key_derivation_seed {
        Some(seed) => Some(decode_key_derivation_seed(seed)?),
        None => None,
    };

    let winternitz_seed = match &key_manager_config.winternitz_seed {
        Some(seed) => Some(decode_winternitz_seed(seed)?),
        None => None,
    };

    let network =
        Network::from_str(&key_manager_config.network).map_err(|_| ConfigError::InvalidNetwork)?;

    let key_manager = KeyManager::new(
        network,
        key_derivation_seed,
        winternitz_seed,
        storage_config,
    )?;

    Ok(key_manager)
}

fn decode_winternitz_seed(seed: &str) -> Result<[u8; 32], ConfigError> {
    let winternitz_seed = hex::decode(seed).map_err(|_| ConfigError::InvalidWinternitzSeed)?;
    if winternitz_seed.len() > 32 {
        return Err(ConfigError::InvalidWinternitzSeed);
    }
    winternitz_seed
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::InvalidWinternitzSeed)
}

fn decode_key_derivation_seed(seed: &str) -> Result<[u8; 32], ConfigError> {
    let key_derivation_seed =
        hex::decode(seed).map_err(|_| ConfigError::InvalidKeyDerivationSeed)?;
    if key_derivation_seed.len() > 32 {
        return Err(ConfigError::InvalidKeyDerivationSeed);
    }
    key_derivation_seed
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::InvalidKeyDerivationSeed)
}
