use bitcoin::Network;
use config::KeyManagerConfig;
use errors::{ConfigError, KeyManagerError};
use key_manager::KeyManager;
use key_store::KeyStore;
use std::rc::Rc;
use std::str::FromStr;
use storage_backend::storage::Storage;

pub mod cli;
pub mod config;
pub mod errors;
pub mod key_manager;
pub mod key_store;
pub mod musig2;
pub mod tests;
pub mod verifier;
pub mod winternitz;

pub fn create_key_manager_from_config(
    key_manager_config: &KeyManagerConfig,
    keystore: KeyStore,
    store: Rc<Storage>,
) -> Result<KeyManager, KeyManagerError> {
    let key_derivation_seed = decode_key_derivation_seed(&key_manager_config.key_derivation_seed)?;
    let key_derivation_path = &key_manager_config.key_derivation_path;
    let winternitz_seed = decode_winternitz_seed(&key_manager_config.winternitz_seed)?;
    let network =
        Network::from_str(&key_manager_config.network).map_err(|_| ConfigError::InvalidNetwork)?;

    let key_manager = KeyManager::new(
        network,
        key_derivation_path,
        key_derivation_seed,
        winternitz_seed,
        keystore,
        store,
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
