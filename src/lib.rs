use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::Network;
use config::{KeyManagerConfig, KeyStorageConfig};
use errors::{ConfigError, KeyManagerError};
use key_manager::KeyManager;
use keystorage::{database::DatabaseKeyStore, file::FileKeyStore, keystore::KeyStore};

pub mod cli;
pub mod config;
pub mod errors;
pub mod key_manager;
pub mod keystorage;
pub mod verifier;
pub mod winternitz;

fn decode_data(
    store_config: &KeyStorageConfig,
    network: &str,
) -> Result<(PathBuf, Vec<u8>, Network), KeyManagerError> {
    let path = PathBuf::from(&store_config.path);
    let password: Vec<u8> = store_config.password.as_bytes().to_vec();
    let network = Network::from_str(network).map_err(|_| ConfigError::InvalidNetwork)?;
    Ok((path, password, network))
}

pub fn create_file_key_store_from_config(
    store_config: &KeyStorageConfig,
    network: &str,
) -> Result<FileKeyStore, KeyManagerError> {
    let (path, password, network) = decode_data(store_config, network)?;
    Ok(FileKeyStore::new(path, password, network)?)
}

pub fn create_database_key_store_from_config(
    store_config: &KeyStorageConfig,
    network: &str,
) -> Result<DatabaseKeyStore, KeyManagerError> {
    let (path, password, network) = decode_data(store_config, network)?;
    Ok(DatabaseKeyStore::new(path, password, network)?)
}

pub fn create_key_manager_from_config<K: KeyStore>(
    key_manager_config: &KeyManagerConfig,
    keystore: K,
) -> Result<KeyManager<K>, KeyManagerError> {
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
    )?;

    Ok(key_manager)
}

fn decode_winternitz_seed(seed: &str) -> Result<[u8; 32], ConfigError> {
    let winternitz_seed = hex::decode(seed).map_err(|_| ConfigError::InvalidWinternitzSeed)?;
    if winternitz_seed.len() > 32 {
        return Err(ConfigError::InvalidWinternitzSeed);
    }
    Ok(winternitz_seed
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::InvalidWinternitzSeed)?)
}

fn decode_key_derivation_seed(seed: &str) -> Result<[u8; 32], ConfigError> {
    let key_derivation_seed =
        hex::decode(seed).map_err(|_| ConfigError::InvalidKeyDerivationSeed)?;
    if key_derivation_seed.len() > 32 {
        return Err(ConfigError::InvalidKeyDerivationSeed);
    }
    Ok(key_derivation_seed
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::InvalidKeyDerivationSeed)?)
}
