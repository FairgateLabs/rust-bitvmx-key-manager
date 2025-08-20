use bitcoin::Network;
use config::KeyManagerConfig;
use errors::{ConfigError, KeyManagerError};
use key_manager::KeyManager;
use key_store::KeyStore;
use std::rc::Rc;
use std::str::FromStr;
use storage_backend::storage::Storage;
use bip39::{Language, Mnemonic};

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
    let key_derivation_seed = match &key_manager_config.key_derivation_mnemonic {
        Some(mnemonic_config) => {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_config.words.to_string())?;
            // Optional BIP39 passphrase (not the same as a wallet password!)
            let passphrase = mnemonic_config.passphrase.clone().unwrap_or("".to_string());
            let seed = mnemonic.to_seed(passphrase);
            Some(seed.to_vec())
        }
        None => {
            match &key_manager_config.key_derivation_seed {
                Some(seed) => Some(decode_key_derivation_seed(seed)?),
                None => None,
            }
        }
    };

    let key_derivation_path = &key_manager_config
        .key_derivation_path
        .as_deref()
        .unwrap_or("m/101/1/0/0/");

    let winternitz_seed = match &key_manager_config.winternitz_seed {
        Some(seed) => Some(decode_winternitz_seed(seed)?),
        None => None,
    };

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

fn decode_key_derivation_seed(seed: &str) -> Result<Vec<u8>, ConfigError> {
    let key_derivation_seed =
        hex::decode(seed).map_err(|_| ConfigError::InvalidKeyDerivationSeed)?;
    let seed_len = key_derivation_seed.len();
    if seed_len != 32 && seed_len != 64 {
        return Err(ConfigError::InvalidKeyDerivationSeed);
    }
    Ok(key_derivation_seed)
}
