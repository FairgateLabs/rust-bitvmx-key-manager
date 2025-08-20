use serde::Deserialize;
use storage_backend::storage_config::StorageConfig;

#[derive(Debug, Deserialize, Clone)]
pub struct KeyManagerConfig {
    pub network: String,
    pub key_derivation_mnemonic: Option<MnemonicConfig>,
    pub key_derivation_seed: Option<String>,
    pub key_derivation_path: Option<String>,
    pub winternitz_seed: Option<String>,
}


impl KeyManagerConfig {
    pub fn new(
        network: String,
        key_derivation_mnemonic: Option<MnemonicConfig>,
        key_derivation_seed: Option<String>,
        key_derivation_path: Option<String>,
        winternitz_seed: Option<String>,
    ) -> Self {
        Self {
            network,
            key_derivation_mnemonic,
            key_derivation_seed,
            key_derivation_path,
            winternitz_seed,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct MnemonicConfig {
    pub words: String,
    pub passphrase: Option<String>, // Optional BIP39 passphrase (not the same as a wallet password!)
}

impl MnemonicConfig {
    pub fn new(words: String, passphrase: Option<String>) -> Self {
        Self { words, passphrase }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub key_manager: KeyManagerConfig,
    pub storage: StorageConfig,
}
