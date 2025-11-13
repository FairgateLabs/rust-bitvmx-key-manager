use serde::Deserialize;
use storage_backend::storage_config::StorageConfig;

#[derive(Debug, Deserialize, Clone)]
pub struct KeyManagerConfig {
    pub network: String,
    pub mnemonic_sentence: Option<String>,
    pub mnemonic_passphrase: Option<String>,
}

impl KeyManagerConfig {
    pub fn new(
        network: String,
        mnemonic_sentence: Option<String>,
        mnemonic_passphrase: Option<String>,
    ) -> Self {
        Self {
            network,
            mnemonic_sentence,
            mnemonic_passphrase,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub key_manager: KeyManagerConfig,
    pub storage: StorageConfig,
}
