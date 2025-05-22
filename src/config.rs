use serde::Deserialize;
use storage_backend::storage_config::StorageConfig;

#[derive(Debug, Deserialize, Clone)]
pub struct KeyManagerConfig {
    pub network: String,
    pub key_derivation_seed: Option<String>,
    pub key_derivation_path: Option<String>,
    pub winternitz_seed: Option<String>,
}

impl KeyManagerConfig {
    pub fn new(
        network: String,
        key_derivation_seed: Option<String>,
        key_derivation_path: Option<String>,
        winternitz_seed: Option<String>,
    ) -> Self {
        Self {
            network,
            key_derivation_seed,
            key_derivation_path,
            winternitz_seed,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub key_manager: KeyManagerConfig,
    pub storage: StorageConfig,
}
