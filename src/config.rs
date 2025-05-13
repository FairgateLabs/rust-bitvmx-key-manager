use serde::Deserialize;
use storage_backend::storage_config::StorageConfig;

#[derive(Debug, Deserialize, Clone)]
pub struct KeyManagerConfig {
    pub network: String,
    pub key_derivation_seed: String,
    pub key_derivation_path: String,
    pub winternitz_seed: String,
}
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub key_manager: KeyManagerConfig,
    pub storage: StorageConfig,
}
