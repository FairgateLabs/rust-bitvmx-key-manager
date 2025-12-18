use redact::Secret;
use serde::{Deserialize, Deserializer};
use storage_backend::storage_config::StorageConfig;
use zeroize::Zeroizing;

fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<Secret<Zeroizing<String>>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.and_then(|s| {
        if s.is_empty() {
            None
        } else {
            Some(Secret::new(Zeroizing::new(s)))
        }
    }))
}

#[derive(Debug, Deserialize, Clone)]
pub struct KeyManagerConfig {
    pub network: String,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    pub mnemonic_sentence: Option<Secret<Zeroizing<String>>>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    pub mnemonic_passphrase: Option<Secret<Zeroizing<String>>>,
}

impl KeyManagerConfig {
    pub fn new(
        network: String,
        mnemonic_sentence: Option<Zeroizing<String>>,
        mnemonic_passphrase: Option<Zeroizing<String>>,
    ) -> Self {
        Self {
            network,
            mnemonic_sentence: mnemonic_sentence.map(|s| Secret::new(s)),
            mnemonic_passphrase: mnemonic_passphrase.map(|s| Secret::new(s)),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub key_manager: KeyManagerConfig,
    pub storage: StorageConfig,
}
