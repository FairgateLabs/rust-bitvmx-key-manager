use config as settings;
use serde::Deserialize;
use tracing::warn;
use std::env;

use crate::errors::ConfigError;

static DEFAULT_ENV: &str = "development";
static CONFIG_PATH: &str = "config";

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    pub network: String,
    pub storage_password: String,
    pub storage_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub storage: StorageConfig,
}

impl Config {
    pub fn new(path: Option<String>) -> Result<Config, ConfigError> {
        match path {
            Some(p) => Config::parse_config(p),
            None => {
                let env = Config::get_env();
                Config::parse_config(env)
            }
        }
        
    }

    fn get_env() -> String {
        env::var("BITVMX_ENV")
            .unwrap_or_else(|_| {
                let default_env = DEFAULT_ENV.to_string();
                warn!("BITVMX_ENV not set. Using default environment: {}", default_env);
                default_env
            }
        )
    }

    fn parse_config(env: String) -> Result<Config, ConfigError> {
        let config_path = format!("{}/{}.json", CONFIG_PATH, env);

        let settings = settings::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .build()
            .map_err(ConfigError::ConfigFileError)?;

        settings.try_deserialize::<Config>()
            .map_err(ConfigError::ConfigFileError)
    }
}
