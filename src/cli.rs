use std::{env, path::PathBuf};

use anyhow::{Ok, Result};

use bitcoin::{key::rand::RngCore, secp256k1, Network};
use clap::{Parser, Subcommand};
use tracing::info;

use crate::{errors::CliError, key_manager::KeyManager};

pub struct Cli {
}

#[derive(Parser)]
#[command(about = "Key Manager CLI", long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Menu {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    NewKey {
        #[arg(value_name = "label", short = 'l', long = "label")]
        label: String,

        #[arg(value_name = "network", short = 'n', long = "network")]
        network: String,

        #[arg(value_name = "password", short = 'p', long = "password")]
        storage_password: String,

        #[arg(value_name = "storage_path", short = 's', long = "storage")]
        storage_path: Option<String>,
    }
}

impl Cli {
    pub fn new() -> Result<Self> {
        Ok(Self {
        })
    }

    pub fn run(&self) -> Result<()> {
        let menu = Menu::parse();

        match &menu.command {
            Commands::NewKey { label, network, storage_password, storage_path }=> {
                self.generate_key(label, network, storage_password, storage_path)?;
            }
        }

        Ok(())
    }

    // 
    // Commands
    //
    fn generate_key(&self, label: &str, network: &str, storage_password: &str, storage_path: &Option<String>) -> Result<()>{
        let mut key_manager = self.key_manager(network, storage_path, storage_password)?;
        let mut rng = secp256k1::rand::thread_rng();
        
        let pk = key_manager.generate_key(Some(label.to_string()), &mut rng).unwrap();

        info!("New key pair created and stored with label '{}'. Public key is: {}", label, pk.to_string());

        Ok(())
    }

    fn key_manager(&self, network: &str, storage_path: &Option<String>, storage_password: &str) -> Result<KeyManager> {
        let key_derivation_path: &str = "101/1/0/0/";
        let key_derivation_seed = self.get_random_bytes();
        let winternitz_secret = self.get_random_bytes();
        let network = self.get_network(network)?;
        let storage_path = self.get_storage_path(storage_path)?;
        let storage_password: Vec<u8> = storage_password.as_bytes().to_vec();

        let key_manager = KeyManager::new(
            network, 
            key_derivation_path, 
            &key_derivation_seed, 
            winternitz_secret,
            storage_path.to_str().unwrap(), 
            storage_password, 
        )?;

        Ok(key_manager)
    }

    fn get_network(&self, network: &str) -> Result<Network> {
        match network {
            "mainnet" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(CliError::InvalidNetwork(network.to_string()).into()),
        }
    }   

    fn get_storage_path(&self, storage_path: &Option<String>) -> Result<PathBuf> {
        let path = match storage_path {
            Some(path) => PathBuf::from(path),
            None => {
                let path = PathBuf::from(env::current_dir()?);
                path.join("secure_storage.db")
            },
        };

        Ok(path)
    }

    fn get_random_bytes(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }
}
