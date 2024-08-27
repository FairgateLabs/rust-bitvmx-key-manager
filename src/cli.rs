use std::{env, path::PathBuf, str::FromStr};

use anyhow::{Ok, Result};

use bitcoin::{key::rand::RngCore, secp256k1::{self, Message}, Network, PublicKey};
use clap::{Parser, Subcommand};
use tracing::info;
use crate::{config::Config, errors::CliError, key_manager::KeyManager, verifier::SignatureVerifier, winternitz};
use hex;

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

        #[arg(value_name = "config_path_file", short = 'c', long = "config_path_file")]
        config_file_path: String,
    },

    NewWinternitzKey {
        #[arg(value_name = "winternitz_type", short = 'w', long = "winternitz_type")]
        winternitz_type: String,

        #[arg(value_name = "message_length", short = 'm', long = "message_length")]
        message_length: usize,

        #[arg(value_name = "index", short = 'i', long = "index")]
        index: u32,

        #[arg(value_name = "config_path_file", short = 'c', long = "config_path_file")]
        config_file_path: String,
    },

    NewDeterministicKey {
        #[arg(value_name = "label", short = 'l', long = "label")]
        label: String,

        #[arg(value_name = "config_path_file", short = 'c', long = "config_path_file")]
        config_file_path: String,
    },

    SignECDSA {
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,

        #[arg(value_name = "config_path_file", short = 'c', long = "config_path_file")]
        config_file_path: String,
    },

    SignSchnorr{
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,

        #[arg(value_name = "key_spent", short = 'k', long = "key_spent")]
        key_spent: bool,

        #[arg(value_name = "config_path_file", short = 'c', long = "config_path_file")]
        config_file_path: String,
    },

    SignWinternitz{
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "winternitz_type", short = 'w', long = "winternitz_type")]
        winternitz_type: String,

        #[arg(value_name = "message_length", short = 'm', long = "message_length")]
        message_length: usize,

        #[arg(value_name = "index", short = 'i', long = "index")]
        index: u32,

        #[arg(value_name = "config_path_file", short = 'c', long = "config_path_file")]
        config_file_path: String,
    },

    VerifyEcdsaSignature{
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,

        #[arg(value_name = "signature", short = 's', long = "signature")]
        signature: String,
    },

    VerifySchnorrSignature{
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,

        #[arg(value_name = "signature", short = 's', long = "signature")]
        signature: String,
    },

    VerifyWinternitzSignature{
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "winternitz_type", short = 'w', long = "winternitz_type")]
        winternitz_type: String,

        #[arg(value_name = "message_length", short = 'm', long = "message_length")]
        message_length: usize,

        #[arg(value_name = "signature", short = 's', long = "signature")]
        signature: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,
    },

    RandomMessage,
}

impl Cli {
    pub fn new() -> Result<Self> {
        Ok(Self {
        })
    }

    pub fn run(&self) -> Result<()> {
        let menu = Menu::parse();

        match &menu.command {
            Commands::NewKey { label, config_file_path }=> {
                let key_manager_config = Config::new(Some(config_file_path.to_string()))?;
                self.generate_key(label, key_manager_config)?;
            }

            Commands::NewDeterministicKey { label, config_file_path }=> {
                let key_manager_config = Config::new(Some(config_file_path.to_string()))?;
                self.generate_deterministic_key(label, key_manager_config)?;
            }

            Commands::NewWinternitzKey { winternitz_type, message_length, index, config_file_path}=> {
                let key_manager_config = Config::new(Some(config_file_path.to_string()))?;
                self.generate_winternitz_key(winternitz_type, *message_length, *index,key_manager_config)?;
            }

            Commands::SignECDSA {message, public_key,config_file_path }=> {
                let key_manager_config = Config::new(Some(config_file_path.to_string()))?;
                self.sign_ecdsa(message, public_key, key_manager_config)?;
            }

            Commands::SignSchnorr {message, public_key,key_spent,config_file_path }=> {
                let key_manager_config = Config::new(Some(config_file_path.to_string()))?;
                self.sign_schnorr(message, public_key, *key_spent, key_manager_config)?;
            }

            Commands::SignWinternitz {message, winternitz_type, message_length, index, config_file_path}=> {
                let key_manager_config = Config::new(Some(config_file_path.to_string()))?;
                self.sign_winternitz(message, winternitz_type, *message_length, *index, key_manager_config)?;
            }

            Commands::VerifyEcdsaSignature { message, public_key, signature } => {
                self.verify_ecdsa_signature(signature, message, public_key)?;
            }

            Commands::VerifySchnorrSignature { message, public_key, signature } => {
                self.verify_schnorr_signature(signature, message, public_key)?;
            }

            Commands::VerifyWinternitzSignature {message, winternitz_type, message_length, signature, public_key} => {
                self.verify_winternitz_signature(signature, message, *message_length, public_key, winternitz_type)?;
            }

            Commands::RandomMessage => {
                let message = self.get_random_bytes();
                info!("Random message: {:?}", message);
            }
        }

        Ok(())
    }

    // 
    // Commands
    //
    fn generate_key(&self, label: &str, key_manager_config: Config) -> Result<()>{
        let mut key_manager = self.key_manager(&key_manager_config.network, &key_manager_config.storage_path, &key_manager_config.storage_password)?;
        let mut rng = secp256k1::rand::thread_rng();
        
        let pk = key_manager.generate_key(Some(label.to_string()), &mut rng).unwrap();

        info!("New key pair created and stored with label '{}'. Public key is: {}", label, pk.to_string());

        Ok(())
    }

    fn generate_winternitz_key(&self, winternitz_type: &str, msg_len_bytes: usize, index: u32, key_manager_config: Config) -> Result<()>{
        let mut key_manager = self.key_manager(&key_manager_config.network, &key_manager_config.storage_path, &key_manager_config.storage_password)?;
        let key_type = self.get_witnernitz_type(winternitz_type)?;
        
        let pk = key_manager.generate_winternitz_key(msg_len_bytes, key_type, index)?;

        info!("New key pair created of Winternitz Key. Public key is: {:?}", pk);

        Ok(())
    }

    fn sign_ecdsa(&self, message: &str, public_key: &str, key_manager_config: Config) -> Result<()>{
        let key_manager = self.key_manager(&key_manager_config.network, &key_manager_config.storage_path, &key_manager_config.storage_password)?;
        if message.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be less than 32 bytes".to_string() }.into());
        }
        let message: [u8; 32] = message.to_string().as_bytes().try_into()?;
        
        let signature = key_manager.sign_ecdsa_message(&Message::from_digest(message), PublicKey::from_str(public_key).unwrap()).unwrap();

        info!("ECDSA Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn sign_winternitz(&self, message: &str, winternitz_type: &str, msg_len_bytes: usize, index: u32, key_manager_config: Config) -> Result<()>{
        let key_manager = self.key_manager(&key_manager_config.network, &key_manager_config.storage_path, &key_manager_config.storage_password)?;
        let key_type = self.get_witnernitz_type(winternitz_type)?;

        let message_bytes = message.as_bytes();
        
        let signature = key_manager.sign_winternitz_message(message_bytes, msg_len_bytes, index, key_type).unwrap();

        info!("Winternitz Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn sign_schnorr(&self, message: &str, public_key: &str, key_spent:bool, key_manager_config: Config) -> Result<()>{
        let key_manager = self.key_manager(&key_manager_config.network, &key_manager_config.storage_path, &key_manager_config.storage_password)?;
        if message.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be less than 32 bytes".to_string() }.into());
        }
        let message: [u8; 32] = message.to_string().as_bytes().try_into().unwrap();
        
        let signature = key_manager.sign_schnorr_message(&Message::from_digest(message), &PublicKey::from_str(public_key).unwrap(),key_spent).unwrap();

        info!("Schnorr Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn generate_deterministic_key(&self, label: &str, key_manager_config: Config) -> Result<()>{
        let mut key_manager = self.key_manager(&key_manager_config.network, &key_manager_config.storage_path, &key_manager_config.storage_password)?;
        
        let pk = key_manager.derive_bip32(Some(label.to_string())).unwrap();

        info!("New deterministic key pair created and stored with label '{}'. Public key is: {}", label, pk.to_string());

        Ok(())
    }

    fn verify_ecdsa_signature(&self, signature: &str, message: &str, public_key: &str) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let signature = secp256k1::ecdsa::Signature::from_str(signature)?;
        let message = Message::from_digest(message.to_string().as_bytes().try_into()?);
        let public_key = PublicKey::from_str(public_key)?;
        match verifier.verify_ecdsa_signature(&signature, &message, public_key){
            true => info!("ECDSA Signature is valid"),
            false => info!("ECDSA Signature is invalid"),
        };
        Ok(())
    }

    fn verify_schnorr_signature(&self, signature: &str, message: &str, public_key: &str) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let signature = secp256k1::schnorr::Signature::from_str(signature)?;
        let message = Message::from_digest(message.to_string().as_bytes().try_into()?);
        let public_key = PublicKey::from_str(public_key)?;
        match verifier.verify_schnorr_signature(&signature, &message, public_key){
            true => info!("Schnorr Signature is valid"),
            false => info!("Schnorr Signature is invalid"),
        };
        Ok(())
    }
    
    fn verify_winternitz_signature(&self, signature: &str, message: &str, msg_len_bytes: usize, public_key: &str, winternitz_type: &str) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let signature = [self.hex_string_to_bytes(signature)?];
        let message = message.as_bytes();
        let public_key = [self.hex_string_to_bytes(public_key)?];
        let key_type = self.get_witnernitz_type(winternitz_type)?;
        match verifier.verify_winternitz_signature(&signature, message, msg_len_bytes, &public_key, key_type){
            true => info!("Winternitz Signature is valid"),
            false => info!("Winternitz Signature is invalid"),
        };
        Ok(())
    }

    fn hex_string_to_bytes(&self, hex_string: &str) -> Result<Vec<u8>> {
        let bytes = hex::decode(hex_string).map_err(|_| CliError::InvalidHexString(hex_string.to_string()))?;
        Ok(bytes)
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

    fn get_witnernitz_type(&self, winternitz_type: &str) -> Result<winternitz::WinternitzType> {
        match winternitz_type {
            "wsha256" => Ok(winternitz::WinternitzType::WSHA256),
            "wripemd160" => Ok(winternitz::WinternitzType::WRIPEMD160),
            _ => Err(CliError::InvalidWinternitzType(winternitz_type.to_string()).into()),
        }
    }

    fn get_storage_path(&self, storage_path: &Option<String>) -> Result<PathBuf> {
        let path = match storage_path {
            Some(path) => PathBuf::from(path),
            None => {
                let path = env::current_dir()?;
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

