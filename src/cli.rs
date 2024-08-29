use std::{path::PathBuf, str::FromStr};

use anyhow::{Ok, Result};

use bitcoin::{key::rand::RngCore, secp256k1::{self, Message}, Network, PublicKey};
use clap::{Parser, Subcommand};
use tracing::info;
use crate::{config::Config, errors::CliError, key_manager::KeyManager, verifier::SignatureVerifier, winternitz::{WinternitzSignature, WinternitzType}};
use hex;

pub struct Cli {
    config: Config,
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
    NewKey,

    NewDeterministicKey,

    NewWinternitzKey {
        #[arg(value_name = "winternitz_type", short = 'w', long = "winternitz_type")]
        winternitz_type: String,

        #[arg(value_name = "message_length", short = 'm', long = "message_length")]
        message_length: usize,

        #[arg(value_name = "key_index", short = 'k', long = "key_index")]
        key_index: u32,
    },

    SignECDSA {
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,
    },

    SignSchnorr {
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,
    },

    SignWinternitz {
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "winternitz_type", short = 'w', long = "winternitz_type")]
        winternitz_type: String,

        #[arg(value_name = "key_index", short = 'k', long = "key_index")]
        key_index: u32,
    },

    VerifyEcdsa {
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,

        #[arg(value_name = "signature", short = 's', long = "signature")]
        signature: String,
    },

    VerifySchnorr {
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,

        #[arg(value_name = "signature", short = 's', long = "signature")]
        signature: String,
    },

    VerifyWinternitz {
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "winternitz_type", short = 'w', long = "winternitz_type")]
        winternitz_type: String,

        #[arg(value_name = "signature", short = 's', long = "signature")]
        signature: String,

        #[arg(value_name = "key_index", short = 'k', long = "key_index")]
        key_index: u32,
    },

    RandomMessage {
        #[arg(value_name = "size", short = 's', long = "size")]
        size: usize,
    },
}

impl Cli {
    pub fn new() -> Result<Self> {
        let config = Config::new()?;
        Ok(Self {
            config,
        })
    }

    pub fn run(&self) -> Result<()> {
        let menu = Menu::parse();

        match &menu.command {
            Commands::NewKey => {
                self.generate_key()?;
            }

            Commands::NewDeterministicKey => {
                self.generate_deterministic_key()?;
            }

            Commands::NewWinternitzKey { winternitz_type, message_length, key_index }=> {
                self.generate_winternitz_key(winternitz_type, *message_length, *key_index)?;
            }

            Commands::SignECDSA {message, public_key }=> {
                self.sign_ecdsa(message, public_key)?;
            }

            Commands::SignSchnorr {message, public_key }=> {
                self.sign_schnorr(message, public_key)?;
            }

            Commands::SignWinternitz {message, winternitz_type, key_index }=> {
                self.sign_winternitz(message, winternitz_type, *key_index)?;
            }

            Commands::VerifyEcdsa { message, public_key, signature } => {
                self.verify_ecdsa_signature(signature, message, public_key)?;
            }

            Commands::VerifySchnorr { message, public_key, signature } => {
                self.verify_schnorr_signature(signature, message, public_key)?;
            }

            Commands::VerifyWinternitz {message, winternitz_type, signature, key_index} => {
                self.verify_winternitz_signature(signature, message, *key_index, winternitz_type)?;
            }

            Commands::RandomMessage { size } => {
                let message = hex::encode(self.get_random_bytes(*size));
                info!("Random message: {:?}", message);
            }
        }

        Ok(())
    }

    // 
    // Commands
    //
    fn generate_key(&self) -> Result<()>{
        let mut key_manager = self.key_manager()?;
        let mut rng = secp256k1::rand::thread_rng();
        
        let pk = key_manager.generate_key(&mut rng).unwrap();

        info!("New key pair created and stored. Public key is: {}", pk.to_string());

        Ok(())
    }

    fn generate_winternitz_key(&self, winternitz_type: &str, msg_len_bytes: usize, index: u32) -> Result<()>{
        let mut key_manager = self.key_manager()?;
        let key_type = self.get_witnernitz_type(winternitz_type)?;
        
        let public_key = key_manager.generate_winternitz_key(msg_len_bytes, key_type, index)?;

        info!("New key pair created of Winternitz Key. Public key is: {:?}", hex::encode(&public_key.to_bytes()));

        Ok(())
    }

    fn sign_ecdsa(&self, message: &str, public_key: &str) -> Result<()>{
        let key_manager = self.key_manager()?;
        let bytes = hex::decode(message)?;
        
        if bytes.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be 32 bytes".to_string() }.into());
        }
    
        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let signature = key_manager.sign_ecdsa_message(&Message::from_digest(digest), PublicKey::from_str(public_key).unwrap()).unwrap();

        info!("ECDSA Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn sign_winternitz(&self, message: &str, winternitz_type: &str, key_index: u32) -> Result<()>{
        let key_manager = self.key_manager()?;
        let key_type = self.get_witnernitz_type(winternitz_type)?;

        let message_bytes = hex::decode(message)?;
    
        let signature = key_manager.sign_winternitz_message(message_bytes.as_slice(), key_index, key_type).unwrap();

        info!("Winternitz Message signed. Signature is: {:?}", hex::encode(&signature.to_bytes()));

        Ok(())
    }

    fn sign_schnorr(&self, message: &str, public_key: &str) -> Result<()>{
        let key_manager = self.key_manager()?;
        let bytes = hex::decode(message)?;
        
        if bytes.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be less 32 bytes".to_string() }.into());
        }

        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let signature = key_manager.sign_schnorr_message(&Message::from_digest(digest), &PublicKey::from_str(public_key).unwrap()).unwrap();

        info!("Schnorr Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn generate_deterministic_key(&self) -> Result<()>{
        let mut key_manager = self.key_manager()?;
        
        let pk = key_manager.derive_bip32().unwrap();

        info!("New deterministic key pair created and stored. Public key is: {}", pk.to_string());

        Ok(())
    }

    fn verify_ecdsa_signature(&self, signature: &str, message: &str, public_key: &str) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let signature = secp256k1::ecdsa::Signature::from_str(signature)?;
        let bytes = hex::decode(message)?;

        if bytes.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be less 32 bytes".to_string() }.into());
        }

        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let message = Message::from_digest(digest);
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
        let bytes = hex::decode(message)?;

        if bytes.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be 32 bytes".to_string() }.into());
        }

        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let message = Message::from_digest(digest);
        let public_key = PublicKey::from_str(public_key)?;

        match verifier.verify_schnorr_signature(&signature, &message, public_key){
            true => info!("Schnorr Signature is valid"),
            false => info!("Schnorr Signature is invalid"),
        };

        Ok(())
    }
    
    fn verify_winternitz_signature(&self, signature: &str, message: &str, key_index: u32, winternitz_type: &str) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let key_type = self.get_witnernitz_type(winternitz_type)?;

        let signature_bytes = hex::decode(signature).map_err(|_| CliError::InvalidHexString(signature.to_string()))?;
        let signature = WinternitzSignature::from_bytes(&signature_bytes, key_type).map_err(|_| CliError::InvalidHexString(signature.to_string()))?;

        let message_bytes = hex::decode(message)?;

        let public_key = self.key_manager()?.generate_winternitz_key(message_bytes.len(), key_type, key_index)?;

        match verifier.verify_winternitz_signature(&signature, &message_bytes, &public_key){
            true => info!("Winternitz Signature is valid"),
            false => info!("Winternitz Signature is invalid"),
        };

        Ok(())
    }

    fn key_manager(&self) -> Result<KeyManager> {
        let key_derivation_seed = self.get_key_derivation_seed()?;
        let key_derivation_path = &self.config.key_manager.key_derivation_path;
        let winternitz_secret = self.get_winternitz_secret()?;
        let network = self.get_network()?;
        let storage_path = self.get_storage_path()?;
        let storage_password: Vec<u8> = self.config.storage.password.as_bytes().to_vec();

        let key_manager = KeyManager::new(
            network, 
            key_derivation_path, 
            key_derivation_seed, 
            winternitz_secret,
            storage_path.to_str().unwrap(), 
            storage_password, 
        )?;

        Ok(key_manager)
    }

    fn get_network(&self) -> Result<Network> {
        let network = &self.config.key_manager.network;

        match network.as_str() {
            "mainnet" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(CliError::InvalidNetwork(network.to_string()).into()),
        }
    }

    fn get_witnernitz_type(&self, winternitz_type: &str) -> Result<WinternitzType> {
        match winternitz_type {
            "sha256" => Ok(WinternitzType::SHA256),
            "ripemd160" => Ok(WinternitzType::RIPEMD160),
            _ => Err(CliError::InvalidWinternitzType(winternitz_type.to_string()).into()),
        }
    }

    fn get_storage_path(&self) -> Result<PathBuf> {
        Ok(PathBuf::from(&self.config.storage.path))
    }

    fn get_winternitz_secret(&self) -> Result<[u8; 32]> {
        let winternitz_secret = hex::decode(self.config.key_manager.winternitz_seed.clone())?;

        if winternitz_secret.len() > 32 {
            return Err(CliError::BadArgument { msg: "Winternitz secret length must be 32 bytes".to_string() }.into());
        }

        Ok(winternitz_secret.as_slice().try_into()?)
    }

    fn get_key_derivation_seed(&self) -> Result<[u8; 32]> {
        let key_derivation_seed = hex::decode(self.config.key_manager.key_derivation_seed.clone())?;

        if key_derivation_seed.len() > 32 {
            return Err(CliError::BadArgument { msg: "Key derivation seed length must be 32 bytes".to_string() }.into());
        }

        Ok(key_derivation_seed.as_slice().try_into()?)
    }

    fn get_random_bytes(&self, size: usize) -> Vec<u8> {
        let mut seed = vec![0u8; size];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }
}

