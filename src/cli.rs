use std::{path::PathBuf, str::FromStr};

use anyhow::{Ok, Result};

use bitcoin::{key::rand::RngCore, secp256k1::{self, Message}, Network, PublicKey};
use clap::{Parser, Subcommand};
use tracing::info;
use crate::{config::Config, errors::CliError, key_manager::KeyManager, verifier::SignatureVerifier, winternitz};
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
    NewKey {
        #[arg(value_name = "label", short = 'l', long = "label")]
        label: String,
    },

    NewWinternitzKey {
        #[arg(value_name = "winternitz_type", short = 'w', long = "winternitz_type")]
        winternitz_type: String,

        #[arg(value_name = "message_length", short = 'm', long = "message_length")]
        message_length: usize,

        #[arg(value_name = "key_index", short = 'k', long = "key_index")]
        key_index: u32,
    },

    NewDeterministicKey {
        #[arg(value_name = "label", short = 'l', long = "label")]
        label: String,
    },

    SignECDSA {
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,
    },

    SignSchnorr{
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "public_key", short = 'p', long = "public_key")]
        public_key: String,

        #[arg(value_name = "key_spent", short = 'k', long = "key_spent")]
        key_spent: bool,
    },

    SignWinternitz{
        #[arg(value_name = "message", short = 'm', long = "message")]
        message: String,

        #[arg(value_name = "winternitz_type", short = 'w', long = "winternitz_type")]
        winternitz_type: String,

        #[arg(value_name = "key_index", short = 'k', long = "key_index")]
        key_index: u32,
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

        #[arg(value_name = "signature", short = 's', long = "signature")]
        signature: String,

        #[arg(value_name = "key_index", short = 'k', long = "key_index")]
        key_index: u32,
    },

    RandomMessage,

    RandomWinternitzMessage,
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
            Commands::NewKey { label }=> {
                self.generate_key(label)?;
            }

            Commands::NewDeterministicKey { label }=> {
                self.generate_deterministic_key(label)?;
            }

            Commands::NewWinternitzKey { winternitz_type, message_length, key_index }=> {
                self.generate_winternitz_key(winternitz_type, *message_length, *key_index)?;
            }

            Commands::SignECDSA {message, public_key }=> {
                self.sign_ecdsa(message, public_key)?;
            }

            Commands::SignSchnorr {message, public_key,key_spent }=> {
                self.sign_schnorr(message, public_key, *key_spent)?;
            }

            Commands::SignWinternitz {message, winternitz_type, key_index }=> {
                self.sign_winternitz(message, winternitz_type, *key_index)?;
            }

            Commands::VerifyEcdsaSignature { message, public_key, signature } => {
                self.verify_ecdsa_signature(signature, message, public_key)?;
            }

            Commands::VerifySchnorrSignature { message, public_key, signature } => {
                self.verify_schnorr_signature(signature, message, public_key)?;
            }

            Commands::VerifyWinternitzSignature {message, winternitz_type, signature, key_index} => {
                self.verify_winternitz_signature(signature, message, *key_index, winternitz_type)?;
            }

            Commands::RandomMessage => {
                let message = hex::encode(self.get_random_bytes());
                info!("Random message: {:?}", message);
            }

            Commands::RandomWinternitzMessage => {
                let message = hex::encode(self.get_random_bytes_for_winternitz());
                info!("Random Winternitz message: {:?}", message);
            }
        }

        Ok(())
    }

    // 
    // Commands
    //
    fn generate_key(&self, label: &str) -> Result<()>{
        let mut key_manager = self.key_manager()?;
        let mut rng = secp256k1::rand::thread_rng();
        
        let pk = key_manager.generate_key(Some(label.to_string()), &mut rng).unwrap();

        info!("New key pair created and stored with label '{}'. Public key is: {}", label, pk.to_string());

        Ok(())
    }

    fn generate_winternitz_key(&self, winternitz_type: &str, msg_len_bytes: usize, index: u32) -> Result<()>{
        let mut key_manager = self.key_manager()?;
        let key_type = self.get_witnernitz_type(winternitz_type)?;
        
        let public_key = key_manager.generate_winternitz_key(msg_len_bytes, key_type, index)?;

        let hex_public_key: Vec<String> = public_key.iter().map(|s| hex::encode(s)).collect();

        info!("New key pair created of Winternitz Key. Public key is: {:?}", hex_public_key.join(""));

        Ok(())
    }

    fn sign_ecdsa(&self, message: &str, public_key: &str) -> Result<()>{
        let key_manager = self.key_manager()?;
        let bytes = hex::decode(message)?;
        
        if bytes.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be than 32 bytes".to_string() }.into());
        }
    
        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let signature = key_manager.sign_ecdsa_message(&Message::from_digest(digest), PublicKey::from_str(public_key).unwrap()).unwrap();

        info!("ECDSA Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn sign_winternitz(&self, message: &str, winternitz_type: &str, index: u32) -> Result<()>{
        let key_manager = self.key_manager()?;
        let key_type = self.get_witnernitz_type(winternitz_type)?;

        let message_bytes = message.as_bytes();
        
        let signature = key_manager.sign_winternitz_message(message_bytes, message_bytes.len(), index, key_type).unwrap();

        let hex_signature: Vec<String> = signature.iter().map(|s| hex::encode(s)).collect();


        info!("Winternitz Message signed. Signature is: {:?}", hex_signature.join(""));

        Ok(())
    }

    fn sign_schnorr(&self, message: &str, public_key: &str, key_spent:bool) -> Result<()>{
        let key_manager = self.key_manager()?;
        let bytes = hex::decode(message)?;
        
        if bytes.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be less than 32 bytes".to_string() }.into());
        }

        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let signature = key_manager.sign_schnorr_message(&Message::from_digest(digest), &PublicKey::from_str(public_key).unwrap(),key_spent).unwrap();

        info!("Schnorr Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn generate_deterministic_key(&self, label: &str) -> Result<()>{
        let mut key_manager = self.key_manager()?;
        
        let pk = key_manager.derive_bip32(Some(label.to_string())).unwrap();

        info!("New deterministic key pair created and stored with label '{}'. Public key is: {}", label, pk.to_string());

        Ok(())
    }

    fn verify_ecdsa_signature(&self, signature: &str, message: &str, public_key: &str) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let signature = secp256k1::ecdsa::Signature::from_str(signature)?;
        let bytes = hex::decode(message)?;

        if bytes.len() > 32 {
            return Err(CliError::BadArgument { msg: "Message length must be less than 32 bytes".to_string() }.into());
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
            return Err(CliError::BadArgument { msg: "Message length must be than 32 bytes".to_string() }.into());
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
        let chunk_size = match key_type {
            winternitz::WinternitzType::WSHA256 => winternitz::SHA256_SIZE,
            winternitz::WinternitzType::WRIPEMD160 => winternitz::RIPEMD160_SIZE,

        };
        let signature = self.hex_string_to_bytes(signature)?.chunks(chunk_size).map(|s| s.to_vec()).collect::<Vec<Vec<u8>>>();
        let message_bytes = message.as_bytes();
        

        let public_key = self.key_manager()?.generate_winternitz_key(message_bytes.len(), key_type, key_index)?;

        match verifier.verify_winternitz_signature(&signature, message_bytes, message_bytes.len(), &public_key, key_type){
            true => info!("Winternitz Signature is valid"),
            false => info!("Winternitz Signature is invalid"),
        };
        Ok(())
    }

    fn hex_string_to_bytes(&self, hex_string: &str) -> Result<Vec<u8>> {
        let bytes = hex::decode(hex_string).map_err(|_| CliError::InvalidHexString(hex_string.to_string()))?;
        Ok(bytes)
    }

    fn key_manager(&self) -> Result<KeyManager> {
        let key_derivation_path: &str = "101/1/0/0/";
        let key_derivation_seed: [u8; 32] = self.get_random_bytes();
        let winternitz_secret = hex::decode(self.config.key_manager.winternitz_seed.clone())?;

        if winternitz_secret.len() > 32 {
            return Err(CliError::BadArgument { msg: "Winternitz Secret length must be than 32 bytes".to_string() }.into());
        }

        let winternitz_secret: [u8; 32] = winternitz_secret.as_slice().try_into()?;
        let network = self.get_network(&self.config.key_manager.network)?;
        let storage_path = self.get_storage_path(&self.config.storage.path)?;
        let storage_password: Vec<u8> = self.config.storage.password.as_bytes().to_vec();

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

    fn get_storage_path(&self, storage_path: &str) -> Result<PathBuf> {
        Ok(PathBuf::from(storage_path))
    }

    fn get_random_bytes(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }

    fn get_random_bytes_for_winternitz(&self) -> [u8; 8] {
        let mut seed = [0u8; 8];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }
}

