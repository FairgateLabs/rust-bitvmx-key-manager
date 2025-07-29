use anyhow::{Ok, Result};
use bitvmx_settings::settings::ConfigurationFile;
use std::{str::FromStr, sync::Arc};
use storage_backend::storage::Storage;

use crate::{
    config::Config, create_key_manager_from_config, errors::CliError, key_manager::KeyManager,
    key_store::KeyStore, verifier::SignatureVerifier, winternitz::WinternitzSignature,
};
use bitcoin::{
    bip32::Xpub,
    key::rand::RngCore,
    secp256k1::{self, Message},
    PublicKey,
};
use clap::{Parser, Subcommand};
use hex;
use tracing::info;

pub struct Cli {
    config: Config,
}

#[derive(Parser)]
#[command(about = "Key Manager CLI", long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Menu {
    #[command(subcommand)]
    command: Commands,

    #[clap(flatten)]
    configuration: ConfigurationFile,
}

#[derive(Subcommand)]
enum Commands {
    NewKey,

    NewMasterXpub,

    DerivePublicKey {
        #[arg(value_name = "key_index", short = 'k', long = "key_index")]
        key_index: u32,

        #[arg(value_name = "master_xpub", short = 'm', long = "master_xpub")]
        master_xpub: String,
    },

    DeriveKeypair {
        #[arg(value_name = "key_index", short = 'k', long = "key_index")]
        key_index: u32,
    },

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

        #[arg(
            value_name = "message_digits_len",
            short = 'l',
            long = "message_digits_length"
        )]
        message_digits_length: usize,

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
        let menu = Menu::parse();
        let config = bitvmx_settings::settings::load_config_file::<Config>(
            menu.configuration.configuration,
        )?;
        Ok(Self { config })
    }

    pub fn run(&self) -> Result<()> {
        let menu = Menu::parse();

        match &menu.command {
            Commands::NewKey => {
                self.generate_key()?;
            }

            Commands::NewMasterXpub => {
                let key_manager = self.key_manager()?;
                let xpub = key_manager.generate_master_xpub()?;
                info!("Master Xpub: {}", xpub);
            }

            Commands::DerivePublicKey {
                key_index,
                master_xpub,
            } => {
                self.derive_public_key(master_xpub, key_index)?;
            }

            Commands::DeriveKeypair { key_index } => {
                self.derive_keypair(*key_index)?;
            }

            Commands::NewWinternitzKey {
                winternitz_type,
                message_length,
                key_index,
            } => {
                self.generate_winternitz_key(winternitz_type, *message_length, *key_index)?;
            }

            Commands::SignECDSA {
                message,
                public_key,
            } => {
                self.sign_ecdsa(message, public_key)?;
            }

            Commands::SignSchnorr {
                message,
                public_key,
            } => {
                self.sign_schnorr(message, public_key)?;
            }

            Commands::SignWinternitz {
                message,
                winternitz_type,
                key_index,
            } => {
                self.sign_winternitz(message, winternitz_type, *key_index)?;
            }

            Commands::VerifyEcdsa {
                message,
                public_key,
                signature,
            } => {
                self.verify_ecdsa_signature(signature, message, public_key)?;
            }

            Commands::VerifySchnorr {
                message,
                public_key,
                signature,
            } => {
                self.verify_schnorr_signature(signature, message, public_key)?;
            }

            Commands::VerifyWinternitz {
                message,
                message_digits_length,
                winternitz_type,
                signature,
                key_index,
            } => {
                self.verify_winternitz_signature(
                    signature,
                    message,
                    *message_digits_length,
                    *key_index,
                    winternitz_type,
                )?;
            }

            Commands::RandomMessage { size } => {
                let message = hex::encode(self.get_random_bytes(*size));
                info!("Random message: {}", message);
            }
        }

        Ok(())
    }

    //
    // Commands
    //
    fn generate_key(&self) -> Result<()> {
        let key_manager = self.key_manager()?;
        let mut rng = secp256k1::rand::thread_rng();

        let pk = key_manager.generate_keypair(&mut rng)?;

        info!(
            "New key pair created and stored. Public key is: {}",
            pk.to_string()
        );

        Ok(())
    }

    fn generate_winternitz_key(
        &self,
        winternitz_type: &str,
        msg_len_bytes: usize,
        index: u32,
    ) -> Result<()> {
        let key_manager = self.key_manager()?;

        let public_key =
            key_manager.derive_winternitz(msg_len_bytes, winternitz_type.parse()?, index)?;

        info!(
            "New key pair created of Winternitz Key. Public key is: {}",
            hex::encode(public_key.to_bytes())
        );

        Ok(())
    }

    fn sign_ecdsa(&self, message: &str, public_key: &str) -> Result<()> {
        let key_manager = self.key_manager()?;
        let bytes = hex::decode(message)?;

        if bytes.len() > 32 {
            return Err(CliError::BadArgument {
                msg: "Message length must be 32 bytes".to_string(),
            }
            .into());
        }

        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let signature = key_manager.sign_ecdsa_message(
            &Message::from_digest(digest),
            &PublicKey::from_str(public_key)?,
        )?;

        info!("ECDSA Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn sign_winternitz(&self, message: &str, winternitz_type: &str, key_index: u32) -> Result<()> {
        let key_manager = self.key_manager()?;

        let message_bytes = hex::decode(message)?;

        let signature = key_manager.sign_winternitz_message(
            message_bytes.as_slice(),
            winternitz_type.parse()?,
            key_index,
        )?;

        info!(
            "Winternitz Message signed. Signature is: {}",
            hex::encode(signature.to_bytes())
        );

        Ok(())
    }

    fn sign_schnorr(&self, message: &str, public_key: &str) -> Result<()> {
        let key_manager = self.key_manager()?;
        let bytes = hex::decode(message)?;

        if bytes.len() > 32 {
            return Err(CliError::BadArgument {
                msg: "Message length must be less 32 bytes".to_string(),
            }
            .into());
        }

        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let signature = key_manager.sign_schnorr_message(
            &Message::from_digest(digest),
            &PublicKey::from_str(public_key)?,
        )?;

        info!("Schnorr Message signed. Signature is: {:?}", signature);

        Ok(())
    }

    fn derive_keypair(&self, key_index: u32) -> Result<()> {
        let key_manager = self.key_manager()?;

        let pk = key_manager.derive_keypair(key_index)?;

        info!("New Keypair created. Public key is: {}", pk.to_string());

        Ok(())
    }

    fn verify_ecdsa_signature(
        &self,
        signature: &str,
        message: &str,
        public_key: &str,
    ) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let signature = secp256k1::ecdsa::Signature::from_str(signature)?;
        let bytes = hex::decode(message)?;

        if bytes.len() > 32 {
            return Err(CliError::BadArgument {
                msg: "Message length must be less 32 bytes".to_string(),
            }
            .into());
        }

        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let message = Message::from_digest(digest);
        let public_key = PublicKey::from_str(public_key)?;

        match verifier.verify_ecdsa_signature(&signature, &message, public_key) {
            true => info!("ECDSA Signature is valid"),
            false => info!("ECDSA Signature is invalid"),
        };

        Ok(())
    }

    fn verify_schnorr_signature(
        &self,
        signature: &str,
        message: &str,
        public_key: &str,
    ) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let signature = secp256k1::schnorr::Signature::from_str(signature)?;
        let bytes = hex::decode(message)?;

        if bytes.len() > 32 {
            return Err(CliError::BadArgument {
                msg: "Message length must be 32 bytes".to_string(),
            }
            .into());
        }

        let digest: [u8; 32] = bytes.as_slice().try_into()?;
        let message = Message::from_digest(digest);
        let public_key = PublicKey::from_str(public_key)?;

        match verifier.verify_schnorr_signature(&signature, &message, public_key) {
            true => info!("Schnorr Signature is valid"),
            false => info!("Schnorr Signature is invalid"),
        };

        Ok(())
    }

    fn verify_winternitz_signature(
        &self,
        signature: &str,
        message: &str,
        message_digits_length: usize,
        key_index: u32,
        winternitz_type: &str,
    ) -> Result<()> {
        let verifier = SignatureVerifier::new();
        let key_type = winternitz_type.parse()?;

        let signature_bytes = hex::decode(signature)
            .map_err(|_| CliError::InvalidHexString(signature.to_string()))?;
        let signature =
            WinternitzSignature::from_bytes(&signature_bytes, message_digits_length, key_type)
                .map_err(|_| CliError::InvalidHexString(signature.to_string()))?;

        let message_bytes = hex::decode(message)?;

        let public_key =
            self.key_manager()?
                .derive_winternitz(message_bytes.len(), key_type, key_index)?;

        match verifier.verify_winternitz_signature(&signature, &message_bytes, &public_key) {
            true => info!("Winternitz Signature is valid"),
            false => info!("Winternitz Signature is invalid"),
        };

        Ok(())
    }

    fn derive_public_key(&self, master_xpub: &str, key_index: &u32) -> Result<(), anyhow::Error> {
        let key_manager = self.key_manager()?;
        let master_xpub = Xpub::from_str(master_xpub)?;
        let public_key = key_manager.derive_public_key(master_xpub, *key_index)?;
        info!("Derived public key: {}", public_key);
        Ok(())
    }

    fn key_manager(&self) -> Result<KeyManager> {
        let store = Arc::new(Storage::new(&self.config.storage)?);
        let keystore = KeyStore::new(store.clone());

        Ok(create_key_manager_from_config(
            &self.config.key_manager,
            keystore,
            store,
        )?)
    }

    fn get_random_bytes(&self, size: usize) -> Vec<u8> {
        let mut seed = vec![0u8; size];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }
}
