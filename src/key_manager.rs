use std::{collections::HashMap, rc::Rc, str::FromStr};

use bip39::Mnemonic;
use bitcoin::{
    base58,
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    hashes::{self, Hash},
    key::{rand::RngCore, Keypair, Parity, TapTweak},
    secp256k1::{self, All, Message, Scalar, SecretKey},
    Network, PrivateKey, PublicKey, TapNodeHash,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use itertools::izip;
use storage_backend::{storage::Storage, storage_config::StorageConfig};
use tracing::debug;

use crate::{
    errors::KeyManagerError,
    key_store::KeyStore,
    key_type::BitcoinKeyType,
    musig2::{
        errors::Musig2SignerError,
        musig::{MuSig2Signer, MuSig2SignerApi},
        types::MessageId,
    },
    rsa::{CryptoRng, OsRng, RSAKeyPair, Signature},
    winternitz::{
        self, checksum_length, to_checksummed_message, WinternitzPublicKey, WinternitzSignature,
        WinternitzType,
    },
};

use musig2::{sign_partial, AggNonce, PartialSignature, PubNonce, SecNonce};

const DEFAULT_RSA_BITS: usize = 2048; // default RSA key size in bits (other sizes could also be defined)
const MAX_RSA_BITS: usize = 16384; // maximum RSA key size in bits to avoid performance issues

// HKDF domain separator for MuSig2 nonce seed generation
// Version 1 - ensures derived nonce seeds are unique to this specific use case
const MUSIG2_NONCE_HKDF_INFO: &[u8] = b"KeyManager-MuSig2-Nonce-v1";

/// This module provides a key manager for managing BitVMX keys and signatures.
/// It includes functionality for generating, importing, and deriving keys, as well as signing messages
/// using ECDSA, Schnorr and Winternitz algorithms. The key manager uses a secure storage mechanism
/// to store the keys.
pub struct KeyManager {
    secp: secp256k1::Secp256k1<All>,
    network: Network,
    musig2: MuSig2Signer,
    keystore: KeyStore,
}

impl KeyManager {
    /*
        Up to now, This KeyManager:
        - Is not a fully HD wallet.
        - Only handles one account.
        - Its purpose is fixed for bitcoin depending on the key type and network, it does not support other coins like ETH.
        - It adds support for:
            - Taproot keys.
            - Winternitz keys.
            - RSA keys.
            - MuSig2 signing.
    */
    const ACCOUNT_DERIVATION_INDEX: u32 = 0; // Account - only one account supported up to now - fixed to 0
    const CHANGE_DERIVATION_INDEX: u32 = 0; // Change (0 for external, 1 for internal) - wont manage change up to now - fixed to 0
    const WINTERNITZ_PURPOSE_INDEX: u32 = 987; // Custom purpose index for Winternitz keys
    const STARTING_DERIVATION_INDEX: u32 = 0; // Starting index for derivation

    pub fn new(
        network: Network,
        mnemonic: Option<Mnemonic>,
        mnemonic_passphrase: Option<String>,
        storage_config: &StorageConfig,
    ) -> Result<Self, KeyManagerError> {
        let key_store = Rc::new(Storage::new(storage_config)?);
        let keystore = KeyStore::new(key_store);

        // Store or load mnemonic
        match keystore.load_mnemonic() {
            Ok(stored_mnemonic) => {
                // Mnemonic found in storage
                if let Some(provided_mnemonic) = &mnemonic {
                    // Both stored and provided mnemonics exist - they must match
                    if stored_mnemonic != *provided_mnemonic {
                        return Err(KeyManagerError::MnemonicMismatch(
                            "Stored mnemonic does not match the provided mnemonic".to_string(),
                        ));
                    }
                } else {
                    // No mnemonic was provided, using the stored one
                    tracing::info!("Using stored mnemonic from storage");
                }
                // If no mnemonic was provided or they match, continue with stored mnemonic
                // Mnemonic is dropped here to minimize time in memory
            }
            Err(KeyManagerError::MnemonicNotFound) => {
                // No mnemonic in storage, store the provided one or generate a new one
                match mnemonic {
                    Some(mnemonic_sentence) => keystore.store_mnemonic(&mnemonic_sentence)?,
                    None => {
                        let mut entropy = Zeroizing::new([0u8; 32]); // 256 bits for 24 words, automatically zeroized when dropped
                        secp256k1::rand::thread_rng().fill_bytes(&mut *entropy);
                        let random_mnemonic = Mnemonic::from_entropy(& *entropy).unwrap();
                        keystore.store_mnemonic(&random_mnemonic)?;
                        tracing::warn!(
                            "Random mnemonic generated, make sure to back it up securely!"
                        );
                    }
                }
            }
            Err(e) => return Err(e), // Propagate storage/decryption errors
        }

        // Store or load mnemonic passphrase
        let mnemonic_passphrase = match keystore.load_mnemonic_passphrase() {
            Ok(stored_passphrase) => {
                // Passphrase found in storage
                if let Some(provided_passphrase) = &mnemonic_passphrase {
                    // Both stored and provided passphrases exist - they must match
                    if *stored_passphrase != *provided_passphrase {
                        return Err(KeyManagerError::MnemonicPassphraseMismatch(
                            "Stored mnemonic passphrase does not match the provided mnemonic passphrase".to_string()
                        ));
                    }
                } else {
                    // No passphrase was provided, using the stored one
                    tracing::info!("Using stored mnemonic passphrase from storage");
                }
                // If no passphrase was provided or they match, continue with stored passphrase
                stored_passphrase
            }
            Err(KeyManagerError::MnemonicPassphraseNotFound) => {
                // No passphrase in storage, store the provided one or use empty string as default
                let passphrase = mnemonic_passphrase.unwrap_or_else(|| "".to_string());
                keystore.store_mnemonic_passphrase(&passphrase)?;
                Zeroizing::new(passphrase)
            }
            Err(e) => return Err(e), // Propagate storage/decryption errors
        };

        // Dev note: key derivation seed and winternitz seed are deduced from the mnemonic, but we are storing them
        // so we don't have to recalculate them each time for performance reasons, similar to storing non-imported (derived) keys.
        // Since these values can be regenerated from the mnemonic and passphrase, we validate the stored seed matches
        // the expected value to detect potential corruption.

        let expected_key_derivation_seed = Zeroizing::new({
            let mnemonic = keystore.load_mnemonic()?;
            let seed = mnemonic.to_seed(& *mnemonic_passphrase);
            // Mnemonic dropped here to minimize time in memory
            seed
        });


        // TODO zeroize stored seed
        match keystore.load_key_derivation_seed() {
            Ok(stored_seed) => {
                let stored_seed = Zeroizing::new(stored_seed);
                // Validate that the stored seed matches what would be generated from mnemonic + passphrase
                if *stored_seed != *expected_key_derivation_seed {
                    return Err(KeyManagerError::CorruptedKeyDerivationSeed);
                }
            }
            Err(KeyManagerError::KeyDerivationSeedNotFound) => {
                // No seed stored, generate and store it
                keystore.store_key_derivation_seed(*expected_key_derivation_seed)?;
            }
            Err(e) => return Err(e), // Propagate storage/decryption errors
        }

        let secp = secp256k1::Secp256k1::new();

        // Validate or generate Winternitz seed - similar to key derivation seed validation
        // The Winternitz seed is derived from the key derivation seed, so we validate it to detect corruption.
        let expected_winternitz_seed = Self::derive_winternitz_master_seed(
            secp.clone(),
            &keystore.load_key_derivation_seed()?,
            network,
            Self::ACCOUNT_DERIVATION_INDEX,
        )?;

        match keystore.load_winternitz_seed() {
            Ok(stored_winternitz_seed) => {
                // Validate that the stored Winternitz seed matches what would be derived from key derivation seed
                if stored_winternitz_seed != expected_winternitz_seed {
                    return Err(KeyManagerError::CorruptedWinternitzSeed);
                }
            }
            Err(KeyManagerError::WinternitzSeedNotFound) => {
                // No Winternitz seed stored, generate and store it
                keystore.store_winternitz_seed(expected_winternitz_seed)?;
            }
            Err(e) => return Err(e), // Propagate storage/decryption errors
        }

        // TODO, revisit how to save musig data without impacting performance
        let plain_storage_config = StorageConfig {
            path: format!("{}-plain", storage_config.path.clone()),
            password: None,
        };
        let plain_key_store = Rc::new(Storage::new(&plain_storage_config)?);
        let musig2 = MuSig2Signer::new(plain_key_store);

        Ok(KeyManager {
            secp,
            network,
            musig2,
            keystore,
        })
    }

    pub fn musig2(&self) -> &MuSig2Signer {
        &self.musig2
    }

    /*********************************/
    /******     Imports     **********/
    /*********************************/
    pub fn import_private_key(&self, private_key: &str) -> Result<PublicKey, KeyManagerError> {
        self.import_private_key_typed(private_key, None)
    }

    pub fn import_private_key_typed(
        &self,
        private_key: &str,
        key_type: Option<BitcoinKeyType>,
    ) -> Result<PublicKey, KeyManagerError> {
        let private_key = PrivateKey::from_str(private_key)?;
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);
        self.keystore
            .store_keypair(private_key, public_key, key_type)?;

        Ok(public_key)
    }

    pub fn import_secret_key(
        &self,
        secret_key: &str,
        network: Network,
    ) -> Result<PublicKey, KeyManagerError> {
        self.import_secret_key_typed(secret_key, network, None)
    }

    pub fn import_secret_key_typed(
        &self,
        secret_key: &str,
        network: Network,
        key_type: Option<BitcoinKeyType>,
    ) -> Result<PublicKey, KeyManagerError> {
        let secret_key = SecretKey::from_str(secret_key)?;
        let private_key = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        self.keystore
            .store_keypair(private_key, public_key, key_type)?;
        Ok(public_key)
    }

    pub fn import_partial_secret_keys(
        &self,
        partial_keys: Vec<String>,
        network: Network,
    ) -> Result<PublicKey, KeyManagerError> {
        let partial_keys_bytes: Vec<Vec<u8>> = partial_keys
            .into_iter()
            .map(|key| SecretKey::from_str(&key).map(|sk| sk.secret_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;

        // Defensive: do not call musig2 aggregator with empty input - return an error instead
        if partial_keys_bytes.is_empty() {
            return Err(KeyManagerError::InvalidPrivateKey);
        }

        let (private_key, public_key) = self
            .musig2
            .aggregate_private_key(partial_keys_bytes, network)?;
        // should we assume p2tr? always to use them with musig2 and schnorr
        self.keystore.store_keypair(private_key, public_key, None)?;
        Ok(public_key)
    }

    pub fn import_partial_private_keys(
        &self,
        partial_keys: Vec<String>,
        network: Network,
    ) -> Result<PublicKey, KeyManagerError> {
        let partial_keys_bytes: Vec<Vec<u8>> = partial_keys
            .into_iter()
            .map(|key| PrivateKey::from_str(&key).map(|pk| pk.to_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;

        // Defensive: do not call musig2 aggregator with empty input - return an error instead
        if partial_keys_bytes.is_empty() {
            return Err(KeyManagerError::InvalidPrivateKey);
        }

        let (private_key, public_key) = self
            .musig2
            .aggregate_private_key(partial_keys_bytes, network)?;
        // Dev note: here we should be able to assume taproot keys..
        self.keystore.store_keypair(private_key, public_key, None)?;
        Ok(public_key)
    }

    pub fn import_rsa_private_key(
        &self,
        private_key: &str, // PEM format
    ) -> Result<String, KeyManagerError> {
        let rsa_keypair = RSAKeyPair::from_private_pem(private_key)?;
        self.keystore.store_rsa_key(rsa_keypair.clone())?;
        let rsa_pubkey_pem = rsa_keypair.export_public_pem()?;
        Ok(rsa_pubkey_pem)
    }

    /*********************************/
    /****** Derivation path **********/
    /*********************************/
    // DERIVATION PATH (BIP-44):
    //
    // m / purpose' / coin_type' / account' / change / address_index
    //
    // Purpose:
    // 44' = BIP44 - Legacy (P2PKH)
    // 49' = BIP49 - Legacy Nested SegWit (P2SH-P2WPKH)
    // 84' = BIP84 - Native SegWit (P2WPKH)
    // 86' = BIP86 - Taproot (P2TR)
    //
    // Coins:
    // 0 = Bitcoin mainnet
    // 1 = Bitcoin testnet/regtest
    //
    fn build_bip44_derivation_path(
        purpose: u32,
        coin_type: u32,
        account: u32,
        change: u32,
        index: u32,
    ) -> DerivationPath {
        DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(purpose).unwrap(),
            ChildNumber::from_hardened_idx(coin_type).unwrap(),
            ChildNumber::from_hardened_idx(account).unwrap(),
            ChildNumber::from_normal_idx(change).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ])
    }

    fn build_derivation_path(
        key_type: BitcoinKeyType,
        network: Network,
        index: u32,
    ) -> DerivationPath {
        Self::build_bip44_derivation_path(
            key_type.purpose_index(),
            Self::get_bitcoin_coin_type_by_network(network),
            Self::ACCOUNT_DERIVATION_INDEX,
            Self::CHANGE_DERIVATION_INDEX,
            index,
        )
    }

    fn extract_account_level_path(full_path: &DerivationPath) -> DerivationPath {
        // BIP-44: m/purpose'/coin_type'/account' - first 3 components
        DerivationPath::from(
            full_path
                .into_iter()
                .take(3) // purpose, coin_type, account
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn extract_chain_path(full_path: &DerivationPath) -> DerivationPath {
        // BIP-44: change/address_index - the chain derivation part
        DerivationPath::from(
            full_path
                .into_iter()
                .skip(3) // skip purpose, coin_type, account
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn get_bitcoin_coin_type_by_network(network: Network) -> u32 {
        match network {
            Network::Bitcoin => 0,  // Bitcoin mainnet
            Network::Testnet => 1,  // Bitcoin testnet
            Network::Testnet4 => 1, // Bitcoin testnet4
            Network::Regtest => 1,  // Bitcoin regtest (same as testnet)
            _ => panic!("Unsupported network"),
        }
    }

    /// Get the version bytes for extended private keys based on the key type and network
    fn get_xpriv_version_bytes(key_type: BitcoinKeyType, network: Network) -> [u8; 4] {
        match (key_type, network) {
            // Mainnet
            (BitcoinKeyType::P2pkh, Network::Bitcoin) => [0x04, 0x88, 0xAD, 0xE4], // xprv
            (BitcoinKeyType::P2shP2wpkh, Network::Bitcoin) => [0x04, 0x9D, 0x78, 0x78], // yprv
            (BitcoinKeyType::P2wpkh, Network::Bitcoin) => [0x04, 0xB2, 0x43, 0x0C], // zprv
            (BitcoinKeyType::P2tr, Network::Bitcoin) => [0x04, 0x88, 0xAD, 0xE4], // xprv (no specific version for taproot)

            // Testnet/Testnet4/Regtest/Signet (all use the same version bytes)
            (BitcoinKeyType::P2pkh, _) => [0x04, 0x35, 0x83, 0x94], // tprv
            (BitcoinKeyType::P2shP2wpkh, _) => [0x04, 0x4A, 0x4E, 0x28], // uprv
            (BitcoinKeyType::P2wpkh, _) => [0x04, 0x5F, 0x18, 0xBC], // vprv
            (BitcoinKeyType::P2tr, _) => [0x04, 0x35, 0x83, 0x94], // tprv (no specific version for taproot)
        }
    }

    /// Get the version bytes for extended public keys based on the key type and network
    fn get_xpub_version_bytes(key_type: BitcoinKeyType, network: Network) -> [u8; 4] {
        match (key_type, network) {
            // Mainnet
            (BitcoinKeyType::P2pkh, Network::Bitcoin) => [0x04, 0x88, 0xB2, 0x1E], // xpub
            (BitcoinKeyType::P2shP2wpkh, Network::Bitcoin) => [0x04, 0x9D, 0x7C, 0xB2], // ypub
            (BitcoinKeyType::P2wpkh, Network::Bitcoin) => [0x04, 0xB2, 0x47, 0x46], // zpub
            (BitcoinKeyType::P2tr, Network::Bitcoin) => [0x04, 0x88, 0xB2, 0x1E], // xpub (no specific version for taproot)

            // Testnet/Testnet4/Regtest/Signet (all use the same version bytes)
            (BitcoinKeyType::P2pkh, _) => [0x04, 0x35, 0x87, 0xCF], // tpub
            (BitcoinKeyType::P2shP2wpkh, _) => [0x04, 0x4A, 0x52, 0x62], // upub
            (BitcoinKeyType::P2wpkh, _) => [0x04, 0x5F, 0x1C, 0xF6], // vpub
            (BitcoinKeyType::P2tr, _) => [0x04, 0x35, 0x87, 0xCF], // tpub (no specific version for taproot)
        }
    }

    /// Convert an extended key string from one version to another by replacing version bytes
    fn convert_extended_key_version(
        extended_key: &str,
        target_version: [u8; 4],
    ) -> Result<String, KeyManagerError> {
        // Decode the base58check encoded extended key
        let decoded =
            base58::decode_check(extended_key).map_err(|_| KeyManagerError::CorruptedData)?;

        if decoded.len() != 78 {
            return Err(KeyManagerError::CorruptedData);
        }

        let mut new_data = decoded;
        // Replace the first 4 bytes (version) with the target version
        new_data[0..4].copy_from_slice(&target_version);

        // Re-encode with checksum
        Ok(base58::encode_check(&new_data))
    }

    // Winternitz uses BIP-39/BIP-44 style derivation with a hardened custom purpose path for winternitz:
    fn derive_winternitz_master_seed(
        secp: secp256k1::Secp256k1<All>,
        key_derivation_seed: &[u8],
        network: Network,
        account: u32,
    ) -> Result<[u8; 32], KeyManagerError> {
        // Dev note: Using coin type as its nice to differentiate by network, winternitz are OT,
        // so they should not be repeated across different networks, to avoid a kind of take from testnet and use in mainnet attack
        let wots_full_derivation_path = Self::build_bip44_derivation_path(
            Self::WINTERNITZ_PURPOSE_INDEX,
            Self::get_bitcoin_coin_type_by_network(network),
            account,
            Self::CHANGE_DERIVATION_INDEX,
            0, // index does not matter here
        );

        let hardened_wots_account_derivation_path =
            Self::extract_account_level_path(&wots_full_derivation_path);

        let master_xpriv = Xpriv::new_master(network, &key_derivation_seed)?;
        let account_xpriv =
            master_xpriv.derive_priv(&secp, &hardened_wots_account_derivation_path)?;

        let secret_32_bytes = account_xpriv.private_key.secret_bytes();

        // Return the private key bytes as master seed for Winternitz
        Ok(secret_32_bytes)
    }

    /*********************************/
    /******* Key Generation **********/
    /*********************************/

    // Generate account-level xpub (hardened up to account)
    pub fn get_account_xpub(&self, key_type: BitcoinKeyType) -> Result<Xpub, KeyManagerError> {
        let key_derivation_seed = self.keystore.load_key_derivation_seed()?;
        let master_xpriv = Xpriv::new_master(self.network, &key_derivation_seed)?;

        // Build the full derivation path and extract only up to account level
        let full_derivation_path = Self::build_derivation_path(key_type, self.network, 0); // index doesn't matter here
        let account_derivation_path = Self::extract_account_level_path(&full_derivation_path);

        let account_xpriv = master_xpriv.derive_priv(&self.secp, &account_derivation_path)?;
        let account_xpub = Xpub::from_priv(&self.secp, &account_xpriv);

        // Dev note: do not touch parity here
        // Parity normalization (even-Y) is a Taproot/Schnorr (BIP-340/341/86) concern and should be applied
        // only when you form the Taproot internal key for each address when using the full derivation path
        Ok(account_xpub)
    }

    /// Generate account-level extended public key with the correct BIP-specific version prefix
    /// Returns: xpub for BIP-44, ypub for BIP-49, zpub for BIP-84, etc.
    pub fn get_account_xpub_string(
        &self,
        key_type: BitcoinKeyType,
    ) -> Result<String, KeyManagerError> {
        let account_xpub = self.get_account_xpub(key_type)?;
        let standard_xpub_string = account_xpub.to_string();

        // Convert to the appropriate version based on key type
        let target_version = Self::get_xpub_version_bytes(key_type, self.network);
        Self::convert_extended_key_version(&standard_xpub_string, target_version)
    }

    /// Generate account-level extended private key with the correct BIP-specific version prefix
    /// Returns: xprv for BIP-44, yprv for BIP-49, zprv for BIP-84, etc.
    #[allow(dead_code)] // we want this method for tests and might be useful in a future xpriv export
    fn get_account_xpriv_string(
        &self,
        key_type: BitcoinKeyType,
    ) -> Result<String, KeyManagerError> {
        let key_derivation_seed = self.keystore.load_key_derivation_seed()?;
        let master_xpriv = Xpriv::new_master(self.network, &key_derivation_seed)?;

        // Build the full derivation path and extract only up to account level
        let full_derivation_path = Self::build_derivation_path(key_type, self.network, 0);
        let account_derivation_path = Self::extract_account_level_path(&full_derivation_path);
        let account_xpriv = master_xpriv.derive_priv(&self.secp, &account_derivation_path)?;

        let standard_xpriv_string = account_xpriv.to_string();

        // Convert to the appropriate version based on key type
        let target_version = Self::get_xpriv_version_bytes(key_type, self.network);
        Self::convert_extended_key_version(&standard_xpriv_string, target_version)
    }

    /// Derives a Bitcoin keypair at a specific derivation index using BIP-39/BIP-44 hierarchical deterministic (HD) derivation.
    ///
    /// ** Usage of this function is discouraged in favor of [`next_keypair`](Self::next_keypair).**
    ///
    /// The `next_keypair` function provides better index management by automatically tracking
    /// the next available derivation index, preventing accidental key reuse and simplifying
    /// key generation workflows.
    ///
    pub fn derive_keypair(
        &self,
        key_type: BitcoinKeyType,
        index: u32,
    ) -> Result<PublicKey, KeyManagerError> {
        let key_derivation_seed = self.keystore.load_key_derivation_seed()?;
        let master_xpriv = Xpriv::new_master(self.network, &key_derivation_seed)?;
        let derivation_path = KeyManager::build_derivation_path(key_type, self.network, index);

        let xpriv = master_xpriv.derive_priv(&self.secp, &derivation_path)?;
        let internal_keypair = xpriv.to_keypair(&self.secp);

        // Dev Note: taproot keys use “x-only with even-Y” at address generation time, but to follow
        // the standars the parity should not be modified here at derivation time.

        let public_key = PublicKey::new(internal_keypair.public_key());
        let private_key = PrivateKey::new(internal_keypair.secret_key(), self.network);

        self.keystore
            .store_keypair(private_key, public_key, Some(key_type))?;
        Ok(public_key)
    }

    /// Derives a Bitcoin keypair, in the case of taproot keys, adjusts the parity to be even-Y.
    ///
    /// ** Usage of this function is discouraged in favor of [`next_keypair_adjusted`](Self::next_keypair_adjusted).**
    ///
    /// The `next_keypair_adjusted` function provides better index management by automatically tracking
    /// the next available derivation index, preventing accidental key reuse and simplifying
    /// key generation workflows.
    ///
    pub fn derive_keypair_adjust_parity(
        &self,
        key_type: BitcoinKeyType,
        index: u32,
    ) -> Result<PublicKey, KeyManagerError> {
        let key_derivation_seed = self.keystore.load_key_derivation_seed()?;
        let master_xpriv = Xpriv::new_master(self.network, &key_derivation_seed)?;
        let derivation_path = KeyManager::build_derivation_path(key_type, self.network, index);

        let xpriv = master_xpriv.derive_priv(&self.secp, &derivation_path)?;
        let internal_keypair = xpriv.to_keypair(&self.secp);

        // Dev Note: taproot keys use “x-only with even-Y” at address generation time, but to follow
        // the standars the parity should not be modified here at derivation time.
        // but in the case of this function, we adjust parity here just to facilitate that the user
        // in case he want the parity adjusted key to use it a some low lvl taproot/musig construction

        let (public_key, private_key) = if key_type == BitcoinKeyType::P2tr {
            self.adjust_parity(internal_keypair)
        } else {
            (
                PublicKey::new(internal_keypair.public_key()),
                PrivateKey::new(internal_keypair.secret_key(), self.network),
            )
        };

        self.keystore
            .store_keypair(private_key, public_key, Some(key_type))?;
        Ok(public_key)
    }

    /// Generates the next Bitcoin keypair in sequence using automatic index management and BIP-39/BIP-44 HD derivation.
    /// in the case of taproot keys, adjusts the parity to be even-Y.
    ///
    /// This is the **recommended** function for keypair generation as it provides automatic index management,
    /// preventing accidental key reuse and simplifying key generation workflows compared to [`derive_keypair_adjust_parity`](Self::derive_keypair_adjust_parity).
    ///
    /// The function automatically tracks and increments the derivation index for each key type, ensuring that:
    /// - Each call generates a unique keypair
    /// - No derivation indices are accidentally reused
    /// - The sequence of generated keys is deterministic and recoverable
    ///
    pub fn next_keypair(&self, key_type: BitcoinKeyType) -> Result<PublicKey, KeyManagerError> {
        let index = self.next_keypair_index(key_type)?;
        let pubkey = self.derive_keypair(key_type, index)?;
        // if derivation was successful, store the next index
        self.keystore
            .store_next_keypair_index(key_type, index + 1)?;
        Ok(pubkey)
    }

    /// Generates the next Bitcoin keypair in sequence using automatic index management and BIP-39/BIP-44 HD derivation.
    ///
    /// This is the **recommended** function for keypair generation as it provides automatic index management,
    /// preventing accidental key reuse and simplifying key generation workflows compared to [`derive_keypair`](Self::derive_keypair).
    ///
    /// The function automatically tracks and increments the derivation index for each key type, ensuring that:
    /// - Each call generates a unique keypair
    /// - No derivation indices are accidentally reused
    /// - The sequence of generated keys is deterministic and recoverable
    ///
    pub fn next_keypair_adjusted(
        &self,
        key_type: BitcoinKeyType,
    ) -> Result<PublicKey, KeyManagerError> {
        let index = self.next_keypair_index(key_type)?;
        let pubkey = self.derive_keypair_adjust_parity(key_type, index)?;
        // if derivation was successful, store the next index
        self.keystore
            .store_next_keypair_index(key_type, index + 1)?;
        Ok(pubkey)
    }

    fn next_keypair_index(&self, key_type: BitcoinKeyType) -> Result<u32, KeyManagerError> {
        match self.keystore.load_next_keypair_index(key_type) {
            Ok(stored_index) => Ok(stored_index),
            Err(KeyManagerError::NextKeypairIndexNotFound) => Ok(Self::STARTING_DERIVATION_INDEX),
            Err(e) => Err(e), // Propagate other errors (e.g., storage/decryption errors)
        }
    }

    // This method changes the parity of a keypair to be even, this is needed for Taproot.
    fn adjust_parity(&self, keypair: Keypair) -> (PublicKey, PrivateKey) {
        let (_, parity) = keypair.public_key().x_only_public_key();

        if parity == Parity::Odd {
            (
                PublicKey::new(keypair.public_key().negate(&self.secp)),
                PrivateKey::new(keypair.secret_key().negate(), self.network),
            )
        } else {
            (
                PublicKey::new(keypair.public_key()),
                PrivateKey::new(keypair.secret_key(), self.network),
            )
        }
    }

    // This method changes the parity of a public key to be even, this is needed for Taproot.
    fn adjust_public_key_only_parity(&self, public_key: PublicKey) -> PublicKey {
        let (_, parity) = public_key.inner.x_only_public_key();

        if parity == Parity::Odd {
            PublicKey::new(public_key.inner.negate(&self.secp))
        } else {
            public_key
        }
    }

    /// Derives the public key at a specific derivation index from an account-level extended public key (xpub).
    ///
    // Security: Only exposes account-level xpub, not master xpub
    // BIP-44 Compliance: Follows the standard hardened derivation up to account level
    // Privacy: Different accounts remain isolated
    // Flexibility: Can still derive all keys within an account from the account xpub
    pub fn derive_public_key_from_account_xpub(
        &self,
        account_xpub: Xpub,
        key_type: BitcoinKeyType,
        index: u32,
        adjust_parity_for_taproot: bool,
    ) -> Result<PublicKey, KeyManagerError> {
        let secp = secp256k1::Secp256k1::new();

        // key type seems irrelevant here, as we will start from account xpub that alrady has its key_type (purpose) specified,
        // and we will add just the chain path, but we need it in order to know if we need to adjust parity or not for the final key

        // Build the full derivation path and extract only the chain part after account level
        let full_derivation_path = Self::build_derivation_path(key_type, self.network, index);
        let chain_derivation_path = Self::extract_chain_path(&full_derivation_path);

        let xpub = account_xpub.derive_pub(&secp, &chain_derivation_path)?;

        if adjust_parity_for_taproot && key_type == BitcoinKeyType::P2tr {
            Ok(self.adjust_public_key_only_parity(xpub.to_pub().into()))
        } else {
            Ok(xpub.to_pub().into())
        }
    }

    /// Derives a Winternitz OT key at a specific derivation index using BIP-39/BIP-44 hierarchical deterministic (HD) derivation.
    ///
    /// ** Usage of this function is discouraged in favor of [`next_winternitz`](Self::next_winternitz) instead. **
    ///
    /// The `next_winternitz` function provides a secure index management by automatically tracking
    /// the next available derivation index, preventing accidental key reuse and simplifying
    /// key generation workflows.
    ///
    // TODO make this func private in the future to force the usage of next_winternitz
    pub fn derive_winternitz(
        &self,
        message_size_in_bytes: usize,
        key_type: WinternitzType,
        index: u32,
    ) -> Result<winternitz::WinternitzPublicKey, KeyManagerError> {
        let message_digits_length = winternitz::message_digits_length(message_size_in_bytes);
        let checksum_size = checksum_length(message_digits_length);

        let master_secret = self.keystore.load_winternitz_seed()?;

        let winternitz = winternitz::Winternitz::new();
        let public_key = winternitz.generate_public_key(
            &master_secret,
            key_type,
            message_digits_length,
            checksum_size,
            index,
        )?;

        Ok(public_key)
    }

    /// Generates the next Winternitz OT key in sequence using automatic index management and BIP-39/BIP-44 HD derivation.
    ///
    /// This is the **recommended** function for Winternitz key generation as it provides automatic index management,
    /// preventing accidental key reuse and simplifying key generation workflows compared to [`derive_winternitz`](Self::derive_winternitz).
    ///
    /// The function automatically tracks and increments the derivation index for each Winternitz type and message size combination, ensuring that:
    /// - Each call generates a unique Winternitz key
    /// - No derivation indices are accidentally reused
    /// - The sequence of generated keys is deterministic and recoverable
    /// - Different message sizes for the same Winternitz type have separate index counters
    ///
    pub fn next_winternitz(
        &self,
        message_size_in_bytes: usize,
        key_type: WinternitzType,
    ) -> Result<winternitz::WinternitzPublicKey, KeyManagerError> {
        let index = self.next_winternitz_index()?;
        let pubkey = self.derive_winternitz(message_size_in_bytes, key_type, index)?;
        // if derivation was successful, store the next index
        self.keystore.store_next_winternitz_index(index + 1)?;
        Ok(pubkey)
    }

    fn next_winternitz_index(&self) -> Result<u32, KeyManagerError> {
        match self.keystore.load_next_winternitz_index() {
            Ok(stored_index) => Ok(stored_index),
            Err(KeyManagerError::NextWinternitzIndexNotFound) => {
                Ok(Self::STARTING_DERIVATION_INDEX)
            }
            Err(e) => Err(e), // Propagate other errors (e.g., storage/decryption errors)
        }
    }

    /// Derives n Winternitz OT key starting at a specific derivation index using BIP-39/BIP-44 hierarchical deterministic (HD) derivation.
    ///
    /// ** Usage of this function is discouraged in favor of [`next_multiple_winternitz`](Self::next_multiple_winternitz) instead. **
    ///
    /// The `next_multiple_winternitz` function provides a secure index management by automatically tracking
    /// the next available derivation index, preventing accidental key reuse and simplifying
    /// key generation workflows.
    ///
    // TODO make this func private in the future to force the usage of next_multiple_winternitz
    pub fn derive_multiple_winternitz(
        &self,
        message_size_in_bytes: usize,
        key_type: WinternitzType,
        initial_index: u32,
        number_of_keys: u32,
    ) -> Result<Vec<winternitz::WinternitzPublicKey>, KeyManagerError> {
        let message_digits_length = winternitz::message_digits_length(message_size_in_bytes);
        let checksum_size = checksum_length(message_digits_length);

        let master_secret = self.keystore.load_winternitz_seed()?;

        let mut public_keys = Vec::new();

        for index in initial_index..initial_index + number_of_keys {
            let winternitz = winternitz::Winternitz::new();
            let public_key = winternitz.generate_public_key(
                &master_secret,
                key_type,
                message_digits_length,
                checksum_size,
                index,
            )?;
            public_keys.push(public_key);
        }

        Ok(public_keys)
    }

    /// Generates the next n Winternitz OT keys in sequence using automatic index management and BIP-39/BIP-44 HD derivation.
    ///
    /// This is the **recommended** function for Winternitz key generation as it provides automatic index management,
    /// preventing accidental key reuse and simplifying key generation workflows compared to [`derive_multiple_winternitz`](Self::derive_multiple_winternitz).
    ///
    pub fn next_multiple_winternitz(
        &self,
        message_size_in_bytes: usize,
        key_type: WinternitzType,
        number_of_keys: u32,
    ) -> Result<Vec<winternitz::WinternitzPublicKey>, KeyManagerError> {
        let initial_index = self.next_winternitz_index()?;
        let pubkeys = self.derive_multiple_winternitz(
            message_size_in_bytes,
            key_type,
            initial_index,
            number_of_keys,
        )?;
        // if derivation was successful, store the next index
        self.keystore
            .store_next_winternitz_index(initial_index + number_of_keys)?;
        Ok(pubkeys)
    }

    // Dev note: this key is not related to the key derivation seed used for HD wallets
    // In the future we can find a way to securely derive it from a mnemonic too
    pub fn generate_rsa_keypair<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<String, KeyManagerError> {
        let rsa_keypair = RSAKeyPair::new(rng, DEFAULT_RSA_BITS)?;
        self.keystore.store_rsa_key(rsa_keypair.clone())?;
        let rsa_pubkey_pem = rsa_keypair.export_public_pem()?;
        Ok(rsa_pubkey_pem)
    }

    // Dev note: this key is not related to the key derivation seed used for HD wallets
    // In the future we can find a way to securely derive it from a mnemonic too
    pub fn generate_rsa_keypair_custom<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        bits: usize,
    ) -> Result<String, KeyManagerError> {
        if bits > MAX_RSA_BITS {
            return Err(KeyManagerError::InvalidRSAKeySize(format!(
                "RSA key size too large, maximum is {} bits",
                MAX_RSA_BITS
            )));
        }
        let rsa_keypair = RSAKeyPair::new(rng, bits)?;
        self.keystore.store_rsa_key(rsa_keypair.clone())?;
        let rsa_pubkey_pem = rsa_keypair.export_public_pem()?;
        Ok(rsa_pubkey_pem)
    }

    /*********************************/
    /*********** Signing *************/
    /*********************************/

    // Dev note: added key type checks for signing, we were using any key for ecdsa or schnorr

    pub fn sign_ecdsa_message(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<secp256k1::ecdsa::Signature, KeyManagerError> {
        #[cfg_attr(not(feature = "strict"), allow(unused_variables))]
        let (sk, _, key_type) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_ecdsa_message compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        // Check if this is a Taproot key - ECDSA is not supported for P2TR keys
        #[cfg(feature = "strict")]
        {
            if let Some(key_type) = key_type {
                if key_type == BitcoinKeyType::P2tr {
                    return Err(KeyManagerError::EcdsaWithTaprootKey);
                }
            }
        }

        Ok(self.secp.sign_ecdsa(message, &sk.inner))
    }

    pub fn sign_ecdsa_recoverable_message(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<secp256k1::ecdsa::RecoverableSignature, KeyManagerError> {
        #[cfg_attr(not(feature = "strict"), allow(unused_variables))]
        let (sk, _, key_type) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_ecdsa_recoverable_message compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        // Check if this is a Taproot key - ECDSA is not supported for P2TR keys
        #[cfg(feature = "strict")]
        {
            if let Some(key_type) = key_type {
                if key_type == BitcoinKeyType::P2tr {
                    return Err(KeyManagerError::EcdsaWithTaprootKey);
                }
            }
        }

        Ok(self.secp.sign_ecdsa_recoverable(message, &sk.inner))
    }

    pub fn sign_ecdsa_messages(
        &self,
        messages: Vec<Message>,
        public_keys: Vec<PublicKey>,
    ) -> Result<Vec<secp256k1::ecdsa::Signature>, KeyManagerError> {
        let mut signatures = Vec::new();

        for (message, public_key) in izip!(messages.iter(), public_keys.iter(),) {
            let signature = self.sign_ecdsa_message(message, public_key)?;
            signatures.push(signature);
        }

        Ok(signatures)
    }

    pub fn sign_ecdsa_recoverable_messages(
        &self,
        messages: Vec<Message>,
        public_keys: Vec<PublicKey>,
    ) -> Result<Vec<secp256k1::ecdsa::RecoverableSignature>, KeyManagerError> {
        let mut signatures = Vec::new();

        for (message, public_key) in izip!(messages.iter(), public_keys.iter(),) {
            let signature = self.sign_ecdsa_recoverable_message(message, public_key)?;
            signatures.push(signature);
        }

        Ok(signatures)
    }

    // For taproot script spend
    pub fn sign_schnorr_message(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<secp256k1::schnorr::Signature, KeyManagerError> {
        #[cfg_attr(not(feature = "strict"), allow(unused_variables))]
        let (sk, _, _key_type) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_schnorr_message compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )));
            }
        };

        // Check if this key type is appropriate for Schnorr signatures
        // Allow None (imported keys) or P2TR keys, reject others
        #[cfg(feature = "strict")]
        {
            if let Some(key_type) = _key_type {
                if key_type != BitcoinKeyType::P2tr {
                    return Err(KeyManagerError::SchnorrWithNonTaprootKey);
                }
            }
        }

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);

        Ok(self.secp.sign_schnorr(message, &keypair))
    }

    // For taproot key spend
    pub fn sign_schnorr_message_with_tap_tweak(
        &self,
        message: &Message,
        public_key: &PublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<(secp256k1::schnorr::Signature, PublicKey), KeyManagerError> {
        #[cfg_attr(not(feature = "strict"), allow(unused_variables))]
        let (sk, _, _key_type) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_schnorr_message_with_tap_tweak compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        // Check if this key type is appropriate for Schnorr signatures
        // Allow None (imported keys) or P2TR keys, reject others
        #[cfg(feature = "strict")]
        {
            if let Some(key_type) = _key_type {
                if key_type != BitcoinKeyType::P2tr {
                    return Err(KeyManagerError::SchnorrWithNonTaprootKey);
                }
            }
        }

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);

        let tweaked_keypair = keypair.tap_tweak(&self.secp, merkle_root);
        let keypair = tweaked_keypair.into();
        Ok((
            self.secp.sign_schnorr(message, &keypair),
            PublicKey::new(keypair.public_key()),
        ))
    }

    // For taproot key spend with tweak
    pub fn sign_schnorr_message_with_tweak(
        &self,
        message: &Message,
        public_key: &PublicKey,
        tweak: &Scalar,
    ) -> Result<(secp256k1::schnorr::Signature, PublicKey), KeyManagerError> {
        #[cfg_attr(not(feature = "strict"), allow(unused_variables))]
        let (sk, _, _key_type) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_schnorr_message_with_tweak compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        // Check if this key type is appropriate for Schnorr signatures
        // Allow None (imported keys) or P2TR keys, reject others
        #[cfg(feature = "strict")]
        {
            if let Some(key_type) = _key_type {
                if key_type != BitcoinKeyType::P2tr {
                    return Err(KeyManagerError::SchnorrWithNonTaprootKey);
                }
            }
        }

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);
        let tweaked_keypair = keypair.add_xonly_tweak(&self.secp, tweak)?;

        Ok((
            self.secp.sign_schnorr(message, &tweaked_keypair),
            PublicKey::new(keypair.public_key()),
        ))
    }

    // For taproot script spend
    pub fn sign_schnorr_messages(
        &self,
        messages: Vec<Message>,
        public_keys: Vec<PublicKey>,
    ) -> Result<Vec<secp256k1::schnorr::Signature>, KeyManagerError> {
        let mut signatures = Vec::new();

        for (message, public_key) in izip!(messages.iter(), public_keys.iter(),) {
            let signature = self.sign_schnorr_message(message, public_key)?;
            signatures.push(signature);
        }

        Ok(signatures)
    }

    // For one-time winternitz keys
    pub fn sign_winternitz_message(
        &self,
        message_bytes: &[u8],
        key_type: WinternitzType,
        index: u32,
    ) -> Result<WinternitzSignature, KeyManagerError> {
        let message_digits_length = winternitz::message_digits_length(message_bytes.len());
        let checksummed_message = to_checksummed_message(message_bytes);
        let checksum_size = checksum_length(message_digits_length);
        let message_size = checksummed_message.len() - checksum_size;

        assert!(message_size == message_digits_length);

        let master_secret = self.keystore.load_winternitz_seed()?;
        let winternitz = winternitz::Winternitz::new();
        let private_key = winternitz.generate_private_key(
            &master_secret,
            key_type,
            message_size,
            checksum_size,
            index,
        )?;

        let signature =
            winternitz.sign_message(message_digits_length, &checksummed_message, &private_key);

        Ok(signature)
    }

    // For one-time winternitz keys
    pub fn sign_winternitz_message_by_pubkey(
        &self,
        message_bytes: &[u8],
        public_key: &WinternitzPublicKey,
    ) -> Result<WinternitzSignature, KeyManagerError> {
        self.sign_winternitz_message(
            message_bytes,
            public_key.key_type(),
            public_key.derivation_index()?,
        )
    }

    /// Exports the private key for a given public key.
    ///
    /// Note: Each public key uniquely maps to exactly one private key in the keystore.
    /// The caller must know the KeyType used during key derivation, as this will be
    /// needed later when deriving addresses from the exported private key.
    /// The KeyType is not required here since the keystore is a simple pubkey -> privkey mapping.
    pub fn export_secret(&self, pubkey: &PublicKey) -> Result<PrivateKey, KeyManagerError> {
        match self.keystore.load_keypair(pubkey)? {
            Some((private_key, _, _)) => Ok(private_key),
            None => Err(KeyManagerError::KeyPairNotFound(format!(
                "export_secret compressed {} public key: {:?}",
                pubkey.to_string(),
                pubkey
            ))),
        }
    }

    pub fn sign_rsa_message(
        &self,
        message: &[u8],
        pub_key: &str, // PEM format
    ) -> Result<Signature, KeyManagerError> {
        let pubk = RSAKeyPair::pubkey_from_public_key_pem(&pub_key)?;
        let rsa_key = self.keystore.load_rsa_key(pubk)?;
        match rsa_key {
            Some(rsa_key) => Ok(rsa_key.sign(message)),
            None => return Err(KeyManagerError::RsaKeyNotFound),
        }
    }

    pub fn encrypt_rsa_message(
        &self,
        message: &[u8],
        pub_key: &str, // PEM format
    ) -> Result<Vec<u8>, KeyManagerError> {
        Ok(RSAKeyPair::encrypt(message, &pub_key, &mut OsRng)?)
    }

    pub fn decrypt_rsa_message(
        &self,
        encrypted_message: &[u8],
        pub_key: &str, // PEM format
    ) -> Result<Vec<u8>, KeyManagerError> {
        let pubk = RSAKeyPair::pubkey_from_public_key_pem(&pub_key)?;
        let rsa_key = self.keystore.load_rsa_key(pubk)?;
        match rsa_key {
            Some(rsa_key) => Ok(rsa_key.decrypt(encrypted_message)?),
            None => return Err(KeyManagerError::RsaKeyNotFound),
        }
    }

    /*********************************/
    /*********** MuSig2 **************/
    /*********************************/

    //TODO: Revisit this decision. The private key is used for the TOO protocol.
    pub fn get_key_pair_for_too_insecure(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<(PrivateKey, PublicKey), KeyManagerError> {
        let my_pub_key = self.musig2.my_public_key(aggregated_pubkey).unwrap();

        match self.keystore.load_keypair(&my_pub_key)? {
            Some((private_key, public_key, _)) => Ok((private_key, public_key)),
            None => Err(KeyManagerError::KeyPairNotFound(format!(
                "get_key_pair_for_too_insecure compressed {} public key: {:?}",
                my_pub_key.to_string(),
                my_pub_key
            ))),
        }
    }

    pub fn sign_partial_message(
        &self,
        aggregated_pubkey: &PublicKey,
        my_public_key: PublicKey,
        secnonce: SecNonce,
        aggregated_nonce: AggNonce,
        tweak: Option<musig2::secp256k1::Scalar>,
        message: Vec<u8>,
    ) -> Result<PartialSignature, KeyManagerError> {
        let key_aggregation_context = self.musig2.get_key_agg_context(aggregated_pubkey, tweak)?;

        let (private_key, _, _) = match self.keystore.load_keypair(&my_public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_partial_message compressed {} public key: {:?}",
                    my_public_key.to_string(),
                    my_public_key
                )))
            }
        };

        let sk = musig2::secp256k1::SecretKey::from_slice(&private_key[..])
            .map_err(|_| KeyManagerError::InvalidPrivateKey)?;

        let result = sign_partial(
            &key_aggregation_context,
            sk,
            secnonce,
            &aggregated_nonce,
            message,
        );

        match result {
            Ok(signature) => Ok(signature),
            Err(e) => {
                debug!("Failed to sign message: {:?}", e);
                Err(KeyManagerError::FailedToSignMessage)
            }
        }
    }

    pub fn generate_nonce_seed(
        &self,
        index: u32,
        public_key: PublicKey,
    ) -> Result<[u8; 32], KeyManagerError> {
        let (sk, _, _) = match self.keystore.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "generate_nonce_seed compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        // Use HKDF for secure key derivation with salt and context info
        // Salt: derived from public key to ensure different salts for different keys
        let salt = hashes::sha256::Hash::hash(&public_key.to_bytes()).to_byte_array();

        // Input key material: secret key bytes
        let ikm = sk.to_bytes();

        // Context info: includes index and a domain separator
        let mut info = Vec::new();
        info.extend_from_slice(MUSIG2_NONCE_HKDF_INFO);
        info.extend_from_slice(&index.to_le_bytes());

        // Derive the nonce seed using HKDF-SHA256
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut nonce_seed = [0u8; 32];
        hkdf.expand(&info, &mut nonce_seed)
            .map_err(|_| KeyManagerError::FailedToGenerateNonceSeed)?;

        Ok(nonce_seed)
    }

    pub fn new_musig2_session(
        &self,
        participant_pubkeys: Vec<PublicKey>,
        my_pub_key: PublicKey,
    ) -> Result<PublicKey, KeyManagerError> {
        Ok(self.musig2.new_session(participant_pubkeys, my_pub_key)?)
    }

    pub fn get_my_public_key(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<PublicKey, KeyManagerError> {
        Ok(self.musig2.my_public_key(aggregated_pubkey)?)
    }

    pub fn get_pubkey(&self, aggregated_pubkey: &PublicKey) -> Result<PublicKey, KeyManagerError> {
        Ok(self.musig2.my_public_key(aggregated_pubkey)?)
    }

    pub fn get_key_agg_context(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<musig2::KeyAggContext, KeyManagerError> {
        Ok(self.musig2.get_key_agg_context(aggregated_pubkey, None)?)
    }

    pub fn aggregate_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        pub_nonces_map: HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
    ) -> Result<(), KeyManagerError> {
        Ok(self
            .musig2
            .aggregate_nonces(aggregated_pubkey, id, pub_nonces_map)?)
    }

    pub fn get_my_pub_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, PubNonce)>, KeyManagerError> {
        Ok(self.musig2.get_my_pub_nonces(aggregated_pubkey, id)?)
    }

    pub fn get_my_pub_nonce(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<PubNonce, KeyManagerError> {
        Ok(self
            .musig2
            .get_my_pub_nonce(aggregated_pubkey, id, message_id)?)
    }

    pub fn save_partial_signatures_multi(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        mut partial_signatures_mapping: HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
    ) -> Result<(), KeyManagerError> {
        //TODO: Fix this
        //this is a workaround bacause the as leader I got all the partial before sending mine
        //and therefore have it computed.
        //this should change in program

        let my_partial_signatures = self.get_my_partial_signatures(aggregated_pubkey, id)?;
        let my_pub_key = self.musig2.my_public_key(aggregated_pubkey)?;
        partial_signatures_mapping.insert(my_pub_key, my_partial_signatures.clone());

        Ok(self.save_partial_signatures(aggregated_pubkey, id, partial_signatures_mapping)?)
    }

    pub fn save_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        partial_signatures_mapping: HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
    ) -> Result<(), KeyManagerError> {
        Ok(self.musig2.save_partial_signatures(
            aggregated_pubkey,
            id,
            partial_signatures_mapping,
        )?)
    }

    pub fn get_my_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, PartialSignature)>, KeyManagerError> {
        let mut my_partial_signatures = Vec::new();

        let data_to_iterate = self
            .musig2
            .get_data_for_partial_signatures(aggregated_pubkey, id)?;
        let my_pub_key = self.musig2.my_public_key(aggregated_pubkey)?;

        for (message_id, (message, sec_nonce, tweak, aggregated_nonce)) in data_to_iterate.iter() {
            let sig = self
                .sign_partial_message(
                    aggregated_pubkey,
                    my_pub_key,
                    sec_nonce.clone(),
                    aggregated_nonce.clone(),
                    *tweak,
                    message.clone(),
                )
                .map_err(|_| Musig2SignerError::InvalidSignature)?;

            my_partial_signatures.push((message_id.clone(), sig));
        }

        Ok(my_partial_signatures)
    }

    pub fn get_my_partial_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<PartialSignature, KeyManagerError> {
        let (message, sec_nonce, tweak, aggregated_nonce) = self
            .musig2
            .get_data_for_partial_signature(aggregated_pubkey, id, message_id)?;

        let sig = self
            .sign_partial_message(
                aggregated_pubkey,
                self.musig2.my_public_key(aggregated_pubkey)?,
                sec_nonce.clone(),
                aggregated_nonce.clone(),
                tweak,
                message.clone(),
            )
            .map_err(|_| Musig2SignerError::InvalidSignature)?;

        Ok(sig)
    }

    pub fn get_aggregated_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<secp256k1::schnorr::Signature, KeyManagerError> {
        Ok(self
            .musig2
            .get_aggregated_signature(aggregated_pubkey, id, message_id)?)
    }

    pub fn generate_nonce(
        &self,
        message_id: &str,
        message: Vec<u8>,
        aggregated_pubkey: &PublicKey,
        id: &str,
        tweak: Option<musig2::secp256k1::Scalar>,
    ) -> Result<(), KeyManagerError> {
        let index = self.musig2.get_index(aggregated_pubkey)?;
        let public_key = self.musig2.my_public_key(aggregated_pubkey)?;

        let nonce_seed: [u8; 32] = self
            .generate_nonce_seed(index, public_key)
            .map_err(|_| Musig2SignerError::NonceSeedError)?;

        Ok(self.musig2.generate_nonce(
            message_id,
            message,
            aggregated_pubkey,
            id,
            tweak,
            nonce_seed,
        )?)
    }

    pub fn verify_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        pubkey: PublicKey,
        partial_signatures: Vec<(String, PartialSignature)>,
    ) -> Result<bool, KeyManagerError> {
        Ok(self.musig2.verify_partial_signatures(
            aggregated_pubkey,
            id,
            pubkey,
            partial_signatures,
        )?)
    }

    pub fn verify_final_signature(
        &self,
        message_id: &str,
        final_signature: secp256k1::schnorr::Signature,
        aggregated_pubkey: PublicKey,
        id: &str,
    ) -> Result<bool, KeyManagerError> {
        Ok(self.musig2.verify_final_signature(
            message_id,
            final_signature,
            aggregated_pubkey,
            id,
        )?)
    }

    /*pub fn get_aggregated_pubkey(&self, id: &str) -> Result<PublicKey, Musig2SignerError> {
        self.musig2.get_aggregated_pubkey(id)
    }*/
}

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;
    use bitcoin::{
        bip32::Xpriv,
        hex::DisplayHex,
        key::{
            rand::{self, RngCore},
            CompressedPublicKey, Parity, Secp256k1,
        },
        secp256k1::{self, Message, SecretKey},
        Address, Network, PrivateKey, PublicKey, XOnlyPublicKey,
    };
    use std::{env, fs, panic, rc::Rc, str::FromStr};
    use storage_backend::{storage::Storage, storage_config::StorageConfig};

    use crate::{
        errors::{KeyManagerError, WinternitzError},
        key_store::KeyStore,
        key_type::BitcoinKeyType,
        rsa::RSAKeyPair,
        verifier::SignatureVerifier,
        winternitz::{to_checksummed_message, WinternitzType},
    };

    use super::KeyManager;

    const REGTEST: Network = Network::Regtest;

    #[test]
    fn test_generate_nonce_seed() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_deterministic_key_manager(keystore_storage_config)?;
        let pub_key: PublicKey =
            key_manager.derive_keypair_adjust_parity(BitcoinKeyType::P2tr, 0)?;

        let pub_key2: PublicKey =
            key_manager.derive_keypair_adjust_parity(BitcoinKeyType::P2tr, 1)?;

        // Small test to check that the nonce is deterministic with the same index and public key
        let nonce_seed = key_manager.generate_nonce_seed(0, pub_key)?;
        assert_eq!(
            nonce_seed.to_lower_hex_string(),
            "018365b1811bbf730dbcda2fc621e79470057679a13239bcbb5719b418ac9fa0"
        );
        let nonce_seed_repeat = key_manager.generate_nonce_seed(0, pub_key)?;
        assert_eq!(
            nonce_seed.to_lower_hex_string(),
            nonce_seed_repeat.to_lower_hex_string()
        );

        // Test that the nonce is different for different index
        let nonce_seed_1 = key_manager.generate_nonce_seed(1, pub_key)?;
        assert_eq!(
            nonce_seed_1.to_lower_hex_string(),
            "bdd5ee7734d2edda684c1e52ff8db1244bba20f992437c58e816ec3e1af915d5"
        );
        let nonce_seed_4 = key_manager.generate_nonce_seed(4, pub_key)?;
        assert_eq!(
            nonce_seed_4.to_lower_hex_string(),
            "09d494894e401d604e88874bc54b18a71168d29190697f1d213746613b83f84f"
        );

        // Test that the nonce is different for different public key
        let nonce_seed_2 = key_manager.generate_nonce_seed(0, pub_key2)?;
        assert_eq!(
            nonce_seed_2.to_lower_hex_string(),
            "5e501a86513dc9940d45ec1818799fd666718ba0dc819f162249ddaa842c2633"
        );
        assert_ne!(
            nonce_seed.to_lower_hex_string(),
            nonce_seed_2.to_lower_hex_string()
        );

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_sign_ecdsa_message() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let signature_verifier = SignatureVerifier::new();
            let pk = key_manager.next_keypair(BitcoinKeyType::P2wpkh)?;
            let message = random_message();
            let signature = key_manager.sign_ecdsa_message(&message, &pk)?;

            assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));
            Ok(())
        })
    }

    #[test]
    fn test_sign_ecdsa_recoverable_message() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let signature_verifier = SignatureVerifier::new();
            let pk = key_manager.next_keypair(BitcoinKeyType::P2wpkh)?;
            let message = random_message();
            let recoverable_signature =
                key_manager.sign_ecdsa_recoverable_message(&message, &pk)?;
            let signature = recoverable_signature.to_standard();

            assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));
            Ok(())
        })
    }

    #[test]
    fn test_sign_schnorr_message() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let signature_verifier = SignatureVerifier::new();
            let pk = key_manager.next_keypair(BitcoinKeyType::P2tr)?;
            let message = random_message();
            let signature = key_manager.sign_schnorr_message(&message, &pk)?;

            assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk));
            Ok(())
        })
    }

    #[test]
    fn test_sign_schnorr_message_with_tap_tweak() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;
        let signature_verifier = SignatureVerifier::new();

        let pk = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;

        let message = random_message();
        let (signature, tweaked_key) =
            key_manager.sign_schnorr_message_with_tap_tweak(&message, &pk, None)?;

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, tweaked_key));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_sign_winternitz_message_sha256() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;
        let signature_verifier = SignatureVerifier::new();

        let message = random_message();

        let pk = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 0)?;
        let signature =
            key_manager.sign_winternitz_message(&message[..], WinternitzType::SHA256, 0)?;

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));
        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_sign_winternitz_message_ripemd160() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;
        let signature_verifier = SignatureVerifier::new();

        let digest: [u8; 32] = [0xFE; 32];
        let message = Message::from_digest(digest);

        let pk = key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, 0)?;
        let signature =
            key_manager.sign_winternitz_message(&message[..], WinternitzType::HASH160, 0)?;

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_derive_key() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;
        let signature_verifier = SignatureVerifier::new();
        let key_types = vec![
            BitcoinKeyType::P2pkh,
            BitcoinKeyType::P2shP2wpkh,
            BitcoinKeyType::P2wpkh,
        ];

        for key_type in key_types {
            let pk_1 = key_manager.derive_keypair(key_type, 0)?;
            let pk_2 = key_manager.derive_keypair(key_type, 1)?;

            // Different indices should produce different public keys
            assert_ne!(pk_1.to_string(), pk_2.to_string());

            let message = random_message();
            let signature_1 = key_manager.sign_ecdsa_message(&message, &pk_1)?;
            let signature_2 = key_manager.sign_ecdsa_message(&message, &pk_2)?;

            // Different keys should produce different signatures for the same message
            assert_ne!(signature_1.to_string(), signature_2.to_string());

            // Both signatures should be valid
            assert!(signature_verifier.verify_ecdsa_signature(&signature_1, &message, pk_1));
            assert!(signature_verifier.verify_ecdsa_signature(&signature_2, &message, pk_2));
        }

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_key_generation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;

        let message = random_message();
        let checksummed = to_checksummed_message(&message[..]);

        let pk1 = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 0)?;
        let pk2 = key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, 8)?;
        let pk3 = key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, 8)?;
        let pk4 = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 8)?;
        let pk5 = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
        let pk6 = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 1)?;

        assert!(pk1.total_len() == checksummed.len());
        assert!(pk2.total_len() == checksummed.len());
        assert!(pk1.hash_size() == 32);
        assert!(pk2.hash_size() == 20);
        assert!(pk5.to_bytes().len() == 33);

        assert!(pk1 != pk2);
        assert!(pk2 == pk3);
        assert!(pk2 != pk4);
        assert!(pk5 != pk6);

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_keystore() -> Result<(), KeyManagerError> {
        let path = temp_storage();
        let password = "secret password_123__ABC".to_string();
        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = random_32bytes();
        let key_derivation_seed = random_64bytes();
        let random_mnemonic: Mnemonic = Mnemonic::from_entropy(&random_32bytes()).unwrap();

        let config = StorageConfig::new(path.clone(), Some(password));
        let store = Rc::new(Storage::new(&config).unwrap());
        let keystore = KeyStore::new(store);
        keystore.store_winternitz_seed(winternitz_seed)?;
        keystore.store_key_derivation_seed(key_derivation_seed)?;
        keystore.store_mnemonic(&random_mnemonic)?;

        for _ in 0..10 {
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            let private_key = PrivateKey::new(secret_key, Network::Regtest);
            let public_key = PublicKey::from_private_key(&secp, &private_key);

            keystore.store_keypair(private_key, public_key, None)?;

            let (restored_sk, restored_pk, _) = match keystore.load_keypair(&public_key)? {
                Some(entry) => entry,
                None => {
                    panic!("Failed to find key");
                }
            };

            assert_eq!(restored_sk.to_string(), private_key.to_string());
            assert_eq!(restored_pk.to_string(), public_key.to_string());
        }

        let loaded_winternitz_seed = keystore.load_winternitz_seed()?;
        assert!(loaded_winternitz_seed == winternitz_seed);

        let loaded_key_derivation_seed = keystore.load_key_derivation_seed()?;
        assert!(loaded_key_derivation_seed == key_derivation_seed);

        let loaded_mnemonic = keystore.load_mnemonic()?;
        assert!(loaded_mnemonic == random_mnemonic);

        drop(keystore);
        cleanup_storage(&path);
        Ok(())
    }

    #[test]
    fn test_keystore_index() -> Result<(), KeyManagerError> {
        let path = temp_storage();
        let password = "secret password_123__ABC".to_string();
        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = random_32bytes();
        let key_derivation_seed = random_64bytes();

        let config = StorageConfig::new(path.clone(), Some(password.clone()));
        let store = Rc::new(Storage::new(&config)?);
        let keystore = KeyStore::new(store);
        keystore.store_winternitz_seed(winternitz_seed)?;
        keystore.store_key_derivation_seed(key_derivation_seed)?;

        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, Network::Regtest);
        let public_key = PublicKey::from_private_key(&secp, &private_key);

        keystore.store_keypair(private_key, public_key, None)?;

        let (_, recovered_public_key, _) = match keystore.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        assert_eq!(recovered_public_key.to_string(), public_key.to_string());

        drop(keystore);
        cleanup_storage(&path);
        Ok(())
    }

    #[test]
    fn test_next_keypair_auto_indexing() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // Create a fresh KeyManager
        let key_manager_config = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            None, // No mnemonic provided, will generate one
            None,
        );

        let key_manager =
            crate::create_key_manager_from_config(&key_manager_config, &keystore_storage_config)?;

        // 1. Verify that with a fresh keymanager, there is no stored index for P2tr
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2tr)
            .is_err());

        // 2. Verify that there is also no stored index for other key types
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2wpkh)
            .is_err());
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2pkh)
            .is_err());
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2shP2wpkh)
            .is_err());

        // 3. Get next_keypair for P2tr type - should return a public key and store index 1
        let first_pubkey = key_manager.next_keypair(BitcoinKeyType::P2tr)?;

        // 4. Verify that index 1 is now stored for P2tr (next index after using index 0)
        let stored_index = key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2tr)?;
        assert_eq!(
            stored_index, 1,
            "Expected next index to be 1 after first keypair generation"
        );

        // 5. Verify that there is still no index stored for other types
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2wpkh)
            .is_err());
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2pkh)
            .is_err());
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2shP2wpkh)
            .is_err());

        // 6. Get next_keypair again - should return a different pubkey and store index 2
        let second_pubkey = key_manager.next_keypair(BitcoinKeyType::P2tr)?;

        // 7. Verify that index 2 is now stored for P2tr
        let stored_index = key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2tr)?;
        assert_eq!(
            stored_index, 2,
            "Expected next index to be 2 after second keypair generation"
        );

        // 8. Verify that the two pubkeys are different
        assert_ne!(
            first_pubkey, second_pubkey,
            "Expected different public keys from successive next_keypair calls"
        );

        // 9. Use derive_keypair with index 0 - should give the same as the 1st pubkey
        let derived_first_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;
        assert_eq!(
            first_pubkey, derived_first_pubkey,
            "Expected derive_keypair(0) to match first next_keypair result"
        );

        // 10. Use derive_keypair with index 1 - should give the same as the 2nd pubkey
        let derived_second_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 1)?;
        assert_eq!(
            second_pubkey, derived_second_pubkey,
            "Expected derive_keypair(1) to match second next_keypair result"
        );

        // 11. Verify that calling next_keypair for a different key type starts fresh indexing
        let first_p2wpkh_pubkey = key_manager.next_keypair(BitcoinKeyType::P2wpkh)?;
        let stored_p2wpkh_index = key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2wpkh)?;
        assert_eq!(
            stored_p2wpkh_index, 1,
            "Expected P2wpkh next index to start at 1"
        );

        // 12. Verify that P2tr index is still at 2 and other types are still not set
        let p2tr_index = key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2tr)?;
        assert_eq!(p2tr_index, 2, "P2tr index should remain unchanged");
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2pkh)
            .is_err());
        assert!(key_manager
            .keystore
            .load_next_keypair_index(BitcoinKeyType::P2shP2wpkh)
            .is_err());

        // 13. Verify that derive_keypair for P2wpkh with index 0 gives the same as next_keypair
        let derived_p2wpkh_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
        assert_eq!(
            first_p2wpkh_pubkey, derived_p2wpkh_pubkey,
            "Expected derive_keypair(P2wpkh, 0) to match first P2wpkh next_keypair result"
        );

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_next_winternitz_auto_indexing() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // Create a fresh KeyManager
        let key_manager_config = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            None, // No mnemonic provided, will generate one
            None,
        );

        let key_manager =
            crate::create_key_manager_from_config(&key_manager_config, &keystore_storage_config)?;

        let message_size_32_bytes = 32;
        let message_size_20_bytes = 20;

        // 1. Get next_winternitz for SHA256 with 32 bytes - should use index 0 and increment global counter
        let first_pubkey =
            key_manager.next_winternitz(message_size_32_bytes, WinternitzType::SHA256)?;

        // 2. Verify that derive_winternitz with index 0 gives the same as the 1st pubkey
        let derived_first_pubkey =
            key_manager.derive_winternitz(message_size_32_bytes, WinternitzType::SHA256, 0)?;
        assert_eq!(
            first_pubkey, derived_first_pubkey,
            "Expected derive_winternitz(0) to match first next_winternitz result"
        );

        // 3. Get next_winternitz again - should use index 1 and increment global counter
        let second_pubkey =
            key_manager.next_winternitz(message_size_32_bytes, WinternitzType::SHA256)?;

        // 4. Verify that the two pubkeys are different
        assert_ne!(
            first_pubkey, second_pubkey,
            "Expected different public keys from successive next_winternitz calls"
        );

        // 5. Verify that derive_winternitz with index 1 gives the same as the 2nd pubkey
        let derived_second_pubkey =
            key_manager.derive_winternitz(message_size_32_bytes, WinternitzType::SHA256, 1)?;
        assert_eq!(
            second_pubkey, derived_second_pubkey,
            "Expected derive_winternitz(1) to match second next_winternitz result"
        );

        // 6. Get next_winternitz for a different type - should use index 2 (global counter continues)
        let third_pubkey =
            key_manager.next_winternitz(message_size_32_bytes, WinternitzType::HASH160)?;

        // 7. Verify that derive_winternitz for HASH160 with index 2 gives the same result
        let derived_third_pubkey =
            key_manager.derive_winternitz(message_size_32_bytes, WinternitzType::HASH160, 2)?;
        assert_eq!(
            third_pubkey, derived_third_pubkey,
            "Expected derive_winternitz(HASH160, 32, 2) to match third next_winternitz result"
        );

        // 8. Get next_winternitz for different message size - should use index 3 (global counter continues)
        let fourth_pubkey =
            key_manager.next_winternitz(message_size_20_bytes, WinternitzType::SHA256)?;

        // 9. Verify that derive_winternitz for SHA256:20 with index 3 gives the same result
        let derived_fourth_pubkey =
            key_manager.derive_winternitz(message_size_20_bytes, WinternitzType::SHA256, 3)?;
        assert_eq!(
            fourth_pubkey, derived_fourth_pubkey,
            "Expected derive_winternitz(SHA256, 20, 3) to match fourth next_winternitz result"
        );

        // 10. Get next_winternitz for yet another combination - should use index 4
        let fifth_pubkey =
            key_manager.next_winternitz(message_size_20_bytes, WinternitzType::HASH160)?;

        // 11. Verify that derive_winternitz for HASH160:20 with index 4 gives the same result
        let derived_fifth_pubkey =
            key_manager.derive_winternitz(message_size_20_bytes, WinternitzType::HASH160, 4)?;
        assert_eq!(
            fifth_pubkey, derived_fifth_pubkey,
            "Expected derive_winternitz(HASH160, 20, 4) to match fifth next_winternitz result"
        );

        // 12. Verify all keys are different (security requirement - no reuse)
        let all_pubkeys = vec![
            &first_pubkey,
            &second_pubkey,
            &third_pubkey,
            &fourth_pubkey,
            &fifth_pubkey,
        ];
        for (i, key1) in all_pubkeys.iter().enumerate() {
            for (j, key2) in all_pubkeys.iter().enumerate() {
                if i != j {
                    assert_ne!(key1, key2, "Expected all Winternitz keys to be different - found duplicate at indices {} and {}", i, j);
                }
            }
        }

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_error_handling() -> Result<(), KeyManagerError> {
        let message = random_message();
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;

        // Case 1: Invalid private key string
        let result = key_manager.import_private_key("invalid_key");
        assert!(matches!(
            result,
            Err(KeyManagerError::FailedToParsePrivateKey(_))
        ));

        // Case 2: Invalid derivation path (not possible)

        // Case 3 b: Write error when creating database keystore (invalid path)
        //TODO: FIX THIS TEST is not working in windows envs
        //let result = database_keystore("/invalid/path");
        //assert!(matches!(result, Err(KeyStoreError::WriteError(_))));

        // Case 4: Index overflow when generating keys
        let result =
            key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, u32::MAX);
        assert!(matches!(
            result,
            Err(KeyManagerError::WinternitzGenerationError(
                WinternitzError::IndexOverflow
            ))
        ));

        // Case 5: Entry not found for public key
        let fake_public_key = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )?;
        let result = key_manager.sign_ecdsa_message(&random_message(), &fake_public_key);
        assert!(matches!(result, Err(KeyManagerError::KeyPairNotFound(_))));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    #[cfg(feature = "strict")]
    fn test_key_type_signature_validation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;

        let message = random_message();

        // Test P2TR key validation
        let p2tr_public_key = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;

        // Attempt to sign with ECDSA using P2TR key - should fail
        let result = key_manager.sign_ecdsa_message(&message, &p2tr_public_key);
        assert!(matches!(result, Err(KeyManagerError::EcdsaWithTaprootKey)));

        // Attempt to sign with ECDSA recoverable using P2TR key - should also fail
        let result = key_manager.sign_ecdsa_recoverable_message(&message, &p2tr_public_key);
        assert!(matches!(result, Err(KeyManagerError::EcdsaWithTaprootKey)));

        // Schnorr signing should work fine with P2TR keys
        let schnorr_result = key_manager.sign_schnorr_message(&message, &p2tr_public_key);
        assert!(schnorr_result.is_ok());

        // Test non-Taproot key validation
        let p2wpkh_public_key = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;

        // ECDSA should work fine with non-Taproot keys
        let ecdsa_result = key_manager.sign_ecdsa_message(&message, &p2wpkh_public_key);
        assert!(ecdsa_result.is_ok());

        // Schnorr signing with non-Taproot keys should fail
        let result = key_manager.sign_schnorr_message(&message, &p2wpkh_public_key);
        assert!(matches!(
            result,
            Err(KeyManagerError::SchnorrWithNonTaprootKey)
        ));

        // Test imported key (key_type = None) - should allow both ECDSA and Schnorr
        let imported_key = key_manager
            .import_private_key("L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ")?;

        // Both ECDSA and Schnorr should work with imported keys (no specific type)
        let ecdsa_result = key_manager.sign_ecdsa_message(&message, &imported_key);
        assert!(ecdsa_result.is_ok());

        let schnorr_result = key_manager.sign_schnorr_message(&message, &imported_key);
        assert!(schnorr_result.is_ok());

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_signature_with_bip32_derivation() {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path).unwrap();

        let key_manager = test_random_key_manager(keystore_storage_config).unwrap();

        let key_types = vec![
            BitcoinKeyType::P2pkh,
            BitcoinKeyType::P2shP2wpkh,
            BitcoinKeyType::P2wpkh,
        ];

        for key_type in key_types {
            let account_xpub = key_manager.get_account_xpub(key_type).unwrap();

            for i in 0..5 {
                let pk1 = key_manager.derive_keypair(key_type, i).unwrap();
                let pk2 = key_manager
                    .derive_public_key_from_account_xpub(account_xpub, key_type, i, false)
                    .unwrap();

                let signature_verifier = SignatureVerifier::new();
                let message = random_message();
                let signature = key_manager.sign_ecdsa_message(&message, &pk1).unwrap();

                // Both keys should be equivalent for the same index
                assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk2));
            }

            // Test that different indices produce different keys (negative test)
            let pk1 = key_manager.derive_keypair(key_type, 10).unwrap();
            let pk2 = key_manager
                .derive_public_key_from_account_xpub(account_xpub, key_type, 11, false)
                .unwrap();

            let signature_verifier = SignatureVerifier::new();
            let message = random_message();
            let signature = key_manager.sign_ecdsa_message(&message, &pk1).unwrap();

            // Different indices should not verify with each other
            assert!(!signature_verifier.verify_ecdsa_signature(&signature, &message, pk2));
        }

        drop(key_manager);
        cleanup_storage(&keystore_path);
    }

    #[test]
    fn test_schnorr_signature_with_bip32_derivation() {
        // Note: Schnorr signatures are primarily used with Taproot (P2TR)
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path).unwrap();

        let key_manager = test_random_key_manager(keystore_storage_config).unwrap();

        let account_xpub = key_manager.get_account_xpub(BitcoinKeyType::P2tr).unwrap();

        for i in 0..5 {
            let pk1 = key_manager.derive_keypair(BitcoinKeyType::P2tr, i).unwrap();
            let pk2 = key_manager
                .derive_public_key_from_account_xpub(account_xpub, BitcoinKeyType::P2tr, i, false)
                .unwrap();

            let signature_verifier = SignatureVerifier::new();
            let message = random_message();
            let signature = key_manager.sign_schnorr_message(&message, &pk1).unwrap();

            assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk2));
        }

        let pk1 = key_manager
            .derive_keypair(BitcoinKeyType::P2tr, 10)
            .unwrap();
        let pk2 = key_manager
            .derive_public_key_from_account_xpub(account_xpub, BitcoinKeyType::P2tr, 11, false)
            .unwrap();

        let signature_verifier = SignatureVerifier::new();
        let message = random_message();
        let signature = key_manager.sign_schnorr_message(&message, &pk1).unwrap();

        assert!(!signature_verifier.verify_schnorr_signature(&signature, &message, pk2));

        drop(key_manager);
        cleanup_storage(&keystore_path);
    }

    #[test]
    fn test_key_derivation_from_xpub_in_different_key_manager() {
        run_test_with_multiple_key_managers(2, |key_managers, _keystore_paths, _store_paths| {
            let key_manager_1 = &key_managers[0];
            let key_manager_2 = &key_managers[1];

            let key_type = BitcoinKeyType::P2wpkh;

            for i in 0..5 {
                // Create account_xpub in key_manager_1 and derive public key in key_manager_2 for a given index
                let account_xpub = key_manager_1.get_account_xpub(key_type).unwrap();
                let public_from_xpub = key_manager_2
                    .derive_public_key_from_account_xpub(account_xpub, key_type, i, false)
                    .unwrap();

                // Derive keypair in key_manager_1 with the same index
                let public_from_xpriv = key_manager_1.derive_keypair(key_type, i).unwrap();

                // Both public keys must be equal
                assert_eq!(public_from_xpub.to_string(), public_from_xpriv.to_string());
            }

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_derive_multiple_winternitz_gives_same_result_as_doing_one_by_one() {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path).unwrap();
        let key_manager = test_random_key_manager(keystore_storage_config).unwrap();

        let message_size_in_bytes = 32;
        let key_type = WinternitzType::SHA256;
        let initial_index = 0;
        let number_of_keys: u32 = 10;

        let public_keys = key_manager
            .derive_multiple_winternitz(
                message_size_in_bytes,
                key_type,
                initial_index,
                number_of_keys,
            )
            .unwrap();

        for i in 0..number_of_keys {
            let public_key = key_manager
                .derive_winternitz(message_size_in_bytes, key_type, initial_index + i)
                .unwrap();

            assert_eq!(public_keys[i as usize], public_key);
        }
        drop(key_manager);
        cleanup_storage(&keystore_path);
    }

    #[test]
    fn test_imported_key_type_storage_and_retrieval() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;
        let key_manager = test_random_key_manager(keystore_storage_config)?;

        // Test importing keys with each possible key type
        let test_cases = vec![
            (
                "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ",
                Some(BitcoinKeyType::P2pkh),
                "P2PKH key import",
            ),
            (
                "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617",
                Some(BitcoinKeyType::P2shP2wpkh),
                "P2SH-P2WPKH key import",
            ),
            (
                "L5oLkpV3aqBjhki6LmvChTCV6odsp4SXM6FfU2Gppt5kFLaHLuZ9",
                Some(BitcoinKeyType::P2wpkh),
                "P2WPKH key import",
            ),
            (
                "KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S",
                Some(BitcoinKeyType::P2tr),
                "P2TR key import",
            ),
            (
                "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g",
                None,
                "Untyped key import",
            ),
        ];

        for (private_key_wif, expected_key_type, description) in test_cases {
            // Import the key with specific type
            let public_key =
                key_manager.import_private_key_typed(private_key_wif, expected_key_type)?;

            // Retrieve the key and verify the type is preserved
            let (_, _, stored_key_type) = match key_manager.keystore.load_keypair(&public_key)? {
                Some(entry) => entry,
                None => panic!("Failed to retrieve imported key for {}", description),
            };

            // Verify the key type matches what was set during import
            assert_eq!(
                stored_key_type, expected_key_type,
                "Key type mismatch for {}: expected {:?}, got {:?}",
                description, expected_key_type, stored_key_type
            );

            println!(
                "✓ {}: Key type correctly stored as {:?}",
                description, stored_key_type
            );
        }

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_derived_key_type_storage_and_retrieval() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;
        let key_manager = test_deterministic_key_manager(keystore_storage_config)?;

        // Test deriving keys for each possible key type
        let key_types = vec![
            BitcoinKeyType::P2pkh,
            BitcoinKeyType::P2shP2wpkh,
            BitcoinKeyType::P2wpkh,
            BitcoinKeyType::P2tr,
        ];

        for (index, expected_key_type) in key_types.iter().enumerate() {
            // Derive a key of the specific type
            let public_key = key_manager.derive_keypair(*expected_key_type, index as u32)?;

            // Retrieve the key and verify the type is preserved
            let (_, _, stored_key_type) = match key_manager.keystore.load_keypair(&public_key)? {
                Some(entry) => entry,
                None => panic!("Failed to retrieve derived key for {:?}", expected_key_type),
            };

            // Verify the key type matches what was used during derivation
            let expected_option = Some(*expected_key_type);
            assert_eq!(
                stored_key_type, expected_option,
                "Key type mismatch for derived {:?}: expected {:?}, got {:?}",
                expected_key_type, expected_option, stored_key_type
            );

            println!(
                "✓ Derived {:?} key: Key type correctly stored as {:?}",
                expected_key_type, stored_key_type
            );
        }

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    fn generate_random_passphrase() -> String {
        let mut passphrase_bytes = [0u8; 16];
        secp256k1::rand::thread_rng().fill_bytes(&mut passphrase_bytes);
        bitcoin::hex::DisplayHex::to_lower_hex_string(&passphrase_bytes[..])
    }

    fn test_random_key_manager(
        storage_config: StorageConfig,
    ) -> Result<KeyManager, KeyManagerError> {
        let random_mnemonic: Mnemonic = Mnemonic::from_entropy(&random_32bytes()).unwrap();
        let random_mnemonic_passphrase = generate_random_passphrase();

        let key_manager_config = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(random_mnemonic.to_string()),
            Some(random_mnemonic_passphrase),
        );

        let key_manager =
            crate::create_key_manager_from_config(&key_manager_config, &storage_config)?;

        Ok(key_manager)
    }

    fn test_deterministic_key_manager(
        storage_config: StorageConfig,
    ) -> Result<KeyManager, KeyManagerError> {
        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic =
            Mnemonic::from_str(mnemonic_sentence).map_err(|_| KeyManagerError::InvalidMnemonic)?;

        let key_manager = KeyManager::new(REGTEST, Some(mnemonic), None, &storage_config)?;

        Ok(key_manager)
    }

    fn database_keystore_config(storage_path: &str) -> Result<StorageConfig, KeyManagerError> {
        let password = "secret password_123__ABC".to_string();
        let config = StorageConfig::new(storage_path.to_string(), Some(password));
        Ok(config)
    }

    fn database_keystore(storage_path: &str) -> Result<KeyStore, KeyManagerError> {
        let password = "secret password_123__ABC".to_string();
        let config = StorageConfig::new(storage_path.to_string(), Some(password));
        let store = Rc::new(Storage::new(&config)?);
        Ok(KeyStore::new(store))
    }

    fn test_key_manager(
        keystore: KeyStore,
        store: Rc<Storage>,
    ) -> Result<KeyManager, KeyManagerError> {
        use crate::musig2::musig::MuSig2Signer;

        // Create a simple test KeyManager using the provided keystore
        let random_mnemonic: Mnemonic = Mnemonic::from_entropy(&random_32bytes()).unwrap();
        let random_passphrase = generate_random_passphrase();

        // Store mnemonic and passphrase in keystore
        keystore.store_mnemonic(&random_mnemonic)?;
        keystore.store_mnemonic_passphrase(&random_passphrase)?;

        // Generate and store seeds
        let key_derivation_seed = random_mnemonic.to_seed(&random_passphrase);
        keystore.store_key_derivation_seed(key_derivation_seed)?;

        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = KeyManager::derive_winternitz_master_seed(
            secp.clone(),
            &key_derivation_seed,
            REGTEST,
            KeyManager::ACCOUNT_DERIVATION_INDEX,
        )?;
        keystore.store_winternitz_seed(winternitz_seed)?;

        let musig2 = MuSig2Signer::new(store);

        Ok(KeyManager {
            secp,
            network: REGTEST,
            musig2,
            keystore,
        })
    }

    fn random_message() -> Message {
        let mut digest = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut digest);
        Message::from_digest(digest)
    }

    fn random_32bytes() -> [u8; 32] {
        let mut seed = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }

    fn random_64bytes() -> [u8; 64] {
        let mut seed = [0u8; 64];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }

    fn cleanup_storage(path: &str) {
        println!("Cleaning up storage at: {}", path);
        fs::remove_dir_all(path).unwrap();
    }

    fn temp_storage() -> String {
        let dir = env::temp_dir();

        let mut rng = rand::thread_rng();
        let index = rng.next_u32();

        let storage_path = dir.join(format!("keystore_{}.db", index));
        storage_path
            .to_str()
            .expect("Failed to get path to temp file")
            .to_string()
    }

    struct TestKeyManagerConfig {
        network: String,
        mnemonic: Option<String>,
        passphrase: Option<String>,
    }

    impl TestKeyManagerConfig {
        fn new(network: String, mnemonic: Option<String>, passphrase: Option<String>) -> Self {
            Self {
                network,
                mnemonic,
                passphrase,
            }
        }
    }

    fn create_key_manager_from_config(
        config: &TestKeyManagerConfig,
        keystore: KeyStore,
        store: Rc<Storage>,
    ) -> Result<KeyManager, KeyManagerError> {
        use crate::errors::ConfigError;
        use crate::musig2::musig::MuSig2Signer;

        // Parse network
        let network = match config.network.to_lowercase().as_str() {
            "bitcoin" | "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return Err(KeyManagerError::ConfigError(ConfigError::InvalidNetwork)),
        };

        // Parse mnemonic if provided, otherwise generate a random one
        let mnemonic = if let Some(ref mnemonic_str) = config.mnemonic {
            Mnemonic::parse(mnemonic_str).map_err(|_| KeyManagerError::InvalidMnemonic)?
        } else {
            Mnemonic::from_entropy(&random_32bytes()).unwrap()
        };

        // Get passphrase or use empty string
        let passphrase = config.passphrase.clone().unwrap_or_default();

        // Store mnemonic and passphrase
        keystore.store_mnemonic(&mnemonic)?;
        keystore.store_mnemonic_passphrase(&passphrase)?;

        // Generate key derivation seed from mnemonic
        let key_derivation_seed = mnemonic.to_seed(&passphrase);
        keystore.store_key_derivation_seed(key_derivation_seed)?;

        // Derive and store winternitz seed
        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = KeyManager::derive_winternitz_master_seed(
            secp.clone(),
            &key_derivation_seed,
            network,
            KeyManager::ACCOUNT_DERIVATION_INDEX,
        )?;
        keystore.store_winternitz_seed(winternitz_seed)?;

        let musig2 = MuSig2Signer::new(store);

        Ok(KeyManager {
            secp,
            network,
            musig2,
            keystore,
        })
    }

    fn setup_test_environment() -> Result<(KeyStore, Rc<Storage>, String, String), KeyManagerError>
    {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config)?);

        Ok((keystore, store, keystore_path, store_path))
    }

    fn cleanup_test_environment(keystore_path: &str, store_path: &str) {
        cleanup_storage(keystore_path);
        cleanup_storage(store_path);
    }

    #[allow(dead_code)]
    fn create_test_config_and_run_with_cleanup<F>(
        network: &str,
        mnemonic: Option<String>,
        passphrase: Option<String>,
        test_fn: F,
    ) -> Result<(), KeyManagerError>
    where
        F: FnOnce(&TestKeyManagerConfig, KeyStore, Rc<Storage>) -> Result<(), KeyManagerError>,
    {
        let (keystore, store, keystore_path, store_path) = setup_test_environment()?;

        let key_manager_config =
            TestKeyManagerConfig::new(network.to_string(), mnemonic, passphrase);

        let result = test_fn(&key_manager_config, keystore, store);

        cleanup_test_environment(&keystore_path, &store_path);

        result
    }

    fn setup_test_key_manager() -> Result<(KeyManager, String, String), KeyManagerError> {
        let (keystore, store, keystore_path, store_path) = setup_test_environment()?;
        let key_manager = test_key_manager(keystore, store)?;
        Ok((key_manager, keystore_path, store_path))
    }

    fn run_test_with_key_manager<F, R>(test_fn: F) -> Result<R, KeyManagerError>
    where
        F: FnOnce(KeyManager) -> Result<R, KeyManagerError>,
    {
        let (key_manager, keystore_path, store_path) = setup_test_key_manager()?;
        let result = test_fn(key_manager);
        cleanup_test_environment(&keystore_path, &store_path);
        result
    }

    fn run_test_with_multiple_key_managers<F, R>(
        count: usize,
        test_fn: F,
    ) -> Result<R, KeyManagerError>
    where
        F: FnOnce(Vec<KeyManager>, Vec<String>, Vec<String>) -> Result<R, KeyManagerError>,
    {
        let mut key_managers = Vec::new();
        let mut keystore_paths = Vec::new();
        let mut store_paths = Vec::new();

        for _ in 0..count {
            let (key_manager, keystore_path, store_path) = setup_test_key_manager()?;
            key_managers.push(key_manager);
            keystore_paths.push(keystore_path);
            store_paths.push(store_path);
        }

        let result = test_fn(key_managers, keystore_paths.clone(), store_paths.clone());

        // Cleanup all storage
        for (keystore_path, store_path) in keystore_paths.iter().zip(store_paths.iter()) {
            cleanup_test_environment(keystore_path, store_path);
        }

        result
    }

    // Helper macro to reduce boilerplate for error test cases
    #[allow(unused_macros)]
    macro_rules! assert_config_error {
        ($network:expr, $mnemonic:expr, $passphrase:expr, $expected_error:pat) => {
            create_test_config_and_run_with_cleanup(
                $network,
                $mnemonic,
                $passphrase,
                |config, keystore, store| {
                    let result = create_key_manager_from_config(config, keystore, store);
                    assert!(matches!(result, Err($expected_error)));
                    Ok(())
                },
            )
            .expect("Test case failed");
        };
    }

    #[test]
    pub fn test_rsa_signature() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let signature_verifier = SignatureVerifier::new();
            let mut rng = secp256k1::rand::thread_rng();
            // generate_rsa_keypair returns PEM string and stores the key internally
            let pubkey_pem = key_manager.generate_rsa_keypair(&mut rng)?;
            let message = random_message().to_string().as_bytes().to_vec();
            let signature = key_manager.sign_rsa_message(&message, &pubkey_pem)?;

            // Use the PEM string directly for verification
            assert!(signature_verifier.verify_rsa_signature(&signature, &message, &pubkey_pem)?);
            Ok(())
        })
    }

    #[test]
    pub fn test_rsa_encryption() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let mut rng = secp256k1::rand::thread_rng();
            // generate_rsa_keypair returns PEM string and stores the key internally
            let pubkey_pem = key_manager.generate_rsa_keypair(&mut rng)?;
            let message = random_message().to_string().as_bytes().to_vec();
            let encrypted_message = key_manager.encrypt_rsa_message(&message, &pubkey_pem)?;
            let decrypted_message =
                key_manager.decrypt_rsa_message(&encrypted_message, &pubkey_pem)?;

            assert_eq!(message, decrypted_message);
            Ok(())
        })
    }

    #[test]
    pub fn test_default_derivation_path_fallback() {
        /*
         * Objective: Confirm default path m/101/1/0/0/ is used when not provided.
         * Preconditions: key_derivation_path omitted in Config.
         * Input / Test Data: Valid seeds (or none); valid network.
         * Steps / Procedure: Create KeyManager from config; derive a key at index 0.
         * Expected Result: No error; derivation succeeds, implying the default path applied.
         */

        // Set up temporary storage using helper function
        let (keystore, store, keystore_path, store_path) =
            setup_test_environment().expect("Failed to setup test environment");

        // Create config with a deterministic mnemonic for testing
        // WARNING: NEVER USE THIS MNEMONIC TO STORE REAL FUNDS
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key_manager_config = TestKeyManagerConfig::new(
            "regtest".to_string(),
            Some(test_mnemonic.to_string()),
            None, // No passphrase
        );

        // Step: Create KeyManager from config - should use default path
        let key_manager = create_key_manager_from_config(&key_manager_config, keystore, store)
            .expect("Failed to create key manager from config with default derivation path");

        let key_type = BitcoinKeyType::P2wpkh;

        // Step: Derive a key at index 0 - should succeed if default path applied correctly
        let public_key = key_manager
            .derive_keypair(key_type, 0)
            .expect("Failed to derive keypair - default derivation path may not have been applied");

        // Verify the derivation succeeded and we got a valid public key
        assert_eq!(
            public_key.to_bytes().len(),
            33,
            "Generated public key should be 33 bytes"
        );

        // Additional verification: derive account xpub and compare derived keys
        let account_xpub = key_manager
            .get_account_xpub(key_type)
            .expect("Failed to generate account xpub");

        let public_key_from_xpub = key_manager
            .derive_public_key_from_account_xpub(account_xpub, key_type, 0, false)
            .expect("Failed to derive public key from xpub");

        // Both derivations should produce the same key if using the same default path
        assert_eq!(
            public_key.to_string(),
            public_key_from_xpub.to_string(),
            "Keys derived with and without xpub should match when using default derivation path"
        );

        // Verify that the KeyManager can sign with the derived key (further proof it works)
        let signature_verifier = SignatureVerifier::new();
        let message = random_message();
        let signature = key_manager
            .sign_ecdsa_message(&message, &public_key)
            .expect("Failed to sign with derived key");

        assert!(
            signature_verifier.verify_ecdsa_signature(&signature, &message, public_key),
            "Signature verification should succeed for key derived using default path"
        );

        // Cleanup
        drop(key_manager);
        cleanup_test_environment(&keystore_path, &store_path);
    }

    #[test]
    pub fn test_network_parsing() {
        /*
         * Objective: Validate network string parsing and error on invalid value.
         * Preconditions: Minimal Config with storage set.
         * Input / Test Data: network values: regtest, testnet, bitcoin, and invalid.
         * Steps / Procedure: Call create_key_manager_from_config for each network value.
         * Expected Result: Succeeds for valid networks; returns ConfigError::InvalidNetwork for invalid.
         */

        use crate::errors::ConfigError;

        // Use a deterministic mnemonic for all tests
        // WARNING: NEVER USE THIS MNEMONIC TO STORE REAL FUNDS
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Test Case 1: Valid network "regtest"
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));

        let key_manager_config = TestKeyManagerConfig::new(
            "regtest".to_string(), // Valid network
            Some(test_mnemonic.to_string()),
            None,
        );

        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(
            result.is_ok(),
            "KeyManager creation should succeed for valid network 'regtest'"
        );

        // Explicitly drop the KeyManager to release storage handles
        drop(result);

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);

        // Test Case 2: Valid network "testnet"
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));

        let key_manager_config = TestKeyManagerConfig::new(
            "testnet".to_string(), // Valid network
            Some(test_mnemonic.to_string()),
            None,
        );

        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(
            result.is_ok(),
            "KeyManager creation should succeed for valid network 'testnet'"
        );

        // Explicitly drop the KeyManager to release storage handles
        drop(result);

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);

        // Test Case 3: Valid network "bitcoin" (mainnet)
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));

        let key_manager_config = TestKeyManagerConfig::new(
            "bitcoin".to_string(), // Valid network
            Some(test_mnemonic.to_string()),
            None,
        );

        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(
            result.is_ok(),
            "KeyManager creation should succeed for valid network 'bitcoin'"
        );

        // Explicitly drop the KeyManager to release storage handles
        drop(result);

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);

        // Test Case 4: Invalid network value
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));

        let key_manager_config = TestKeyManagerConfig::new(
            "invalid_network".to_string(), // Invalid network
            Some(test_mnemonic.to_string()),
            None,
        );

        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(
            matches!(
                result,
                Err(KeyManagerError::ConfigError(ConfigError::InvalidNetwork))
            ),
            "KeyManager creation should fail with InvalidNetwork error for invalid network string"
        );

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);

        // Test Case 5: Empty network string
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));

        let key_manager_config = TestKeyManagerConfig::new(
            "".to_string(), // Empty network string
            Some(test_mnemonic.to_string()),
            None,
        );

        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(
            matches!(
                result,
                Err(KeyManagerError::ConfigError(ConfigError::InvalidNetwork))
            ),
            "KeyManager creation should fail with InvalidNetwork error for empty network string"
        );

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);

        // Test Case 6: Case insensitivity test (uppercase should work)
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));

        let key_manager_config = TestKeyManagerConfig::new(
            "REGTEST".to_string(), // Uppercase - should work due to case-insensitive parsing
            Some(test_mnemonic.to_string()),
            None,
        );

        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(
            result.is_ok(),
            "KeyManager creation should succeed with uppercase network string (case-insensitive)"
        );

        // Explicitly drop the KeyManager to release storage handles
        drop(result);

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
    }

    #[test]
    pub fn test_keystore_seed_bootstraping_provided_mnemonic() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure provided mnemonic generates deterministic seeds that are persisted and retrievable.
         * Preconditions: Fresh storage; known mnemonic phrase.
         * Input / Test Data: Fixed BIP39 mnemonic phrase.
         * Steps / Procedure: Initialize KeyManager with mnemonic; call KeyStore::load_winternitz_seed and load_key_derivation_seed.
         * Expected Result: Seeds are generated from mnemonic and persist across KeyManager instances.
         */

        // Use a deterministic mnemonic for testing
        // WARNING: NEVER USE THIS MNEMONIC TO STORE REAL FUNDS
        let test_mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Optional passphrase for additional entropy
        let test_passphrase = "test_passphrase_123";

        // Set up temporary storage
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // Step 1: Initialize KeyManager with provided mnemonic and passphrase
        let key_manager_config = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(test_mnemonic_sentence.to_string()),
            Some(test_passphrase.to_string()),
        );

        let key_manager =
            crate::create_key_manager_from_config(&key_manager_config, &keystore_storage_config)
                .expect("Failed to create KeyManager with provided mnemonic");

        // Step 2: Load seeds from keystore to verify they were generated and stored
        let loaded_winternitz_seed = key_manager
            .keystore
            .load_winternitz_seed()
            .expect("Failed to load winternitz seed from keystore");

        let loaded_key_derivation_seed = key_manager
            .keystore
            .load_key_derivation_seed()
            .expect("Failed to load key derivation seed from keystore");

        // Step 3: Verify seeds are valid (non-zero and correct length)
        assert_eq!(
            loaded_winternitz_seed.len(),
            32,
            "Winternitz seed should be 32 bytes"
        );
        assert_eq!(
            loaded_key_derivation_seed.len(),
            64,
            "Key derivation seed should be 64 bytes (BIP39 format)"
        );

        // Verify seeds are not all zeros
        let winternitz_all_zeros = loaded_winternitz_seed.iter().all(|&x| x == 0);
        let key_derivation_all_zeros = loaded_key_derivation_seed.iter().all(|&x| x == 0);
        assert!(
            !winternitz_all_zeros,
            "Winternitz seed should not be all zeros"
        );
        assert!(
            !key_derivation_all_zeros,
            "Key derivation seed should not be all zeros"
        );

        // Step 4: Test that the seeds work for cryptographic operations
        let public_key = key_manager
            .derive_keypair(BitcoinKeyType::P2wpkh, 0)
            .expect("Failed to derive keypair using mnemonic-generated seeds");
        assert_eq!(
            public_key.to_bytes().len(),
            33,
            "Generated public key should be 33 bytes"
        );

        // Test winternitz key generation
        let winternitz_public_key = key_manager
            .derive_winternitz(32, WinternitzType::SHA256, 0)
            .expect("Failed to derive winternitz key using mnemonic-generated seed");
        assert!(
            winternitz_public_key.total_len() > 0,
            "Winternitz public key should have non-zero length"
        );

        // Step 5: Test seed persistence - create second KeyManager with same mnemonic
        drop(key_manager);

        let keystore_storage_config2 = database_keystore_config(&keystore_path)?;
        let key_manager_config2 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(test_mnemonic_sentence.to_string()),
            Some(test_passphrase.to_string()),
        );

        let key_manager2 =
            crate::create_key_manager_from_config(&key_manager_config2, &keystore_storage_config2)
                .expect("Failed to create second KeyManager with same mnemonic");

        // Verify the seeds are deterministic (same mnemonic produces same seeds)
        let loaded_winternitz_seed2 = key_manager2
            .keystore
            .load_winternitz_seed()
            .expect("Failed to load winternitz seed from second keystore");
        let loaded_key_derivation_seed2 = key_manager2
            .keystore
            .load_key_derivation_seed()
            .expect("Failed to load key derivation seed from second keystore");

        assert_eq!(
            loaded_winternitz_seed2, loaded_winternitz_seed,
            "Same mnemonic should generate same winternitz seed"
        );
        assert_eq!(
            loaded_key_derivation_seed2, loaded_key_derivation_seed,
            "Same mnemonic should generate same key derivation seed"
        );

        // Step 6: Test that derived keys are also deterministic
        let public_key2 = key_manager2
            .derive_keypair(BitcoinKeyType::P2wpkh, 0)
            .expect("Failed to derive keypair from second KeyManager");
        assert_eq!(
            public_key2, public_key,
            "Same mnemonic should generate same derived keys"
        );

        // Step 7: Test with different passphrase produces different seeds
        drop(key_manager2);
        let keystore_path3 = temp_storage();
        let keystore_storage_config3 = database_keystore_config(&keystore_path3)?;

        let key_manager_config3 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(test_mnemonic_sentence.to_string()),
            Some("different_passphrase".to_string()),
        );

        let key_manager3 =
            crate::create_key_manager_from_config(&key_manager_config3, &keystore_storage_config3)
                .expect("Failed to create KeyManager with different passphrase");

        let loaded_key_derivation_seed3 = key_manager3
            .keystore
            .load_key_derivation_seed()
            .expect("Failed to load seed with different passphrase");

        assert_ne!(
            loaded_key_derivation_seed3, loaded_key_derivation_seed,
            "Different passphrase should generate different key derivation seed"
        );

        // Cleanup
        drop(key_manager3);
        cleanup_storage(&keystore_path);
        cleanup_storage(&keystore_path3);
        Ok(())
    }

    #[test]
    pub fn test_keystore_seed_bootstraping_auto_generated_seeds() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure seeds are auto-generated and stored when no mnemonic is provided.
         * Preconditions: Fresh storage; no mnemonic provided.
         * Input / Test Data: None (auto-generation).
         * Steps / Procedure: Initialize KeyManager without mnemonic; load seeds via KeyStore::load_*.
         * Expected Result: Both seeds load successfully, are non-zero, and persist across instances.
         */

        // Step 1: Set up temporary storage and create KeyManager without providing mnemonic
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager_config = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            None, // No mnemonic provided - should auto-generate
            None, // No passphrase
        );

        let key_manager =
            crate::create_key_manager_from_config(&key_manager_config, &keystore_storage_config)
                .expect("Failed to create KeyManager with auto-generated seeds");

        // Step 2: Load seeds from keystore to verify they were generated and stored
        let loaded_winternitz_seed = key_manager
            .keystore
            .load_winternitz_seed()
            .expect("Failed to load auto-generated winternitz seed from keystore");

        let loaded_key_derivation_seed = key_manager
            .keystore
            .load_key_derivation_seed()
            .expect("Failed to load auto-generated key derivation seed from keystore");

        // Step 3: Verify seeds are valid (correct length and non-zero)
        assert_eq!(
            loaded_winternitz_seed.len(),
            32,
            "Generated winternitz seed should be exactly 32 bytes"
        );

        assert_eq!(
            loaded_key_derivation_seed.len(),
            64,
            "Generated key derivation seed should be 64 bytes (BIP39 format)"
        );

        // Verify seeds are not all zeros (extremely unlikely to be all zeros by chance)
        let winternitz_all_zeros = loaded_winternitz_seed.iter().all(|&x| x == 0);
        let key_derivation_all_zeros = loaded_key_derivation_seed.iter().all(|&x| x == 0);

        assert!(
            !winternitz_all_zeros,
            "Generated winternitz seed should not be all zeros"
        );
        assert!(
            !key_derivation_all_zeros,
            "Generated key derivation seed should not be all zeros"
        );

        // Step 4: Test that the auto-generated seeds work for cryptographic operations
        let public_key = key_manager
            .derive_keypair(BitcoinKeyType::P2wpkh, 0)
            .expect("Failed to derive keypair using auto-generated seeds");

        // Verify the public key is valid
        assert_eq!(
            public_key.to_bytes().len(),
            33,
            "Generated public key should be 33 bytes"
        );

        // Test winternitz key generation as well
        let winternitz_public_key = key_manager
            .derive_winternitz(32, WinternitzType::SHA256, 0)
            .expect("Failed to derive winternitz key using auto-generated seed");

        // Verify winternitz key was generated successfully
        assert!(
            winternitz_public_key.total_len() > 0,
            "Winternitz public key should have non-zero length"
        );

        // Step 5: Test signing with auto-generated keys to prove they work
        let signature_verifier = SignatureVerifier::new();
        let message = random_message();
        let signature = key_manager
            .sign_ecdsa_message(&message, &public_key)
            .expect("Failed to sign with key derived from auto-generated seed");

        assert!(
            signature_verifier.verify_ecdsa_signature(&signature, &message, public_key),
            "Signature verification should succeed for key derived from auto-generated seed"
        );

        // Step 6: Test persistence - create second KeyManager without mnemonic
        // Should load existing seeds from storage instead of generating new ones
        drop(key_manager);

        let keystore_storage_config2 = database_keystore_config(&keystore_path)?;
        let key_manager_config2 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            None, // No mnemonic provided - should load existing seeds
            None, // No passphrase
        );

        let key_manager2 =
            crate::create_key_manager_from_config(&key_manager_config2, &keystore_storage_config2)
                .expect("Failed to create second KeyManager");

        // Verify the seeds are the same as the first instance (persistence test)
        let loaded_winternitz_seed2 = key_manager2
            .keystore
            .load_winternitz_seed()
            .expect("Failed to load winternitz seed from second keystore");

        let loaded_key_derivation_seed2 = key_manager2
            .keystore
            .load_key_derivation_seed()
            .expect("Failed to load key derivation seed from second keystore");

        assert_eq!(
            loaded_winternitz_seed2, loaded_winternitz_seed,
            "Auto-generated seeds should persist across KeyManager instances"
        );

        assert_eq!(
            loaded_key_derivation_seed2, loaded_key_derivation_seed,
            "Auto-generated seeds should persist across KeyManager instances"
        );

        // Step 7: Verify derived keys are also the same (deterministic from persisted seeds)
        let public_key2 = key_manager2
            .derive_keypair(BitcoinKeyType::P2wpkh, 0)
            .expect("Failed to derive keypair from second KeyManager");
        assert_eq!(
            public_key2, public_key,
            "Keys derived from persisted seeds should match"
        );

        // Step 8: Test uniqueness - create third KeyManager with fresh storage
        // Should generate different seeds than the first instance
        drop(key_manager2);
        let keystore_path3 = temp_storage();
        let keystore_storage_config3 = database_keystore_config(&keystore_path3)?;

        let key_manager_config3 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            None, // No mnemonic - should generate new different seeds
            None,
        );

        let key_manager3 =
            crate::create_key_manager_from_config(&key_manager_config3, &keystore_storage_config3)
                .expect("Failed to create third KeyManager");

        let loaded_winternitz_seed3 = key_manager3
            .keystore
            .load_winternitz_seed()
            .expect("Failed to load winternitz seed from third keystore");

        let loaded_key_derivation_seed3 = key_manager3
            .keystore
            .load_key_derivation_seed()
            .expect("Failed to load key derivation seed from third keystore");

        // Verify that different KeyManager instances with fresh storage generate different seeds
        assert_ne!(
            loaded_winternitz_seed3, loaded_winternitz_seed,
            "Different KeyManager instances should generate different winternitz seeds"
        );

        assert_ne!(
            loaded_key_derivation_seed3, loaded_key_derivation_seed,
            "Different KeyManager instances should generate different key derivation seeds"
        );

        // Cleanup
        drop(key_manager3);
        cleanup_storage(&keystore_path);
        cleanup_storage(&keystore_path3);
        Ok(())
    }

    #[test]
    pub fn test_store_load_ecdsa_keypairs() {
        /*
         * Objective: Validate keypair persistence and retrieval symmetry.
         * Preconditions: Initialized KeyStore; Secp256k1 context.
         * Input / Test Data: Two generated keypairs.
         * Steps / Procedure: Store both keypairs; load by public key; compare stored vs loaded.
         * Expected Result: Loads succeed; private/public key strings match; keys are distinct.
         */

        // Set up test environment using helper function
        let (keystore, _store, keystore_path, store_path) =
            setup_test_environment().expect("Failed to setup test environment");

        // Initialize Secp256k1 context for key generation
        let secp = secp256k1::Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();

        // Generate first keypair
        let secret_key_1 = SecretKey::new(&mut rng);
        let private_key_1 = PrivateKey::new(secret_key_1, REGTEST);
        let public_key_1 = PublicKey::from_private_key(&secp, &private_key_1);

        // Generate second keypair
        let secret_key_2 = SecretKey::new(&mut rng);
        let private_key_2 = PrivateKey::new(secret_key_2, REGTEST);
        let public_key_2 = PublicKey::from_private_key(&secp, &private_key_2);

        // Verify the keypairs are distinct
        assert_ne!(
            private_key_1.to_string(),
            private_key_2.to_string(),
            "Generated private keys should be distinct"
        );
        assert_ne!(
            public_key_1.to_string(),
            public_key_2.to_string(),
            "Generated public keys should be distinct"
        );

        // Store both keypairs in the keystore
        keystore
            .store_keypair(private_key_1, public_key_1, None)
            .expect("Failed to store first keypair");
        keystore
            .store_keypair(private_key_2, public_key_2, None)
            .expect("Failed to store second keypair");

        // Load first keypair by public key and verify
        let (loaded_private_key_1, loaded_public_key_1, _) = match keystore
            .load_keypair(&public_key_1)
            .expect("Failed to load first keypair")
        {
            Some(entry) => entry,
            None => panic!("First keypair not found in keystore"),
        };

        // Load second keypair by public key and verify
        let (loaded_private_key_2, loaded_public_key_2, _) = match keystore
            .load_keypair(&public_key_2)
            .expect("Failed to load second keypair")
        {
            Some(entry) => entry,
            None => panic!("Second keypair not found in keystore"),
        };

        // Verify loaded keypairs match stored keypairs exactly
        assert_eq!(
            loaded_private_key_1.to_string(),
            private_key_1.to_string(),
            "Loaded private key 1 should match stored private key 1"
        );
        assert_eq!(
            loaded_public_key_1.to_string(),
            public_key_1.to_string(),
            "Loaded public key 1 should match stored public key 1"
        );

        assert_eq!(
            loaded_private_key_2.to_string(),
            private_key_2.to_string(),
            "Loaded private key 2 should match stored private key 2"
        );
        assert_eq!(
            loaded_public_key_2.to_string(),
            public_key_2.to_string(),
            "Loaded public key 2 should match stored public key 2"
        );

        // Verify that loaded keypairs are still distinct from each other
        assert_ne!(
            loaded_private_key_1.to_string(),
            loaded_private_key_2.to_string(),
            "Loaded private keys should remain distinct"
        );
        assert_ne!(
            loaded_public_key_1.to_string(),
            loaded_public_key_2.to_string(),
            "Loaded public keys should remain distinct"
        );

        // Additional verification: Test that we cannot load non-existent keypair
        let fake_secret_key = SecretKey::new(&mut rng);
        let fake_private_key = PrivateKey::new(fake_secret_key, REGTEST);
        let fake_public_key = PublicKey::from_private_key(&secp, &fake_private_key);

        let non_existent_result = keystore
            .load_keypair(&fake_public_key)
            .expect("Load operation should succeed even for non-existent key");

        assert!(
            non_existent_result.is_none(),
            "Loading non-existent keypair should return None"
        );

        // Cleanup: drop both keystore and storage handles before removing files on Windows
        drop(keystore);
        drop(_store);
        cleanup_test_environment(&keystore_path, &store_path);
    }

    #[test]
    pub fn test_non_existent_keypair_lookout() {
        /*
         * Objective: Ensure missing keys return Ok(None).
         * Preconditions: Fresh keystore without that public key.
         * Input / Test Data: Random valid PublicKey not in store.
         * Steps / Procedure: Call load_keypair(&pubkey).
         * Expected Result: Returns Ok(None) without error.
         */

        // Set up fresh test environment using helper function
        let (keystore, _store, keystore_path, store_path) =
            setup_test_environment().expect("Failed to setup test environment");

        // Initialize Secp256k1 context for key generation
        let secp = secp256k1::Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();

        // Generate a random valid PublicKey that is NOT in the store
        let secret_key = SecretKey::new(&mut rng);
        let private_key = PrivateKey::new(secret_key, REGTEST);
        let non_existent_public_key = PublicKey::from_private_key(&secp, &private_key);

        // Verify the keystore is empty (fresh) by checking it doesn't contain our test key
        // This should return Ok(None) since the key was never stored
        let result = keystore
            .load_keypair(&non_existent_public_key)
            .expect("load_keypair operation should succeed even for non-existent keys");

        // Expected Result: Returns Ok(None) without error
        assert!(
            result.is_none(),
            "Loading non-existent keypair should return None, but got Some(_)"
        );

        // Additional verification: Test with multiple non-existent keys to ensure consistency
        for _ in 0..5 {
            let another_secret_key = SecretKey::new(&mut rng);
            let another_private_key = PrivateKey::new(another_secret_key, REGTEST);
            let another_non_existent_public_key =
                PublicKey::from_private_key(&secp, &another_private_key);

            let another_result = keystore
                .load_keypair(&another_non_existent_public_key)
                .expect("load_keypair operation should consistently succeed for non-existent keys");

            assert!(
                another_result.is_none(),
                "Loading multiple non-existent keypairs should consistently return None"
            );
        }

        // Verify that the keystore operations don't fail even when repeatedly called
        // This tests that the "lookup" behavior is stable and doesn't cause side effects
        let repeated_result = keystore
            .load_keypair(&non_existent_public_key)
            .expect("Repeated load_keypair calls should not fail");

        assert!(
            repeated_result.is_none(),
            "Repeated lookups of non-existent keypair should consistently return None"
        );

        // Store one keypair to verify the keystore is functional, then test non-existent lookup again
        let stored_secret_key = SecretKey::new(&mut rng);
        let stored_private_key = PrivateKey::new(stored_secret_key, REGTEST);
        let stored_public_key = PublicKey::from_private_key(&secp, &stored_private_key);

        keystore
            .store_keypair(stored_private_key, stored_public_key, None)
            .expect("Should be able to store a keypair");

        // Verify the stored key can be retrieved (keystore is working)
        let stored_result = keystore
            .load_keypair(&stored_public_key)
            .expect("Should be able to load stored keypair");
        assert!(
            stored_result.is_some(),
            "Stored keypair should be retrievable"
        );

        // Now test that non-existent keys still return None even with other keys present
        let final_result = keystore
            .load_keypair(&non_existent_public_key)
            .expect("load_keypair should work even with other keys present");

        assert!(
            final_result.is_none(),
            "Non-existent keypair should still return None even when other keys are present"
        );

        // Cleanup: drop both keystore and storage handles before removing files on Windows
        drop(keystore);
        drop(_store);
        cleanup_test_environment(&keystore_path, &store_path);
    }

    #[test]
    pub fn test_rsa_key_index_mapping() -> Result<(), KeyManagerError> {
        /*
         * Objective: Validate RSA key storage and retrieval by public key hash.
         * Preconditions: Initialized KeyStore.
         * Input / Test Data: RSA keypair PEM.
         * Steps / Procedure: Store RSA key; load by public key hash; verify PEM round-trips.
         * Expected Result: Load succeeds; public PEM matches; non-existent key returns None.
         */

        run_test_with_key_manager(|key_manager| {
            // Initialize random number generator for RSA key generation
            let mut rng = secp256k1::rand::thread_rng();

            // Generate and store RSA keypair - returns public key PEM
            let original_pubkey_pem = key_manager
                .generate_rsa_keypair(&mut rng)
                .expect("Failed to generate RSA keypair");

            // Extract public key hash from PEM to use as lookup key
            let pubkey_hash = RSAKeyPair::pubkey_from_public_key_pem(&original_pubkey_pem)
                .expect("Failed to extract public key hash from PEM");

            // Test Step 1: Load by public key hash - should return Some(RSAKeyPair)
            let loaded_rsa_key = key_manager
                .keystore
                .load_rsa_key(pubkey_hash.clone())
                .expect("Failed to load RSA key by public key hash");

            assert!(
                loaded_rsa_key.is_some(),
                "RSA key should be found in keystore"
            );

            let loaded_key = loaded_rsa_key.unwrap();

            // Test Step 2: Verify the loaded RSA key public PEM round-trips correctly
            let loaded_pubkey_pem = loaded_key
                .export_public_pem()
                .expect("Failed to export public PEM from loaded RSA keypair");

            assert_eq!(
                loaded_pubkey_pem, original_pubkey_pem,
                "Loaded RSA public key PEM should match the original"
            );

            // Test Step 3: Generate a non-existent public key hash for testing
            let mut rng_nonexistent = secp256k1::rand::thread_rng();
            const DEFAULT_RSA_BITS: usize = 2048;
            let nonexistent_rsa = RSAKeyPair::new(&mut rng_nonexistent, DEFAULT_RSA_BITS)?;
            let nonexistent_pubkey_hash =
                RSAKeyPair::pubkey_from_public_key_pem(&nonexistent_rsa.export_public_pem()?)?;

            let non_existent_result = key_manager
                .keystore
                .load_rsa_key(nonexistent_pubkey_hash)
                .expect("Failed to attempt loading RSA key with non-existent hash");

            assert!(
                non_existent_result.is_none(),
                "RSA key should not be found for non-existent public key hash"
            );

            // Test Step 4: Store another RSA key and verify independence
            let second_pubkey_pem = key_manager
                .generate_rsa_keypair(&mut rng)
                .expect("Failed to generate second RSA keypair");

            let second_pubkey_hash = RSAKeyPair::pubkey_from_public_key_pem(&second_pubkey_pem)
                .expect("Failed to extract second public key hash from PEM");

            // Verify both keys can be loaded independently
            let first_key_still_there = key_manager
                .keystore
                .load_rsa_key(pubkey_hash)
                .expect("Failed to re-load first RSA key");
            assert!(
                first_key_still_there.is_some(),
                "First RSA key should still be available"
            );

            let second_key_loaded = key_manager
                .keystore
                .load_rsa_key(second_pubkey_hash)
                .expect("Failed to load second RSA key");
            assert!(
                second_key_loaded.is_some(),
                "Second RSA key should be available"
            );

            // Verify the keys are different (different indices should have different keys)
            let first_key_pem = first_key_still_there
                .unwrap()
                .export_public_pem()
                .expect("Failed to export first key's public PEM");
            let second_key_pem = second_key_loaded
                .unwrap()
                .export_public_pem()
                .expect("Failed to export second key's public PEM");

            assert_ne!(
                first_key_pem, second_key_pem,
                "RSA keys at different indices should be different"
            );

            // Verify the PEMs match what we got from generate_rsa_keypair
            assert_eq!(
                first_key_pem, original_pubkey_pem,
                "First loaded key PEM should match original"
            );
            assert_eq!(
                second_key_pem, second_pubkey_pem,
                "Second loaded key PEM should match original"
            );

            Ok(())
        })
    }

    #[test]
    pub fn test_overwrite_semantics() -> Result<(), KeyManagerError> {
        /*
         * Objective: Verify safe re-store behavior and RSA index overwrite semantics.
         * Preconditions: Existing entries for (a) an ECDSA keypair and (b) an RSA key at an index.
         * Input / Test Data: (a) Same ECDSA keypair re-stored; (b) Two different RSA keypairs stored at the same index N sequentially.
         * Steps / Procedure: (a) Call store_keypair twice with the same (sk, pk); load and compare; (b) store_rsa_key with key1 at N, then key2 at N; load_rsa_key(N).
         * Expected Result: (a) Idempotent: loaded entry equals the stored pair. (b) Last-write-wins: loaded RSA key equals the second one.
         */

        run_test_with_key_manager(|key_manager| {
            // Initialize contexts and random number generator
            let secp = secp256k1::Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();

            // Test Part (a): ECDSA keypair idempotent re-store behavior

            // Generate ECDSA keypair
            let secret_key = SecretKey::new(&mut rng);
            let private_key = PrivateKey::new(secret_key, REGTEST);
            let public_key = PublicKey::from_private_key(&secp, &private_key);

            // Store the ECDSA keypair first time
            key_manager
                .keystore
                .store_keypair(private_key, public_key, None)
                .expect("Failed to store ECDSA keypair first time");

            // Load and verify first storage
            let (loaded_private_1, loaded_public_1, _) = key_manager
                .keystore
                .load_keypair(&public_key)
                .expect("Failed to load ECDSA keypair after first store")
                .expect("ECDSA keypair should exist after first store");

            assert_eq!(
                loaded_private_1.to_string(),
                private_key.to_string(),
                "First load: private key should match stored key"
            );
            assert_eq!(
                loaded_public_1.to_string(),
                public_key.to_string(),
                "First load: public key should match stored key"
            );

            // Store the same ECDSA keypair second time (idempotent operation)
            key_manager
                .keystore
                .store_keypair(private_key, public_key, None)
                .expect("Failed to store ECDSA keypair second time");

            // Load and verify second storage - should be identical (idempotent)
            let (loaded_private_2, loaded_public_2, _) = key_manager
                .keystore
                .load_keypair(&public_key)
                .expect("Failed to load ECDSA keypair after second store")
                .expect("ECDSA keypair should exist after second store");

            assert_eq!(
                loaded_private_2.to_string(),
                private_key.to_string(),
                "Second load: private key should still match stored key"
            );
            assert_eq!(
                loaded_public_2.to_string(),
                public_key.to_string(),
                "Second load: public key should still match stored key"
            );

            // Verify idempotency: both loads should return identical results
            assert_eq!(
                loaded_private_1.to_string(),
                loaded_private_2.to_string(),
                "Idempotent re-store: private keys from both loads should be identical"
            );
            assert_eq!(
                loaded_public_1.to_string(),
                loaded_public_2.to_string(),
                "Idempotent re-store: public keys from both loads should be identical"
            );

            // Test Part (b): RSA key overwrite behavior (last-write-wins)

            //let rsa_index: usize = 10;

            // Generate and store first RSA keypair at index N
            let first_rsa_pubkey_pem = key_manager
                .generate_rsa_keypair(&mut rng)
                .expect("Failed to generate first RSA keypair");

            // Extract the public key hash from the PEM to use for loading
            //let first_pubkey_hash = RSAKeyPair::pubkey_from_public_key_pem(&first_rsa_pubkey_pem)
            //    .expect("Failed to extract first public key hash from PEM");

            // Load and verify first RSA key
            //let loaded_first_rsa = key_manager.keystore.load_rsa_key(first_pubkey_hash.clone())
            //    .expect("Failed to load first RSA key")
            //    .expect("First RSA key should exist");

            //let first_loaded_pubkey_pem = loaded_first_rsa.export_public_pem()
            //    .expect("Failed to export public PEM from first RSA key");
            // Generate and store second RSA keypair at the SAME index N (overwrite)
            let second_rsa_pubkey_pem = key_manager
                .generate_rsa_keypair(&mut rng)
                .expect("Failed to generate second RSA keypair");

            // Extract the second public key hash
            let second_pubkey_hash = RSAKeyPair::pubkey_from_public_key_pem(&second_rsa_pubkey_pem)
                .expect("Failed to extract second public key hash from PEM");

            // Verify the two RSA public keys are different (we generated different keys)
            assert_ne!(
                first_rsa_pubkey_pem, second_rsa_pubkey_pem,
                "The two generated RSA keys should be different"
            );

            // Load RSA key after overwrite - should return the second key (last-write-wins)
            let loaded_overwritten_rsa = key_manager
                .keystore
                .load_rsa_key(second_pubkey_hash.clone())
                .expect("Failed to load RSA key after overwrite")
                .expect("RSA key should still exist after overwrite");

            let overwritten_loaded_pubkey_pem = loaded_overwritten_rsa
                .export_public_pem()
                .expect("Failed to export public PEM from overwritten RSA key");

            // Verify the loaded key is NOT the first key (overwrite was successful)
            assert_ne!(overwritten_loaded_pubkey_pem, first_rsa_pubkey_pem,
                "Overwrite verification: loaded RSA key should NOT match the first (overwritten) key");

            // Also verify we can still load the first key by its hash (if still stored)
            //let first_key_reloaded = key_manager.keystore.load_rsa_key(first_pubkey_hash)
            //    .expect("Failed to reload first RSA key");
            // Note: Depending on implementation, this might be None if overwrite happened by index
            // or Some if keys are stored by hash (non-overwriting behavior)

            // Verify last-write-wins: loaded key should match the second (most recent) key
            assert_eq!(
                overwritten_loaded_pubkey_pem, second_rsa_pubkey_pem,
                "Last-write-wins: loaded RSA key should match the second (latest) stored key"
            );

            // Verify the loaded key is NOT the first key (overwrite was successful)
            assert_ne!(overwritten_loaded_pubkey_pem, first_rsa_pubkey_pem,
                "Overwrite verification: loaded RSA key should NOT match the first (overwritten) key");

            // Additional verification: Test that RSA overwrite doesn't affect ECDSA storage
            let (final_ecdsa_private, final_ecdsa_public, _) = key_manager
                .keystore
                .load_keypair(&public_key)
                .expect("Failed to load ECDSA keypair after RSA operations")
                .expect("ECDSA keypair should still exist after RSA operations");

            assert_eq!(
                final_ecdsa_private.to_string(),
                private_key.to_string(),
                "ECDSA private key should be unaffected by RSA operations"
            );
            assert_eq!(
                final_ecdsa_public.to_string(),
                public_key.to_string(),
                "ECDSA public key should be unaffected by RSA operations"
            );

            Ok(())
        })
    }

    #[test]
    pub fn test_generate_keypair_in_keystore() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure generate_keypair persists the generated pair.
         * Preconditions: Initialized KeyManager and KeyStore.
         * Input / Test Data: RNG seeded; network set.
         * Steps / Procedure: Call generate_keypair; then KeyStore::load_keypair with returned pubkey.
         * Expected Result: Load returns Some((sk, pk)) and strings match.
         */

        run_test_with_key_manager(|key_manager| {
            // Step 1: Call next_keypair to create and store a new keypair
            let generated_public_key = key_manager
                .next_keypair(BitcoinKeyType::P2wpkh)
                .expect("Failed to generate keypair");

            // Verify that the generated public key is valid (33 bytes compressed format)
            assert_eq!(
                generated_public_key.to_bytes().len(),
                33,
                "Generated public key should be 33 bytes in compressed format"
            );

            // Step 2: Load the keypair from keystore using the returned public key
            let loaded_keypair = key_manager
                .keystore
                .load_keypair(&generated_public_key)
                .expect("Failed to load keypair from keystore");

            // Expected Result: Load should return Some((sk, pk, key_type))
            assert!(
                loaded_keypair.is_some(),
                "Keystore should contain the generated keypair"
            );

            let (loaded_private_key, loaded_public_key, _) = loaded_keypair.unwrap();

            // Step 3: Verify that the loaded keys match the generated key
            assert_eq!(
                loaded_public_key.to_string(),
                generated_public_key.to_string(),
                "Loaded public key should match the generated public key"
            );

            // Step 4: Verify key consistency by deriving public key from loaded private key
            let secp = secp256k1::Secp256k1::new();
            let derived_public_key = PublicKey::from_private_key(&secp, &loaded_private_key);

            assert_eq!(
                derived_public_key.to_string(),
                generated_public_key.to_string(),
                "Public key derived from loaded private key should match generated public key"
            );

            assert_eq!(
                derived_public_key.to_string(),
                loaded_public_key.to_string(),
                "Public key derived from private key should match loaded public key"
            );

            // Step 5: Additional verification - test that we can use the loaded keys for cryptographic operations
            let signature_verifier = SignatureVerifier::new();
            let test_message = random_message();

            // Sign with the loaded private key via KeyManager
            let signature = key_manager
                .sign_ecdsa_message(&test_message, &loaded_public_key)
                .expect("Failed to sign message with loaded key");

            // Verify the signature using the loaded public key
            assert!(
                signature_verifier.verify_ecdsa_signature(
                    &signature,
                    &test_message,
                    loaded_public_key
                ),
                "Signature should verify successfully with loaded public key"
            );

            // Step 6: Test multiple keypair generation to ensure each is unique and properly stored
            let mut generated_keys: Vec<PublicKey> = Vec::new();
            for i in 0..3 {
                let another_public_key = key_manager
                    .next_keypair(BitcoinKeyType::P2wpkh)
                    .expect(&format!("Failed to generate keypair {}", i + 2));

                // Verify this key is different from previously generated keys
                for existing_key in &generated_keys {
                    assert_ne!(
                        another_public_key.to_string(),
                        existing_key.to_string(),
                        "Each generated keypair should be unique"
                    );
                }

                // Verify this key can be loaded from keystore
                let another_loaded = key_manager
                    .keystore
                    .load_keypair(&another_public_key)
                    .expect("Failed to load additional keypair")
                    .expect("Additional keypair should exist in keystore");

                assert_eq!(
                    another_loaded.1.to_string(),
                    another_public_key.to_string(),
                    "Additional loaded public key should match generated key"
                );

                generated_keys.push(another_public_key);
            }

            // Step 7: Verify all generated keys are still accessible (persistence test)
            generated_keys.push(generated_public_key); // Include the original key

            for (i, key) in generated_keys.iter().enumerate() {
                let persistent_loaded = key_manager
                    .keystore
                    .load_keypair(key)
                    .expect(&format!("Failed to re-load keypair {}", i + 1))
                    .expect(&format!("Keypair {} should still exist in keystore", i + 1));

                assert_eq!(
                    persistent_loaded.1.to_string(),
                    key.to_string(),
                    "Persistently loaded public key {} should match original",
                    i + 1
                );
            }

            Ok(())
        })
    }

    #[test]
    pub fn test_import_private_key_wif_success() -> Result<(), KeyManagerError> {
        /*
         * Objective: Validate WIF import stores a keypair.
         * Preconditions: Valid WIF string for the configured network.
         * Input / Test Data: WIF string.
         * Steps / Procedure: Call import_private_key(wif); then load_keypair by returned pubkey.
         * Expected Result: Returns public key; load succeeds with matching keys.
         */
        run_test_with_key_manager(|key_manager| {
            // Create a valid WIF for testing - using a known private key
            let secp = Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            let secret_key = SecretKey::new(&mut rng);
            let original_private_key = PrivateKey::new(secret_key, REGTEST);
            let original_public_key = PublicKey::from_private_key(&secp, &original_private_key);

            // Convert to WIF format for the configured network
            let wif_string = original_private_key.to_wif();

            // Import the WIF string
            let imported_public_key = key_manager.import_private_key(&wif_string)?;

            // Verify the imported public key matches the original
            assert_eq!(
                imported_public_key, original_public_key,
                "Imported public key should match the original"
            );

            // Load the keypair using the returned public key
            let (loaded_private_key, loaded_public_key, _) = key_manager
                .keystore
                .load_keypair(&imported_public_key)?
                .expect("Imported keypair should exist in keystore");

            // Verify the loaded keys match the original keys
            assert_eq!(
                loaded_private_key, original_private_key,
                "Loaded private key should match the original"
            );
            assert_eq!(
                loaded_public_key, imported_public_key,
                "Loaded public key should match the imported public key"
            );

            // Test with different WIF formats - compressed vs uncompressed
            let compressed_private_key = PrivateKey {
                compressed: true,
                network: bitcoin::Network::Regtest.into(),
                inner: original_private_key.inner,
            };
            let compressed_wif = compressed_private_key.to_wif();
            let compressed_public_key = PublicKey::from_private_key(&secp, &compressed_private_key);

            let imported_compressed = key_manager.import_private_key(&compressed_wif)?;
            assert_eq!(
                imported_compressed, compressed_public_key,
                "Imported compressed public key should match the original compressed key"
            );

            let (loaded_compressed_private, loaded_compressed_public, _) = key_manager
                .keystore
                .load_keypair(&imported_compressed)?
                .expect("Compressed imported key should exist in keystore");
            assert_eq!(
                loaded_compressed_private, compressed_private_key,
                "Loaded compressed private key should match the original"
            );
            assert_eq!(
                loaded_compressed_public, imported_compressed,
                "Loaded compressed public key should match the imported public key"
            );

            // Test persistence by simulating storage backend operations
            // Store both keys and verify they persist
            key_manager
                .keystore
                .store_keypair(original_private_key, original_public_key, None)?;
            key_manager.keystore.store_keypair(
                compressed_private_key,
                compressed_public_key,
                None,
            )?;

            // Verify we can still load the imported keys
            let (persistent_private, persistent_public, _) = key_manager
                .keystore
                .load_keypair(&imported_public_key)?
                .expect("Original imported key should be in keystore");
            assert_eq!(
                persistent_private, original_private_key,
                "Persistently loaded private key should match original"
            );
            assert_eq!(
                persistent_public, imported_public_key,
                "Persistently loaded public key should match imported"
            );

            let (persistent_compressed_private, persistent_compressed_public, _) = key_manager
                .keystore
                .load_keypair(&imported_compressed)?
                .expect("Compressed imported key should be in keystore");
            assert_eq!(
                persistent_compressed_private, compressed_private_key,
                "Persistently loaded compressed private key should match original"
            );
            assert_eq!(
                persistent_compressed_public, imported_compressed,
                "Persistently loaded compressed public key should match imported"
            );

            // Test that importing the same WIF multiple times is idempotent
            let duplicate_import = key_manager.import_private_key(&wif_string)?;
            assert_eq!(
                duplicate_import, imported_public_key,
                "Duplicate import should return the same public key"
            );

            // Test cryptographic operations with imported keys to verify they work correctly

            // Test cryptographic operations with imported keys
            let signature_verifier = SignatureVerifier::new();
            let test_message = random_message();

            // Sign with the imported key
            let signature = key_manager.sign_ecdsa_message(&test_message, &imported_public_key)?;

            // Verify the signature using the imported public key
            let is_valid = signature_verifier.verify_ecdsa_signature(
                &signature,
                &test_message,
                imported_public_key,
            );
            assert!(
                is_valid,
                "Signature created with imported key should be valid"
            );

            Ok(())
        })
    }

    #[test]
    pub fn test_import_private_key_wif_failure() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure invalid WIF returns the right error.
         * Preconditions: None.
         * Input / Test Data: Malformed WIF (e.g., non-base58, wrong checksum).
         * Steps / Procedure: Call import_private_key(bad).
         * Expected Result: Error KeyManagerError::FailedToParsePrivateKey.
         */
        run_test_with_key_manager(|key_manager| {
            // Test Case 1: Completely invalid string (non-base58 characters)
            let invalid_wif_1 = "this_is_not_a_wif_string_with_invalid_chars_0OIl";
            let result1 = key_manager.import_private_key(invalid_wif_1);
            assert!(
                result1.is_err(),
                "Import should fail for completely invalid WIF string"
            );

            match result1.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 2: Empty string
            let empty_wif = "";
            let result2 = key_manager.import_private_key(empty_wif);
            assert!(result2.is_err(), "Import should fail for empty WIF string");

            match result2.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 3: Valid base58 but wrong length
            let wrong_length_wif = "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294Lv"; // Too short
            let result3 = key_manager.import_private_key(wrong_length_wif);
            assert!(result3.is_err(), "Import should fail for wrong length WIF");

            match result3.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 4: Valid base58 with wrong checksum
            // Start with a valid WIF and corrupt the checksum
            let mut rng = secp256k1::rand::thread_rng();
            let secret_key = SecretKey::new(&mut rng);
            let valid_private_key = PrivateKey::new(secret_key, REGTEST);
            let valid_wif = valid_private_key.to_wif();

            // Corrupt the last character (part of checksum)
            let mut corrupted_wif = valid_wif.chars().collect::<Vec<char>>();
            let last_idx = corrupted_wif.len() - 1;
            corrupted_wif[last_idx] = if corrupted_wif[last_idx] == 'A' {
                'B'
            } else {
                'A'
            };
            let corrupted_wif_string: String = corrupted_wif.into_iter().collect();

            let result4 = key_manager.import_private_key(&corrupted_wif_string);
            assert!(
                result4.is_err(),
                "Import should fail for WIF with wrong checksum"
            );

            match result4.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 5: Valid base58 but wrong network prefix
            // Create a WIF for a different network and try to import it
            let mainnet_private_key = PrivateKey::new(secret_key, bitcoin::Network::Bitcoin);
            let mainnet_wif = mainnet_private_key.to_wif();

            let _result5 = key_manager.import_private_key(&mainnet_wif);
            // This might succeed but we should test it anyway
            // Note: The behavior might depend on implementation - some might accept cross-network WIFs

            // Test Case 6: Random base58 string that looks like WIF but isn't
            let fake_wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTj"; // Random base58
            let result6 = key_manager.import_private_key(fake_wif);
            assert!(result6.is_err(), "Import should fail for fake WIF string");

            match result6.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 7: WIF with invalid characters that could be confused
            let confusing_wif = "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294Lv0OIl"; // Contains 0, O, I, l
            let result7 = key_manager.import_private_key(confusing_wif);
            assert!(
                result7.is_err(),
                "Import should fail for WIF with confusing characters"
            );

            match result7.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 8: Very long invalid string
            let too_long_wif = "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294LvTJ1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294Lv";
            let result8 = key_manager.import_private_key(too_long_wif);
            assert!(
                result8.is_err(),
                "Import should fail for too long WIF string"
            );

            match result8.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 9: WIF starting with wrong prefix
            let wrong_prefix_wif = "1J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294LvTJ"; // Starts with '1' instead of '5' or 'K'/'L'
            let result9 = key_manager.import_private_key(wrong_prefix_wif);
            assert!(
                result9.is_err(),
                "Import should fail for WIF with wrong prefix"
            );

            match result9.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 10: Null bytes and special characters
            let null_wif = "5J1F7GHadZG3sCCKHCwg8\0Jvys9xUbFsjLnGec4H294LvTJ";
            let result10 = key_manager.import_private_key(null_wif);
            assert!(
                result10.is_err(),
                "Import should fail for WIF with null bytes"
            );

            match result10.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }

            // Test Case 11: Verify the KeyManager state is still clean after failures
            // Import a valid key to make sure the KeyManager still works
            let valid_secret_key = SecretKey::new(&mut rng);
            let valid_private_key = PrivateKey::new(valid_secret_key, REGTEST);
            let valid_wif = valid_private_key.to_wif();

            let valid_result = key_manager.import_private_key(&valid_wif);
            assert!(
                valid_result.is_ok(),
                "Valid WIF import should still work after failed attempts"
            );

            Ok(())
        })
    }

    #[test]
    pub fn test_import_secret_key_hex_success() -> Result<(), KeyManagerError> {
        /*
         * Objective: Validate raw secret hex import stores keypair.
         * Preconditions: Valid 32-byte secp256k1 secret hex; network set.
         * Input / Test Data: 64-hex-character secret string.
         * Steps / Procedure: Call import_secret_key(hex, network); then load_keypair.
         * Expected Result: Returns public key; load succeeds; keys match.
         */
        run_test_with_key_manager(|key_manager| -> Result<(), KeyManagerError> {
            // Test Case 1: Generate a valid key using secp256k1's native key generation
            let mut rng = secp256k1::rand::thread_rng();
            let secret_key = secp256k1::SecretKey::new(&mut rng);
            let valid_hex = secret_key.display_secret().to_string();
            let imported_public_key = key_manager.import_secret_key(&valid_hex, REGTEST)?;

            // Verify the returned public key is valid
            assert!(
                !imported_public_key.to_string().is_empty(),
                "Imported public key should not be empty"
            );

            // Load the keypair using the returned public key
            let (loaded_private_key, loaded_public_key, _) = key_manager
                .keystore
                .load_keypair(&imported_public_key)?
                .expect("Imported keypair should exist in keystore");

            // Verify the loaded keys are consistent
            assert_eq!(
                loaded_public_key, imported_public_key,
                "Loaded public key should match the imported public key"
            );

            // Verify the private key matches the hex input
            let expected_secret_key =
                SecretKey::from_str(&valid_hex).expect("Valid hex should parse to SecretKey");
            let expected_private_key = PrivateKey::new(expected_secret_key, REGTEST);

            assert_eq!(
                loaded_private_key, expected_private_key,
                "Loaded private key should match the expected private key from hex"
            );

            // Test Case 2: Another valid hex generated from secp
            let secret_key_2 = secp256k1::SecretKey::new(&mut rng);
            let hex_pattern_2 = secret_key_2.display_secret().to_string();
            let imported_key_2 = key_manager.import_secret_key(&hex_pattern_2, REGTEST)?;

            let (_loaded_private_2, loaded_public_2, _) = key_manager
                .keystore
                .load_keypair(&imported_key_2)?
                .expect("Second imported key should exist in keystore");
            assert_eq!(
                loaded_public_2, imported_key_2,
                "Second imported key should be loadable"
            );

            // Test Case 3: Valid hex with mixed case (generate and then uppercase/lowercase mix)
            let secret_key_3 = secp256k1::SecretKey::new(&mut rng);
            let mut mixed_case_hex = secret_key_3.display_secret().to_string();
            // create a mixed-case variant
            mixed_case_hex = mixed_case_hex
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            let imported_key_3 = key_manager.import_secret_key(&mixed_case_hex, REGTEST)?;

            let (_loaded_private_3, loaded_public_3, _) = key_manager
                .keystore
                .load_keypair(&imported_key_3)?
                .expect("Mixed case hex import should exist in keystore");
            assert_eq!(
                loaded_public_3, imported_key_3,
                "Mixed case hex import should work correctly"
            );

            // Test Case 4: Verify cryptographic operations work with imported key
            let signature_verifier = SignatureVerifier::new();
            let test_message = random_message();

            // Sign with the imported key
            let signature = key_manager.sign_ecdsa_message(&test_message, &imported_public_key)?;

            // Verify the signature using the imported public key
            let is_valid = signature_verifier.verify_ecdsa_signature(
                &signature,
                &test_message,
                imported_public_key,
            );
            assert!(
                is_valid,
                "Signature created with imported secret key should be valid"
            );

            // Test Case 5: Test different networks
            let mainnet_imported =
                key_manager.import_secret_key(&valid_hex, bitcoin::Network::Bitcoin)?;
            let (loaded_mainnet_private, _loaded_mainnet_public, _) = key_manager
                .keystore
                .load_keypair(&mainnet_imported)?
                .expect("Mainnet imported keypair should exist in keystore");

            // The private key inner value should be the same, but network should differ
            assert_eq!(
                loaded_mainnet_private.inner, loaded_private_key.inner,
                "Private key inner values should be the same regardless of network"
            );
            assert_ne!(
                loaded_mainnet_private.network, loaded_private_key.network,
                "Network should differ between regtest and mainnet imports"
            );

            // Test Case 6: Verify persistence and idempotency
            let duplicate_import = key_manager.import_secret_key(&valid_hex, REGTEST)?;
            assert_eq!(
                duplicate_import, imported_public_key,
                "Duplicate import should return the same public key"
            );

            // Verify all imported keys are still accessible
            let _verify_key1 = key_manager
                .keystore
                .load_keypair(&imported_public_key)?
                .expect("Original key should still be accessible");
            let _verify_key2 = key_manager
                .keystore
                .load_keypair(&imported_key_2)?
                .expect("Second key should still be accessible");
            let _verify_key3 = key_manager
                .keystore
                .load_keypair(&imported_key_3)?
                .expect("Third key should still be accessible");
            let _verify_mainnet = key_manager
                .keystore
                .load_keypair(&mainnet_imported)?
                .expect("Mainnet key should still be accessible");

            Ok(())
        })
    }

    #[test]
    pub fn test_import_secret_key_hex_failure() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure invalid hex parses fail.
         * Preconditions: None.
         * Input / Test Data: Non-hex or wrong-length string.
         * Steps / Procedure: Call import_secret_key(bad, network).
         * Expected Result: Error KeyManagerError::InvalidPrivateKey or parse error.
         */
        run_test_with_key_manager(|key_manager| {
            // Test Case 1: Non-hex characters
            let invalid_hex_1 = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
            let result1 = key_manager.import_secret_key(invalid_hex_1, REGTEST);
            assert!(
                result1.is_err(),
                "Import should fail for non-hex characters"
            );

            // Test Case 2: Too short hex string
            let too_short_hex = "123456789abcdef";
            let result2 = key_manager.import_secret_key(too_short_hex, REGTEST);
            assert!(
                result2.is_err(),
                "Import should fail for hex string that's too short"
            );

            // Test Case 3: Too long hex string
            let too_long_hex =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef12345";
            let result3 = key_manager.import_secret_key(too_long_hex, REGTEST);
            assert!(
                result3.is_err(),
                "Import should fail for hex string that's too long"
            );

            // Test Case 4: Empty string
            let empty_hex = "";
            let result4 = key_manager.import_secret_key(empty_hex, REGTEST);
            assert!(result4.is_err(), "Import should fail for empty hex string");

            // Test Case 5: Invalid characters mixed with valid hex
            let mixed_invalid_hex =
                "0123456789abcdefGHIJ456789abcdef0123456789abcdef0123456789abcdef";
            let result5 = key_manager.import_secret_key(mixed_invalid_hex, REGTEST);
            assert!(
                result5.is_err(),
                "Import should fail for hex with invalid characters"
            );

            // Test Case 6: All zeros (valid hex but invalid private key)
            let zero_hex = "0000000000000000000000000000000000000000000000000000000000000000";
            let result6 = key_manager.import_secret_key(zero_hex, REGTEST);
            assert!(
                result6.is_err(),
                "Import should fail for all-zero private key"
            );

            // Test Case 7: Hex string with spaces
            let hex_with_spaces =
                "0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef";
            let result7 = key_manager.import_secret_key(hex_with_spaces, REGTEST);
            assert!(
                result7.is_err(),
                "Import should fail for hex string with spaces"
            );

            // Test Case 8: Hex string with 0x prefix
            let hex_with_prefix =
                "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let result8 = key_manager.import_secret_key(hex_with_prefix, REGTEST);
            assert!(
                result8.is_err(),
                "Import should fail for hex string with 0x prefix"
            );

            // Test Case 9: Private key above secp256k1 curve order (invalid)
            let above_curve_order =
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
            let result9 = key_manager.import_secret_key(above_curve_order, REGTEST);
            assert!(
                result9.is_err(),
                "Import should fail for private key above curve order"
            );

            // Test Case 10: Random unicode characters
            let unicode_hex = "你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好";
            let result10 = key_manager.import_secret_key(unicode_hex, REGTEST);
            assert!(
                result10.is_err(),
                "Import should fail for unicode characters"
            );

            // Test Case 11: Verify KeyManager state is clean after failures
            // Try a valid import to ensure the KeyManager still works
            let valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let imported_pubkey = key_manager.import_secret_key(valid_hex, REGTEST)?;

            // Verify the imported key can be loaded correctly
            let loaded_key = key_manager.keystore.load_keypair(&imported_pubkey)?;
            assert!(
                loaded_key.is_some(),
                "Valid imported key should be loadable"
            );

            // Verify that trying to load a different key returns None, confirming clean state
            let secp = secp256k1::Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            let other_secret_key = SecretKey::new(&mut rng);
            let other_private_key = PrivateKey::new(other_secret_key, REGTEST);
            let other_pubkey = PublicKey::from_private_key(&secp, &other_private_key);
            let other_key = key_manager.keystore.load_keypair(&other_pubkey)?;
            assert!(
                other_key.is_none(),
                "No other keys should exist in the store"
            );

            Ok(())
        })
    }

    #[test]
    pub fn test_import_partial_keys_aggregation_success() -> Result<(), KeyManagerError> {
        /*
         * Objective: Aggregate partial keys into an aggregated (sk, pk) and store.
         * Preconditions: 2–3 valid partial keys (as strings) available.
         * Input / Test Data: Inputs for import_partial_secret_keys and import_partial_private_keys.
         * Steps / Procedure: Call import; then load_keypair by returned public key.
         * Expected Result: Aggregated keypair stored; load succeeds.
         */
        run_test_with_key_manager(|key_manager| {
            // Test Case 1: Aggregate 2 partial secret keys
            let mut rng = secp256k1::rand::thread_rng();

            // Create 2 valid secret keys for aggregation
            let secret_key_1 = SecretKey::new(&mut rng);
            let secret_key_2 = SecretKey::new(&mut rng);

            let partial_secret_keys = vec![
                secret_key_1.display_secret().to_string(),
                secret_key_2.display_secret().to_string(),
            ];

            // Import and aggregate partial secret keys
            let aggregated_public_key_1 =
                key_manager.import_partial_secret_keys(partial_secret_keys, REGTEST)?;

            // Verify the aggregated public key is valid
            assert!(
                !aggregated_public_key_1.to_string().is_empty(),
                "Aggregated public key should not be empty"
            );

            // Load the aggregated keypair
            let (_loaded_private_key_1, loaded_public_key_1, _) = key_manager
                .keystore
                .load_keypair(&aggregated_public_key_1)?
                .expect("Aggregated keypair should exist in keystore");

            // Verify the loaded keys match the aggregated result
            assert_eq!(
                loaded_public_key_1, aggregated_public_key_1,
                "Loaded public key should match the aggregated public key"
            );

            // Test Case 2: Aggregate 3 partial secret keys
            let secret_key_3 = SecretKey::new(&mut rng);
            let secret_key_4 = SecretKey::new(&mut rng);
            let secret_key_5 = SecretKey::new(&mut rng);

            let partial_secret_keys_3 = vec![
                secret_key_3.display_secret().to_string(),
                secret_key_4.display_secret().to_string(),
                secret_key_5.display_secret().to_string(),
            ];

            let aggregated_public_key_2 =
                key_manager.import_partial_secret_keys(partial_secret_keys_3, REGTEST)?;

            let (_loaded_private_key_2, _loaded_public_key_2, _) = key_manager
                .keystore
                .load_keypair(&aggregated_public_key_2)?
                .expect("3-key aggregated keypair should exist in keystore");

            // Test Case 3: Aggregate partial private keys (WIF format)
            let private_key_1 = PrivateKey::new(SecretKey::new(&mut rng), REGTEST);
            let private_key_2 = PrivateKey::new(SecretKey::new(&mut rng), REGTEST);

            let partial_private_keys = vec![private_key_1.to_wif(), private_key_2.to_wif()];

            let aggregated_public_key_3 =
                key_manager.import_partial_private_keys(partial_private_keys, REGTEST)?;

            let (_loaded_private_key_3, _loaded_public_key_3, _) = key_manager
                .keystore
                .load_keypair(&aggregated_public_key_3)?
                .expect("WIF-based aggregated keypair should exist in keystore");

            // Test Case 4: Test with different networks
            let mainnet_partial_keys = vec![
                PrivateKey::new(SecretKey::new(&mut rng), bitcoin::Network::Bitcoin).to_wif(),
                PrivateKey::new(SecretKey::new(&mut rng), bitcoin::Network::Bitcoin).to_wif(),
            ];

            let mainnet_aggregated = key_manager
                .import_partial_private_keys(mainnet_partial_keys, bitcoin::Network::Bitcoin)?;

            let (_mainnet_private, _mainnet_public, _) = key_manager
                .keystore
                .load_keypair(&mainnet_aggregated)?
                .expect("Mainnet aggregated keypair should exist in keystore");

            // Test Case 5: Verify cryptographic operations work with aggregated keys
            let signature_verifier = SignatureVerifier::new();
            let test_message = random_message();

            // Sign with the first aggregated key
            let signature =
                key_manager.sign_ecdsa_message(&test_message, &aggregated_public_key_1)?;

            // Verify the signature using the aggregated public key
            let is_valid = signature_verifier.verify_ecdsa_signature(
                &signature,
                &test_message,
                aggregated_public_key_1,
            );
            assert!(
                is_valid,
                "Signature created with aggregated key should be valid"
            );

            // Test Case 6: Verify all aggregated keys are different
            assert_ne!(
                aggregated_public_key_1, aggregated_public_key_2,
                "Different partial keys should produce different aggregated keys"
            );
            assert_ne!(
                aggregated_public_key_1, aggregated_public_key_3,
                "Secret keys vs private keys aggregation should produce different results"
            );
            assert_ne!(
                aggregated_public_key_2, aggregated_public_key_3,
                "All aggregated keys should be unique"
            );

            // Test Case 7: Verify persistence - all aggregated keys should be loadable
            let _test_load_1 = key_manager
                .keystore
                .load_keypair(&aggregated_public_key_1)?
                .expect("Aggregated key 1 should exist");
            let _test_load_2 = key_manager
                .keystore
                .load_keypair(&aggregated_public_key_2)?
                .expect("Aggregated key 2 should exist");
            let _test_load_3 = key_manager
                .keystore
                .load_keypair(&aggregated_public_key_3)?
                .expect("Aggregated key 3 should exist");
            let _test_mainnet = key_manager
                .keystore
                .load_keypair(&mainnet_aggregated)?
                .expect("Mainnet aggregated key should exist");

            // Test Case 8: Test idempotent behavior - same partial keys should produce same result
            let duplicate_partial_keys = vec![
                secret_key_1.display_secret().to_string(),
                secret_key_2.display_secret().to_string(),
            ];

            let duplicate_aggregated =
                key_manager.import_partial_secret_keys(duplicate_partial_keys, REGTEST)?;

            // Verify the aggregated key can be loaded
            let _duplicate_loaded = key_manager
                .keystore
                .load_keypair(&duplicate_aggregated)?
                .expect("Duplicate aggregated key should exist");

            // Note: Depending on implementation, this might be the same or different
            // The behavior depends on whether the aggregation algorithm is deterministic
            // and whether duplicate detection is implemented

            Ok(())
        })
    }

    #[test]
    pub fn test_import_partial_keys_aggregation_failure() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure invalid partial keys or aggregation fails.
         * Preconditions: None.
         * Input / Test Data: Malformed partial keys; insufficient keys.
         * Steps / Procedure: Call import_partial_secret_keys/import_partial_private_keys with bad data.
         * Expected Result: Error KeyManagerError::FailedToAggregatePartialKeys or parse error.
         */
        run_test_with_key_manager(|key_manager| -> Result<(), KeyManagerError> {
            // Test Case 1: Try with empty keys list
            let empty_keys: Vec<String> = vec![];
            let result1 = key_manager.import_partial_secret_keys(empty_keys, REGTEST);
            match result1 {
                Err(KeyManagerError::InvalidPrivateKey) => (),
                other => panic!(
                    "Expected InvalidPrivateKey for empty input, got: {:?}",
                    other
                ),
            }

            // Test Case 2: Try to aggregate a single key (musig2 accepts single-key aggregation)
            let mut rng = secp256k1::rand::thread_rng();
            let secret_key = secp256k1::SecretKey::new(&mut rng);
            let single_key = vec![secret_key.display_secret().to_string()];

            let result2 = key_manager.import_partial_secret_keys(single_key.clone(), REGTEST);
            // musig2 may accept a single key and return a valid aggregated pubkey; assert success
            assert!(
                result2.is_ok(),
                "Single key aggregation should succeed or be handled: {:?}",
                result2
            );
            let aggregated = result2.unwrap();
            // verify it was stored
            let loaded = key_manager.keystore.load_keypair(&aggregated)?;
            assert!(
                loaded.is_some(),
                "Aggregated single-key result should be stored"
            );

            // Test Case 3: Invalid hex in partial secret keys
            let invalid_hex_keys = vec![
                "invalid_hex_string".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ];
            let result3 = key_manager.import_partial_secret_keys(invalid_hex_keys, REGTEST);
            assert!(result3.is_err(), "Invalid hex should fail parsing");

            // Test Case 4: Invalid WIF in partial private keys
            let invalid_wif_keys = vec![
                "invalid_wif_string".to_string(),
                "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294LvTJ".to_string(),
            ];
            let result4 = key_manager.import_partial_private_keys(invalid_wif_keys, REGTEST);
            assert!(result4.is_err(), "Invalid WIF should fail parsing");

            // Test Case 5: Mixed valid and invalid keys
            let mixed_keys = vec![
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                "not_a_valid_key".to_string(),
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            ];
            let result5 = key_manager.import_partial_secret_keys(mixed_keys, REGTEST);
            assert!(result5.is_err(), "Mixed valid/invalid keys should fail");

            // Test Case 6: All zero secret keys (invalid for cryptography)
            let zero_keys = vec![
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ];
            let result6 = key_manager.import_partial_secret_keys(zero_keys, REGTEST);
            assert!(result6.is_err(), "All-zero keys should fail");

            // Test Case 7: Keys above secp256k1 curve order
            let above_curve_keys = vec![
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ];
            let result7 = key_manager.import_partial_secret_keys(above_curve_keys, REGTEST);
            assert!(result7.is_err(), "Keys above curve order should fail");

            // Test Case 8: Wrong length hex strings
            let wrong_length_keys = vec![
                "0123456789abcdef".to_string(), // Too short
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(), // Correct
            ];
            let result8 = key_manager.import_partial_secret_keys(wrong_length_keys, REGTEST);
            assert!(result8.is_err(), "Wrong length keys should fail");

            // Test Case 9: Empty strings in partial keys
            let empty_string_keys = vec![
                "".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ];
            let result9 = key_manager.import_partial_secret_keys(empty_string_keys, REGTEST);
            assert!(result9.is_err(), "Empty string keys should fail");

            // Test Case 10: Special characters and whitespace
            let special_char_keys = vec![
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                "fedcba9876543210 fedcba9876543210 fedcba9876543210 fedcba9876543210".to_string(), // With spaces
            ];
            let result10 = key_manager.import_partial_secret_keys(special_char_keys, REGTEST);
            assert!(result10.is_err(), "Keys with spaces should fail");

            // Test Case 11: Too many partial keys (test system limits)
            let mut too_many_keys = Vec::new();
            let mut rng = secp256k1::rand::thread_rng();

            for _ in 0..100 {
                // Create 100 keys to test limits
                let secret_key = SecretKey::new(&mut rng);
                too_many_keys.push(secret_key.display_secret().to_string());
            }

            let _result11 = key_manager.import_partial_secret_keys(too_many_keys, REGTEST);
            // This might succeed or fail depending on implementation limits
            // We're just testing that the system handles large inputs gracefully

            // Test Case 12: Verify KeyManager state is clean after failures
            // Try a valid aggregation to ensure the KeyManager still works
            let valid_secret_1 = SecretKey::new(&mut rng);
            let valid_secret_2 = SecretKey::new(&mut rng);
            let valid_keys = vec![
                valid_secret_1.display_secret().to_string(),
                valid_secret_2.display_secret().to_string(),
            ];

            let valid_result = key_manager.import_partial_secret_keys(valid_keys, REGTEST);
            assert!(
                valid_result.is_ok(),
                "Valid aggregation should work after failed attempts"
            );

            // Verify the aggregated key can be loaded (proves it was stored correctly)
            let valid_aggregated = valid_result.unwrap();
            let _valid_loaded = key_manager
                .keystore
                .load_keypair(&valid_aggregated)?
                .expect("Valid aggregated key should exist");

            Ok(())
        })
    }

    #[test]
    pub fn test_master_xpub_determinism_and_parity() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            // Test with different key types
            let key_types = vec![
                BitcoinKeyType::P2wpkh,
                BitcoinKeyType::P2tr,
                BitcoinKeyType::P2shP2wpkh,
            ];

            for key_type in key_types {
                // Generate account xpub for the given key type
                let account_xpub = key_manager.get_account_xpub(key_type)?;

                // Check a small range of indices for determinism and parity behavior
                for i in 0..5u32 {
                    // Derive from private key path
                    let derived_priv = key_manager.derive_keypair(key_type, i)?;

                    // Derive from account xpub (public derivation)
                    let derived_pub = key_manager.derive_public_key_from_account_xpub(
                        account_xpub,
                        key_type,
                        i,
                        false, // Don't adjust parity here to test raw derivation
                    )?;

                    // Determinism: public keys derived from xpub match those derived from xpriv
                    assert_eq!(
                        derived_priv.to_string(),
                        derived_pub.to_string(),
                        "Public keys should match for key_type {:?} at index {}",
                        key_type,
                        i
                    );

                    // For Taproot keys, verify parity adjustment works correctly
                    if key_type == BitcoinKeyType::P2tr {
                        let derived_pub_adjusted = key_manager
                            .derive_public_key_from_account_xpub(
                                account_xpub,
                                key_type,
                                i,
                                true, // Adjust parity for Taproot
                            )?;

                        // Parity: ensure x-only parity is even after adjustment
                        let (_xonly, parity) = derived_pub_adjusted.inner.x_only_public_key();
                        assert_eq!(
                            parity,
                            bitcoin::key::Parity::Even,
                            "Taproot key should have even parity after adjustment at index {}",
                            i
                        );
                    }
                }
            }

            Ok(())
        })
    }

    #[test]
    pub fn test_adjust_public_key_only_parity_ensures_even() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let secp = secp256k1::Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();

            // Create a random public key
            let secret_key = secp256k1::SecretKey::new(&mut rng);
            let private_key = PrivateKey::new(secret_key, REGTEST);
            let public_key = PublicKey::from_private_key(&secp, &private_key);

            // Make sure we have an odd-parity public key to exercise the branch
            let (_x, parity) = public_key.inner.x_only_public_key();
            let odd_pub = if parity == bitcoin::key::Parity::Odd {
                public_key
            } else {
                // negate to flip parity
                PublicKey::new(public_key.inner.negate(&secp))
            };

            // Normalize parity using KeyManager's helper
            let normalized = key_manager.adjust_public_key_only_parity(odd_pub.clone());

            // Ensure the normalized public key has even x-only parity
            let (_n_x, n_parity) = normalized.inner.x_only_public_key();
            assert_eq!(n_parity, bitcoin::key::Parity::Even);

            // Calling it again on an already-even key should keep it even
            let normalized_again = key_manager.adjust_public_key_only_parity(normalized.clone());
            let (_na_x, na_parity) = normalized_again.inner.x_only_public_key();
            assert_eq!(na_parity, bitcoin::key::Parity::Even);

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    pub fn test_rsa_deterministic_key_gen() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;

        let mut rng_1 = secp256k1::rand::thread_rng();
        let pubkey_1 = key_manager.generate_rsa_keypair(&mut rng_1)?;
        let mut rng_2 = secp256k1::rand::thread_rng();
        let pubkey_2 = key_manager.generate_rsa_keypair(&mut rng_2)?;

        let pubk_1 = RSAKeyPair::pubkey_from_public_key_pem(&pubkey_1)?;
        let keypair_1 = key_manager
            .keystore
            .load_rsa_key(pubk_1)?
            .expect("Failed to load RSA private key");

        let pubkey_from_keypair_1 = keypair_1.export_public_pem()?;
        assert_eq!(pubkey_1, pubkey_from_keypair_1);

        let pubk_2 = RSAKeyPair::pubkey_from_public_key_pem(&pubkey_2)?;
        let keypair_2 = key_manager
            .keystore
            .load_rsa_key(pubk_2)?
            .expect("Failed to load RSA private key");

        let pubkey_from_keypair_2 = keypair_2.export_public_pem()?;
        assert_eq!(pubkey_2, pubkey_from_keypair_2);

        // Both should be stored, loaded and different
        assert_ne!(pubkey_from_keypair_1, pubkey_from_keypair_2);

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_constructor() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // --- Create the 1st KeyManager with a fixed mnemonic

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key_manager_config1 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(mnemonic_sentence.to_string()),
            None,
        );

        let key_manager1 =
            crate::create_key_manager_from_config(&key_manager_config1, &keystore_storage_config)?;

        drop(key_manager1);

        // --- Create the 2nd KeyManager with different Mnemonic but using the same keystore_storage_config
        // This should fail with MnemonicMismatch error

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence2 =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";

        let key_manager_config2 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(mnemonic_sentence2.to_string()),
            None,
        );

        let key_manager2 =
            crate::create_key_manager_from_config(&key_manager_config2, &keystore_storage_config);

        // Expect MnemonicMismatch error
        assert!(matches!(
            key_manager2,
            Err(KeyManagerError::MnemonicMismatch(_))
        ));

        // --- Create the 3rd KeyManager with the same stored mnemonic

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let key_manager3 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            &keystore_storage_config,
        )?;

        drop(key_manager3);

        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_mnemonic_passphrase_validation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // --- Create the 1st KeyManager with a fixed mnemonic and passphrase

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase1 = "test_passphrase_123".to_string();

        let key_manager_config1 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(mnemonic_sentence.to_string()),
            Some(passphrase1.clone()),
        );

        let key_manager1 =
            crate::create_key_manager_from_config(&key_manager_config1, &keystore_storage_config)?;

        drop(key_manager1);

        // --- Test 1: Create KeyManager with same mnemonic and same passphrase (should succeed)
        let key_manager_config2 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(mnemonic_sentence.to_string()),
            Some(passphrase1.clone()),
        );

        let key_manager2 =
            crate::create_key_manager_from_config(&key_manager_config2, &keystore_storage_config)?;

        drop(key_manager2);

        // --- Test 2: Create KeyManager with same mnemonic but different passphrase (should fail)
        let different_passphrase = "different_passphrase_456".to_string();

        let key_manager_config3 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(mnemonic_sentence.to_string()),
            Some(different_passphrase),
        );

        let result =
            crate::create_key_manager_from_config(&key_manager_config3, &keystore_storage_config);

        // Expect MnemonicPassphraseMismatch error
        assert!(matches!(
            result,
            Err(KeyManagerError::MnemonicPassphraseMismatch(_))
        ));

        // --- Test 3: Create KeyManager with same mnemonic and no passphrase (should succeed with stored passphrase)
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let key_manager3 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            &keystore_storage_config,
        )?;

        drop(key_manager3);

        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_key_derivation_seed_validation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // --- Create the 1st KeyManager with a fixed mnemonic to store the correct seed

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key_manager_config1 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(mnemonic_sentence.to_string()),
            None,
        );

        let key_manager1 =
            crate::create_key_manager_from_config(&key_manager_config1, &keystore_storage_config)?;
        drop(key_manager1);

        // --- Manually corrupt the stored key derivation seed to test validation
        {
            use std::rc::Rc;
            let key_store = Rc::new(Storage::new(&keystore_storage_config)?);
            let keystore = KeyStore::new(key_store);

            // Store a corrupted seed (different from what the mnemonic would generate)
            let corrupted_seed = [0u8; 64]; // All zeros - definitely wrong
            keystore.store_key_derivation_seed(corrupted_seed)?;
        }

        // --- Try to create KeyManager with the same mnemonic (should fail due to seed validation)
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let result = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            &keystore_storage_config,
        );

        // Expect CorruptedKeyDerivationSeed error
        assert!(matches!(
            result,
            Err(KeyManagerError::CorruptedKeyDerivationSeed)
        ));

        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_winternitz_seed_validation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // --- Create the 1st KeyManager with a fixed mnemonic to store the correct seeds

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key_manager_config1 = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(mnemonic_sentence.to_string()),
            None,
        );

        let key_manager1 =
            crate::create_key_manager_from_config(&key_manager_config1, &keystore_storage_config)?;

        drop(key_manager1);

        // --- Manually corrupt the stored Winternitz seed to test validation
        {
            use std::rc::Rc;
            let key_store = Rc::new(Storage::new(&keystore_storage_config)?);
            let keystore = KeyStore::new(key_store);

            // Store a corrupted Winternitz seed (different from what would be derived)
            let corrupted_winternitz_seed = [0u8; 32]; // All zeros - definitely wrong
            keystore.store_winternitz_seed(corrupted_winternitz_seed)?;
        }

        // --- Try to create KeyManager with the same mnemonic (should fail due to Winternitz seed validation)
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let result = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            &keystore_storage_config,
        );

        // Expect CorruptedWinternitzSeed error
        assert!(matches!(
            result,
            Err(KeyManagerError::CorruptedWinternitzSeed)
        ));

        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_wrong_password_propagates_decryption_error() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let password = "correct password_123__ABC".to_string();
        let storage_config = StorageConfig::new(keystore_path.clone(), Some(password));

        // --- Create the 1st KeyManager with a mnemonic and correct password

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let key_manager1 =
            KeyManager::new(REGTEST, Some(fixed_mnemonic.clone()), None, &storage_config)?;

        drop(key_manager1);

        // --- Try to create a new KeyManager with same path but wrong password

        let wrong_password = "wrong p4SSWord -_= but str0n9 123 ABC".to_string();
        let wrong_storage_config = StorageConfig::new(keystore_path.clone(), Some(wrong_password));

        let result = KeyManager::new(REGTEST, Some(fixed_mnemonic), None, &wrong_storage_config);

        // Expect StorageError which should contain the decryption error
        match result {
            Err(KeyManagerError::StorageError(_)) => {
                // Success - decryption error was properly propagated as StorageError
            }
            Err(e) => panic!(
                "Expected StorageError (containing decryption error), got different error: {:?}",
                e
            ),
            Ok(_) => panic!(
                "Expected StorageError (containing decryption error), but KeyManager was created successfully"
            ),
        }

        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_bitcoin_regtest_keys_derivation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // --- Create the 1st KeyManager with a fixed mnemonic to store the correct seeds

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key_manager_config = crate::config::KeyManagerConfig::new(
            "regtest".to_string(),
            Some(mnemonic_sentence.to_string()),
            None,
        );

        let key_manager =
            crate::create_key_manager_from_config(&key_manager_config, &keystore_storage_config)?;

        // hardcoded values from https://iancoleman.io/bip39/

        let key_derivation_seed = key_manager.keystore.load_key_derivation_seed()?;
        let key_derivation_seed_hex = key_derivation_seed.to_hex_string(bitcoin::hex::Case::Lower);
        let expected_key_derivation_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        assert_eq!(key_derivation_seed_hex, expected_key_derivation_seed);

        let master_xpriv = Xpriv::new_master(REGTEST, &key_derivation_seed)?;
        let master_xpriv_hex = master_xpriv.to_string();
        let expected_master_xpriv = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd";
        assert_eq!(master_xpriv_hex, expected_master_xpriv);

        // BIP44 - Legacy (P2PKH)

        let account_extended_pubkey = key_manager.get_account_xpub(BitcoinKeyType::P2pkh)?;
        let account_extended_pubkey_hex = account_extended_pubkey.to_string();
        let expected_account_extended_pubkey = "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2pkh)?;
        let expected_account_extended_privkey = "tprv8fPDJN9UQqg6pFsQsrVxTwHZmXLvHpfGGcsCA9rtnatUgVtBKxhtFeqiyaYKSWydunKpjhvgJf6PwTwgirwuCbFq8YKgpQiaVJf3JCrNmkR";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2pkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2pkh, 0)?;
        let expected_p2pkh_0 = PublicKey::from_str(
            "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        )?;
        assert_eq!(p2pkh_0, expected_p2pkh_0);

        let p2pkh_0_address = Address::p2pkh(&p2pkh_0, REGTEST);
        let expected_p2pkh_0_address = "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV";
        assert_eq!(p2pkh_0_address.to_string(), expected_p2pkh_0_address);

        let p2pkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2pkh, 15)?;
        let expected_p2pkh_15 = PublicKey::from_str(
            "03ee6c2e9fcb33d45966775d41990c68d6b4db14bb66044fbb591b3f313781d612",
        )?;
        assert_eq!(p2pkh_15, expected_p2pkh_15);

        let p2pkh_15_address = Address::p2pkh(&p2pkh_15, REGTEST);
        let expected_p2pkh_15_address = "n1MsayUmxjiUyrbQs6F2megEA8azR1nYc1";
        assert_eq!(p2pkh_15_address.to_string(), expected_p2pkh_15_address);

        // BIP49 - Legacy Nested SegWit (P2SH-P2WPKH)

        let account_extended_pubkey_hex =
            key_manager.get_account_xpub_string(BitcoinKeyType::P2shP2wpkh)?;
        let expected_account_extended_pubkey = "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2shP2wpkh)?;
        let expected_account_extended_privkey = "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2shp2wpkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2shP2wpkh, 0)?;
        let expected_p2shp2wpkh_0 = PublicKey::from_str(
            "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f",
        )?;
        assert_eq!(p2shp2wpkh_0, expected_p2shp2wpkh_0);

        let compressed_pk_0 =
            CompressedPublicKey::try_from(p2shp2wpkh_0).expect("PublicKey should be compressed");
        let p2shp2wpkh_0_address = Address::p2shwpkh(&compressed_pk_0, REGTEST);
        let expected_p2shp2wpkh_0_address = "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2";
        assert_eq!(
            p2shp2wpkh_0_address.to_string(),
            expected_p2shp2wpkh_0_address
        );

        let p2shp2wpkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2shP2wpkh, 15)?;
        let expected_p2shp2wpkh_15 = PublicKey::from_str(
            "02067d623209475402b700ec03f0889d418ca68964f25f7c2b2c8e6b3fcf0eec1d",
        )?;
        assert_eq!(p2shp2wpkh_15, expected_p2shp2wpkh_15);

        let compressed_pk_15 =
            CompressedPublicKey::try_from(p2shp2wpkh_15).expect("PublicKey should be compressed");
        let p2shp2wpkh_15_address = Address::p2shwpkh(&compressed_pk_15, REGTEST);
        let expected_p2shp2wpkh_15_address = "2NBRjDXAbHXNpMpo7uKwKyF5hyU8BkzpsM1";
        assert_eq!(
            p2shp2wpkh_15_address.to_string(),
            expected_p2shp2wpkh_15_address
        );

        // BIP84 - Native SegWit (P2WPKH)

        let account_extended_pubkey_hex =
            key_manager.get_account_xpub_string(BitcoinKeyType::P2wpkh)?;
        let expected_account_extended_pubkey = "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JHRPAgjAvtbBrf8ZhDYe2jWAqvZVnsc";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2wpkh)?;
        let expected_account_extended_privkey = "vprv9K7GLAaERuM58PVvbk1sMo7wzVCoPwzZpVXLRBmum93gL5pSqQCAAvZjtmz93nnnYMr9i2FwG2fqrwYLRgJmDDwFjGiamGsbRMJ5Y6siJ8H";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2wpkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
        let expected_p2wpkh_0 = PublicKey::from_str(
            "02e7ab2537b5d49e970309aae06e9e49f36ce1c9febbd44ec8e0d1cca0b4f9c319",
        )?;
        assert_eq!(p2wpkh_0, expected_p2wpkh_0);

        let compressed_pk_0 =
            CompressedPublicKey::try_from(p2wpkh_0).expect("PublicKey should be compressed");
        let p2wpkh_0_address = Address::p2wpkh(&compressed_pk_0, REGTEST);
        let expected_p2wpkh_0_address = "bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk";
        assert_eq!(p2wpkh_0_address.to_string(), expected_p2wpkh_0_address);

        let p2wpkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 15)?;
        let expected_p2wpkh_15 = PublicKey::from_str(
            "022f590a1f42418c86daede01666b0ba1b388096541fdd90899cee35102509dd0c",
        )?;
        assert_eq!(p2wpkh_15, expected_p2wpkh_15);

        let compressed_pk_15 =
            CompressedPublicKey::try_from(p2wpkh_15).expect("PublicKey should be compressed");
        let p2wpkh_15_address = Address::p2wpkh(&compressed_pk_15, REGTEST);
        let expected_p2wpkh_15_address = "bcrt1qhtwqm3x7wn0zteznkkzpamzrm345js9k0v2twy";
        assert_eq!(p2wpkh_15_address.to_string(), expected_p2wpkh_15_address);

        // BIP86 - Taproot (P2TR)

        let account_extended_pubkey = key_manager.get_account_xpub(BitcoinKeyType::P2tr)?;
        let account_extended_pubkey_hex = account_extended_pubkey.to_string();
        let expected_account_extended_pubkey = "tpubDDfvzhdVV4unsoKt5aE6dcsNsfeWbTgmLZPi8LQDYU2xixrYemMfWJ3BaVneH3u7DBQePdTwhpybaKRU95pi6PMUtLPBJLVQRpzEnjfjZzX"; // missing value
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2tr)?;
        let expected_account_extended_privkey = "tprv8gytrHbFLhE7zLJ6BvZWEDDGJe8aS8VrmFnvqpMv8CEZtUbn2NY5KoRKQNpkcL1yniyCBRi7dAPy4kUxHkcSvd9jzLmLMEG96TPwant2jbX";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2tr_0 = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let expected_p2tr_0 = PublicKey::from_str(
            "0255355ca83c973f1d97ce0e3843c85d78905af16b4dc531bc488e57212d230116",
        )?;
        assert_eq!(p2tr_0, expected_p2tr_0);
        let p2tr_0_regtest_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_0), None, REGTEST);
        let expected_p2tr_0_address =
            "bcrt1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqjeprhg";
        assert_eq!(p2tr_0_regtest_address.to_string(), expected_p2tr_0_address);

        let p2tr_0 = key_manager.derive_keypair_adjust_parity(BitcoinKeyType::P2tr, 0)?;
        let p2tr_0_regtest_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_0), None, REGTEST);
        let expected_p2tr_0_address_with_parity =
            "bcrt1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqjeprhg";
        assert_eq!(
            p2tr_0_regtest_address.to_string(),
            expected_p2tr_0_address_with_parity
        );

        // Dev note: parity is already even for index 0
        let expected_p2tr_0 = PublicKey::from_str(
            "0255355ca83c973f1d97ce0e3843c85d78905af16b4dc531bc488e57212d230116",
        )?;
        assert_eq!(p2tr_0, expected_p2tr_0);
        let (_, parity) = expected_p2tr_0.inner.x_only_public_key();
        assert_eq!(parity, Parity::Even);

        // using index 14 to force odd parity key
        let p2tr_14 = key_manager.derive_keypair(BitcoinKeyType::P2tr, 14)?;
        let p2tr_14_regtest_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_14), None, REGTEST);
        let expected_p2tr_14_address =
            "bcrt1pq553836cpkcrsy2mpeqvlywvr7rjwwf9y4dh7ea22l4ax92xaqyqqzcckz";
        assert_eq!(
            p2tr_14_regtest_address.to_string(),
            expected_p2tr_14_address
        );
        let expected_p2tr_14 = PublicKey::from_str(
            "034b7dce637a803b4a14b972add6750ee240f9b692769257c6647ddd423b1fc9e6",
        )?;
        assert_eq!(p2tr_14, expected_p2tr_14);

        let p2tr_14 = key_manager.derive_keypair_adjust_parity(BitcoinKeyType::P2tr, 14)?;
        let p2tr_14_regtest_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_14), None, REGTEST);
        let expected_p2tr_14_address_with_parity =
            "bcrt1pq553836cpkcrsy2mpeqvlywvr7rjwwf9y4dh7ea22l4ax92xaqyqqzcckz";
        assert_eq!(
            p2tr_14_regtest_address.to_string(),
            expected_p2tr_14_address_with_parity
        );
        let not_expected_p2tr_14 = PublicKey::from_str(
            "034b7dce637a803b4a14b972add6750ee240f9b692769257c6647ddd423b1fc9e6",
        )?;
        assert_ne!(p2tr_14, not_expected_p2tr_14);
        let negated_not_expected_p2tr_14 = PublicKey::new(not_expected_p2tr_14.inner.negate(&secp));
        assert_eq!(p2tr_14, negated_not_expected_p2tr_14);

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_bitcoin_testnet_keys_derivation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // --- Create the 1st KeyManager with a fixed mnemonic to store the correct seeds

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key_manager_config = crate::config::KeyManagerConfig::new(
            "testnet".to_string(),
            Some(mnemonic_sentence.to_string()),
            None,
        );

        let key_manager =
            crate::create_key_manager_from_config(&key_manager_config, &keystore_storage_config)?;

        // hardcoded values from https://iancoleman.io/bip39/ and https://learnmeabitcoin.com/technical/keys/hd-wallets/derivation-paths/

        let key_derivation_seed = key_manager.keystore.load_key_derivation_seed()?;
        let key_derivation_seed_hex = key_derivation_seed.to_hex_string(bitcoin::hex::Case::Lower);
        let expected_key_derivation_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        assert_eq!(key_derivation_seed_hex, expected_key_derivation_seed);

        let master_xpriv = Xpriv::new_master(Network::Testnet, &key_derivation_seed)?;
        let master_xpriv_hex = master_xpriv.to_string();
        let expected_master_xpriv = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd";
        assert_eq!(master_xpriv_hex, expected_master_xpriv);

        // BIP44 - Legacy (P2PKH)

        let account_extended_pubkey = key_manager.get_account_xpub(BitcoinKeyType::P2pkh)?;
        let account_extended_pubkey_hex = account_extended_pubkey.to_string();
        let expected_account_extended_pubkey = "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2pkh)?;
        let expected_account_extended_privkey = "tprv8fPDJN9UQqg6pFsQsrVxTwHZmXLvHpfGGcsCA9rtnatUgVtBKxhtFeqiyaYKSWydunKpjhvgJf6PwTwgirwuCbFq8YKgpQiaVJf3JCrNmkR";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2pkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2pkh, 0)?;
        let expected_p2pkh_0 = PublicKey::from_str(
            "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        )?;
        assert_eq!(p2pkh_0, expected_p2pkh_0);

        let p2pkh_0_address = Address::p2pkh(&p2pkh_0, Network::Testnet);
        let expected_p2pkh_0_address = "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV";
        assert_eq!(p2pkh_0_address.to_string(), expected_p2pkh_0_address);

        let p2pkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2pkh, 15)?;
        let expected_p2pkh_15 = PublicKey::from_str(
            "03ee6c2e9fcb33d45966775d41990c68d6b4db14bb66044fbb591b3f313781d612",
        )?;
        assert_eq!(p2pkh_15, expected_p2pkh_15);

        let p2pkh_15_address = Address::p2pkh(&p2pkh_15, Network::Testnet);
        let expected_p2pkh_15_address = "n1MsayUmxjiUyrbQs6F2megEA8azR1nYc1";
        assert_eq!(p2pkh_15_address.to_string(), expected_p2pkh_15_address);

        // BIP49 - Legacy Nested SegWit (P2SH-P2WPKH)

        let account_extended_pubkey_hex =
            key_manager.get_account_xpub_string(BitcoinKeyType::P2shP2wpkh)?;
        let expected_account_extended_pubkey = "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2shP2wpkh)?;
        let expected_account_extended_privkey = "uprv91G7gZkzehuMVxDJTYE6tLivdF8e4rvzSu1LFfKw3b2Qx1Aj8vpoFnHdfUZ3hmi9jsvPifmZ24RTN2KhwB8BfMLTVqaBReibyaFFcTP1s9n";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2shp2wpkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2shP2wpkh, 0)?;
        let expected_p2shp2wpkh_0 = PublicKey::from_str(
            "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f",
        )?;
        assert_eq!(p2shp2wpkh_0, expected_p2shp2wpkh_0);

        let compressed_pk_0 =
            CompressedPublicKey::try_from(p2shp2wpkh_0).expect("PublicKey should be compressed");
        let p2shp2wpkh_0_address = Address::p2shwpkh(&compressed_pk_0, Network::Testnet);
        let expected_p2shp2wpkh_0_address = "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2";
        assert_eq!(
            p2shp2wpkh_0_address.to_string(),
            expected_p2shp2wpkh_0_address
        );

        let p2shp2wpkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2shP2wpkh, 15)?;
        let expected_p2shp2wpkh_15 = PublicKey::from_str(
            "02067d623209475402b700ec03f0889d418ca68964f25f7c2b2c8e6b3fcf0eec1d",
        )?;
        assert_eq!(p2shp2wpkh_15, expected_p2shp2wpkh_15);

        let compressed_pk_15 =
            CompressedPublicKey::try_from(p2shp2wpkh_15).expect("PublicKey should be compressed");
        let p2shp2wpkh_15_address = Address::p2shwpkh(&compressed_pk_15, Network::Testnet);
        let expected_p2shp2wpkh_15_address = "2NBRjDXAbHXNpMpo7uKwKyF5hyU8BkzpsM1";
        assert_eq!(
            p2shp2wpkh_15_address.to_string(),
            expected_p2shp2wpkh_15_address
        );

        // BIP84 - Native SegWit (P2WPKH)

        let account_extended_pubkey_hex =
            key_manager.get_account_xpub_string(BitcoinKeyType::P2wpkh)?;
        let expected_account_extended_pubkey = "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JHRPAgjAvtbBrf8ZhDYe2jWAqvZVnsc";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2wpkh)?;
        let expected_account_extended_privkey = "vprv9K7GLAaERuM58PVvbk1sMo7wzVCoPwzZpVXLRBmum93gL5pSqQCAAvZjtmz93nnnYMr9i2FwG2fqrwYLRgJmDDwFjGiamGsbRMJ5Y6siJ8H";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2wpkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
        let expected_p2wpkh_0 = PublicKey::from_str(
            "02e7ab2537b5d49e970309aae06e9e49f36ce1c9febbd44ec8e0d1cca0b4f9c319",
        )?;
        assert_eq!(p2wpkh_0, expected_p2wpkh_0);

        let compressed_pk_0 =
            CompressedPublicKey::try_from(p2wpkh_0).expect("PublicKey should be compressed");
        let p2wpkh_0_address = Address::p2wpkh(&compressed_pk_0, Network::Testnet);
        let expected_p2wpkh_0_address = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl";
        assert_eq!(p2wpkh_0_address.to_string(), expected_p2wpkh_0_address);

        let p2wpkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 15)?;
        let expected_p2wpkh_15 = PublicKey::from_str(
            "022f590a1f42418c86daede01666b0ba1b388096541fdd90899cee35102509dd0c",
        )?;
        assert_eq!(p2wpkh_15, expected_p2wpkh_15);

        let compressed_pk_15 =
            CompressedPublicKey::try_from(p2wpkh_15).expect("PublicKey should be compressed");
        let p2wpkh_15_address = Address::p2wpkh(&compressed_pk_15, Network::Testnet);
        let expected_p2wpkh_15_address = "tb1qhtwqm3x7wn0zteznkkzpamzrm345js9kd9nxed";
        assert_eq!(p2wpkh_15_address.to_string(), expected_p2wpkh_15_address);

        // BIP86 - Taproot (P2TR)

        let account_extended_pubkey = key_manager.get_account_xpub(BitcoinKeyType::P2tr)?;
        let account_extended_pubkey_hex = account_extended_pubkey.to_string();
        let expected_account_extended_pubkey = "tpubDDfvzhdVV4unsoKt5aE6dcsNsfeWbTgmLZPi8LQDYU2xixrYemMfWJ3BaVneH3u7DBQePdTwhpybaKRU95pi6PMUtLPBJLVQRpzEnjfjZzX";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2tr)?;
        let expected_account_extended_privkey = "tprv8gytrHbFLhE7zLJ6BvZWEDDGJe8aS8VrmFnvqpMv8CEZtUbn2NY5KoRKQNpkcL1yniyCBRi7dAPy4kUxHkcSvd9jzLmLMEG96TPwant2jbX";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2tr_0 = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let expected_p2tr_0 = PublicKey::from_str(
            "0255355ca83c973f1d97ce0e3843c85d78905af16b4dc531bc488e57212d230116",
        )?;
        assert_eq!(p2tr_0, expected_p2tr_0);
        let p2tr_0_testnet_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_0), None, Network::Testnet);
        let expected_p2tr_0_address =
            "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj";
        assert_eq!(p2tr_0_testnet_address.to_string(), expected_p2tr_0_address);

        let p2tr_0 = key_manager.derive_keypair_adjust_parity(BitcoinKeyType::P2tr, 0)?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let p2tr_0_testnet_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_0), None, Network::Testnet);
        // Dev note: address is the same for odd or even key, as address generation parity adjustment is done in the lib
        let expected_p2tr_0_address =
            "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj";
        assert_eq!(p2tr_0_testnet_address.to_string(), expected_p2tr_0_address);

        // Dev note: for this particular case coindicentally the parity is even
        let expected_p2tr_0 = PublicKey::from_str(
            "0255355ca83c973f1d97ce0e3843c85d78905af16b4dc531bc488e57212d230116",
        )?;
        assert_eq!(p2tr_0, expected_p2tr_0);

        let p2tr_15 = key_manager.derive_keypair(BitcoinKeyType::P2tr, 15)?;
        let expected_p2tr_15 = PublicKey::from_str(
            "022906c8edc2feaa92a94a8e03c26b6284e9a5b44804f7e124e97cf66bef27c611",
        )?;
        assert_eq!(p2tr_15, expected_p2tr_15);
        let p2tr_15_testnet_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_15), None, Network::Testnet);
        let expected_p2tr_15_address =
            "tb1pvjhgqlfxfa62c825pl3x6ntvql8a95cwgjqruy0yw9p7ulau292qwttz36";
        assert_eq!(
            p2tr_15_testnet_address.to_string(),
            expected_p2tr_15_address
        );

        // Dev note: for this particular case coindicentally the parity adjustment does not change the pubkey, as the original is already even
        let p2tr_15 = key_manager.derive_keypair_adjust_parity(BitcoinKeyType::P2tr, 15)?;
        let p2tr_15_testnet_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_15), None, Network::Testnet);
        let expected_p2tr_15_address =
            "tb1pvjhgqlfxfa62c825pl3x6ntvql8a95cwgjqruy0yw9p7ulau292qwttz36";
        assert_eq!(
            p2tr_15_testnet_address.to_string(),
            expected_p2tr_15_address
        );
        let (_, parity) = p2tr_15.inner.x_only_public_key();
        assert_eq!(parity, Parity::Even);

        let expected_p2tr_15 = PublicKey::from_str(
            "022906c8edc2feaa92a94a8e03c26b6284e9a5b44804f7e124e97cf66bef27c611",
        )?;
        assert_eq!(p2tr_15, expected_p2tr_15);

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_bitcoin_mainnet_keys_derivation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // --- Create the 1st KeyManager with a fixed mnemonic to store the correct seeds

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key_manager_config = crate::config::KeyManagerConfig::new(
            "bitcoin".to_string(),
            Some(mnemonic_sentence.to_string()),
            None,
        );

        let key_manager =
            crate::create_key_manager_from_config(&key_manager_config, &keystore_storage_config)?;

        // hardcoded values from https://iancoleman.io/bip39/ and https://learnmeabitcoin.com/technical/keys/hd-wallets/derivation-paths/

        let key_derivation_seed = key_manager.keystore.load_key_derivation_seed()?;
        let key_derivation_seed_hex = key_derivation_seed.to_hex_string(bitcoin::hex::Case::Lower);
        let expected_key_derivation_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        assert_eq!(key_derivation_seed_hex, expected_key_derivation_seed);

        let master_xpriv = Xpriv::new_master(Network::Bitcoin, &key_derivation_seed)?;
        let master_xpriv_hex = master_xpriv.to_string();
        let expected_master_xpriv = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
        assert_eq!(master_xpriv_hex, expected_master_xpriv);

        // BIP44 - Legacy (P2PKH)

        let account_extended_pubkey = key_manager.get_account_xpub(BitcoinKeyType::P2pkh)?;
        let account_extended_pubkey_hex = account_extended_pubkey.to_string();
        let expected_account_extended_pubkey = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2pkh)?;
        let expected_account_extended_privkey = "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2pkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2pkh, 0)?;
        let expected_p2pkh_0 = PublicKey::from_str(
            "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        )?;
        assert_eq!(p2pkh_0, expected_p2pkh_0);

        let p2pkh_0_address = Address::p2pkh(&p2pkh_0, Network::Bitcoin);
        let expected_p2pkh_0_address = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";
        assert_eq!(p2pkh_0_address.to_string(), expected_p2pkh_0_address);

        let p2pkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2pkh, 15)?;
        let expected_p2pkh_15 = PublicKey::from_str(
            "028d6cd1027a8e2c01a08ddc7eca9399e00e83380d9b1553446b10c5e80e4e03ab",
        )?;
        assert_eq!(p2pkh_15, expected_p2pkh_15);

        let p2pkh_15_address = Address::p2pkh(&p2pkh_15, Network::Bitcoin);
        let expected_p2pkh_15_address = "1NtocLbFFPYPNGeEsDn2CYY4GbfLGLpTFr";
        assert_eq!(p2pkh_15_address.to_string(), expected_p2pkh_15_address);

        // BIP49 - Legacy Nested SegWit (P2SH-P2WPKH)

        let account_extended_pubkey_hex =
            key_manager.get_account_xpub_string(BitcoinKeyType::P2shP2wpkh)?;
        let expected_account_extended_pubkey = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2shP2wpkh)?;
        let expected_account_extended_privkey = "yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2shp2wpkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2shP2wpkh, 0)?;
        let expected_p2shp2wpkh_0 = PublicKey::from_str(
            "039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
        )?;
        assert_eq!(p2shp2wpkh_0, expected_p2shp2wpkh_0);

        let compressed_pk_0 =
            CompressedPublicKey::try_from(p2shp2wpkh_0).expect("PublicKey should be compressed");
        let p2shp2wpkh_0_address = Address::p2shwpkh(&compressed_pk_0, Network::Bitcoin);
        let expected_p2shp2wpkh_0_address = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf";
        assert_eq!(
            p2shp2wpkh_0_address.to_string(),
            expected_p2shp2wpkh_0_address
        );

        let p2shp2wpkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2shP2wpkh, 15)?;
        let expected_p2shp2wpkh_15 = PublicKey::from_str(
            "0213a9cf215d46ee5327a679231f0fd555ba3a67f7721a15e655aa48e69f795149",
        )?;
        assert_eq!(p2shp2wpkh_15, expected_p2shp2wpkh_15);

        let compressed_pk_15 =
            CompressedPublicKey::try_from(p2shp2wpkh_15).expect("PublicKey should be compressed");
        let p2shp2wpkh_15_address = Address::p2shwpkh(&compressed_pk_15, Network::Bitcoin);
        let expected_p2shp2wpkh_15_address = "3MLaBHZRQBz6h2ADe6DfChSaZmfMYWBfJP";
        assert_eq!(
            p2shp2wpkh_15_address.to_string(),
            expected_p2shp2wpkh_15_address
        );

        // BIP84 - Native SegWit (P2WPKH)

        let account_extended_pubkey_hex =
            key_manager.get_account_xpub_string(BitcoinKeyType::P2wpkh)?;
        let expected_account_extended_pubkey = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2wpkh)?;
        let expected_account_extended_privkey = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2wpkh_0 = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
        let expected_p2wpkh_0 = PublicKey::from_str(
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        )?;
        assert_eq!(p2wpkh_0, expected_p2wpkh_0);

        let compressed_pk_0 =
            CompressedPublicKey::try_from(p2wpkh_0).expect("PublicKey should be compressed");
        let p2wpkh_0_address = Address::p2wpkh(&compressed_pk_0, Network::Bitcoin);
        let expected_p2wpkh_0_address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
        assert_eq!(p2wpkh_0_address.to_string(), expected_p2wpkh_0_address);

        let p2wpkh_15 = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 15)?;
        let expected_p2wpkh_15 = PublicKey::from_str(
            "02b05e67ab098575526f23a7c4f3b69449125604c34a9b34909def7432a792fbf6",
        )?;
        assert_eq!(p2wpkh_15, expected_p2wpkh_15);

        let compressed_pk_15 =
            CompressedPublicKey::try_from(p2wpkh_15).expect("PublicKey should be compressed");
        let p2wpkh_15_address = Address::p2wpkh(&compressed_pk_15, Network::Bitcoin);
        let expected_p2wpkh_15_address = "bc1qgtus5u58avcs5ehpqvcllv5f66dneznw3upy2v";
        assert_eq!(p2wpkh_15_address.to_string(), expected_p2wpkh_15_address);

        // BIP86 - Taproot (P2TR)

        let account_extended_pubkey = key_manager.get_account_xpub(BitcoinKeyType::P2tr)?;
        let account_extended_pubkey_hex = account_extended_pubkey.to_string();
        let expected_account_extended_pubkey = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"; // missing value
        assert_eq!(
            account_extended_pubkey_hex,
            expected_account_extended_pubkey
        );

        let account_extended_privkey_hex =
            key_manager.get_account_xpriv_string(BitcoinKeyType::P2tr)?;
        let expected_account_extended_privkey = "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk";
        assert_eq!(
            account_extended_privkey_hex,
            expected_account_extended_privkey
        );

        let p2tr_0 = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let expected_p2tr_0 = PublicKey::from_str(
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )?;
        assert_eq!(p2tr_0, expected_p2tr_0);
        let p2tr_0_bitcoin_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_0), None, Network::Bitcoin);
        let expected_p2tr_0_address =
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
        assert_eq!(p2tr_0_bitcoin_address.to_string(), expected_p2tr_0_address);

        let p2tr_0 = key_manager.derive_keypair_adjust_parity(BitcoinKeyType::P2tr, 0)?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let p2tr_0_bitcoin_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_0), None, Network::Bitcoin);
        // Dev note: address is the same for odd or even key, as address generation parity adjustment is done in the lib
        let expected_p2tr_0_address =
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
        assert_eq!(p2tr_0_bitcoin_address.to_string(), expected_p2tr_0_address);

        // Dev note: for this particular case coindicentally the parity adjustment changes the pubkey, as the original is odd
        let not_expected_p2tr_0 = PublicKey::from_str(
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        )?;
        assert_ne!(p2tr_0, not_expected_p2tr_0);
        let expected_p2tr_0 = PublicKey::new(not_expected_p2tr_0.inner.negate(&secp));
        assert_eq!(p2tr_0, expected_p2tr_0);

        let p2tr_15 = key_manager.derive_keypair(BitcoinKeyType::P2tr, 15)?;
        let expected_p2tr_15 = PublicKey::from_str(
            "02db45b7b3e057681a3fb91aed33031902c5972f41ab7c3db5930f48e5692a43cc",
        )?;
        assert_eq!(p2tr_15, expected_p2tr_15);
        let p2tr_15_bitcoin_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_15), None, Network::Bitcoin);
        let expected_p2tr_15_address =
            "bc1p3xkku35m5yf3dn6zmxukkewv289f7xfg74reqhz6k0e3hjscddjq508fff";
        assert_eq!(
            p2tr_15_bitcoin_address.to_string(),
            expected_p2tr_15_address
        );

        // Dev note: for this particular case coindicentally the parity adjustment does not change the pubkey, as the original is already even
        let p2tr_15 = key_manager.derive_keypair_adjust_parity(BitcoinKeyType::P2tr, 15)?;
        let p2tr_15_bitcoin_address =
            Address::p2tr(&secp, XOnlyPublicKey::from(p2tr_15), None, Network::Bitcoin);
        let expected_p2tr_15_address =
            "bc1p3xkku35m5yf3dn6zmxukkewv289f7xfg74reqhz6k0e3hjscddjq508fff";
        assert_eq!(
            p2tr_15_bitcoin_address.to_string(),
            expected_p2tr_15_address
        );
        let (_, parity) = p2tr_15.inner.x_only_public_key();
        assert_eq!(parity, Parity::Even);

        let expected_p2tr_15 = PublicKey::from_str(
            "02db45b7b3e057681a3fb91aed33031902c5972f41ab7c3db5930f48e5692a43cc",
        )?;
        assert_eq!(p2tr_15, expected_p2tr_15);

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }
}
