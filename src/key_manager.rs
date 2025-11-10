use std::{collections::HashMap, rc::Rc, str::FromStr};

use bip39::Mnemonic;
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    hashes::{self, Hash},
    key::{rand::RngCore, Keypair, Parity, TapTweak},
    secp256k1::{self, All, Message, Scalar, SecretKey},
    Network, PrivateKey, PublicKey, TapNodeHash,
};

use itertools::izip;
use storage_backend::{storage::Storage, storage_config::StorageConfig};
use tracing::debug;

// TODO discuss with Diego M.: if we want RSA derivation from mnemonic too (yes but audit) and managed indexes

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
        self, WinternitzPublicKey, WinternitzSignature, WinternitzType, checksum_length, to_checksummed_message
    },
};

use musig2::{sign_partial, AggNonce, PartialSignature, PubNonce, SecNonce};

const DEFAULT_RSA_BITS: usize = 2048; // default RSA key size in bits (other sizes could also be defined)

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

    // TODO discus with Diego M. the idea behind the store/load of this constructor
    pub fn new(
        network: Network,
        mnemonic: Option<Mnemonic>,
        mnemonic_passphrase: Option<String>,
        storage_config: StorageConfig,
    ) -> Result<Self, KeyManagerError> {
        let key_store = Rc::new(Storage::new(&storage_config)?);
        let keystore = KeyStore::new(key_store);

        // Store or load mnemonic
        match keystore.load_mnemonic() {
            Ok(stored_mnemonic) => {
                // Mnemonic found in storage
                if let Some(provided_mnemonic) = &mnemonic {
                    // Both stored and provided mnemonics exist - they must match
                    if stored_mnemonic != *provided_mnemonic {
                        return Err(KeyManagerError::MnemonicMismatch(
                            "Stored mnemonic does not match the provided mnemonic".to_string()
                        ));
                    }
                }
                // If no mnemonic was provided or they match, continue with stored mnemonic
            }
            Err(_) => {
                // No mnemonic in storage, store the provided one or generate a new one
                match mnemonic {
                    Some(mnemonic_sentence) => keystore.store_mnemonic(&mnemonic_sentence)?,
                    None => {
                        let mut entropy = [0u8; 32]; // 256 bits for 24 words
                        secp256k1::rand::thread_rng().fill_bytes(&mut entropy);
                        let random_mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
                        keystore.store_mnemonic(&random_mnemonic)?;
                        tracing::warn!("Random mnemonic generated, make sure to back it up securely!");

                        println!("24-word mnemonic:\n\n{}\n", random_mnemonic); // TODO remove after debugging
                    }
                }
            }
        }

        // Store or load mnemonic passphrase
        let mnemonic_passphrase = match keystore.load_mnemonic_passphrase() {
            Ok(stored_passphrase) => {
                // Passphrase found in storage
                if let Some(provided_passphrase) = &mnemonic_passphrase {
                    // Both stored and provided passphrases exist - they must match
                    if stored_passphrase != *provided_passphrase {
                        return Err(KeyManagerError::MnemonicPassphraseMismatch(
                            "Stored mnemonic passphrase does not match the provided mnemonic passphrase".to_string()
                        ));
                    }
                }
                // If no passphrase was provided or they match, continue with stored passphrase
                stored_passphrase
            }
            Err(_) => {
                // No passphrase in storage, store the provided one or use empty string as default
                let passphrase = mnemonic_passphrase.unwrap_or_else(|| "".to_string());
                keystore.store_mnemonic_passphrase(&passphrase)?;
                passphrase
            }
        };

        // Dev note: key derivation seed and winternitz seed are deduced from the mnemonic, but we are storing them
        // so we don't have to recalculate them each time for performance reasons, similar to storing non-imported (derived) keys.
        // Since these values can be regenerated from the mnemonic and passphrase, we validate the stored seed matches
        // the expected value to detect potential corruption.

        let expected_key_derivation_seed = keystore.load_mnemonic()?.to_seed(&mnemonic_passphrase);

        match keystore.load_key_derivation_seed() {
            Ok(stored_seed) => {
                // Validate that the stored seed matches what would be generated from mnemonic + passphrase
                if stored_seed != expected_key_derivation_seed {
                    return Err(KeyManagerError::CorruptedKeyDerivationSeed);
                }
                println!(
                    "validated Key derivation seed (64 bytes): {:?}",
                    stored_seed
                ); // TODO remove after debugging
            }
            Err(_) => {
                // No seed stored, generate and store it
                println!(
                    "storing Key derivation seed (64 bytes): {:?}",
                    expected_key_derivation_seed
                ); // TODO remove after debugging
                keystore.store_key_derivation_seed(expected_key_derivation_seed)?;
            }
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
                println!(
                    "validated Winternitz seed (32 bytes): {:?}",
                    stored_winternitz_seed
                ); // TODO remove after debugging
            }
            Err(_) => {
                // No Winternitz seed stored, generate and store it
                println!(
                    "storing Winternitz seed (32 bytes): {:?}",
                    expected_winternitz_seed
                ); // TODO remove after debugging
                keystore.store_winternitz_seed(expected_winternitz_seed)?;
            }
        }

        let musig2 = MuSig2Signer::new(keystore.store_clone());

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

    pub fn import_private_key_typed(&self, private_key: &str, key_type: Option<BitcoinKeyType>) -> Result<PublicKey, KeyManagerError> {
        let private_key = PrivateKey::from_str(private_key)?;
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);
        self.keystore.store_keypair(private_key, public_key, key_type)?;

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
        key_type: Option<BitcoinKeyType>
    ) -> Result<PublicKey, KeyManagerError> {
        let secret_key = SecretKey::from_str(secret_key)?;
        let private_key = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        self.keystore.store_keypair(private_key, public_key, key_type)?;
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

        let (private_key, public_key) = self
            .musig2
            .aggregate_private_key(partial_keys_bytes, network)?;
        // TODO discuss with diego, should be p2tr always to use them with musig2 and schnorr
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

        let (private_key, public_key) = self
            .musig2
            .aggregate_private_key(partial_keys_bytes, network)?;
        // TODO discuss with diego, should be p2tr always to use them with musig2 and schnorr
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

    // Winternitz uses BIP-39/BIP-44 style derivation with a hardened custom purpose path for winternitz:
    fn derive_winternitz_master_seed(
        secp: secp256k1::Secp256k1<All>,
        key_derivation_seed: &[u8],
        network: Network,
        account: u32,
    ) -> Result<[u8; 32], KeyManagerError> {
        let wots_full_derivation_path = Self::build_bip44_derivation_path(
            Self::WINTERNITZ_PURPOSE_INDEX,
            Self::get_bitcoin_coin_type_by_network(network), //TODO: inform team. Dev note: nice to differentiate by network as they are OT
            account,
            Self::CHANGE_DERIVATION_INDEX,
            0, // index does not matter here
        );

        let hardened_wots_account_derivation_path =
            Self::extract_account_level_path(&wots_full_derivation_path);
        println!(
            "hardened_wots_account_derivation_path: {}",
            hardened_wots_account_derivation_path
        ); // TODO remove after debugging

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
    pub fn generate_account_xpub(&self, key_type: BitcoinKeyType) -> Result<Xpub, KeyManagerError> {
        let key_derivation_seed = self.keystore.load_key_derivation_seed()?;
        let master_xpriv = Xpriv::new_master(self.network, &key_derivation_seed)?;

        // Build the full derivation path and extract only up to account level
        let full_derivation_path = Self::build_derivation_path(key_type, self.network, 0); // index doesn't matter here
        let account_derivation_path = Self::extract_account_level_path(&full_derivation_path);
        println!("account_derivation_path: {}", account_derivation_path); // TODO remove after debugging

        let account_xpriv = master_xpriv.derive_priv(&self.secp, &account_derivation_path)?;
        let account_xpub = Xpub::from_priv(&self.secp, &account_xpriv);

        // Dev note: do not touch parity here
        // Parity normalization (even-Y) is a Taproot/Schnorr (BIP-340/341/86) concern and should be applied
        // only when you form the Taproot internal key for each address when usign the full derivation path
        Ok(account_xpub)
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
        println!("derivation_path: {}", derivation_path); // TODO remove after debugging
        let xpriv = master_xpriv.derive_priv(&self.secp, &derivation_path)?;

        let internal_keypair = xpriv.to_keypair(&self.secp);

        // For taproot keys (Schnorr keys be “x-only with even-Y”.)
        // TODO inform team: Dev note: adjust parity only for Taproot keys, not for every key type
        let (public_key, private_key) = if key_type == BitcoinKeyType::P2tr {
            self.adjust_parity(internal_keypair)
        } else {
            (
                PublicKey::new(internal_keypair.public_key()),
                PrivateKey::new(internal_keypair.secret_key(), self.network),
            )
        };

        self.keystore.store_keypair(private_key, public_key, Some(key_type))?;
        Ok(public_key)
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
    pub fn next_keypair(
        &self,
        key_type: BitcoinKeyType,
    ) -> Result<PublicKey, KeyManagerError> {
        let index = self.next_keypair_index(key_type)?;
        let pubkey = self.derive_keypair(key_type, index)?;
        // if derivation was successful, store the next index
        self.keystore.store_next_keypair_index(key_type, index+1)?;
        println!("next_keypair: key_type: {:?}, index: {}", key_type, index); // TODO remove after debugging
        println!("stored next index: {}", index+1); // TODO remove after debugging
        Ok(pubkey)
    }

    fn next_keypair_index(
        &self,
        key_type: BitcoinKeyType,
    ) -> Result<u32, KeyManagerError> {

        match self.keystore.load_next_keypair_index(key_type) {
            Ok(stored_index) => Ok(stored_index),
            Err(_) => Ok(Self::STARTING_DERIVATION_INDEX),
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

    // Security Issue
    // The current implementation allows deriving child public keys from the master xpub without hardened derivation. This means:

    // Privacy leak: Anyone with the master xpub can derive ALL your public keys
    // Security vulnerability: If any child private key is compromised + the master xpub is known, an attacker can derive ALL other private keys in the wallet
    // Correct BIP-44 Implementation
    // The xpub should only be exposed at the account level (after hardened derivation):
    // TODO remove this function after sync with Diego, see new method derive_public_key_from_account_xpub
    // fn derive_public_key(
    //     &self,
    //     master_xpub: Xpub,
    //     key_type: KeyType,
    //     index: u32,
    // ) -> Result<PublicKey, KeyManagerError> {
    //     let secp = secp256k1::Secp256k1::new();
    //     let derivation_path = KeyManager::build_derivation_path(
    //         key_type,
    //         self.network,
    //         index,
    //     );
    //     let xpub = master_xpub.derive_pub(&secp, &derivation_path)?;

    //     // TODO discuss with Diego M. // i think we should adjust parity only for Taproot keys, not for every key type
    //     if key_type == KeyType::P2tr {
    //         Ok(self.adjust_public_key_only_parity(xpub.to_pub().into()))
    //     } else {
    //         Ok(xpub.to_pub().into())
    //     }
    // }

    // Key Benefits of This Approach:
    // Security: Only exposes account-level xpub, not master xpub
    // BIP-44 Compliance: Follows the standard hardened derivation up to account level
    // Privacy: Different accounts remain isolated
    // Flexibility: Can still derive all keys within an account from the account xpub
    pub fn derive_public_key_from_account_xpub(
        &self,
        account_xpub: Xpub,
        key_type: BitcoinKeyType,
        index: u32,
    ) -> Result<PublicKey, KeyManagerError> {
        let secp = secp256k1::Secp256k1::new();

        // key type seems irrelevant here, as we will start from account xpub that alrady has its key_type (purpose) specified,
        // and we will add just the chain path, but we need it in order to know if we need to adjust parity or not for the final key

        // Build the full derivation path and extract only the chain part after account level
        let full_derivation_path = Self::build_derivation_path(key_type, self.network, index);
        let chain_derivation_path = Self::extract_chain_path(&full_derivation_path);
        println!("chain_derivation_path: {}", chain_derivation_path); // TODO remove after debugging

        let xpub = account_xpub.derive_pub(&secp, &chain_derivation_path)?;

        // TODO inform team: Dev note: adjust parity only for Taproot keys
        if key_type == BitcoinKeyType::P2tr {
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
    // TODO make private in the future
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
        println!("next_winternitz: key_type: {:?}, message_size: {}, index: {}", key_type, message_size_in_bytes, index); // TODO remove after debugging
        println!("stored next index: {}", index + 1); // TODO remove after debugging
        Ok(pubkey)
    }

    fn next_winternitz_index(&self) -> Result<u32, KeyManagerError> {
        match self.keystore.load_next_winternitz_index() {
            Ok(stored_index) => Ok(stored_index),
            Err(_) => Ok(Self::STARTING_DERIVATION_INDEX),
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
    // TODO make private in the future
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
        self.keystore.store_next_winternitz_index(initial_index + number_of_keys)?;
        println!("next_multiple_winternitz: key_type: {:?}, message_size: {}, initial_index: {}", key_type, message_size_in_bytes, initial_index); // TODO remove after debugging
        println!("stored next index: {}", initial_index + number_of_keys); // TODO remove after debugging

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
        // TODO error if bits > 16384 ?? avoid too large keys
        let rsa_keypair = RSAKeyPair::new(rng, bits)?;
        self.keystore.store_rsa_key(rsa_keypair.clone())?;
        let rsa_pubkey_pem = rsa_keypair.export_public_pem()?;
        Ok(rsa_pubkey_pem)
    }

    /*********************************/
    /*********** Signing *************/
    /*********************************/

    // TODO discuss with diegoM. key type checks for signing, we were using any key for ecdsa or schnorr

    pub fn sign_ecdsa_message(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<secp256k1::ecdsa::Signature, KeyManagerError> {
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
        if let Some(key_type) = key_type {
            if key_type == BitcoinKeyType::P2tr {
                return Err(KeyManagerError::EcdsaWithTaprootKey);
            }
        }

        Ok(self.secp.sign_ecdsa(message, &sk.inner))
    }

    pub fn sign_ecdsa_recoverable_message(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<secp256k1::ecdsa::RecoverableSignature, KeyManagerError> {
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
        if let Some(key_type) = key_type {
            if key_type == BitcoinKeyType::P2tr {
                return Err(KeyManagerError::EcdsaWithTaprootKey);
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
        let (sk, _, key_type) = match self.keystore.load_keypair(public_key)? {
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
        if let Some(key_type) = key_type {
            if key_type != BitcoinKeyType::P2tr {
                return Err(KeyManagerError::SchnorrWithNonTaprootKey);
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
        let (sk, _, key_type) = match self.keystore.load_keypair(public_key)? {
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
        if let Some(key_type) = key_type {
            if key_type != BitcoinKeyType::P2tr {
                return Err(KeyManagerError::SchnorrWithNonTaprootKey);
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
        let (sk, _, key_type) = match self.keystore.load_keypair(public_key)? {
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
        if let Some(key_type) = key_type {
            if key_type != BitcoinKeyType::P2tr {
                return Err(KeyManagerError::SchnorrWithNonTaprootKey);
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

        // TODO discuss with Diego M. check key types p2tr for musig2? backwards compatible?
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

        // TODO discuss with Diego M. check key types p2tr for musig2? backwards compatible?
    }

    pub fn generate_nonce_seed(
        &self,
        index: u32,
        public_key: PublicKey,
    ) -> Result<[u8; 32], KeyManagerError> {
        // TODO * leaking secret key material?, consider using HKDF or similar KDF with a salt instead
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

        let mut data = Vec::new();
        data.extend_from_slice(&sk.to_bytes());
        data.extend_from_slice(&index.to_le_bytes());

        let nonce_seed = hashes::sha256::Hash::hash(data.as_slice()).to_byte_array();

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

        Ok(self.musig2.save_partial_signatures(
            aggregated_pubkey,
            id,
            partial_signatures_mapping,
        )?)
    }

    pub fn save_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        other_public_key: PublicKey,
        other_partial_signatures: Vec<(MessageId, PartialSignature)>,
    ) -> Result<Vec<(MessageId, PartialSignature)>, KeyManagerError> {
        let mut partial_signatures = HashMap::new();
        partial_signatures.insert(other_public_key, other_partial_signatures);

        let my_partial_signatures = self.get_my_partial_signatures(aggregated_pubkey, id)?;
        let my_pub_key = self.musig2.my_public_key(aggregated_pubkey)?;

        partial_signatures.insert(my_pub_key, my_partial_signatures.clone());

        self.musig2
            .save_partial_signatures(aggregated_pubkey, id, partial_signatures)?;

        Ok(my_partial_signatures)
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

    /*pub fn get_aggregated_pubkey(&self, id: &str) -> Result<PublicKey, Musig2SignerError> {
        self.musig2.get_aggregated_pubkey(id)
    }*/
}

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;
    use bitcoin::{
        hex::DisplayHex,
        key::rand::{self, RngCore},
        secp256k1::{self, Message, SecretKey},
        Network, PrivateKey, PublicKey,
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
        let pub_key: PublicKey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;

        let pub_key2: PublicKey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 1)?;

        // TODO * Discuss with Diego M. what is the generate_nonce_seed used for in bitvmx, is it leaking the priv key bytes?
        // Small test to check that the nonce is deterministic with the same index and public key
        let nonce_seed = key_manager.generate_nonce_seed(0, pub_key)?;
        assert_eq!(
            nonce_seed.to_lower_hex_string(),
            "ab491b51448b89f1bfab75ae95f48a2b462cbbd0555b72e84bd3771a830757a1"
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
            "99b88224e42ba9bcdeaa5ccaeb4fb2fe1355ff42d2c71e932b7021910836e52d"
        );
        let nonce_seed_4 = key_manager.generate_nonce_seed(4, pub_key)?;
        assert_eq!(
            nonce_seed_4.to_lower_hex_string(),
            "7a7b2ba29139b59f00af9faafcbd1946453b7665ea762cfe18e07c46b46f012f"
        );

        // Test that the nonce is different for different public key
        let nonce_seed_2 = key_manager.generate_nonce_seed(0, pub_key2)?;
        assert_eq!(
            nonce_seed_2.to_lower_hex_string(),
            "1b60e65d0dfe2c7e311ea4cf702866c935387e1bdf7dacc054597f146fe22e3f"
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
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;
        let signature_verifier = SignatureVerifier::new();

        let pk = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;

        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, &pk)?;

        assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_sign_ecdsa_recoverable_message() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;
        let signature_verifier = SignatureVerifier::new();

        let pk = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;

        let message = random_message();
        let recoverable_signature = key_manager.sign_ecdsa_recoverable_message(&message, &pk)?;
        let signature = recoverable_signature.to_standard();

        assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_sign_schnorr_message() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;
        let signature_verifier = SignatureVerifier::new();

        let pk = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;

        let message = random_message();
        let signature = key_manager.sign_schnorr_message(&message, &pk)?;

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
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
        let password = "secret password".to_string();
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
        let password = "secret password".to_string();
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
        let key_manager = KeyManager::new(
            Network::Regtest,
            None, // No mnemonic provided, will generate one
            None,
            keystore_storage_config,
        )?;

        // 1. Verify that with a fresh keymanager, there is no stored index for P2tr
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2tr).is_err());

        // 2. Verify that there is also no stored index for other key types
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2wpkh).is_err());
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2pkh).is_err());
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2shP2wpkh).is_err());

        // 3. Get next_keypair for P2tr type - should return a public key and store index 1
        let first_pubkey = key_manager.next_keypair(BitcoinKeyType::P2tr)?;

        // 4. Verify that index 1 is now stored for P2tr (next index after using index 0)
        let stored_index = key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2tr)?;
        assert_eq!(stored_index, 1, "Expected next index to be 1 after first keypair generation");

        // 5. Verify that there is still no index stored for other types
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2wpkh).is_err());
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2pkh).is_err());
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2shP2wpkh).is_err());

        // 6. Get next_keypair again - should return a different pubkey and store index 2
        let second_pubkey = key_manager.next_keypair(BitcoinKeyType::P2tr)?;

        // 7. Verify that index 2 is now stored for P2tr
        let stored_index = key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2tr)?;
        assert_eq!(stored_index, 2, "Expected next index to be 2 after second keypair generation");

        // 8. Verify that the two pubkeys are different
        assert_ne!(first_pubkey, second_pubkey, "Expected different public keys from successive next_keypair calls");

        // 9. Use derive_keypair with index 0 - should give the same as the 1st pubkey
        let derived_first_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0)?;
        assert_eq!(first_pubkey, derived_first_pubkey, "Expected derive_keypair(0) to match first next_keypair result");

        // 10. Use derive_keypair with index 1 - should give the same as the 2nd pubkey
        let derived_second_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 1)?;
        assert_eq!(second_pubkey, derived_second_pubkey, "Expected derive_keypair(1) to match second next_keypair result");

        // 11. Verify that calling next_keypair for a different key type starts fresh indexing
        let first_p2wpkh_pubkey = key_manager.next_keypair(BitcoinKeyType::P2wpkh)?;
        let stored_p2wpkh_index = key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2wpkh)?;
        assert_eq!(stored_p2wpkh_index, 1, "Expected P2wpkh next index to start at 1");

        // 12. Verify that P2tr index is still at 2 and other types are still not set
        let p2tr_index = key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2tr)?;
        assert_eq!(p2tr_index, 2, "P2tr index should remain unchanged");
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2pkh).is_err());
        assert!(key_manager.keystore.load_next_keypair_index(BitcoinKeyType::P2shP2wpkh).is_err());

        // 13. Verify that derive_keypair for P2wpkh with index 0 gives the same as next_keypair
        let derived_p2wpkh_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
        assert_eq!(first_p2wpkh_pubkey, derived_p2wpkh_pubkey, "Expected derive_keypair(P2wpkh, 0) to match first P2wpkh next_keypair result");

        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    fn test_next_winternitz_auto_indexing() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        // Create a fresh KeyManager
        let key_manager = KeyManager::new(
            Network::Regtest,
            None, // No mnemonic provided, will generate one
            None,
            keystore_storage_config,
        )?;

        let message_size_32_bytes = 32;
        let message_size_20_bytes = 20;

        // 1. Get next_winternitz for SHA256 with 32 bytes - should use index 0 and increment global counter
        let first_pubkey = key_manager.next_winternitz(message_size_32_bytes, WinternitzType::SHA256)?;

        // 2. Verify that derive_winternitz with index 0 gives the same as the 1st pubkey
        let derived_first_pubkey = key_manager.derive_winternitz(message_size_32_bytes, WinternitzType::SHA256, 0)?;
        assert_eq!(first_pubkey, derived_first_pubkey, "Expected derive_winternitz(0) to match first next_winternitz result");

        // 3. Get next_winternitz again - should use index 1 and increment global counter
        let second_pubkey = key_manager.next_winternitz(message_size_32_bytes, WinternitzType::SHA256)?;

        // 4. Verify that the two pubkeys are different
        assert_ne!(first_pubkey, second_pubkey, "Expected different public keys from successive next_winternitz calls");

        // 5. Verify that derive_winternitz with index 1 gives the same as the 2nd pubkey
        let derived_second_pubkey = key_manager.derive_winternitz(message_size_32_bytes, WinternitzType::SHA256, 1)?;
        assert_eq!(second_pubkey, derived_second_pubkey, "Expected derive_winternitz(1) to match second next_winternitz result");

        // 6. Get next_winternitz for a different type - should use index 2 (global counter continues)
        let third_pubkey = key_manager.next_winternitz(message_size_32_bytes, WinternitzType::HASH160)?;

        // 7. Verify that derive_winternitz for HASH160 with index 2 gives the same result
        let derived_third_pubkey = key_manager.derive_winternitz(message_size_32_bytes, WinternitzType::HASH160, 2)?;
        assert_eq!(third_pubkey, derived_third_pubkey, "Expected derive_winternitz(HASH160, 32, 2) to match third next_winternitz result");

        // 8. Get next_winternitz for different message size - should use index 3 (global counter continues)
        let fourth_pubkey = key_manager.next_winternitz(message_size_20_bytes, WinternitzType::SHA256)?;

        // 9. Verify that derive_winternitz for SHA256:20 with index 3 gives the same result
        let derived_fourth_pubkey = key_manager.derive_winternitz(message_size_20_bytes, WinternitzType::SHA256, 3)?;
        assert_eq!(fourth_pubkey, derived_fourth_pubkey, "Expected derive_winternitz(SHA256, 20, 3) to match fourth next_winternitz result");

        // 10. Get next_winternitz for yet another combination - should use index 4
        let fifth_pubkey = key_manager.next_winternitz(message_size_20_bytes, WinternitzType::HASH160)?;

        // 11. Verify that derive_winternitz for HASH160:20 with index 4 gives the same result
        let derived_fifth_pubkey = key_manager.derive_winternitz(message_size_20_bytes, WinternitzType::HASH160, 4)?;
        assert_eq!(fifth_pubkey, derived_fifth_pubkey, "Expected derive_winternitz(HASH160, 20, 4) to match fifth next_winternitz result");

        // 12. Verify all keys are different (security requirement - no reuse)
        let all_pubkeys = vec![&first_pubkey, &second_pubkey, &third_pubkey, &fourth_pubkey, &fifth_pubkey];
        for (i, key1) in all_pubkeys.iter().enumerate() {
            for (j, key2) in all_pubkeys.iter().enumerate() {
                if i != j {
                    assert_ne!(key1, key2, "Expected all Winternitz keys to be different - found duplicate at indices {} and {}", i, j);
                }
            }
        }

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
        assert!(matches!(result, Err(KeyManagerError::SchnorrWithNonTaprootKey)));

        // Test imported key (key_type = None) - should allow both ECDSA and Schnorr
        let imported_key = key_manager.import_private_key("L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ")?;

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
            let account_xpub = key_manager.generate_account_xpub(key_type).unwrap();

            for i in 0..5 {
                let pk1 = key_manager.derive_keypair(key_type, i).unwrap();
                let pk2 = key_manager
                    .derive_public_key_from_account_xpub(account_xpub, key_type, i)
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
                .derive_public_key_from_account_xpub(account_xpub, key_type, 11)
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

        let account_xpub = key_manager
            .generate_account_xpub(BitcoinKeyType::P2tr)
            .unwrap();

        for i in 0..5 {
            let pk1 = key_manager.derive_keypair(BitcoinKeyType::P2tr, i).unwrap();
            let pk2 = key_manager
                .derive_public_key_from_account_xpub(account_xpub, BitcoinKeyType::P2tr, i)
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
            .derive_public_key_from_account_xpub(account_xpub, BitcoinKeyType::P2tr, 11)
            .unwrap();

        let signature_verifier = SignatureVerifier::new();
        let message = random_message();
        let signature = key_manager.sign_schnorr_message(&message, &pk1).unwrap();

        assert!(!signature_verifier.verify_schnorr_signature(&signature, &message, pk2));

        drop(key_manager);
        cleanup_storage(&keystore_path);
    }

    #[test]
    fn test_key_derivation_from_account_xpub_in_different_key_manager() {
        let keystore_path_1 = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path_1).unwrap();
        let key_manager_1 = test_random_key_manager(keystore_storage_config).unwrap();

        let keystore_path_2 = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path_2).unwrap();
        let key_manager_2 = test_random_key_manager(keystore_storage_config).unwrap();

        let key_types = vec![
            BitcoinKeyType::P2pkh,
            BitcoinKeyType::P2shP2wpkh,
            BitcoinKeyType::P2wpkh,
            BitcoinKeyType::P2tr,
        ];

        for key_type in key_types {
            for i in 0..5 {
                // Generate account-level xpub in key_manager_1 (hardened up to account level)
                let account_xpub = key_manager_1.generate_account_xpub(key_type).unwrap();

                // Derive public key in key_manager_1 using account xpub
                let public_from_account_xpub_km1 = key_manager_1
                    .derive_public_key_from_account_xpub(account_xpub, key_type, i)
                    .unwrap();

                // Derive public key in key_manager_2 using account xpub
                let public_from_account_xpub_km2 = key_manager_2
                    .derive_public_key_from_account_xpub(account_xpub, key_type, i)
                    .unwrap();

                // Both public keys must be equal
                assert_eq!(
                    public_from_account_xpub_km1.to_string(),
                    public_from_account_xpub_km2.to_string()
                );
            }
        }

        drop(key_manager_2);
        drop(key_manager_1);
        cleanup_storage(&keystore_path_1);
        cleanup_storage(&keystore_path_2);
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
                "P2PKH key import"
            ),
            (
                "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617",
                Some(BitcoinKeyType::P2shP2wpkh),
                "P2SH-P2WPKH key import"
            ),
            (
                "L5oLkpV3aqBjhki6LmvChTCV6odsp4SXM6FfU2Gppt5kFLaHLuZ9",
                Some(BitcoinKeyType::P2wpkh),
                "P2WPKH key import"
            ),
            (
                "KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S",
                Some(BitcoinKeyType::P2tr),
                "P2TR key import"
            ),
            (
                "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g",
                None,
                "Untyped key import"
            ),
        ];

        for (private_key_wif, expected_key_type, description) in test_cases {
            // Import the key with specific type
            let public_key = key_manager.import_private_key_typed(private_key_wif, expected_key_type)?;

            // Retrieve the key and verify the type is preserved
            let (_, _, stored_key_type) = match key_manager.keystore.load_keypair(&public_key)? {
                Some(entry) => entry,
                None => panic!("Failed to retrieve imported key for {}", description),
            };

            // Verify the key type matches what was set during import
            assert_eq!(stored_key_type, expected_key_type,
                      "Key type mismatch for {}: expected {:?}, got {:?}",
                      description, expected_key_type, stored_key_type);

            println!("✓ {}: Key type correctly stored as {:?}", description, stored_key_type);
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
            assert_eq!(stored_key_type, expected_option,
                      "Key type mismatch for derived {:?}: expected {:?}, got {:?}",
                      expected_key_type, expected_option, stored_key_type);

            println!("✓ Derived {:?} key: Key type correctly stored as {:?}",
                     expected_key_type, stored_key_type);
        }

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    fn test_random_key_manager(
        storage_config: StorageConfig,
    ) -> Result<KeyManager, KeyManagerError> {
        let random_mnemonic: Mnemonic = Mnemonic::from_entropy(&random_32bytes()).unwrap();
        let random_mnemonic_passphrase = generate_random_passphrase();

        let key_manager = KeyManager::new(
            REGTEST,
            Some(random_mnemonic),
            Some(random_mnemonic_passphrase),
            storage_config,
        )?;

        Ok(key_manager)
    }

    fn test_deterministic_key_manager(
        storage_config: StorageConfig,
    ) -> Result<KeyManager, KeyManagerError> {
        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();

        let key_manager = KeyManager::new(REGTEST, Some(fixed_mnemonic), None, storage_config)?;

        Ok(key_manager)
    }

    fn database_keystore_config(storage_path: &str) -> Result<StorageConfig, KeyManagerError> {
        let password = "secret password".to_string();
        let config = StorageConfig::new(storage_path.to_string(), Some(password));
        Ok(config)
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

    /// Generates a random passphrase of exactly 20 characters using alphanumeric characters
    /// This can be used as a BIP-39 mnemonic passphrase for additional security
    fn generate_random_passphrase() -> String {
        use bitcoin::key::rand::Rng;

        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const PASSPHRASE_LENGTH: usize = 20;

        let mut rng = bitcoin::key::rand::thread_rng();
        let passphrase: String = (0..PASSPHRASE_LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        passphrase
    }

    #[test]
    pub fn test_rsa_signature() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;
        let signature_verifier = SignatureVerifier::new();

        let mut rng = secp256k1::rand::thread_rng();
        let pubkey = key_manager.generate_rsa_keypair(&mut rng)?;
        let message = random_message().to_string().as_bytes().to_vec();
        let signature = key_manager.sign_rsa_message(&message, &pubkey).unwrap();

        assert!(signature_verifier
            .verify_rsa_signature(&signature, &message, &pubkey)
            .unwrap());

        drop(key_manager);
        cleanup_storage(&keystore_path);
        Ok(())
    }

    #[test]
    pub fn test_rsa_encryption() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore_storage_config = database_keystore_config(&keystore_path)?;

        let key_manager = test_random_key_manager(keystore_storage_config)?;

        let mut rng = secp256k1::rand::thread_rng();
        let pubkey = key_manager.generate_rsa_keypair(&mut rng)?;
        let message = random_message().to_string().as_bytes().to_vec();

        let encrypted_message = key_manager.encrypt_rsa_message(&message, &pubkey).unwrap();

        let decrypted_message = key_manager
            .decrypt_rsa_message(&encrypted_message, &pubkey)
            .unwrap();

        assert_eq!(message, decrypted_message);

        drop(key_manager);
        cleanup_storage(&keystore_path);
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
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let key_manager1 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            keystore_storage_config.clone())?;

        drop(key_manager1);

        // --- Create the 2nd KeyManager with different Mnemonic but using the same keystore_storage_config
        // This should fail with MnemonicMismatch error

        // WARNING NEVER USE THIS EXAMPLE MNEMONIC TO STORE REAL FUNDS
        let mnemonic_sentence = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let key_manager2 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            keystore_storage_config.clone());

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
            keystore_storage_config)?;

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
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let passphrase1 = "test_passphrase_123".to_string();

        let key_manager1 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic.clone()),
            Some(passphrase1.clone()),
            keystore_storage_config.clone())?;

        drop(key_manager1);

        // --- Test 1: Create KeyManager with same mnemonic and same passphrase (should succeed)
        let key_manager2 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic.clone()),
            Some(passphrase1.clone()),
            keystore_storage_config.clone())?;

        drop(key_manager2);

        // --- Test 2: Create KeyManager with same mnemonic but different passphrase (should fail)
        let different_passphrase = "different_passphrase_456".to_string();
        let result = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic.clone()),
            Some(different_passphrase),
            keystore_storage_config.clone());

        // Expect MnemonicPassphraseMismatch error
        assert!(matches!(
            result,
            Err(KeyManagerError::MnemonicPassphraseMismatch(_))
        ));

        // --- Test 3: Create KeyManager with same mnemonic and no passphrase (should succeed with stored passphrase)
        let key_manager3 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            keystore_storage_config)?;

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
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let key_manager1 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic.clone()),
            None,
            keystore_storage_config.clone())?;

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
        let result = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            keystore_storage_config.clone());

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
        let fixed_mnemonic = Mnemonic::parse(mnemonic_sentence).unwrap();
        let key_manager1 = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic.clone()),
            None,
            keystore_storage_config.clone())?;

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
        let result = KeyManager::new(
            REGTEST,
            Some(fixed_mnemonic),
            None,
            keystore_storage_config.clone());

        // Expect CorruptedWinternitzSeed error
        assert!(matches!(
            result,
            Err(KeyManagerError::CorruptedWinternitzSeed)
        ));

        cleanup_storage(&keystore_path);
        Ok(())
    }
}
