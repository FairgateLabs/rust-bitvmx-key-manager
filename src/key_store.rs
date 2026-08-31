use crate::{
    errors::KeyManagerError,
    key_type::BitcoinKeyType,
    lamport::{LamportPrivateKey, LamportPubKeyId, LamportPublicKey},
    rsa::RSAKeyPair,
};
use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use bitcoin::{PrivateKey, PublicKey};
use rsa::RsaPublicKey;
use serde::de::DeserializeOwned;
use std::{rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub struct KeyStore {
    store: Rc<Storage>,
}

/* Dev Note: Possible optimization:
saving byte arrays instead of base64 general_purpose::STANDARD.encode/decode will reduce database size and improve performance,
but it would require changing the Storage trait to support byte arrays,
and also adjusting the serialization/deserialization logic accordingly.
This could be a future improvement to consider after evaluating the current implementation's performance and storage efficiency.
*/

impl KeyStore {
    const MNEMONIC_KEY: &str = "bip39_mnemonic"; // Key for the BIP-39 mnemonic
    const MNEMONIC_PASSPHRASE_KEY: &str = "bip39_mnemonic_passphrase"; // Key for the BIP-39 mnemonic passphrase
    const WINTERNITZ_KEY: &str = "winternitz_seed"; // Key to use in the database for the Winternitz seed
    const LAMPORT_KEY: &str = "lamport_seed"; // Key to use in the database for the Lamport seed
    const KEY_DERIVATION_SEED_KEY: &str = "bip32_seed"; // Key to use in the database for the bip32 key derivation seed
    const UNKNOWN_TYPE: &str = "unknown"; // Key type string for unknown/unspecified key types
    const NEXT_KEYPAIR_INDEX_KEY: &str = "next_keypair_index"; // Key for storing the next keypair index
    const NEXT_WINTERNITZ_INDEX_KEY: &str = "next_winternitz_index"; // Key for storing the next winternitz index
    const NEXT_LAMPORT_INDEX_KEY: &str = "next_lamport_index"; // Key for storing the next lamport index
    const WINTERNITZ_INDEX_BLOCK_KEY: &str = "winternitz_index_block"; // Key prefix for Winternitz index bitmap blocks
    const LAMPORT_INDEX_BLOCK_KEY: &str = "lamport_index_block"; // Key prefix for Lamport index bitmap blocks
                                                                 // TODO adjust block size to optimize storage, according to the estimation of max winternitz keys needed
    const WOTS_CHECK_BLOCK_SIZE: u64 = 1024; // Number of indices per bitmap block
    const WOTS_CHECK_BLOCK_BYTES: usize = (Self::WOTS_CHECK_BLOCK_SIZE / 8) as usize; // 128 bytes per block
    const LAMPORT_CHECK_BLOCK_SIZE: u64 = 1024; // Number of indices per bitmap block
    const LAMPORT_CHECK_BLOCK_BYTES: usize = (Self::LAMPORT_CHECK_BLOCK_SIZE / 8) as usize; // 128 bytes per block
    const LAMPORT: &str = "lamport"; // Key prefix for Lamport pubkeys

    pub fn new(store: Rc<Storage>) -> Self {
        Self { store }
    }

    #[allow(dead_code)]
    pub(crate) fn store_clone(&self) -> Rc<Storage> {
        Rc::clone(&self.store)
    }

    pub fn begin_transaction(&self) -> Uuid {
        self.store.begin_transaction()
    }

    pub fn commit_transaction(&self, transaction_id: Uuid) -> Result<(), KeyManagerError> {
        self.store
            .commit_transaction(transaction_id)
            .map_err(KeyManagerError::from)
    }

    pub fn rollback_transaction(&self, transaction_id: Uuid) -> Result<(), KeyManagerError> {
        self.store
            .rollback_transaction(transaction_id)
            .map_err(KeyManagerError::from)
    }

    /**
        Dev note: key_type is optional to maintain compatibility with older stored keys
        it is stored as a prefix in the private key string, separated by a ":"
        in the case of no key type, the prefix is "unknown"
    */
    pub fn store_keypair(
        &self,
        private_key: PrivateKey,
        public_key: PublicKey,
        key_type: Option<BitcoinKeyType>,
    ) -> Result<(), KeyManagerError> {
        let key = public_key.to_string();

        let key_type_str = match key_type {
            Some(kt) => format!("{:?}", kt),
            None => Self::UNKNOWN_TYPE.to_string(),
        };

        let typed_private_key = Zeroizing::new(format!("{}:{}", key_type_str, private_key));
        self.store.set(key, (*typed_private_key).clone(), None)?;

        Ok(())
    }

    pub fn keys(&self) -> Result<Vec<String>, KeyManagerError> {
        Ok(self.store.keys(None)?)
    }

    pub fn load_value<V: DeserializeOwned>(&self, key: &str) -> Result<Option<V>, KeyManagerError> {
        Ok(self.store.get::<&str, V>(key, None)?)
    }

    pub fn load_keypair(
        &self,
        public_key: &PublicKey,
    ) -> Result<Option<(PrivateKey, PublicKey, Option<BitcoinKeyType>)>, KeyManagerError> {
        let key = public_key.to_string();
        let data: Option<Zeroizing<String>> = self
            .store
            .get::<String, String>(key, None)?
            .map(Zeroizing::new);

        if let Some(private_key_str) = data {
            if let Some(colon_pos) = private_key_str.find(':') {
                let (key_type_str, private_key_part) = private_key_str.split_at(colon_pos);
                let private_key_part = &private_key_part[1..]; // Remove the ':'

                let key_type = if key_type_str == Self::UNKNOWN_TYPE {
                    None
                } else {
                    key_type_str.parse::<BitcoinKeyType>().ok()
                };

                let private_key = PrivateKey::from_str(private_key_part)?;
                return Ok(Some((private_key, *public_key, key_type)));
            } else {
                // Legacy case: no ":" found, assume old format without key type information
                let private_key = PrivateKey::from_str(&private_key_str)?;
                return Ok(Some((private_key, *public_key, None)));
            }
        }

        Ok(None)
    }

    pub fn store_next_keypair_index(
        &self,
        key_type: BitcoinKeyType,
        index: u32,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        let key_type_str = format!("{:?}", key_type);
        let typed_next_keypair_index_key =
            format!("{}:{}", key_type_str, Self::NEXT_KEYPAIR_INDEX_KEY);
        // this will store the next keypair index for the given key type e.g.: p2tr:next_keypair_index
        self.store
            .set(typed_next_keypair_index_key, index, transaction_id)?;
        Ok(())
    }

    pub fn load_next_keypair_index(
        &self,
        key_type: BitcoinKeyType,
    ) -> Result<u32, KeyManagerError> {
        let key_type_str = format!("{:?}", key_type);
        let typed_next_keypair_index_key =
            format!("{}:{}", key_type_str, Self::NEXT_KEYPAIR_INDEX_KEY);
        match self.store.get(typed_next_keypair_index_key, None)? {
            Some(next_index) => Ok(next_index),
            None => Err(KeyManagerError::NextKeypairIndexNotFound),
        }
    }

    pub fn store_next_winternitz_index(
        &self,
        index: u32,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        // best practice: never reuse the index, as it can compromise security, even if the hash type changes
        // this will store the next winternitz index
        self.store
            .set(Self::NEXT_WINTERNITZ_INDEX_KEY, index, transaction_id)?;
        Ok(())
    }

    pub fn load_next_winternitz_index(&self) -> Result<u32, KeyManagerError> {
        match self.store.get(Self::NEXT_WINTERNITZ_INDEX_KEY, None)? {
            Some(next_index) => Ok(next_index),
            None => Err(KeyManagerError::NextWinternitzIndexNotFound),
        }
    }

    pub fn store_next_lamport_index(
        &self,
        index: u32,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        // best practice: never reuse the index, as it can compromise security, even if the hash type changes
        // this will store the next lamport index
        self.store
            .set(Self::NEXT_LAMPORT_INDEX_KEY, index, transaction_id)?;
        Ok(())
    }

    pub fn load_next_lamport_index(&self) -> Result<u32, KeyManagerError> {
        match self.store.get(Self::NEXT_LAMPORT_INDEX_KEY, None)? {
            Some(next_index) => Ok(next_index),
            None => Err(KeyManagerError::NextLamportIndexNotFound),
        }
    }

    pub fn store_mnemonic(&self, mnemonic: &Mnemonic) -> Result<(), KeyManagerError> {
        let phrase = Zeroizing::new(mnemonic.to_string()); // normalized space-separated phrase
        self.store.set(Self::MNEMONIC_KEY, &(*phrase), None)?;
        Ok(())
    }

    pub fn load_mnemonic(&self) -> Result<Mnemonic, KeyManagerError> {
        let phrase: Zeroizing<String> = match self.store.get(Self::MNEMONIC_KEY, None)? {
            Some(phrase) => Zeroizing::new(phrase),
            None => return Err(KeyManagerError::MnemonicNotFound),
        };
        let m = Mnemonic::parse(&*phrase).map_err(|_| KeyManagerError::InvalidMnemonic)?;
        Ok(m)
    }

    pub fn store_mnemonic_passphrase(&self, passphrase: &str) -> Result<(), KeyManagerError> {
        self.store
            .set(Self::MNEMONIC_PASSPHRASE_KEY, passphrase, None)?;
        Ok(())
    }

    pub fn load_mnemonic_passphrase(&self) -> Result<Zeroizing<String>, KeyManagerError> {
        match self.store.get(Self::MNEMONIC_PASSPHRASE_KEY, None)? {
            Some(passphrase) => Ok(Zeroizing::new(passphrase)),
            None => Err(KeyManagerError::MnemonicPassphraseNotFound),
        }
    }

    pub fn store_winternitz_seed(&self, seed: Zeroizing<[u8; 32]>) -> Result<(), KeyManagerError> {
        self.store.set(Self::WINTERNITZ_KEY, *seed, None)?;
        Ok(())
    }

    pub fn load_winternitz_seed(&self) -> Result<Zeroizing<[u8; 32]>, KeyManagerError> {
        match self.store.get(Self::WINTERNITZ_KEY, None)? {
            Some(entry) => Ok(Zeroizing::new(entry)),
            None => Err(KeyManagerError::WinternitzSeedNotFound),
        }
    }

    pub fn store_lamport_seed(&self, seed: Zeroizing<[u8; 32]>) -> Result<(), KeyManagerError> {
        self.store.set(Self::LAMPORT_KEY, *seed, None)?;
        Ok(())
    }

    pub fn load_lamport_seed(&self) -> Result<Zeroizing<[u8; 32]>, KeyManagerError> {
        match self.store.get(Self::LAMPORT_KEY, None)? {
            Some(entry) => Ok(Zeroizing::new(entry)),
            None => Err(KeyManagerError::LamportSeedNotFound),
        }
    }

    // this index is independent of the index used for key derivation, it is marked when used in a signature
    pub fn check_and_mark_winternitz_index_used(
        &self,
        index: u32,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        // Bitmap with block size of 1024 indices for efficiency
        // Each block represents 1024 indices and uses 128 bytes (1024 bits / 8)

        let block_num = (index as u64) / Self::WOTS_CHECK_BLOCK_SIZE;
        let bit_pos = (index as u64) % Self::WOTS_CHECK_BLOCK_SIZE;

        let byte_index = (bit_pos / 8) as usize;
        let bit_index = (bit_pos % 8) as u8;

        // Load the block from storage (or create new if doesn't exist)
        let block_key = format!("{}:{}", Self::WINTERNITZ_INDEX_BLOCK_KEY, block_num);
        let mut block: Vec<u8> = match self.store.get::<String, Vec<u8>>(block_key.clone(), None)? {
            Some(block) => block,
            None => vec![0u8; Self::WOTS_CHECK_BLOCK_BYTES], // Create new empty block
        };

        // Validate block size
        if block.len() != Self::WOTS_CHECK_BLOCK_BYTES {
            return Err(KeyManagerError::CorruptedWinternitzIndexBitmap);
        }

        // Check if the bit is already set (index already used)
        let mask = 1u8 << bit_index;
        if block[byte_index] & mask != 0 {
            return Err(KeyManagerError::WinternitzIndexAlreadyUsed(index));
        }

        // Mark the bit as used
        block[byte_index] |= mask;

        // Store the updated block back to storage
        self.store.set(block_key, block, transaction_id)?;

        Ok(())
    }

    pub fn store_key_derivation_seed(
        &self,
        seed: Zeroizing<[u8; 64]>,
    ) -> Result<(), KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let mut encoded = general_purpose::STANDARD.encode(*seed);
        self.store
            .set(Self::KEY_DERIVATION_SEED_KEY, &encoded, None)?;
        encoded.zeroize();
        Ok(())
    }

    pub fn load_key_derivation_seed(&self) -> Result<Zeroizing<[u8; 64]>, KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let encoded: Option<Zeroizing<String>> = self
            .store
            .get::<&str, String>(Self::KEY_DERIVATION_SEED_KEY, None)?
            .map(Zeroizing::new);

        let encoded = match encoded {
            Some(encoded) => encoded,
            None => return Err(KeyManagerError::KeyDerivationSeedNotFound),
        };

        let decoded = Zeroizing::new(
            general_purpose::STANDARD
                .decode(&*encoded)
                .map_err(|_| KeyManagerError::CorruptedKeyDerivationSeed)?,
        );

        if decoded.len() != 64 {
            return Err(KeyManagerError::CorruptedKeyDerivationSeed);
        }

        let mut seed = Zeroizing::new([0u8; 64]);
        seed.copy_from_slice(&decoded); // copy from slice supported by zeroize

        Ok(seed)
    }

    pub fn store_rsa_key(&self, rsa_key: RSAKeyPair) -> Result<(), KeyManagerError> {
        let pubk = rsa_key.export_public_pem()?;
        let privk = rsa_key.export_private_pem()?;
        self.store.set(pubk, &(*privk), None)?;
        Ok(())
    }

    /// Load an RSA key pair from the store with the given public key in PEM format.
    pub fn load_rsa_key(
        &self,
        rsa_pub_key: RsaPublicKey,
    ) -> Result<Option<RSAKeyPair>, KeyManagerError> {
        let pubk: String = RSAKeyPair::export_public_pem_from_pubk(rsa_pub_key)?;
        let privk: Option<Zeroizing<String>> = self
            .store
            .get::<String, String>(pubk, None)?
            .map(Zeroizing::new);

        if let Some(privk) = privk {
            let rsa_keypair = RSAKeyPair::from_private_pem(&privk)?;
            return Ok(Some(rsa_keypair));
        }

        Ok(None)
    }

    // Blake3 fingerprint justification: the full LamportPublicKey can be large; using its
    // BLAKE3 hash as the storage key avoids rocksdb performance issues with big keys.
    fn format_lamport_storage_key<K: LamportPubKeyId>(key: &K) -> String {
        format!("{}:{}", Self::LAMPORT, key.key_id().to_hex())
    }

    fn format_lamport_storage_value(private_key: &LamportPrivateKey) -> String {
        format!(
            "{}:{}:{}",
            Self::LAMPORT,
            general_purpose::STANDARD.encode(private_key.to_bytes()),
            private_key.spent(),
        )
    }

    // we are not storing derived keys
    pub fn store_lamport_imported_key(
        &self,
        private_key: &LamportPrivateKey,
        public_key: &LamportPublicKey,
    ) -> Result<(), KeyManagerError> {
        let pubk = Self::format_lamport_storage_key(public_key);
        let privk = Zeroizing::new(Self::format_lamport_storage_value(private_key));
        self.store.set(pubk, &(*privk), None)?;
        Ok(())
    }

    // we are not storing derived keys
    pub fn load_lamport_imported_key<K: LamportPubKeyId>(
        &self,
        public_key: &K,
    ) -> Result<Option<LamportPrivateKey>, KeyManagerError> {
        let pubk = Self::format_lamport_storage_key(public_key);
        let privk: Option<Zeroizing<String>> = self
            .store
            .get::<String, String>(pubk, None)?
            .map(Zeroizing::new);

        if let Some(privk) = privk {
            let parts: Vec<&str> = privk.split(':').collect();

            // Expected format: lamport:base64_key:spent
            if parts.len() != 3 || parts[0] != Self::LAMPORT {
                return Err(KeyManagerError::InvalidLamportPrivateKey);
            }

            let key_bytes_part = parts[1];
            let spent = parts[2]
                .parse::<bool>()
                .map_err(|_| KeyManagerError::InvalidLamportPrivateKey)?;

            let private_key_decoded = general_purpose::STANDARD
                .decode(key_bytes_part.as_bytes())
                .map_err(|_| KeyManagerError::InvalidLamportPrivateKey)?;
            let mut private_key = LamportPrivateKey::from_bytes(
                &private_key_decoded,
                public_key.message_bit_length()?,
                public_key.hash_type(),
                None,
                true, // imported: true for imported keys
            )?;

            // Set the spent flag
            if spent {
                private_key.mark_spent();
            }

            return Ok(Some(private_key));
        }

        Ok(None)
    }

    // this index is independent of the index used for key derivation, it is marked when used in a signature
    pub fn check_and_mark_lamport_index_used_derivated(
        &self,
        index: u32,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        // Bitmap with block size of 1024 indices for efficiency
        // Each block represents 1024 indices and uses 128 bytes (1024 bits / 8)

        let block_num = (index as u64) / Self::LAMPORT_CHECK_BLOCK_SIZE;
        let bit_pos = (index as u64) % Self::LAMPORT_CHECK_BLOCK_SIZE;

        let byte_index = (bit_pos / 8) as usize;
        let bit_index = (bit_pos % 8) as u8;

        // Load the block from storage (or create new if doesn't exist)
        let block_key = format!("{}:{}", Self::LAMPORT_INDEX_BLOCK_KEY, block_num);
        let mut block: Vec<u8> = match self.store.get::<String, Vec<u8>>(block_key.clone(), None)? {
            Some(block) => block,
            None => vec![0u8; Self::LAMPORT_CHECK_BLOCK_BYTES], // Create new empty block
        };

        // Validate block size
        if block.len() != Self::LAMPORT_CHECK_BLOCK_BYTES {
            return Err(KeyManagerError::CorruptedLamportIndexBitmap);
        }

        // Check if the bit is already set (index already used)
        let mask = 1u8 << bit_index;
        if block[byte_index] & mask != 0 {
            return Err(KeyManagerError::LamportIndexAlreadyUsed(index));
        }

        // Mark the bit as used
        block[byte_index] |= mask;

        // Store the updated block back to storage
        self.store.set(block_key, block, transaction_id)?;

        Ok(())
    }

    pub fn check_and_mark_lamport_used_imported(
        &self,
        public_key: &LamportPublicKey,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        // Check if the public key is marked as imported
        if !public_key.imported() {
            return Err(KeyManagerError::LamportKeyNotMarkedAsImported);
        }

        // Load the key from storage
        let optional_private_key = self.load_lamport_imported_key(public_key)?;

        // Check if the key exists
        let mut private_key = match optional_private_key {
            Some(key) => key,
            None => return Err(KeyManagerError::LamportPrivateKeyNotFound),
        };

        // Check if the key was already used to sign (spent)
        if private_key.spent() {
            return Err(KeyManagerError::LamportImportedKeyAlreadyUsed);
        }

        // Mark the key as spent
        private_key.mark_spent();

        // Store the updated key
        let pubk = Self::format_lamport_storage_key(public_key);
        let privk = Zeroizing::new(Self::format_lamport_storage_value(&private_key));
        self.store.set(pubk, &(*privk), transaction_id)?;

        Ok(())
    }
}
