use crate::{errors::KeyManagerError, key_type::BitcoinKeyType, rsa::RSAKeyPair};
use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use bitcoin::{PrivateKey, PublicKey};
use rsa::RsaPublicKey;
use std::{rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub struct KeyStore {
    store: Rc<Storage>,
}

impl KeyStore {
    const MNEMONIC_KEY: &str = "bip39_mnemonic"; // Key for the BIP-39 mnemonic
    const MNEMONIC_PASSPHRASE_KEY: &str = "bip39_mnemonic_passphrase"; // Key for the BIP-39 mnemonic passphrase
    const WINTERNITZ_KEY: &str = "winternitz_seed"; // Key to use in the database for the Winternitz seed
    const KEY_DERIVATION_SEED_KEY: &str = "bip32_seed"; // Key to use in the database for the bip32 key derivation seed
    const UNKNOWN_TYPE: &str = "unknown"; // Key type string for unknown/unspecified key types
    const NEXT_KEYPAIR_INDEX_KEY: &str = "next_keypair_index"; // Key for storing the next keypair index
    const NEXT_WINTERNITZ_INDEX_KEY: &str = "next_winternitz_index"; // Key for storing the next winternitz index
    const WINTERNITZ_INDEX_BLOCK_KEY: &str = "winternitz_index_block"; // Key prefix for Winternitz index bitmap blocks
    // TODO adjust block size to optimize storage, according to the estimation of max winternitz keys needed
    const WOTS_CHECK_BLOCK_SIZE: u64 = 1024; // Number of indices per bitmap block
    const WOTS_CHECK_BLOCK_BYTES: usize = (Self::WOTS_CHECK_BLOCK_SIZE / 8) as usize; // 128 bytes per block

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
            .map_err(|e| KeyManagerError::from(e))
    }

    pub fn rollback_transaction(&self, transaction_id: Uuid) -> Result<(), KeyManagerError> {
        self.store
            .rollback_transaction(transaction_id)
            .map_err(|e| KeyManagerError::from(e))
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

        let typed_private_key =
            Zeroizing::new(format!("{}:{}", key_type_str, private_key.to_string()));
        self.store.set(key, (*typed_private_key).clone(), None)?;

        Ok(())
    }

    pub fn load_keypair(
        &self,
        public_key: &PublicKey,
    ) -> Result<Option<(PrivateKey, PublicKey, Option<BitcoinKeyType>)>, KeyManagerError> {
        let key = public_key.to_string();
        let data: Option<Zeroizing<String>> =
            self.store.get::<String, String>(key)?.map(Zeroizing::new);

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
    ) -> Result<(), KeyManagerError> {
        let key_type_str = format!("{:?}", key_type);
        let typed_next_keypair_index_key =
            format!("{}:{}", key_type_str, Self::NEXT_KEYPAIR_INDEX_KEY);
        // this will store the next keypair index for the given key type e.g.: p2tr:next_keypair_index
        self.store.set(typed_next_keypair_index_key, index, None)?;
        Ok(())
    }

    pub fn load_next_keypair_index(
        &self,
        key_type: BitcoinKeyType,
    ) -> Result<u32, KeyManagerError> {
        let key_type_str = format!("{:?}", key_type);
        let typed_next_keypair_index_key =
            format!("{}:{}", key_type_str, Self::NEXT_KEYPAIR_INDEX_KEY);
        match self.store.get(typed_next_keypair_index_key)? {
            Some(next_index) => Ok(next_index),
            None => Err(KeyManagerError::NextKeypairIndexNotFound),
        }
    }

    pub fn store_next_winternitz_index(&self, index: u32) -> Result<(), KeyManagerError> {
        // best practice: never reuse the index, as it can compromise security, even if the hash type changes
        // this will store the next winternitz index
        self.store
            .set(Self::NEXT_WINTERNITZ_INDEX_KEY, index, None)?;
        Ok(())
    }

    pub fn load_next_winternitz_index(&self) -> Result<u32, KeyManagerError> {
        match self.store.get(Self::NEXT_WINTERNITZ_INDEX_KEY)? {
            Some(next_index) => Ok(next_index),
            None => Err(KeyManagerError::NextWinternitzIndexNotFound),
        }
    }

    pub fn store_mnemonic(&self, mnemonic: &Mnemonic) -> Result<(), KeyManagerError> {
        let phrase = Zeroizing::new(mnemonic.to_string()); // normalized space-separated phrase
        self.store.set(Self::MNEMONIC_KEY, &(*phrase), None)?;
        Ok(())
    }

    pub fn load_mnemonic(&self) -> Result<Mnemonic, KeyManagerError> {
        let phrase: Zeroizing<String> = match self.store.get(Self::MNEMONIC_KEY)? {
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
        match self.store.get(Self::MNEMONIC_PASSPHRASE_KEY)? {
            Some(passphrase) => Ok(Zeroizing::new(passphrase)),
            None => Err(KeyManagerError::MnemonicPassphraseNotFound),
        }
    }

    pub fn store_winternitz_seed(&self, seed: Zeroizing<[u8; 32]>) -> Result<(), KeyManagerError> {
        self.store.set(Self::WINTERNITZ_KEY, *seed, None)?;
        Ok(())
    }

    pub fn load_winternitz_seed(&self) -> Result<Zeroizing<[u8; 32]>, KeyManagerError> {
        match self.store.get(Self::WINTERNITZ_KEY)? {
            Some(entry) => Ok(Zeroizing::new(entry)),
            None => Err(KeyManagerError::WinternitzSeedNotFound),
        }
    }

    // this index is independent of the index used for key derivation, it is marked when used in a signature
    pub fn check_and_mark_winternitz_index_used(
        &self,
        index: u32,
        transaction_id: Option<Uuid>,
    ) -> Result<(),KeyManagerError> {
        // Bitmap with block size of 1024 indices for efficiency
        // Each block represents 1024 indices and uses 128 bytes (1024 bits / 8)

        let block_num = (index as u64) / Self::WOTS_CHECK_BLOCK_SIZE;
        let bit_pos = (index as u64) % Self::WOTS_CHECK_BLOCK_SIZE;

        let byte_index = (bit_pos / 8) as usize;
        let bit_index = (bit_pos % 8) as u8;

        // Load the block from storage (or create new if doesn't exist)
        let block_key = format!("{}:{}", Self::WINTERNITZ_INDEX_BLOCK_KEY, block_num);
        let mut block: Vec<u8> = match self.store.get::<String, Vec<u8>>(block_key.clone())? {
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
        let mut encoded = general_purpose::STANDARD.encode(&(*seed));
        self.store
            .set(Self::KEY_DERIVATION_SEED_KEY, &encoded, None)?;
        encoded.zeroize();
        Ok(())
    }

    pub fn load_key_derivation_seed(&self) -> Result<Zeroizing<[u8; 64]>, KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let encoded: Option<Zeroizing<String>> = self
            .store
            .get::<String, String>(Self::KEY_DERIVATION_SEED_KEY.to_string())?
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
        let privk: Option<Zeroizing<String>> =
            self.store.get::<String, String>(pubk)?.map(Zeroizing::new);

        if let Some(privk) = privk {
            let rsa_keypair = RSAKeyPair::from_private_pem(&privk)?;
            return Ok(Some(rsa_keypair));
        }

        Ok(None)
    }
}
