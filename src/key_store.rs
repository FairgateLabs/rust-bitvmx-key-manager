use crate::{errors::KeyManagerError, key_type::BitcoinKeyType, rsa::RSAKeyPair};
use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use bitcoin::{PrivateKey, PublicKey};
use rsa::RsaPublicKey;
use std::{rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};

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

    // TODO i inform team: storing key type info

    pub fn new(store: Rc<Storage>) -> Self {
        Self { store }
    }

    pub(crate) fn store_clone(&self) -> Rc<Storage> {
        Rc::clone(&self.store)
    }

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

        let typed_private_key = format!("{}:{}", key_type_str, private_key.to_string());
        self.store.set(key, typed_private_key, None)?;

        Ok(())
    }

    pub fn load_keypair(
        &self,
        public_key: &PublicKey,
    ) -> Result<Option<(PrivateKey, PublicKey, Option<BitcoinKeyType>)>, KeyManagerError> {
        let key = public_key.to_string();
        let data = self.store.get::<String, String>(key)?;

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

    pub fn store_next_keypair_index(&self, key_type: BitcoinKeyType, index: u32) -> Result<(), KeyManagerError> {
        let key_type_str = format!("{:?}", key_type);
        let typed_next_keypair_index_key = format!("{}:{}", key_type_str, Self::NEXT_KEYPAIR_INDEX_KEY);
        // this will store the next keypair index for the given key type eg: p2tr:next_keypair_index
        self.store.set(typed_next_keypair_index_key, index, None)?;
        Ok(())
    }

    pub fn load_next_keypair_index(&self, key_type: BitcoinKeyType) -> Result<u32, KeyManagerError> {
        let key_type_str = format!("{:?}", key_type);
        let typed_next_keypair_index_key = format!("{}:{}", key_type_str, Self::NEXT_KEYPAIR_INDEX_KEY);
        let next_index: u32 = self
            .store
            .get(typed_next_keypair_index_key)?
            .ok_or(KeyManagerError::NextKeypairIndexNotFound)?;
        Ok(next_index)
    }

    pub fn store_next_winternitz_index(&self, index: u32) -> Result<(), KeyManagerError> {
        // best practice: never reuse the index, as it can compromise security, even if the hash type changes
        // this will store the next winternitz index
        self.store.set(Self::NEXT_WINTERNITZ_INDEX_KEY, index, None)?;
        Ok(())
    }

    pub fn load_next_winternitz_index(&self) -> Result<u32, KeyManagerError> {
        let next_index: u32 = self
            .store
            .get(Self::NEXT_WINTERNITZ_INDEX_KEY)?
            .ok_or(KeyManagerError::NextWinternitzIndexNotFound)?;
        Ok(next_index)
    }


    pub fn store_mnemonic(&self, mnemonic: &Mnemonic) -> Result<(), KeyManagerError> {
        let phrase = mnemonic.to_string(); // normalized space-separated phrase
        self.store.set(Self::MNEMONIC_KEY, phrase, None)?;
        Ok(())
    }

    pub fn load_mnemonic(&self) -> Result<Mnemonic, KeyManagerError> {
        let phrase: String = self
            .store
            .get(Self::MNEMONIC_KEY)?
            .ok_or(KeyManagerError::MnemonicNotFound)?;
        let m = Mnemonic::parse(&phrase).map_err(|_| KeyManagerError::InvalidMnemonic)?;
        Ok(m)
    }

    pub fn store_mnemonic_passphrase(&self, passphrase: &str) -> Result<(), KeyManagerError> {
        self.store.set(Self::MNEMONIC_PASSPHRASE_KEY, passphrase.to_string(), None)?;
        Ok(())
    }

    pub fn load_mnemonic_passphrase(&self) -> Result<String, KeyManagerError> {
        let passphrase: String = self
            .store
            .get(Self::MNEMONIC_PASSPHRASE_KEY)?
            .ok_or(KeyManagerError::MnemonicPassphraseNotFound)?;
        Ok(passphrase)
    }

    pub fn store_winternitz_seed(&self, seed: [u8; 32]) -> Result<(), KeyManagerError> {
        self.store.set(Self::WINTERNITZ_KEY, seed, None)?;
        Ok(())
    }

    pub fn load_winternitz_seed(&self) -> Result<[u8; 32], KeyManagerError> {
        let entry = self
            .store
            .get(Self::WINTERNITZ_KEY)?
            .ok_or(KeyManagerError::WinternitzSeedNotFound)?;
        Ok(entry)
    }

    pub fn store_key_derivation_seed(&self, seed: [u8; 64]) -> Result<(), KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let encoded = general_purpose::STANDARD.encode(&seed);
        self.store
            .set(Self::KEY_DERIVATION_SEED_KEY, encoded, None)?;
        Ok(())
    }

    pub fn load_key_derivation_seed(&self) -> Result<[u8; 64], KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let encoded: String = self
            .store
            .get(Self::KEY_DERIVATION_SEED_KEY)?
            .ok_or(KeyManagerError::KeyDerivationSeedNotFound)?;

        let decoded = general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|_| KeyManagerError::CorruptedKeyDerivationSeed)?;

        if decoded.len() != 64 {
            return Err(KeyManagerError::CorruptedKeyDerivationSeed);
        }

        let mut seed = [0u8; 64];
        seed.copy_from_slice(&decoded);
        Ok(seed)
    }

    pub fn store_rsa_key(&self, rsa_key: RSAKeyPair) -> Result<(), KeyManagerError> {
        let pubk = rsa_key.export_public_pem()?;
        let privk = rsa_key.export_private_pem()?;
        self.store.set(pubk, privk, None)?;
        Ok(())
    }

    /// Load an RSA key pair from the store with the given public key in PEM format.
    pub fn load_rsa_key(
        &self,
        rsa_pub_key: RsaPublicKey,
    ) -> Result<Option<RSAKeyPair>, KeyManagerError> {
        let pubk: String = RSAKeyPair::export_public_pem_from_pubk(rsa_pub_key)?;
        let privk = self.store.get::<String, String>(pubk)?;
        if let Some(privk) = privk {
            let rsa_keypair = RSAKeyPair::from_private_pem(&privk)?;
            return Ok(Some(rsa_keypair));
        }
        Ok(None)
    }
}
