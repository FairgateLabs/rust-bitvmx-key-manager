use crate::{
    errors::KeyManagerError,
    key_type::BitcoinKeyType,
    lamport::{LamportPrivateKey, LamportPubKeyId, LamportPublicKey, LamportType},
    rsa::RSAKeyPair,
    winternitz::WinternitzType,
};
use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use bitcoin::{PrivateKey, PublicKey};
use rsa::RsaPublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{rc::Rc, str::FromStr};
use storage_backend::{key::StorageKey, storage::Storage};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Value stored under an RSA key's storage key. The key itself is a BLAKE3
/// fingerprint of the public PEM (see `KeyStore::rsa_key`), so unlike before,
/// the public PEM is no longer recoverable from the key text alone and must
/// be stored alongside the private PEM.
#[derive(Serialize, Deserialize)]
pub struct StoredRsaKeyPair {
    pub public_key_pem: String,
    pub private_key_pem: String,
}

/// Issue-time metadata of a Winternitz key, stored under `key_manager/winternitz_key/<index>`.
///
/// Signing checks every request against this record before the index is marked as used, so a
/// request of another hash type or message size, or for an index that was never issued, is
/// rejected instead of burning the index.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WinternitzKeyRecord {
    pub key_type: WinternitzType,
    pub message_size: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct OtsUsageRecord {
    canonical_value: Vec<u8>,
    bit_length: usize,
    lamport_type: Option<LamportType>,
}

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
    const UNKNOWN_TYPE: &str = "unknown"; // Key type string for unknown/unspecified key types
    const LAMPORT: &str = "lamport"; // Value tag inside the stored payload, NOT a storage key

    fn key_manager_key<'a>(
        component: &str,
        tail: impl IntoIterator<Item = &'a str>,
    ) -> Result<StorageKey, KeyManagerError> {
        Ok(StorageKey::new(
            ["key_manager", component]
                .into_iter()
                .map(str::to_string)
                .chain(tail.into_iter().map(str::to_string)),
        )?)
    }

    fn seed_key<'a>(
        tail: impl IntoIterator<Item = &'a str>,
    ) -> Result<StorageKey, KeyManagerError> {
        Self::key_manager_key("seed", tail)
    }

    fn index_key<'a>(
        tail: impl IntoIterator<Item = &'a str>,
    ) -> Result<StorageKey, KeyManagerError> {
        Self::key_manager_key("index", tail)
    }

    fn mnemonic_key() -> Result<StorageKey, KeyManagerError> {
        Self::seed_key(["bip39_mnemonic"])
    }

    fn mnemonic_passphrase_key() -> Result<StorageKey, KeyManagerError> {
        Self::seed_key(["bip39_mnemonic_passphrase"])
    }

    fn winternitz_seed_key() -> Result<StorageKey, KeyManagerError> {
        Self::seed_key(["winternitz"])
    }

    fn lamport_seed_key() -> Result<StorageKey, KeyManagerError> {
        Self::seed_key(["lamport"])
    }

    fn key_derivation_seed_key() -> Result<StorageKey, KeyManagerError> {
        Self::seed_key(["bip32"])
    }

    fn next_keypair_index_key(key_type_str: &str) -> Result<StorageKey, KeyManagerError> {
        Self::index_key(["keypair", key_type_str])
    }

    fn next_winternitz_index_key() -> Result<StorageKey, KeyManagerError> {
        Self::index_key(["winternitz"])
    }

    fn next_lamport_index_key() -> Result<StorageKey, KeyManagerError> {
        Self::index_key(["lamport"])
    }

    fn winternitz_key_record_key(index: u32) -> Result<StorageKey, KeyManagerError> {
        let index_str = index.to_string();
        Self::key_manager_key("winternitz_key", [index_str.as_str()])
    }

    fn winternitz_usage_key(index: u32) -> Result<StorageKey, KeyManagerError> {
        let index_str = index.to_string();
        Self::key_manager_key("winternitz_usage", [index_str.as_str()])
    }

    fn lamport_usage_key(index: u32) -> Result<StorageKey, KeyManagerError> {
        let index_str = index.to_string();
        Self::key_manager_key("lamport_usage", [index_str.as_str()])
    }

    /// BLAKE3 fingerprint of an RSA public PEM, used as the storage-key segment.
    /// The PEM itself can't be a segment (or even a whole key): its base64 body
    /// routinely contains `/`, and it's large.
    fn rsa_key_fingerprint(public_key_pem: &str) -> String {
        blake3::hash(public_key_pem.as_bytes()).to_hex().to_string()
    }

    fn rsa_key(public_key_pem: &str) -> Result<StorageKey, KeyManagerError> {
        Self::key_manager_key("rsa", [Self::rsa_key_fingerprint(public_key_pem).as_str()])
    }

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
        let key = StorageKey::try_from(public_key.to_string())?;

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
        Ok(self.store.get(StorageKey::from_joined(key)?, None)?)
    }

    pub fn load_keypair(
        &self,
        public_key: &PublicKey,
    ) -> Result<Option<(PrivateKey, PublicKey, Option<BitcoinKeyType>)>, KeyManagerError> {
        let key = StorageKey::try_from(public_key.to_string())?;
        let data: Option<Zeroizing<String>> =
            self.store.get::<String>(key, None)?.map(Zeroizing::new);

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
        let key_type_str = format!("{:?}", key_type).to_lowercase();
        let key = Self::next_keypair_index_key(&key_type_str)?;
        self.store.set(key, index, transaction_id)?;
        Ok(())
    }

    pub fn load_next_keypair_index(
        &self,
        key_type: BitcoinKeyType,
    ) -> Result<u32, KeyManagerError> {
        let key_type_str = format!("{:?}", key_type).to_lowercase();
        let key = Self::next_keypair_index_key(&key_type_str)?;
        match self.store.get(key, None)? {
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
            .set(Self::next_winternitz_index_key()?, index, transaction_id)?;
        Ok(())
    }

    pub fn store_winternitz_key_record(
        &self,
        index: u32,
        record: &WinternitzKeyRecord,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        self.store.set(
            Self::winternitz_key_record_key(index)?,
            record,
            transaction_id,
        )?;
        Ok(())
    }

    pub fn load_winternitz_key_record(
        &self,
        index: u32,
    ) -> Result<Option<WinternitzKeyRecord>, KeyManagerError> {
        Ok(self
            .store
            .get(Self::winternitz_key_record_key(index)?, None)?)
    }

    pub fn load_next_winternitz_index(&self) -> Result<u32, KeyManagerError> {
        match self.store.get(Self::next_winternitz_index_key()?, None)? {
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
            .set(Self::next_lamport_index_key()?, index, transaction_id)?;
        Ok(())
    }

    pub fn load_next_lamport_index(&self) -> Result<u32, KeyManagerError> {
        match self.store.get(Self::next_lamport_index_key()?, None)? {
            Some(next_index) => Ok(next_index),
            None => Err(KeyManagerError::NextLamportIndexNotFound),
        }
    }

    pub fn store_mnemonic(&self, mnemonic: &Mnemonic) -> Result<(), KeyManagerError> {
        let phrase = Zeroizing::new(mnemonic.to_string()); // normalized space-separated phrase
        self.store.set(Self::mnemonic_key()?, &(*phrase), None)?;
        Ok(())
    }

    pub fn load_mnemonic(&self) -> Result<Mnemonic, KeyManagerError> {
        let phrase: Zeroizing<String> = match self.store.get(Self::mnemonic_key()?, None)? {
            Some(phrase) => Zeroizing::new(phrase),
            None => return Err(KeyManagerError::MnemonicNotFound),
        };
        let m = Mnemonic::parse(&*phrase).map_err(|_| KeyManagerError::InvalidMnemonic)?;
        Ok(m)
    }

    pub fn store_mnemonic_passphrase(&self, passphrase: &str) -> Result<(), KeyManagerError> {
        self.store
            .set(Self::mnemonic_passphrase_key()?, passphrase, None)?;
        Ok(())
    }

    pub fn load_mnemonic_passphrase(&self) -> Result<Zeroizing<String>, KeyManagerError> {
        match self.store.get(Self::mnemonic_passphrase_key()?, None)? {
            Some(passphrase) => Ok(Zeroizing::new(passphrase)),
            None => Err(KeyManagerError::MnemonicPassphraseNotFound),
        }
    }

    pub fn store_winternitz_seed(&self, seed: Zeroizing<[u8; 32]>) -> Result<(), KeyManagerError> {
        self.store.set(Self::winternitz_seed_key()?, *seed, None)?;
        Ok(())
    }

    pub fn load_winternitz_seed(&self) -> Result<Zeroizing<[u8; 32]>, KeyManagerError> {
        match self.store.get(Self::winternitz_seed_key()?, None)? {
            Some(entry) => Ok(Zeroizing::new(entry)),
            None => Err(KeyManagerError::WinternitzSeedNotFound),
        }
    }

    pub fn store_lamport_seed(&self, seed: Zeroizing<[u8; 32]>) -> Result<(), KeyManagerError> {
        self.store.set(Self::lamport_seed_key()?, *seed, None)?;
        Ok(())
    }

    pub fn load_lamport_seed(&self) -> Result<Zeroizing<[u8; 32]>, KeyManagerError> {
        match self.store.get(Self::lamport_seed_key()?, None)? {
            Some(entry) => Ok(Zeroizing::new(entry)),
            None => Err(KeyManagerError::LamportSeedNotFound),
        }
    }

    pub fn check_and_record_winternitz_usage(
        &self,
        index: u32,
        message: &[u8],
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        let usage_key = Self::winternitz_usage_key(index)?;
        let requested = OtsUsageRecord {
            canonical_value: message.to_vec(),
            bit_length: message.len().saturating_mul(8),
            lamport_type: None,
        };

        if let Some(stored) = self
            .store
            .get::<OtsUsageRecord>(&usage_key, transaction_id)?
        {
            return if stored == requested {
                Ok(())
            } else {
                Err(KeyManagerError::WinternitzIndexAlreadyUsed(index))
            };
        }

        self.store.set(usage_key, requested, transaction_id)?;
        Ok(())
    }

    pub fn store_key_derivation_seed(
        &self,
        seed: Zeroizing<[u8; 64]>,
    ) -> Result<(), KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let mut encoded = general_purpose::STANDARD.encode(*seed);
        self.store
            .set(Self::key_derivation_seed_key()?, &encoded, None)?;
        encoded.zeroize();
        Ok(())
    }

    pub fn load_key_derivation_seed(&self) -> Result<Zeroizing<[u8; 64]>, KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let encoded: Option<Zeroizing<String>> = self
            .store
            .get::<String>(Self::key_derivation_seed_key()?, None)?
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
        let key = Self::rsa_key(&pubk)?;
        let value = StoredRsaKeyPair {
            public_key_pem: pubk,
            private_key_pem: (*privk).clone(),
        };
        self.store.set(key, value, None)?;
        Ok(())
    }

    /// Load an RSA key pair from the store with the given public key in PEM format.
    pub fn load_rsa_key(
        &self,
        rsa_pub_key: RsaPublicKey,
    ) -> Result<Option<RSAKeyPair>, KeyManagerError> {
        let pubk: String = RSAKeyPair::export_public_pem_from_pubk(rsa_pub_key)?;
        let key = Self::rsa_key(&pubk)?;
        let stored: Option<StoredRsaKeyPair> = self.store.get(key, None)?;

        if let Some(stored) = stored {
            let privk = Zeroizing::new(stored.private_key_pem);
            let rsa_keypair = RSAKeyPair::from_private_pem(&privk)?;
            return Ok(Some(rsa_keypair));
        }

        Ok(None)
    }

    // Blake3 fingerprint justification: the full LamportPublicKey can be large; using its
    // BLAKE3 hash as the storage key avoids rocksdb performance issues with big keys.
    fn format_lamport_storage_key<K: LamportPubKeyId>(
        key: &K,
    ) -> Result<StorageKey, KeyManagerError> {
        let fingerprint = key.key_id().to_hex().to_string();
        Self::key_manager_key("lamport", [fingerprint.as_str()])
    }

    fn format_lamport_storage_value(private_key: &LamportPrivateKey) -> String {
        format!(
            "{}:{}:false",
            Self::LAMPORT,
            general_purpose::STANDARD.encode(private_key.to_bytes()),
        )
    }

    fn format_used_lamport_storage_value(
        private_key: &LamportPrivateKey,
        usage: &OtsUsageRecord,
    ) -> String {
        format!(
            "{}:{}:true:{}:{}",
            Self::LAMPORT,
            general_purpose::STANDARD.encode(private_key.to_bytes()),
            usage.bit_length,
            general_purpose::STANDARD.encode(&usage.canonical_value),
        )
    }

    // we are not storing derived keys
    pub fn store_lamport_imported_key(
        &self,
        private_key: &LamportPrivateKey,
        public_key: &LamportPublicKey,
    ) -> Result<(), KeyManagerError> {
        let pubk = Self::format_lamport_storage_key(public_key)?;
        let existing = self.store.get::<String>(&pubk, None)?.map(Zeroizing::new);
        if existing.is_some() {
            return Ok(());
        }

        let privk = Zeroizing::new(Self::format_lamport_storage_value(private_key));
        self.store.set(pubk, &(*privk), None)?;
        Ok(())
    }

    fn load_lamport_imported_record<K: LamportPubKeyId>(
        &self,
        public_key: &K,
        transaction_id: Option<Uuid>,
    ) -> Result<Option<(LamportPrivateKey, Option<OtsUsageRecord>)>, KeyManagerError> {
        let pubk = Self::format_lamport_storage_key(public_key)?;
        let privk: Option<Zeroizing<String>> = self
            .store
            .get::<String>(pubk, transaction_id)?
            .map(Zeroizing::new);

        let Some(privk) = privk else {
            return Ok(None);
        };
        let parts: Vec<&str> = privk.split(':').collect();
        if !matches!(parts.len(), 3 | 5) || parts[0] != Self::LAMPORT {
            return Err(KeyManagerError::InvalidLamportPrivateKey);
        }

        let used = match (parts.len(), parts[2]) {
            (3, "false") => false,
            (5, "true") => true,
            _ => return Err(KeyManagerError::InvalidLamportPrivateKey),
        };
        let expected_bit_length = public_key.message_bit_length()?;
        let private_key_decoded = general_purpose::STANDARD
            .decode(parts[1].as_bytes())
            .map_err(|_| KeyManagerError::InvalidLamportPrivateKey)?;
        let mut private_key = LamportPrivateKey::from_bytes(
            &private_key_decoded,
            expected_bit_length,
            public_key.hash_type(),
            None,
            true,
        )?;
        if used {
            private_key.mark_spent();
        }

        let usage = if used {
            let bit_length = parts[3]
                .parse::<usize>()
                .map_err(|_| KeyManagerError::InvalidLamportPrivateKey)?;
            let canonical_value = general_purpose::STANDARD
                .decode(parts[4].as_bytes())
                .map_err(|_| KeyManagerError::InvalidLamportPrivateKey)?;
            if bit_length != expected_bit_length || canonical_value.len() != bit_length.div_ceil(8)
            {
                return Err(KeyManagerError::InvalidLamportPrivateKey);
            }

            Some(OtsUsageRecord {
                canonical_value,
                bit_length,
                lamport_type: Some(public_key.hash_type()),
            })
        } else {
            None
        };

        Ok(Some((private_key, usage)))
    }

    // we are not storing derived keys
    pub fn load_lamport_imported_key<K: LamportPubKeyId>(
        &self,
        public_key: &K,
    ) -> Result<Option<LamportPrivateKey>, KeyManagerError> {
        Ok(self
            .load_lamport_imported_record(public_key, None)?
            .map(|(private_key, _)| private_key))
    }

    pub fn check_and_record_lamport_usage(
        &self,
        index: u32,
        key_type: LamportType,
        canonical_value: &[u8],
        bit_length: usize,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        let usage_key = Self::lamport_usage_key(index)?;
        let requested = OtsUsageRecord {
            canonical_value: canonical_value.to_vec(),
            bit_length,
            lamport_type: Some(key_type),
        };

        if let Some(stored) = self
            .store
            .get::<OtsUsageRecord>(&usage_key, transaction_id)?
        {
            return if stored == requested {
                Ok(())
            } else {
                Err(KeyManagerError::LamportIndexAlreadyUsed(index))
            };
        }

        self.store.set(usage_key, requested, transaction_id)?;
        Ok(())
    }

    pub fn check_and_record_lamport_imported_usage(
        &self,
        public_key: &LamportPublicKey,
        canonical_value: &[u8],
        bit_length: usize,
        transaction_id: Option<Uuid>,
    ) -> Result<(), KeyManagerError> {
        if !public_key.imported() {
            return Err(KeyManagerError::LamportKeyNotMarkedAsImported);
        }

        let (private_key, stored_usage) = self
            .load_lamport_imported_record(public_key, transaction_id)?
            .ok_or(KeyManagerError::LamportPrivateKeyNotFound)?;
        let requested = OtsUsageRecord {
            canonical_value: canonical_value.to_vec(),
            bit_length,
            lamport_type: Some(public_key.hash_type()),
        };

        if let Some(stored) = stored_usage {
            return if stored == requested {
                Ok(())
            } else {
                Err(KeyManagerError::LamportImportedKeyAlreadyUsed)
            };
        }

        let pubk = Self::format_lamport_storage_key(public_key)?;
        let privk = Zeroizing::new(Self::format_used_lamport_storage_value(
            &private_key,
            &requested,
        ));
        self.store.set(pubk, &(*privk), transaction_id)?;
        Ok(())
    }
}
