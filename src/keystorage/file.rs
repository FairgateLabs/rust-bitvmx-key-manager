use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use bitcoin::{
    hashes::{self, Hash},
    Network, PrivateKey, PublicKey,
};
use cocoon::Cocoon;

use crate::errors::KeyStoreError;

use super::keystore::KeyStore;

const ENTRY_SIZE: u32 = 125; // Size in bytes of each encrypted entry
const KEY_COUNT_SIZE: u32 = 64; // Size in bytes of the encrypted key count
const WINTERNITZ_SEED_SIZE: u32 = 92; // Size in bytes of the encrypted Winternitz seed
const KEY_DERIVATION_SEED_SIZE: u32 = 92; // Size in bytes of the encrypted bip32 key derivation seed

const KEY_COUNT_POSITION: u64 = 0; // Position for the key count
const WINTERNITZ_SEED_POSITION: u64 = KEY_COUNT_SIZE as u64; // Position for the Winternitz seed
const KEY_DERIVATION_SEED_POSITION: u64 = (KEY_COUNT_SIZE + WINTERNITZ_SEED_SIZE) as u64; // Position for the bip32 key derivation seed
const ENTRIES_START_POSITION: u64 =
    (KEY_COUNT_SIZE + WINTERNITZ_SEED_SIZE + KEY_DERIVATION_SEED_SIZE) as u64; // Position for the first entry

pub struct FileKeyStore {
    path: PathBuf,
    network: Network,
    index: HashMap<String, u32>,
    key_count: u32,
    password: Vec<u8>,
}

impl KeyStore for FileKeyStore {
    fn store_keypair(
        &mut self,
        private_key: PrivateKey,
        public_key: PublicKey,
    ) -> Result<(), KeyStoreError> {
        let encoded = self.encode_entry(private_key, public_key);
        let entry = self.encrypt_entry(encoded, ENTRY_SIZE)?;

        self.write_entry(&entry)?;
        self.update_index(public_key, self.key_count);

        self.key_count += 1;
        self.update_key_count()?;

        Ok(())
    }

    fn load_keypair(
        &self,
        public_key: &PublicKey,
    ) -> Result<Option<(PrivateKey, PublicKey)>, KeyStoreError> {
        let key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        let index = self.index.get(&key);

        let entry = match index {
            Some(index) => self.read_entry(index.to_owned())?,
            None => return Ok(None),
        };

        Ok(Some(entry))
    }

    fn store_winternitz_seed(&self, seed: [u8; 32]) -> Result<(), KeyStoreError> {
        let entry = self.encrypt_entry(seed.to_vec(), WINTERNITZ_SEED_SIZE)?;
        self.update_entry_at(&entry, WINTERNITZ_SEED_POSITION)?;

        Ok(())
    }

    fn store_key_derivation_seed(&self, seed: [u8; 32]) -> Result<(), KeyStoreError> {
        let entry = self.encrypt_entry(seed.to_vec(), KEY_DERIVATION_SEED_SIZE)?;
        self.update_entry_at(&entry, KEY_DERIVATION_SEED_POSITION)?;

        Ok(())
    }

    fn load_winternitz_seed(&self) -> Result<[u8; 32], KeyStoreError> {
        let mut storage = OpenOptions::new().read(true).open(&self.path)?;

        storage.seek(SeekFrom::Start(WINTERNITZ_SEED_POSITION))?;

        let mut entry: [u8; WINTERNITZ_SEED_SIZE as usize] = [0; WINTERNITZ_SEED_SIZE as usize];
        let read_amount = storage.read(&mut entry)?;

        assert_eq!(read_amount, WINTERNITZ_SEED_SIZE as usize);

        let encoded = self.decrypt_entry(entry.to_vec())?;

        encoded.try_into().map_err(|_| KeyStoreError::CorruptedData)
    }

    fn load_key_derivation_seed(&self) -> Result<[u8; 32], KeyStoreError> {
        let mut storage = OpenOptions::new().read(true).open(&self.path)?;

        storage.seek(SeekFrom::Start(KEY_DERIVATION_SEED_POSITION))?;

        let mut entry: [u8; KEY_DERIVATION_SEED_SIZE as usize] =
            [0; KEY_DERIVATION_SEED_SIZE as usize];
        let read_amount = storage.read(&mut entry)?;

        assert_eq!(read_amount, KEY_DERIVATION_SEED_SIZE as usize);

        let encoded = self.decrypt_entry(entry.to_vec())?;

        encoded.try_into().map_err(|_| KeyStoreError::CorruptedData)
    }
}

impl FileKeyStore {
    pub fn new<P: AsRef<Path>>(
        path: P,
        password: Vec<u8>,
        network: Network,
    ) -> Result<Self, KeyStoreError> {
        let mut key_storage = FileKeyStore {
            path: path.as_ref().to_path_buf(),
            network,
            index: HashMap::new(),
            key_count: 0,
            password: password.to_vec(),
        };

        key_storage.restore()?;
        Ok(key_storage)
    }

    fn restore_from_file(&mut self) -> Result<(), KeyStoreError> {
        let entry = self.read_key_count()?;
        let encoded = self.decrypt_key_count(entry)?;
        let index: u32 = u32::from_be_bytes(encoded);

        self.key_count = index;

        for i in 0..self.key_count {
            self.restore_index(i)?;
        }

        Ok(())
    }

    fn read_entry(&self, entry_index: u32) -> Result<(PrivateKey, PublicKey), KeyStoreError> {
        let entry = self.read_encrypted(entry_index)?;
        let encoded = self.decrypt_entry(entry)?;

        self.decode_entry(encoded.to_vec())
    }

    fn read_encrypted(&self, entry_index: u32) -> Result<Vec<u8>, KeyStoreError> {
        let position = ENTRIES_START_POSITION + (entry_index * ENTRY_SIZE) as u64;

        let mut storage = File::open(&self.path)?;
        storage.seek(SeekFrom::Start(position))?;

        let mut entry: [u8; ENTRY_SIZE as usize] = [0; ENTRY_SIZE as usize];
        let read_amount = storage.read(&mut entry)?;

        assert_eq!(read_amount, ENTRY_SIZE as usize);

        Ok(entry.to_vec())
    }

    fn write_entry(&mut self, entry: &[u8]) -> Result<(), KeyStoreError> {
        let mut storage = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;

        let write_amount = storage.write(entry)?;

        assert_eq!(write_amount, entry.len());

        Ok(())
    }

    fn read_key_count(&self) -> Result<Vec<u8>, KeyStoreError> {
        let mut storage = OpenOptions::new().read(true).open(&self.path)?;

        storage.seek(SeekFrom::Start(KEY_COUNT_POSITION))?;

        let mut entry: [u8; KEY_COUNT_SIZE as usize] = [0; KEY_COUNT_SIZE as usize];
        let read_amount = storage.read(&mut entry)?;

        assert_eq!(read_amount, KEY_COUNT_SIZE as usize);

        Ok(entry.to_vec())
    }

    fn update_key_count(&mut self) -> Result<(), KeyStoreError> {
        let encoded = self.key_count.to_be_bytes().to_vec();
        let count = self.encrypt_entry(encoded, KEY_COUNT_SIZE)?;
        self.update_entry_at(&count, KEY_COUNT_POSITION)?;
        Ok(())
    }

    fn update_entry_at(&self, entry: &[u8], position: u64) -> Result<(), KeyStoreError> {
        let mut storage = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)?;

        storage.seek(SeekFrom::Start(position))?;
        let write_amount = storage.write(entry)?;

        assert_eq!(write_amount, entry.len());
        Ok(())
    }

    fn encode_entry(&self, sk: PrivateKey, pk: PublicKey) -> Vec<u8> {
        let private_key_bytes = sk.to_bytes();
        let public_key_bytes = pk.to_bytes();

        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&public_key_bytes);
        encoded.extend_from_slice(&private_key_bytes);

        encoded
    }

    fn decode_entry(&self, data: Vec<u8>) -> Result<(PrivateKey, PublicKey), KeyStoreError> {
        let public_key_bytes = &data[0..33];
        let private_key_bytes = &data[33..];

        let private_key = PrivateKey::from_slice(private_key_bytes, self.network)?;
        let public_key = PublicKey::from_slice(public_key_bytes)?;

        Ok((private_key, public_key))
    }

    fn encrypt_entry(&self, entry: Vec<u8>, size: u32) -> Result<Vec<u8>, KeyStoreError> {
        let mut entry_cursor: Cursor<Vec<u8>> = Cursor::new(vec![0; size as usize]);
        let mut cocoon = Cocoon::new(self.password.as_slice());
        cocoon
            .dump(entry, &mut entry_cursor)
            .map_err(|error| KeyStoreError::FailedToEncryptData { error })?;
        Ok(entry_cursor.into_inner())
    }

    fn decrypt_entry(&self, entry: Vec<u8>) -> Result<Vec<u8>, KeyStoreError> {
        let mut entry_cursor = Cursor::new(entry);

        let cocoon = Cocoon::new(self.password.as_slice());
        cocoon
            .parse(&mut entry_cursor)
            .map_err(|error| KeyStoreError::FailedToDecryptData { error })
    }

    fn decrypt_key_count(&self, count: Vec<u8>) -> Result<[u8; 4], KeyStoreError> {
        let mut entry_cursor: Cursor<Vec<u8>> = Cursor::new(count);
        let cocoon = Cocoon::new(self.password.as_slice());
        let encoded = cocoon
            .parse(&mut entry_cursor)
            .map_err(|error| KeyStoreError::FailedToDecryptData { error })?;

        encoded.try_into().map_err(|_| KeyStoreError::CorruptedData)
    }

    fn update_index(&mut self, public_key: PublicKey, position: u32) {
        let pk_key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        self.index.insert(pk_key, position);
    }

    fn restore_index(&mut self, entry_index: u32) -> Result<(), KeyStoreError> {
        let (_, public_key) = self.read_entry(entry_index)?;

        let pk_key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        self.index.insert(pk_key, entry_index);
        Ok(())
    }

    fn restore(&mut self) -> Result<(), KeyStoreError> {
        if Path::new(&self.path).exists() {
            self.restore_from_file()?;
        } else {
            self.update_key_count()?;
        }

        Ok(())
    }
}
