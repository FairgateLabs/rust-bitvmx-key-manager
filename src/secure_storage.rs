use std::{collections::HashMap, fs::{File, OpenOptions}, io::{Cursor, Read, Seek, SeekFrom, Write}, path::{Path, PathBuf}};

use bitcoin::{hashes::{self, Hash}, Network, PrivateKey, PublicKey};
use cocoon::Cocoon;

use crate::helper::{SecureStorageError, SecureStorageError::*};

// Size in bytes of each encrypted entry in storage
const ENTRY_SIZE: u32 = 157;

// Size in bytes of the encrypted key count in storage
const KEY_COUNT_SIZE: u32 = 64;

// Size in bytes of the encrypted winternitz secret in storage
const WINTER_SIZE: u32 = 32 + 60; 
pub struct SecureStorage {
    path: PathBuf, 
    network: Network,
    index_by_label: HashMap<String, u32>,
    index_by_public_key: HashMap<String, u32>,
    key_count: u32,
    password: Vec<u8>,
}

impl SecureStorage {
    pub fn new<P: AsRef<Path>>(path: P, password: Vec<u8>, network: Network) -> Result<Self, SecureStorageError> {
        let mut secure_storage = SecureStorage { 
            path: path.as_ref().to_path_buf(), 
            network, 
            index_by_label: HashMap::new(),
            index_by_public_key: HashMap::new(),
            key_count: 0,
            password: password.to_vec(),
        };
        
        secure_storage.restore()?;
        Ok(secure_storage)
    }

    pub fn store_keypair(&mut self, label: &str, private_key: PrivateKey, public_key: PublicKey) -> Result<(), SecureStorageError>{
        let encoded = self.encode_entry(label, private_key, public_key);  
        let entry = self.encrypt_entry(encoded, ENTRY_SIZE)?;

        self.write_entry(&entry)?;
        self.update_indexes(label, public_key, self.key_count);

        self.key_count += 1;
        self.update_key_count()?;

        Ok(())
    }

    pub fn store_winternitz_secret(&self, master_secret: [u8; 32]) -> Result<(), SecureStorageError>{
        let entry = self.encrypt_entry(master_secret.to_vec(), WINTER_SIZE)?;
        self.update_entry_at(&entry, KEY_COUNT_SIZE as u64)?;
        Ok(())
    }

    pub fn load_winternitz_secret(&self) -> Result<[u8; 32], SecureStorageError> {
        let pos = KEY_COUNT_SIZE as u64; // Position for the second row
    
        let mut storage = OpenOptions::new()
            .read(true)
            .open(&self.path)?;
    
        storage.seek(SeekFrom::Start(pos))?;
    
        let mut entry: [u8; WINTER_SIZE as usize] = [0; WINTER_SIZE as usize];
        let read_amount = storage.read(&mut entry)?;

        assert_eq!(read_amount, WINTER_SIZE as usize);
    
        let encoded = self.decrypt_entry(entry.to_vec())?;

        encoded.try_into().map_err(|_| CorruptedData)
    }

    pub fn load_keypair(&self, public_key: &PublicKey) -> Result<Option<(String, PrivateKey, PublicKey)>, SecureStorageError> {
        let key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        let index = self.index_by_public_key.get(&key);

        let entry = match index {
            Some(index) => self.read_entry(index.to_owned())?,
            None => return Ok(None),
        };

        Ok(Some(entry))
    }

    pub fn load_keypair_by_label(&self, label: &str) -> Result<Option<(String, PrivateKey, PublicKey)>, SecureStorageError> {
        let key = hashes::sha256::Hash::hash(label.as_bytes()).to_string();
        let index = self.index_by_label.get(&key);

        let entry = match index {
            Some(index) => self.read_entry(index.to_owned())?,
            None => return Ok(None),
        };

        Ok(Some(entry))
    }

    fn restore_from_file(&mut self) -> Result<(), SecureStorageError> {
        let entry = self.read_key_count()?;
        let encoded = self.decrypt_key_count(entry)?;
        let index: u32 = u32::from_be_bytes(encoded);

        self.key_count = index;

        for i in 0..self.key_count {
            self.restore_indexes(i)?;
        }

        Ok(())
    }

    fn read_entry(&self, entry_index: u32) -> Result<(String, PrivateKey, PublicKey), SecureStorageError> {
        let entry = self.read_encrypted(entry_index)?;
        let encoded = self.decrypt_entry(entry)?;

        self.decode_entry(encoded.to_vec())
    }

    fn read_encrypted(&self, entry_index: u32) -> Result<Vec<u8>, SecureStorageError>{
        let position = (KEY_COUNT_SIZE + WINTER_SIZE + entry_index * ENTRY_SIZE) as u64;

        let mut storage = File::open(&self.path)?;
        storage.seek(SeekFrom::Start(position))?;

        let mut entry: [u8; ENTRY_SIZE as usize] = [0; ENTRY_SIZE as usize];
        let read_amount = storage.read(&mut entry)?;

        assert_eq!(read_amount, ENTRY_SIZE as usize);

        Ok(entry.to_vec())
    }

    fn write_entry(&mut self, entry: &[u8]) -> Result<(), SecureStorageError> {
        let mut storage = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;

        let write_amount = storage.write(entry)?;

        assert_eq!(write_amount, entry.len());

        Ok(())
    }

    fn read_key_count(&self) -> Result<Vec<u8>, SecureStorageError> {
        let mut storage = OpenOptions::new()
            .read(true)
            .open(&self.path)?;

        storage.seek(SeekFrom::Start(0))?;

        let mut entry: [u8; KEY_COUNT_SIZE as usize] = [0; KEY_COUNT_SIZE as usize];
        let read_amount = storage.read(&mut entry)?;

        assert_eq!(read_amount, KEY_COUNT_SIZE as usize);

        Ok(entry.to_vec())
    }

    fn update_key_count(&mut self) -> Result<(), SecureStorageError> {
        let encoded = self.key_count.to_be_bytes().to_vec();
        let count = self.encrypt_entry(encoded, KEY_COUNT_SIZE)?;
        self.update_entry_at(&count, 0)?;
        Ok(())
    }

    fn update_entry_at(&self, entry: &[u8], position: u64) -> Result<(), SecureStorageError>{
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

    fn encode_entry(&self, label: &str, sk: PrivateKey, pk: PublicKey) -> Vec<u8> {
        let label_hash_bytes = hashes::sha256::Hash::hash(label.as_bytes()).as_byte_array().to_vec();
        let private_key_bytes = sk.to_bytes();
        let public_key_bytes = pk.to_bytes();

        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&label_hash_bytes);
        encoded.extend_from_slice(&public_key_bytes);
        encoded.extend_from_slice(&private_key_bytes);

        encoded
    }   

    fn decode_entry(&self, data: Vec<u8>) -> Result<(String, PrivateKey, PublicKey), SecureStorageError> {
        let label_hash_bytes = &data[0..32];
        let public_key_bytes = &data[32..65];
        let private_key_bytes = &data[65..];

        let label_hash = hashes::sha256::Hash::from_slice(label_hash_bytes)?;
        let private_key = PrivateKey::from_slice(private_key_bytes, self.network)?;
        let public_key = PublicKey::from_slice(public_key_bytes)?;

        Ok((label_hash.to_string(), private_key, public_key))
    }

    fn encrypt_entry(&self, entry: Vec<u8>, size: u32) -> Result<Vec<u8>, SecureStorageError>{
        let mut entry_cursor: Cursor<Vec<u8>> = Cursor::new(vec![0; size as usize]);
        let mut cocoon = Cocoon::new(self.password.as_slice());
        cocoon.dump(entry, &mut entry_cursor).map_err( |error| FailedToEncryptData{ error })?;
        Ok(entry_cursor.into_inner())
    }

    fn decrypt_entry(&self, entry: Vec<u8>) -> Result<Vec<u8>, SecureStorageError> {
        let mut entry_cursor = Cursor::new(entry);

        let cocoon = Cocoon::new(self.password.as_slice());
        cocoon.parse(&mut entry_cursor).map_err( |error| FailedToDecryptData{ error })
    }

    fn decrypt_key_count(&self, count: Vec<u8>) -> Result<[u8; 4], SecureStorageError> {
        let mut entry_cursor: Cursor<Vec<u8>> = Cursor::new(count);
        let cocoon = Cocoon::new(self.password.as_slice());
        let encoded = cocoon.parse(&mut entry_cursor).map_err( |error| FailedToDecryptData{ error })?;
        
        encoded.try_into().map_err(|_| CorruptedData)
    }

    fn update_indexes(&mut self, label: &str, public_key: PublicKey, position: u32) {
        let label_key = hashes::sha256::Hash::hash(label.as_bytes()).to_string();
        self.index_by_label.insert(label_key, position);

        let pk_key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        self.index_by_public_key.insert(pk_key, position);
    }

    fn restore_indexes(&mut self, entry_index: u32) -> Result<(), SecureStorageError> {
        let (label_key, _, public_key) = self.read_entry(entry_index)?;
        self.index_by_label.insert(label_key, entry_index);

        let pk_key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        self.index_by_public_key.insert(pk_key, entry_index);
        Ok(())
    }

    fn restore(&mut self) -> Result<(), SecureStorageError> {
        if Path::new(&self.path).exists() {
            self.restore_from_file()?;
        } else {
            self.update_key_count()?;
        }

        Ok(())
    }
}
