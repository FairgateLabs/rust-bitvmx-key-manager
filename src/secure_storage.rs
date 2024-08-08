use std::{collections::HashMap, fs::{File, OpenOptions}, io::{Cursor, Read, Seek, SeekFrom, Write}, path::Path};

use bitcoin::{hashes::{self, Hash}, Network, PrivateKey, PublicKey};
use cocoon::Cocoon;

// Size in bytes of each encrypted entry in storage
const ENTRY_SIZE: u32 = 157;

// Size in bytes of the encrypted key count in storage
const KEY_COUNT_SIZE: u32 = 64;

// Size in bytes of the encrypted winternitz secret in storage
const WINTER_SIZE: u32 = 32 + 60; 
pub struct SecureStorage {
    path: String, 
    network: Network,
    index_by_label: HashMap<String, u32>,
    index_by_public_key: HashMap<String, u32>,
    key_count: u32,
    password: Vec<u8>,
}

impl SecureStorage {
    pub fn new(path: &str, password: Vec<u8>, network: Network) -> Self {
        let mut secure_storage = SecureStorage { 
            path: path.to_string(), 
            network, 
            index_by_label: HashMap::new(),
            index_by_public_key: HashMap::new(),
            key_count: 0,
            password: password.to_vec(),
        };
        
        secure_storage.restore();
        secure_storage
    }

    pub fn store_entry(&mut self, label: &str, private_key: PrivateKey, public_key: PublicKey) {
        let label_bytes = label.as_bytes();
        let encoded = self.encode_entry(label_bytes, private_key, public_key);  
        let entry = self.encrypt_entry(encoded, ENTRY_SIZE);

        self.write_entry(&entry);
        self.update_indexes(label_bytes, public_key, self.key_count);

        self.key_count += 1;
        self.update_key_count();
    }

    pub fn store_winternitz_secret(&self, master_secret: [u8; 32]) {
        let entry = self.encrypt_entry(master_secret.to_vec(), WINTER_SIZE);
        self.write_winternitz_secret(&entry);
    }

    fn write_winternitz_secret(&self, entry: &[u8]) {
        let pos = KEY_COUNT_SIZE as u64; // Position for the second row
    
        let mut storage = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .expect("Failed to open file in write mode");
    
        storage.seek(SeekFrom::Start(pos)).expect("Failed to seek file");
        storage.write(entry).expect("Failed to write to file");
    }

    pub fn load_winternitz_secret(&self) -> Option<[u8; 32]> {
        let pos = KEY_COUNT_SIZE as u64; // Position for the second row
    
        let mut storage = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .expect("Failed to open file in read mode");
    
        storage.seek(SeekFrom::Start(pos)).expect("Failed to seek file");
    
        let mut entry: [u8; WINTER_SIZE as usize] = [0; WINTER_SIZE as usize];
        storage.read(&mut entry).expect("Failed to read from file");
    
        let encoded = self.decrypt_entry(entry.to_vec());

        Some(encoded.try_into().expect("Failed to convert winternitz secret to array"))
    }

    pub fn entry_by_label(&self, label: &str) -> Option<(String, PrivateKey, PublicKey)> {
        let key = hashes::sha256::Hash::hash(label.as_bytes()).to_string();
        self.index_by_label.get(&key).map(|index| self.load_entry(index.to_owned()))
    }

    pub fn entry_by_key(&self, public_key: &PublicKey) -> Option<(String, PrivateKey, PublicKey)> {
        let key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        self.index_by_public_key.get(&key).map(|index| self.load_entry(index.to_owned()))
    }

    fn update_key_count(&mut self) {
        let encoded = self.key_count.to_be_bytes().to_vec();
        let count = self.encrypt_key_count(encoded);
        self.write_key_count(count);
    }

    fn restore_key_count(&mut self) {
        let entry = self.read_key_count();
        let encoded = self.decrypt_key_count(entry);
        let index: u32 = u32::from_be_bytes(encoded);

        self.key_count = index;

        for i in 0..self.key_count {
            self.restore_indexes(i);
        }
    }

    fn load_entry(&self, entry_index: u32) -> (String, PrivateKey, PublicKey) {
        let entry = self.read_entry(entry_index);
        let encoded = self.decrypt_entry(entry);

        self.decode_entry(encoded.to_vec())
    }

    fn read_entry(&self, entry_index: u32) -> Vec<u8>{
        let position = (KEY_COUNT_SIZE + WINTER_SIZE + entry_index * ENTRY_SIZE) as u64;

        let mut storage = File::open(&self.path).expect("Failed to open file");
        storage.seek(SeekFrom::Start(position)).expect("Failed to seek file");

        let mut entry: [u8; ENTRY_SIZE as usize] = [0; ENTRY_SIZE as usize];
        let read_amount = storage.read(&mut entry).expect("Failed to read from file");

        assert_eq!(read_amount, ENTRY_SIZE as usize);

        entry.to_vec()
    }

    fn write_entry(&mut self, entry: &[u8]) {
        let mut storage = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
            .expect("Failed to open file in append mode");

        let write_amount = storage.write(entry).expect("Failed to write to file"); 

        assert_eq!(write_amount, entry.len());
    }

    fn read_key_count(&self) -> Vec<u8> {
        let mut storage = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .expect("Failed to open file in read mode"); 

        storage.seek(SeekFrom::Start(0)).expect("Failed to seek file");

        let mut entry: [u8; KEY_COUNT_SIZE as usize] = [0; KEY_COUNT_SIZE as usize];
        let read_amount = storage.read(&mut entry).expect("Failed to read from file");

        assert_eq!(read_amount, KEY_COUNT_SIZE as usize);

        entry.to_vec()
    }

    fn write_key_count(&self, count: Vec<u8>) {
        let mut storage = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .expect("Failed to open file in write mode");

        storage.seek(SeekFrom::Start(0)).expect("Failed to seek file");
        let write_amount = storage.write(&count).expect("Failed to write to file"); 

        assert_eq!(write_amount, count.len());
    } 

    fn encode_entry(&self, label_bytes: &[u8], sk: PrivateKey, pk: PublicKey) -> Vec<u8> {
        let label_hash_bytes = hashes::sha256::Hash::hash(label_bytes).as_byte_array().to_vec();
        let private_key_bytes = sk.to_bytes();
        let public_key_bytes = pk.to_bytes();

        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&label_hash_bytes);
        encoded.extend_from_slice(&public_key_bytes);
        encoded.extend_from_slice(&private_key_bytes);

        encoded
    }   

    fn decode_entry(&self, data: Vec<u8>) -> (String, PrivateKey, PublicKey) {
        let label_hash_bytes = &data[0..32];
        let public_key_bytes = &data[32..65];
        let private_key_bytes = &data[65..];

        let label_hash = hashes::sha256::Hash::from_slice(label_hash_bytes).expect("Failed to decode label hash");
        let private_key = PrivateKey::from_slice(private_key_bytes, self.network).expect("Failed to decode private key");
        let public_key = PublicKey::from_slice(public_key_bytes).expect("Failed to decode public key");

        (label_hash.to_string(), private_key, public_key)
    }

    fn encrypt_entry(&self, entry: Vec<u8>, size:u32) -> Vec<u8>{
        let mut entry_cursor: Cursor<Vec<u8>> = Cursor::new(vec![0; size as usize]);
        let mut cocoon = Cocoon::new(self.password.as_slice());
        cocoon.dump(entry, &mut entry_cursor).expect("Failed to store data");
        entry_cursor.into_inner()
    }

    fn decrypt_entry(&self, entry: Vec<u8>) -> Vec<u8> {
        let mut entry_cursor = Cursor::new(entry);

        let cocoon = Cocoon::new(self.password.as_slice());
        cocoon.parse(&mut entry_cursor).expect("Failed to decrypt data")
    } 

    fn encrypt_key_count(&self, count: Vec<u8>) -> Vec<u8>{ 
        let mut cursor: Cursor<Vec<u8>> = Cursor::new(vec![0; KEY_COUNT_SIZE as usize]);

        let mut cocoon = Cocoon::new(self.password.as_slice());
        cocoon.dump(count, &mut cursor).expect("Failed to store data");

        cursor.into_inner()
    }

    fn decrypt_key_count(&self, count: Vec<u8>) -> [u8; 4]{
        let mut entry_cursor: Cursor<Vec<u8>> = Cursor::new(count);
        let cocoon = Cocoon::new(self.password.as_slice());
        let encoded: [u8; 4] = cocoon.parse(&mut entry_cursor).expect("Failed to decrypt key count").try_into().expect("Failed to convert key count to array");
        encoded
    }

    fn update_indexes(&mut self, label_bytes: &[u8], public_key: PublicKey, position: u32) {
        let label_key = hashes::sha256::Hash::hash(label_bytes).to_string();
        self.index_by_label.insert(label_key, position);

        let pk_key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        self.index_by_public_key.insert(pk_key, position);
    }

    fn restore_indexes(&mut self, entry_index: u32) {
        let (label_key, _, public_key) = self.load_entry(entry_index);
        self.index_by_label.insert(label_key, entry_index);

        let pk_key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        self.index_by_public_key.insert(pk_key, entry_index);
    }

    fn restore(&mut self) {
        if Path::new(&self.path).exists() {
            self.restore_key_count();
        } else {
            self.update_key_count();
        }
    }
}
