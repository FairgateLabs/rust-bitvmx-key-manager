use std::{path::Path, io::Cursor};
use anyhow::{Ok, Result};
use bitcoin::{hashes::{self, Hash}, Network, PrivateKey, PublicKey};
use cocoon::Cocoon;
use rocksdb::Options;
use crate::errors::SecureStorageError::*;

const ENTRY_SIZE: u32 = 157; // Size in bytes of each encrypted entry in storage

pub struct SecureStorage {
    db: rocksdb::DB,
    network: Network,
    password: Vec<u8>,
}

impl SecureStorage {
    pub fn new<P: AsRef<Path>>(path: P, password: Vec<u8>, network: Network) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = rocksdb::DB::open(&opts, path.as_ref()).map_err(|_| OpenError)?;
        
        let secure_storage = SecureStorage { 
            db, 
            network, 
            password: password.to_vec(),
        };
        
        Ok(secure_storage)
    }

    pub fn store_keypair(&mut self, label: &str, private_key: PrivateKey, public_key: PublicKey) -> Result<()>{
        let encoded = self.encode_entry(label, private_key, public_key);  
        let entry = self.encrypt_entry(encoded, ENTRY_SIZE)?;

        let key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();
        self.db.put(key, entry).map_err(|e| WriteError(e))?;

        Ok(())
    }

    pub fn load_keypair(&self, public_key: &PublicKey) -> Result<Option<(String, PrivateKey, PublicKey)>> {
        let key = hashes::sha256::Hash::hash(public_key.to_string().as_bytes()).to_string();


        let entry = match self.db.get(key).map_err(|e| ReadError(e))?{
            Some(entry) => {
                let encoded = self.decrypt_entry(entry)?;
                self.decode_entry(encoded.to_vec())
            }
            None => return Ok(None),
        };

        Ok(Some(entry?))
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

    fn encrypt_entry(&self, entry: Vec<u8>, size: u32) -> Result<Vec<u8>>{
        let mut entry_cursor: Cursor<Vec<u8>> = Cursor::new(vec![0; size as usize]);
        let mut cocoon = Cocoon::new(self.password.as_slice());
        cocoon.dump(entry, &mut entry_cursor).map_err( |error| FailedToEncryptData{ error })?;
        Ok(entry_cursor.into_inner())
    }

    fn decrypt_entry(&self, entry: Vec<u8>) -> Result<Vec<u8>> {
        let mut entry_cursor = Cursor::new(entry);

        let cocoon = Cocoon::new(self.password.as_slice());
        Ok(cocoon.parse(&mut entry_cursor).map_err( |error| FailedToDecryptData{ error })?)
    }

    fn decode_entry(&self, data: Vec<u8>) -> Result<(String, PrivateKey, PublicKey)> {
        let label_hash_bytes = &data[0..32];
        let public_key_bytes = &data[32..65];
        let private_key_bytes = &data[65..];

        let label_hash = hashes::sha256::Hash::from_slice(label_hash_bytes)?;
        let private_key = PrivateKey::from_slice(private_key_bytes, self.network)?;
        let public_key = PublicKey::from_slice(public_key_bytes)?;

        Ok((label_hash.to_string(), private_key, public_key))
    }
}