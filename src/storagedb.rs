use std::{path::Path, io::Cursor};
use anyhow::{Ok, Result};
use bitcoin::{Network, PrivateKey, PublicKey};
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

    pub fn store_keypair(&mut self, private_key: PrivateKey, public_key: PublicKey) -> Result<()>{
        let encoded = self.encode_entry(private_key, public_key);  
        let entry = self.encrypt_entry(encoded, ENTRY_SIZE)?;

        let key = public_key.to_string();
        self.db.put(key, entry).map_err(WriteError)?;

        Ok(())
    }

    pub fn load_keypair(&self, public_key: &PublicKey) -> Result<Option<(PrivateKey, PublicKey)>> { 
        let key = public_key.to_string();

        let entry = match self.db.get(key).map_err(ReadError)?{
            Some(entry) => {
                let encoded = self.decrypt_entry(entry)?;
                self.decode_entry(encoded.to_vec())
            }
            None => return Ok(None),
        };

        Ok(Some(entry?))
    }

    pub fn store_winternitz_secret(&self, master_secret: [u8; 32]) -> Result<()>{
        let entry = self.encrypt_entry(master_secret.to_vec(), ENTRY_SIZE)?;
        self.db.put("winternitz", entry).map_err(WriteError)?;
        Ok(())
    }

    pub fn load_winternitz_secret(&self) -> Result<[u8; 32]> {
        let entry = self.db.get("winternitz").map_err(ReadError)?.unwrap();
        let encoded = self.decrypt_entry(entry)?;
        Ok(encoded.try_into().map_err(|_| CorruptedData)?)
    }


    fn encode_entry(&self, sk: PrivateKey, pk: PublicKey) -> Vec<u8> {
        let private_key_bytes = sk.to_bytes();
        let public_key_bytes = pk.to_bytes();

        let mut encoded: Vec<u8> = Vec::new();
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

    fn decode_entry(&self, data: Vec<u8>) -> Result<(PrivateKey, PublicKey)> {
        let public_key_bytes = &data[32..65];
        let private_key_bytes = &data[65..];

        let private_key = PrivateKey::from_slice(private_key_bytes, self.network)?;
        let public_key = PublicKey::from_slice(public_key_bytes)?;

        Ok((private_key, public_key))
    }
}