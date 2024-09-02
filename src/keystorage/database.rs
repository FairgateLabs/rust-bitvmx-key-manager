use std::{io::Cursor, path::Path};

use bitcoin::{Network, PrivateKey, PublicKey};
use cocoon::Cocoon;
use rocksdb::Options;

use crate::errors::KeyStoreError;

use super::keystore::KeyStore;

const ENTRY_SIZE: u32 = 125; // Size in bytes of each encrypted entry in storage
const WINTERNITZ_ENTRY_SIZE: u32 = 92; // Size in bytes of the encrypted winternitz secret in storage
const WINTERNITZ_KEY: &str = "winternitz_seed"; // Key to use in the database for the winternitz seed

pub struct DatabaseKeyStore {
    db: rocksdb::DB,
    network: Network,
    password: Vec<u8>,
}

impl KeyStore for DatabaseKeyStore {
    fn store_keypair(&mut self, private_key: PrivateKey, public_key: PublicKey) -> Result<(), KeyStoreError>{
        let encoded = self.encode_entry(private_key, public_key);  
        let entry = self.encrypt_entry(encoded, ENTRY_SIZE)?;

        let key = public_key.to_string();
        self.db.put(key, entry)?;

        Ok(())
    }

    fn load_keypair(&self, public_key: &PublicKey) -> Result<Option<(PrivateKey, PublicKey)>, KeyStoreError> { 
        let key = public_key.to_string();
        let entry = match self.db.get(key)?{
            Some(entry) => {
                let encoded = self.decrypt_entry(entry)?;
                self.decode_entry(encoded.to_vec())
            }
            None => return Ok(None),
        };

        Ok(Some(entry?))
    }

    fn store_winternitz_seed(&self, master_secret: [u8; 32]) -> Result<(), KeyStoreError> {
        let entry = self.encrypt_entry(master_secret.to_vec(), WINTERNITZ_ENTRY_SIZE)?;
        self.db.put(WINTERNITZ_KEY, entry)?;
        Ok(())
    }

    fn load_winternitz_seed(&self) -> Result<[u8; 32], KeyStoreError> {
        let entry = self.db.get(WINTERNITZ_KEY)?.unwrap();
        let encoded = self.decrypt_entry(entry)?;
        Ok(encoded.try_into().map_err(|_| KeyStoreError::CorruptedData)?)
    }
}

impl DatabaseKeyStore {
    pub fn new<P: AsRef<Path>>(path: P, password: Vec<u8>, network: Network) -> Result<Self, KeyStoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = rocksdb::DB::open(&opts, path.as_ref())?;
        
        let key_storage = DatabaseKeyStore { 
            db, 
            network, 
            password: password.to_vec(),
        };
        
        Ok(key_storage)
    }

    fn encode_entry(&self, sk: PrivateKey, pk: PublicKey) -> Vec<u8> {
        let private_key_bytes = sk.to_bytes();
        let public_key_bytes = pk.to_bytes();

        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&public_key_bytes);
        encoded.extend_from_slice(&private_key_bytes);

        encoded
    }

    fn encrypt_entry(&self, entry: Vec<u8>, size: u32) -> Result<Vec<u8>, KeyStoreError>{
        let mut entry_cursor: Cursor<Vec<u8>> = Cursor::new(vec![0; size as usize]);
        let mut cocoon = Cocoon::new(self.password.as_slice());
        cocoon.dump(entry, &mut entry_cursor).map_err( |error| KeyStoreError::FailedToEncryptData{ error })?;
        Ok(entry_cursor.into_inner())
    }

    fn decrypt_entry(&self, entry: Vec<u8>) -> Result<Vec<u8>, KeyStoreError> {
        let mut entry_cursor = Cursor::new(entry);

        let cocoon = Cocoon::new(self.password.as_slice());
        Ok(cocoon.parse(&mut entry_cursor).map_err( |error| KeyStoreError::FailedToDecryptData{ error })?)
    }

    fn decode_entry(&self, data: Vec<u8>) -> Result<(PrivateKey, PublicKey), KeyStoreError> {
        let public_key_bytes = &data[0..33];
        let private_key_bytes = &data[33..];

        let private_key = PrivateKey::from_slice(private_key_bytes, self.network)?;
        let public_key = PublicKey::from_slice(public_key_bytes)?;

        Ok((private_key, public_key))
    }
}