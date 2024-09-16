use std::{io::Cursor, path::Path};

use bitcoin::{Network, PrivateKey, PublicKey};
use cocoon::Cocoon;
use storage_backend::storage::{Storage, KeyValueStore};

use crate::errors::KeyStoreError;

use super::keystore::KeyStore;

const ENTRY_SIZE: u32 = 125; // Size in bytes of each encrypted entry
const WINTERNITZ_SEED_SIZE: u32 = 92; // Size in bytes of the encrypted Winternitz secret
const WINTERNITZ_KEY: &str = "winternitz_seed"; // Key to use in the database for the Winternitz seed
const KEY_DERIVATION_SEED_SIZE: u32 = 92; // Size in bytes of the encrypted bip32 key derivation seed
const KEY_DERIVATION_SEED_KEY: &str = "bip32_seed"; // Key to use in the database for the bip32 key derivation seed


pub struct DatabaseKeyStore {
    db: Storage,
    network: Network,
    password: Vec<u8>,
}

impl KeyStore for DatabaseKeyStore {
    fn store_keypair(&mut self, private_key: PrivateKey, public_key: PublicKey) -> Result<(), KeyStoreError>{
        let encoded = self.encode_entry(private_key, public_key);  
        let entry = self.encrypt_entry(encoded, ENTRY_SIZE)?;

        let key = public_key.to_string();
        self.db.set(key, entry)?;

        Ok(())
    }

    fn load_keypair(&self, public_key: &PublicKey) -> Result<Option<(PrivateKey, PublicKey)>, KeyStoreError> { 
        let key = public_key.to_string();
        let entry = match self.db.get::<String, Vec<u8>>(key)?{
            Some(entry) => {
                let encoded = self.decrypt_entry(entry)?;
                self.decode_entry(encoded.to_vec())
            }
            None => return Ok(None),
        };

        Ok(Some(entry?))
    }

    fn store_winternitz_seed(&self, seed: [u8; 32]) -> Result<(), KeyStoreError> {
        let entry = self.encrypt_entry(seed.to_vec(), WINTERNITZ_SEED_SIZE)?;
        self.db.set(WINTERNITZ_KEY, entry)?;
        Ok(())
    }

    fn load_winternitz_seed(&self) -> Result<[u8; 32], KeyStoreError> {
        let entry = match self.db.read(WINTERNITZ_KEY)? {
            Some(entry) => entry.as_bytes().to_vec(),
            None => return Err(KeyStoreError::WinternitzSeedNotFound),
        };

        let encoded = self.decrypt_entry(entry)?;
        encoded.try_into().map_err(|_| KeyStoreError::CorruptedData)
    }

    fn store_key_derivation_seed(&self, seed: [u8; 32]) -> Result<(), KeyStoreError> {
        let entry = self.encrypt_entry(seed.to_vec(), KEY_DERIVATION_SEED_SIZE)?;
        self.db.set(KEY_DERIVATION_SEED_KEY, entry)?;
        Ok(())
    }

    fn load_key_derivation_seed(&self) -> Result<[u8; 32], KeyStoreError> {
        let entry = match self.db.get::<&str, Vec<u8>>(KEY_DERIVATION_SEED_KEY)? {
            Some(entry) => entry,
            None => return Err(KeyStoreError::KeyDerivationSeedNotFound),
        };
        
        let encoded = self.decrypt_entry(entry)?;
        encoded.try_into().map_err(|_| KeyStoreError::CorruptedData)
    }
}

impl DatabaseKeyStore {
    pub fn new<P: AsRef<Path>>(path: P, password: Vec<u8>, network: Network) -> Result<Self, KeyStoreError> {
        let db = Storage::new_with_path(&path.as_ref().to_path_buf())?;
        
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
        cocoon.parse(&mut entry_cursor).map_err( |error| KeyStoreError::FailedToDecryptData{ error })
    }

    fn decode_entry(&self, data: Vec<u8>) -> Result<(PrivateKey, PublicKey), KeyStoreError> {
        let public_key_bytes = &data[0..33];
        let private_key_bytes = &data[33..];

        let private_key = PrivateKey::from_slice(private_key_bytes, self.network)?;
        let public_key = PublicKey::from_slice(public_key_bytes)?;

        Ok((private_key, public_key))
    }
}