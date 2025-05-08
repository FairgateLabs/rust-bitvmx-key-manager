use crate::errors::KeyManagerError;
use bitcoin::{PrivateKey, PublicKey};
use std::{rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};

pub struct KeyStore {
    store: Rc<Storage>,
}

impl KeyStore {
    const WINTERNITZ_KEY: &str = "winternitz_seed"; // Key to use in the database for the Winternitz seed
    const KEY_DERIVATION_SEED_KEY: &str = "bip32_seed"; // Key to use in the database for the bip32 key derivation seed

    pub fn new(store: Rc<Storage>) -> Self {
        Self { store }
    }

    pub fn store_keypair(
        &self,
        private_key: PrivateKey,
        public_key: PublicKey,
    ) -> Result<(), KeyManagerError> {
        let key = public_key.to_string();
        self.store.set(key, private_key, None)?;

        Ok(())
    }

    pub fn load_keypair(
        &self,
        public_key: &PublicKey,
    ) -> Result<Option<(PrivateKey, PublicKey)>, KeyManagerError> {
        let key = public_key.to_string();
        let data = self.store.get::<String, String>(key)?;

        if let Some(private_key) = data {
            let private_key = PrivateKey::from_str(&private_key)?;
            return Ok(Some((private_key, public_key.clone())));
        }

        Ok(None)
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

    pub fn store_key_derivation_seed(&self, seed: [u8; 32]) -> Result<(), KeyManagerError> {
        self.store.set(Self::KEY_DERIVATION_SEED_KEY, seed, None)?;
        Ok(())
    }

    pub fn load_key_derivation_seed(&self) -> Result<[u8; 32], KeyManagerError> {
        let entry = self
            .store
            .get(Self::KEY_DERIVATION_SEED_KEY)?
            .ok_or(KeyManagerError::KeyDerivationSeedNotFound)?;

        Ok(entry)
    }
}
