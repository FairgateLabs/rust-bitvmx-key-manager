use crate::{errors::KeyManagerError, rsa::RSAKeyPair};
use bitcoin::{PrivateKey, PublicKey};
use std::{rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};

pub struct KeyStore {
    store: Rc<Storage>,
}

impl KeyStore {
    const WINTERNITZ_KEY: &str = "winternitz_seed"; // Key to use in the database for the Winternitz seed
    const KEY_DERIVATION_SEED_KEY: &str = "bip32_seed"; // Key to use in the database for the bip32 key derivation seed
    const RSA_KEY: &str = "rsa"; // Key to use in the database for the RSA

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
            return Ok(Some((private_key, *public_key)));
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

    fn build_rsa_key(idx: usize) -> String {
        format!("{}_{}", Self::RSA_KEY, idx)
    }

    pub fn store_rsa_key(&self, rsa_key: RSAKeyPair, index: usize) -> Result<(), KeyManagerError> {
        let privk = rsa_key.export_private_pem()?;
        self.store.set(Self::build_rsa_key(index), privk, None)?;
        Ok(())
    }

    /// Load an RSA key pair from the store with the given public key in PEM format.
    pub fn load_rsa_key(&self, index: usize) -> Result<Option<RSAKeyPair>, KeyManagerError> {
        let privk = self
            .store
            .get::<String, String>(Self::build_rsa_key(index))?;
        if let Some(privk) = privk {
            let rsa_keypair = RSAKeyPair::from_private_pem(&privk)?;
            return Ok(Some(rsa_keypair));
        }
        Ok(None)
    }
}
