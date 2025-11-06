use crate::{errors::KeyManagerError, rsa::RSAKeyPair};
use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use bitcoin::{PrivateKey, PublicKey};
use rsa::RsaPublicKey;
use std::{rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};

pub struct KeyStore {
    store: Rc<Storage>,
}

impl KeyStore {
    const MNEMONIC_KEY: &str = "bip39_mnemonic"; // Key for the BIP-39 mnemonic
    const WINTERNITZ_KEY: &str = "winternitz_seed"; // Key to use in the database for the Winternitz seed
    const KEY_DERIVATION_SEED_KEY: &str = "bip32_seed"; // Key to use in the database for the bip32 key derivation seed

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

    pub fn store_mnemonic(&self, mnemonic: &Mnemonic) -> Result<(), KeyManagerError> {
        let phrase = mnemonic.to_string(); // normalized space-separated phrase
        self.store.set(Self::MNEMONIC_KEY, phrase, None)?;
        Ok(())
    }

    pub fn load_mnemonic(&self) -> Result<Mnemonic, KeyManagerError> {
        let phrase: String = self
            .store
            .get(Self::MNEMONIC_KEY)?
            .ok_or(KeyManagerError::MnemonicNotFound)?;
        let m = Mnemonic::parse(&phrase).map_err(|_| KeyManagerError::InvalidMnemonic)?;
        Ok(m)
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

    pub fn store_key_derivation_seed(&self, seed: [u8; 64]) -> Result<(), KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let encoded = general_purpose::STANDARD.encode(&seed);
        self.store
            .set(Self::KEY_DERIVATION_SEED_KEY, encoded, None)?;
        Ok(())
    }

    pub fn load_key_derivation_seed(&self) -> Result<[u8; 64], KeyManagerError> {
        // using base64 encoding to avoid 32 byte limitation in serde
        let encoded: String = self
            .store
            .get(Self::KEY_DERIVATION_SEED_KEY)?
            .ok_or(KeyManagerError::KeyDerivationSeedNotFound)?;

        let decoded = general_purpose::STANDARD
            .decode(&encoded)
            .map_err(|_| KeyManagerError::InvalidKeyDerivationSeed)?;

        if decoded.len() != 64 {
            return Err(KeyManagerError::InvalidKeyDerivationSeed);
        }

        let mut seed = [0u8; 64];
        seed.copy_from_slice(&decoded);
        Ok(seed)
    }

    // TODO remove
    // fn build_rsa_key(idx: usize) -> String {
    //     format!("{}_{}", Self::RSA_KEY, idx)
    // }

    // TODO remove
    // pub fn store_rsa_key(&self, rsa_key: RSAKeyPair, index: usize) -> Result<(), KeyManagerError> {
    //     let privk = rsa_key.export_private_pem()?;
    //     self.store.set(Self::build_rsa_key(index), privk, None)?;
    //     Ok(())
    // }

    pub fn store_rsa_key(&self, rsa_key: RSAKeyPair) -> Result<(), KeyManagerError> {
        let pubk = rsa_key.export_public_pem()?;
        let privk = rsa_key.export_private_pem()?;
        self.store.set(pubk, privk, None)?;
        Ok(())
    }

    // TODO REMOVE
    // /// Load an RSA key pair from the store with the given public key in PEM format.
    // pub fn load_rsa_key(&self, index: usize) -> Result<Option<RSAKeyPair>, KeyManagerError> {
    //     let privk = self
    //         .store
    //         .get::<String, String>(Self::build_rsa_key(index))?;
    //     if let Some(privk) = privk {
    //         let rsa_keypair = RSAKeyPair::from_private_pem(&privk)?;
    //         return Ok(Some(rsa_keypair));
    //     }
    //     Ok(None)
    // }

    /// Load an RSA key pair from the store with the given public key in PEM format.
    pub fn load_rsa_key(
        &self,
        rsa_pub_key: RsaPublicKey,
    ) -> Result<Option<RSAKeyPair>, KeyManagerError> {
        let pubk: String = RSAKeyPair::export_public_pem_from_pubk(rsa_pub_key)?;
        let privk = self.store.get::<String, String>(pubk)?;
        if let Some(privk) = privk {
            let rsa_keypair = RSAKeyPair::from_private_pem(&privk)?;
            return Ok(Some(rsa_keypair));
        }
        Ok(None)
    }
}
