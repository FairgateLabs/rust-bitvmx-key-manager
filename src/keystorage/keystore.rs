use bitcoin::{PrivateKey, PublicKey};

use crate::errors::KeyStoreError;

pub trait KeyStore {
    fn store_keypair(&mut self, private_key: PrivateKey, public_key: PublicKey) -> Result<(), KeyStoreError>;
    fn load_keypair(&self, public_key: &PublicKey) -> Result<Option<(PrivateKey, PublicKey)>, KeyStoreError>;
    fn store_winternitz_seed(&mut self, master_secret: [u8; 32]) -> Result<(), KeyStoreError>;
    fn load_winternitz_seed(&self) -> Result<[u8; 32], KeyStoreError>;
    fn store_key_derivation_seed(&mut self, seed: [u8; 32]) -> Result<(), KeyStoreError>;
    fn load_key_derivation_seed(&self) -> Result<[u8; 32], KeyStoreError>;
}