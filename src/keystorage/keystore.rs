use bitcoin::{PrivateKey, PublicKey};

use crate::errors::KeyStoreError;

pub trait KeyStore {
    fn store_keypair(&mut self, private_key: PrivateKey, public_key: PublicKey) -> Result<(), KeyStoreError>;
    fn load_keypair(&self, public_key: &PublicKey) -> Result<Option<(PrivateKey, PublicKey)>, KeyStoreError>;
    fn store_winternitz_secret(&self, master_secret: [u8; 32]) -> Result<(), KeyStoreError>;
    fn load_winternitz_secret(&self) -> Result<[u8; 32], KeyStoreError>;
}