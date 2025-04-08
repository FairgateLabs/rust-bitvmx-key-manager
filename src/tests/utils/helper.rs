use std::rc::Rc;

use bitcoin::{
    key::rand::{thread_rng, RngCore},
    secp256k1, PublicKey,
};
use storage_backend::storage::Storage;

use crate::{
    key_manager::{self, KeyManager},
    keystorage::{self, database::DatabaseKeyStore},
};

pub fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}

pub fn create_key_manager(
    store_keystore_path: &str,
    store: Rc<Storage>,
) -> Result<KeyManager<DatabaseKeyStore>, anyhow::Error> {
    let key_derivation_seed = random_bytes();
    let winternitz_seed = random_bytes();
    const DERIVATION_PATH: &str = "m/101/1/0/0/";
    let password = b"secret password".to_vec();
    let storage_path = std::path::PathBuf::from(store_keystore_path);
    let keystore = keystorage::database::DatabaseKeyStore::new(
        storage_path,
        password,
        bitcoin::Network::Regtest,
    )?;

    let key_manager = key_manager::KeyManager::new(
        bitcoin::Network::Regtest,
        DERIVATION_PATH,
        key_derivation_seed,
        winternitz_seed,
        keystore,
        store,
    )?;

    Ok(key_manager)
}

pub fn create_pub_key(
    key_manager: &KeyManager<DatabaseKeyStore>,
) -> Result<PublicKey, anyhow::Error> {
    let mut rng = thread_rng();
    let pub_key: PublicKey = key_manager.generate_keypair(&mut rng)?;
    Ok(pub_key)
}

pub fn clear_output() {
    let _ = std::fs::remove_dir_all("test_output");
}
