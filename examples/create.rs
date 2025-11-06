use bitcoin::{key::rand::RngCore, secp256k1, Network};

use key_manager::key_manager::KeyManager;
use storage_backend::storage_config::StorageConfig;

#[allow(dead_code)]
fn main() {
    // see function code, main is just a wrapper to run the example
    create_key_manager_example();
}

pub fn create_key_manager_example() -> KeyManager {
    // --- Creating a KeyManager
    let network = Network::Regtest;
    let keystore_path = "./examples/storage/examples-keystore.db".to_string();
    let password = "secret password".to_string();

    let storage_config = StorageConfig::new(keystore_path, Some(password));

    let key_manager = KeyManager::new(
        network,
        None, // will generate a new random mnemonic internally
        None, // sill use empty passphrase for mnemonic
        storage_config,
    )
    .unwrap();

    key_manager
}

#[allow(dead_code)]
pub fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}
