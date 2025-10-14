use std::rc::Rc;

use bitcoin::{key::rand::RngCore, secp256k1, Network};
use key_manager::{key_manager::KeyManager, key_store::KeyStore};
use storage_backend::{storage::Storage, storage_config::StorageConfig};

fn main() {
    // --- Creating a KeyManager

    let network = Network::Regtest;
    let keystore_path = "./examples/storage/import-keystore.db".to_string();
    let password = "secret password".to_string();
    let key_derivation_seed = random_bytes();
    let key_derivation_path = "m/101/1/0/0/";
    let winternitz_seed = random_bytes();

    let config = StorageConfig::new(keystore_path, Some(password));
    let store = Rc::new(Storage::new(&config).unwrap());
    let keystore = KeyStore::new(store.clone()); // TODO need the clone for keymanager parameter

    let key_manager = KeyManager::new(
        network,
        key_derivation_path,
        Some(key_derivation_seed),
        Some(winternitz_seed),
        keystore,
        store, // TODO, get this from the keystore?
    )
    .unwrap();

    // --- Key importing
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::PrivateKey;
    let secret_key = SecretKey::from_slice(&random_bytes()).unwrap();
    let private_key = PrivateKey::new(secret_key, network);
    let pubkey = key_manager
        .import_private_key(&private_key.to_wif())
        .unwrap();
    println!("Imported public key: {}", pubkey);

    let secret_key2 = SecretKey::from_slice(&random_bytes()).unwrap();
    let private_key2 = PrivateKey::new(secret_key2, network);

    let private_keys: Vec<String> = vec![private_key.to_wif().clone(), private_key2.to_wif().clone()];
    let pubkey = key_manager
        .import_partial_private_keys(private_keys, network)
        .unwrap();
    println!("Imported partial aggregated public key from private keys: {}", pubkey);

    let secret_keys: Vec<String> = vec![secret_key.display_secret().to_string(), secret_key2.display_secret().to_string()];
    let pubkey = key_manager
        .import_partial_secret_keys(secret_keys, network)
        .unwrap();
    println!("Imported partial aggregated public key from secret keys: {}", pubkey);
}

fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}
