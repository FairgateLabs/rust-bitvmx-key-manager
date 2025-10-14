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

    // --- Key generation & Derivation

    // Internally the key manager generates a key pair,
    // stores the private key and the corresponding public key in the encrypted keystore.
    // The public key is later used to select the corresponding private key for signing.

    let mut rng = secp256k1::rand::thread_rng();
    // Generate a keypair
    let keypair_pubkey = key_manager.generate_keypair(&mut rng).unwrap();
    println!("keypair_pubkey: {}", keypair_pubkey);

    // Derive a child keypair (e.g., for indexed wallets)
    let derived_0_pubkey = key_manager.derive_keypair(0).unwrap();
    println!("derived_0_pubkey: {}", derived_0_pubkey);

    // Generate a master extended x public key
    let master_xpub = key_manager.generate_master_xpub().unwrap();

    // Derive public key only
    let pubkey = key_manager.derive_public_key(master_xpub, 1).unwrap();
    println!("Derived pubkey from xpub: {}", pubkey);
}

fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}
