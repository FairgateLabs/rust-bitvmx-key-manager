use std::rc::Rc;

use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self, Message},
    Network,
};
use key_manager::{key_manager::KeyManager, key_store::KeyStore, verifier::SignatureVerifier};
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

    // --- Signing and verifying a message using Schnorr

    let mut rng = secp256k1::rand::thread_rng();

    // Create a random Message.
    let mut digest = [0u8; 32];
    rng.fill_bytes(&mut digest);
    let message = Message::from_digest(digest);

    // Create a key pair
    let public_key = key_manager.generate_keypair(&mut rng).unwrap();

    // Create a Schnorr signature of the random Message by selecting the private associated to the public key passed as parameter
    let signature = key_manager
        .sign_schnorr_message(&message, &public_key)
        .unwrap();

    // Verify the signature
    let signature_verifier = SignatureVerifier::new();
    let sig_ok = signature_verifier.verify_schnorr_signature(&signature, &message, public_key);
    println!("Signature valid: {}", sig_ok);
}

fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}
