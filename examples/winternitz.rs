use std::rc::Rc;

use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self, Message},
    Network,
};
use key_manager::{
    key_manager::KeyManager, key_store::KeyStore, verifier::SignatureVerifier, winternitz::WinternitzType
};
use storage_backend::{storage::Storage, storage_config::StorageConfig};

fn main() {
    // --- Creating a KeyManager

    let network = Network::Regtest;
    let keystore_path = "./examples/storage/winternitz-keystore.db".to_string();
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

    // --- Deriving Winternitz OTS keys

    let mut rng = secp256k1::rand::thread_rng();

    // Key size in bytes. A Winternitz key needs to be of the same size as the message that will be signed with it.
    let key_size = 32;
    let winternitz_key = key_manager
        .derive_winternitz(key_size, WinternitzType::SHA256, 0)
        .unwrap();
    println!(
        "Winternitz public key: {:?}",
        hex::encode(winternitz_key.to_bytes())
    );
    let _ = winternitz_key.checksum_size();

    // --- Signing and verifying a message using Winternitz

    // Create a random Message.
    let mut digest = [0u8; 32];
    rng.fill_bytes(&mut digest);
    let message = Message::from_digest(digest);
    println!("Message: {:?}", message);

    // Create a Winternitz signature. Internally a Winternitz key pair for the derivation index 0 is created using the SHA-256 hash function
    let signature = key_manager
        .sign_winternitz_message(&message[..], WinternitzType::SHA256, 0)
        .unwrap();
    println!(
        "Winternitz signature: {:?}",
        hex::encode(signature.to_bytes())
    );

    // Get the Winternitz public key for the index 0 using the SHA-256 hash function
    let winternitz_key = key_manager
        .derive_winternitz(message[..].len(), WinternitzType::SHA256, 0)
        .unwrap();

    // Verify the signature
    let signature_verifier = SignatureVerifier::new();
    let is_valid =
        signature_verifier.verify_winternitz_signature(&signature, &message[..], &winternitz_key);
    println!("Is signature valid: {:?}", is_valid);
}

fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}
