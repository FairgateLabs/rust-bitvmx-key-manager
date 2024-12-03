#![allow(unused_imports)]
use bitcoin::{
    key::rand::{Rng, RngCore},
    secp256k1::{self, All, Message, Scalar, SecretKey},
    Network, PrivateKey, PublicKey,
};
use key_manager::{
    key_manager::KeyManager,
    keystorage::{database::DatabaseKeyStore, file::FileKeyStore},
    verifier::SignatureVerifier,
    winternitz::{WinternitzSignature, WinternitzType},
};

fn main() {
    // --- Creating a KeyManager

    let network = Network::Regtest;
    let keystore_path = "/tmp/keystore.db";
    let keystore_password = b"secret password".to_vec();
    let key_derivation_seed = random_bytes();
    let key_derivation_path = "m/101/1/0/0/";
    let winternitz_seed = random_bytes();

    // A key manager can use a file based keystore:
    // let keystore = FileKeyStore::new(keystore_path, keystore_password, network).unwrap();

    // Or a database based keystore:
    let keystore = DatabaseKeyStore::new(keystore_path, keystore_password, network).unwrap();

    let mut key_manager = KeyManager::new(
        network,
        key_derivation_path,
        key_derivation_seed,
        winternitz_seed,
        keystore,
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
    winternitz_key.checksum_size();

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
