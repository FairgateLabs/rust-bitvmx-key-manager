mod create;

use create::create_key_manager_example;

use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self, Message},
};

use key_manager::{verifier::SignatureVerifier, winternitz::WinternitzType};

fn main() {
    // see function code, main is just a wrapper to run the example
    sign_verify_winternitz_example();
}

fn sign_verify_winternitz_example() {
    let key_manager = create_key_manager_example("sign_verify_winternitz");

    // --- Signing and verifying a message using Winternitz

    // Create a random Message.
    let mut digest = [0u8; 32];
    let mut rng = secp256k1::rand::thread_rng();
    rng.fill_bytes(&mut digest);
    let message = Message::from_digest(digest);
    println!("Message: {:?}", message);

    // Using next - recommended

    // Get the Winternitz public key for the index 0 using the SHA-256 hash function
    let winternitz_key = key_manager
        .next_winternitz(message[..].len(), WinternitzType::SHA256)
        .unwrap();

    // Create a Winternitz signature
    let signature = key_manager
        .sign_winternitz_message_by_pubkey(&message[..], &winternitz_key)
        .unwrap();
    println!(
        "(using next) Winternitz signature: {:?}",
        hex::encode(signature.to_bytes())
    );
    // Verify the signature
    let signature_verifier = SignatureVerifier::new();
    let is_valid =
        signature_verifier.verify_winternitz_signature(&signature, &message[..], &winternitz_key);
    println!("(using next) Is signature valid: {:?}", is_valid);
    assert!(is_valid);


    // Using derive - discouraged

    // Create a Winternitz signature. Internally a Winternitz key pair for the derivation index 0 is created using the SHA-256 hash function
    let signature = key_manager
        .sign_winternitz_message(&message[..], WinternitzType::SHA256, 0)
        .unwrap();
    println!(
        "(using derive) Winternitz signature: {:?}",
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
    assert!(is_valid);
}
