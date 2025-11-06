mod create;

use create::create_key_manager_example;

use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self, Message, Scalar},
};

use key_manager::{
    key_type::BitcoinKeyType, verifier::SignatureVerifier,
};

fn main () {
    // see function code, main is just a wrapper to run the example
    sign_verify_schnorr_example();
}

fn sign_verify_schnorr_example() {
    let key_manager = create_key_manager_example();

    // --- Signing and verifying a message using Schnorr

    let mut rng = secp256k1::rand::thread_rng();

    // Create a random Message.
    let mut digest = [0u8; 32];
    rng.fill_bytes(&mut digest);
    let message = Message::from_digest(digest);

    // Create a key pair
    let public_key = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0).unwrap();

    // Create a Schnorr signature of the random Message by selecting the private associated to the public key passed as parameter
    let signature = key_manager
        .sign_schnorr_message(&message, &public_key)
        .unwrap();

    // Verify the signature
    let signature_verifier = SignatureVerifier::new();
    let sig_ok = signature_verifier.verify_schnorr_signature(&signature, &message, public_key);
    println!("Signature valid: {}", sig_ok);

    // --- Schnorr & Taproot Signatures

    // Sign with Taproot Script Path
    let signature = key_manager
        .sign_schnorr_message(&message, &public_key)
        .unwrap();
    println!("Schnorr signature: {}", signature);

    // Sign with Taproot Key Spend (Optional Merkle Root)
    let merkle_root = None;
    let (sig, tweaked_pubkey) = key_manager
        .sign_schnorr_message_with_tap_tweak(&message, &public_key, merkle_root)
        .unwrap();
    println!("Taproot Key Spend signature: {}", sig);
    println!("Taproot Key Spend tweaked pubkey: {}", tweaked_pubkey);

    // Sign with Custom Tweak
    let tweak: Scalar = Scalar::ZERO; // Example tweak, replace with actual tweak value
    let (sig, tweaked_pubkey) = key_manager
        .sign_schnorr_message_with_tweak(&message, &public_key, &tweak)
        .unwrap();
    println!("Taproot custom tweak Key Spend signature: {}", sig);
    println!(
        "Taproot custom tweak Key Spend tweaked pubkey: {}",
        tweaked_pubkey
    );
}
