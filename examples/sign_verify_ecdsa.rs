mod create;

use create::create_key_manager_example;

use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self, Message},
};

use key_manager::{key_type::BitcoinKeyType, verifier::SignatureVerifier};

fn main() {
    // see function code, main is just a wrapper to run the example
    sign_verify_ecdsa_example();
}

fn sign_verify_ecdsa_example() {
    let key_manager = create_key_manager_example("sign_verify_ecdsa");

    // --- Signing and verifying a message using ECDSA

    let mut rng = secp256k1::rand::thread_rng();

    // Create a random Message.
    let mut digest = [0u8; 32];
    rng.fill_bytes(&mut digest);
    let message = Message::from_digest(digest);

    // Create a key pair
    let public_key = key_manager
        .derive_keypair(BitcoinKeyType::P2wpkh, 0)
        .unwrap();

    // Create an ECDSA signature of the random Message by selecting the private associated to the public key passed as parameter
    let signature = key_manager
        .sign_ecdsa_message(&message, &public_key)
        .unwrap();

    // Verify the signature
    let signature_verifier = SignatureVerifier::new();
    let sig_ok = signature_verifier.verify_ecdsa_signature(&signature, &message, public_key);
    println!("Signature valid: {}", sig_ok);

    // Recover signature
    let _recoverable_sig = key_manager
        .sign_ecdsa_recoverable_message(&message, &public_key)
        .unwrap();
}
