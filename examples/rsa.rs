mod create;
use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self, Message},
};
use create::create_key_manager_example;
use key_manager::verifier::SignatureVerifier;
use rsa::rand_core::OsRng;

fn main() {
    // see function code, main is just a wrapper to run the example
    rsa_example();
}

fn rsa_example() {
    let key_manager = create_key_manager_example("rsa");

    // --- Key generation

    // Internally the key manager generates a key pair,
    // stores the private key and the corresponding public key in the encrypted keystore.
    // The public key is later used to select the corresponding private key for signing.
    // Entropy source responsibility is delegated to the caller.

    // using secp256k1's thread_rng as an example RNG
    let mut rng = secp256k1::rand::thread_rng();

    let public_key_pem_a = key_manager
        .generate_rsa_keypair(&mut rng)
        .expect("Failed to generate RSA key pair");

    println!(
        "New RSA key pair A created and stored. Public key is: {}",
        public_key_pem_a
    );

    // using OsRng as another example RNG
    let mut os_rng = OsRng;
    let public_key_pem_b = key_manager
        .generate_rsa_keypair_custom(&mut os_rng, 4096)
        .expect("Failed to generate RSA key pair");

    println!(
        "New RSA key pair B created and stored. Public key is: {}",
        public_key_pem_b
    );

    // --- Signing and verification

    let message = random_message().to_string().as_bytes().to_vec();
    let signature_verifier = SignatureVerifier::new();

    let signature = key_manager.sign_rsa_message(&message, &public_key_pem_a).unwrap();
    let verified_a = signature_verifier
        .verify_rsa_signature(&signature, &message, &public_key_pem_a)
        .unwrap();

    println!("RSA signature A verified: {}", verified_a);

    let signature = key_manager.sign_rsa_message(&message, &public_key_pem_b).unwrap();
    let verified_b = signature_verifier
        .verify_rsa_signature(&signature, &message, &public_key_pem_b)
        .unwrap();

    println!("RSA signature B verified: {}", verified_b);
}

fn random_message() -> Message {
    let mut digest = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut digest);
    Message::from_digest(digest)
}