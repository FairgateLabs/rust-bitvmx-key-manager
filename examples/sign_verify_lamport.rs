mod create;

use create::create_key_manager_example;

use bitcoin::key::rand::RngCore;
use bitcoin::secp256k1;

use key_manager::lamport::{Lamport, LamportType};

fn main() {
    // see function code, main is just a wrapper to run the example
    sign_verify_lamport_example();
}

fn sign_verify_lamport_example() {
    let key_manager = create_key_manager_example("sign_verify_lamport");

    // --- Signing and verifying a message using Lamport

    // Create a random message bit (0 or 1) (using bit to mimic the garbled circuit use case)
    // Commonly, you would hash the message and use the hash as input to the Lamport signature scheme
    let mut rng = secp256k1::rand::thread_rng();
    let message_bit = (rng.next_u32() % 2) == 1;
    println!("Message bit: {:?}", message_bit);

    // Using next - recommended

    // Get the Lamport public key with message bit length = 1 using the SHA-256 hash function
    let lamport_pubkey = key_manager.next_lamport(1, LamportType::SHA256).unwrap();

    // Create a Lamport signature
    let signature = key_manager
        .sign_lamport_bit_by_pubkey(message_bit, &lamport_pubkey)
        .unwrap();
    println!(
        "(using next) Lamport signature: {:?}",
        hex::encode(signature.to_bytes())
    );

    // Verify the signature
    let lamport = Lamport::new();
    let is_valid = lamport
        .verify_signature_bit(message_bit, &signature, &lamport_pubkey)
        .unwrap();
    println!("(using next) Is signature valid: {:?}", is_valid);
    assert!(is_valid);
}
