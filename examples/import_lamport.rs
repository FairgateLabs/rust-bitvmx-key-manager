mod create;

use create::create_key_manager_example;

use bitcoin::key::rand::RngCore;
use bitcoin::secp256k1;

use key_manager::lamport::{Lamport, LamportType};

fn main() {
    // see function code, main is just a wrapper to run the example
    import_sign_verify_lamport_example();
}

fn import_sign_verify_lamport_example() {
    let key_manager = create_key_manager_example("sign_verify_lamport");

    // --- Signing and verifying a message using Lamport

    // Create a random message bit (0 or 1) (using bit to mimic the garbled circuit use case)
    // Commonly, you would hash the message and use the hash as input to the Lamport signature scheme

    /*  In the Fairgate Garbled Circuit use case, they use Scalar
        we wont introduce the scalar dependency here but, from their code:
        If you need serialization for persistent storage, Scalar::to_repr() gives you a 32-byte representation, and Scalar::from_repr() reverses it.
        so we will use some random 32-byte values to mimic the private key parts
    */
    let mut rng = secp256k1::rand::thread_rng();
    let message_bit = (rng.next_u32() % 2) == 1;
    println!("Message bit: {:?}", message_bit);

    let mut random_bytes_0 = [0u8; 32];
    rng.fill_bytes(&mut random_bytes_0);

    let mut random_bytes_1 = [0u8; 32];
    rng.fill_bytes(&mut random_bytes_1);

    // Get the Lamport public key with message bit length = 1 using the SHA-256 hash function
    let lamport_pubkey = key_manager
        .import_lamport_private_key(
            &random_bytes_0,
            &random_bytes_1,
            1usize,
            LamportType::SHA256,
        )
        .unwrap();

    // Create a Lamport signature
    let signature = key_manager
        .sign_lamport_bit_by_pubkey(message_bit, &lamport_pubkey)
        .unwrap();
    println!(
        "(using imported) Lamport signature: {:?}",
        hex::encode(signature.to_bytes())
    );

    // Verify the signature
    let lamport = Lamport::new();
    let is_valid = lamport
        .verify_signature_bit(message_bit, &signature, &lamport_pubkey)
        .unwrap();
    println!("(using imported) Is signature valid: {:?}", is_valid);
    assert!(is_valid);
}
