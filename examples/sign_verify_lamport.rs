mod create;

use create::create_key_manager_example;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::rand::RngCore;
use bitcoin::secp256k1;

use key_manager::lamport::{bits_to_bytes, Lamport, LamportCompressedPubKey, LamportType};

fn main() {
    // see function code, main is just a wrapper to run the example
    sign_verify_lamport_example();
}

fn sign_verify_lamport_example() {
    let key_manager = create_key_manager_example("sign_verify_lamport");
    let bincode_config = bincode::config::standard();

    // --- Signing and verifying a message using Lamport

    // Create a random message bit (0 or 1) (using bit to mimic the garbled circuit use case)
    // Commonly, you would hash the message and use the hash as input to the Lamport signature scheme
    let mut rng = secp256k1::rand::thread_rng();
    let message_bit = (rng.next_u32() % 2) == 1;
    println!("Message bit: {:?}", message_bit);

    // Using next - recommended

    // Get the Lamport public key with message bit length = 1 using the SHA-256 hash function
    let lamport_pubkey = key_manager.next_lamport(1, LamportType::SHA256).unwrap();

    // Difference in size between serialized compressed and uncompressed public key
    println!(
        "\nSerialized compressed Lamport public key ({} bytes)",
        bincode::serde::encode_to_vec(lamport_pubkey.to_compressed(), bincode_config)
            .unwrap()
            .len()
    );
    println!(
        "Serialized uncompressed Lamport public key ({} bytes)",
        bincode::serde::encode_to_vec(&lamport_pubkey, bincode_config)
            .unwrap()
            .len()
    );

    // Create a Lamport signature
    let signature = key_manager
        .sign_lamport_message_by_pubkey(message_bit, &lamport_pubkey)
        .unwrap();
    println!(
        "(using next) Lamport signature: {:?}",
        hex::encode(signature.to_bytes())
    );

    // Verify the signature
    let lamport = Lamport::new();
    let (is_valid, _reconstructed_msg) = lamport
        .verify_signature(Some(message_bit), &signature, &lamport_pubkey)
        .unwrap();
    println!("(using next) Is signature valid: {:?}", is_valid);
    assert!(is_valid);

    // --- Signing and verifying a 10-bit message using sign_lamport_message_by_pubkey

    // Create a random 10-bit message
    let message_bits: Vec<bool> = (0..10).map(|_| (rng.next_u32() % 2) == 1).collect();
    println!("\n10-bit message: {:?}", message_bits);

    // Get the Lamport public key with message bit length = 10
    let lamport_pubkey_10bit = key_manager.next_lamport(10, LamportType::SHA256).unwrap();

    // Create a Lamport signature for the message
    let signature_10bit = key_manager
        .sign_lamport_message_by_pubkey(&message_bits, &lamport_pubkey_10bit)
        .unwrap();
    println!(
        "Lamport 10-bit signature: {:?}",
        hex::encode(signature_10bit.to_bytes())
    );

    // Verify the signature
    let (is_valid_10bit, _reconstructed_msg_10bit) = lamport
        .verify_signature(Some(&message_bits), &signature_10bit, &lamport_pubkey_10bit)
        .unwrap();
    println!("Is 10-bit signature valid: {:?}", is_valid_10bit);
    assert!(is_valid_10bit);

    // --- Signing and verifying a message using sign_lamport_message_bytes_by_pubkey

    // Convert the 10-bit message to bytes
    let (message_bytes, padding) = bits_to_bytes(&message_bits).unwrap();
    println!(
        "\nMessage as bytes (with {} padding bits): {:?}",
        padding,
        hex::encode(&message_bytes)
    );

    // Note: For bytes, we need 16 bits (2 bytes) as the message length
    // since bits_to_bytes adds padding to make it a multiple of 8

    let message_bit_lenght_padded_to_use_bytes = message_bits.len() + padding as usize;
    // if the user want to use the bytes methods, it should indicate the message length with padding, otherwise will get an MessageLengthMismatch error at signing time
    let lamport_pubkey_bytes = key_manager
        .next_lamport(message_bit_lenght_padded_to_use_bytes, LamportType::SHA256)
        .unwrap();

    // Create a Lamport signature for the message bytes
    let signature_bytes = key_manager
        .sign_lamport_message_by_pubkey(&message_bytes, &lamport_pubkey_bytes)
        .unwrap();
    println!(
        "Lamport byte signature: {:?}",
        hex::encode(signature_bytes.to_bytes())
    );

    // Verify the signature
    let (is_valid_bytes, _reconstructed_msg_bytes) = lamport
        .verify_signature(
            Some(&message_bytes),
            &signature_bytes,
            &lamport_pubkey_bytes,
        )
        .unwrap();
    println!("Is byte signature valid: {:?}", is_valid_bytes);
    assert!(is_valid_bytes);

    // --- Signing and verifying a string message using SHA256 hash

    // Define a string message
    let message = "hi im the message to be signed with lamport :)";
    println!("\n\nString message: {:?}", message);

    // Hash the message with SHA256 to get a 32-byte digest
    let message_hash = sha256::Hash::hash(message.as_bytes());
    let message_digest = message_hash.to_byte_array();
    println!("SHA256 digest: {:?}", hex::encode(message_digest));

    // For a 32-byte digest, we need 256 bits (32 * 8) as the message length
    let lamport_pubkey_string_example = key_manager.next_lamport(256, LamportType::SHA256).unwrap();

    // Example of storing compressed public keys
    let compressed_lamport_pubkey = lamport_pubkey_string_example.to_compressed();
    let serialized_compressed =
        bincode::serde::encode_to_vec(&compressed_lamport_pubkey, bincode_config).unwrap();
    let (deserialized_compressed, _): (LamportCompressedPubKey, usize) =
        bincode::serde::decode_from_slice(&serialized_compressed, bincode_config).unwrap();
    let decompressed_pubkey = key_manager
        .expand_lamport(&deserialized_compressed)
        .unwrap();
    assert_eq!(
        lamport_pubkey_string_example, decompressed_pubkey,
        "Decompressed public key should match the original"
    );

    // Difference in size between serialized compressed and uncompressed public key
    let serialized_uncompressed =
        bincode::serde::encode_to_vec(&lamport_pubkey_string_example, bincode_config).unwrap();
    println!(
        "\nSerialized compressed Lamport public key ({} bytes)",
        serialized_compressed.len()
    );
    println!(
        "Serialized uncompressed Lamport public key ({} bytes)",
        serialized_uncompressed.len()
    );

    // Use the expanded key for operations
    let lamport_pubkey_string_ex = decompressed_pubkey;

    // Create a Lamport signature for the message digest
    let signature_string = key_manager
        .sign_lamport_message_by_pubkey(&message_digest, &lamport_pubkey_string_ex)
        .unwrap();
    println!(
        "Lamport signature for string message: {:?}",
        hex::encode(signature_string.to_bytes())
    );

    // Verify the signature
    let (is_valid_string, _reconstructed_msg_string) = lamport
        .verify_signature(
            Some(&message_digest),
            &signature_string,
            &lamport_pubkey_string_ex,
        )
        .unwrap();
    println!("Is string message signature valid: {:?}", is_valid_string);
    assert!(is_valid_string);
    println!("\n✓ String message signed and verified successfully!");
}
