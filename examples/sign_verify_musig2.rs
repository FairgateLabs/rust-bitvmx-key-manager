mod create;

use std::collections::HashMap;

use create::create_key_manager_example;

use key_manager::{errors::KeyManagerError, key_type::BitcoinKeyType};

use crate::create::clear_storage;

fn main() -> Result<(), KeyManagerError> {
    // Clear the storage before the example to avoid conflicts
    clear_storage();
    // see function code, main is just a wrapper to run the example
    sign_verify_musig2_example()?;
    Ok(())
}

fn sign_verify_musig2_example() -> Result<(), KeyManagerError> {
    let _ = std::fs::remove_dir_all("test_output");
    // You
    let key_manager = create_key_manager_example("sign_verify_musig2");

    // Other participant
    let other_key_manager = create_key_manager_example("sign_verify_musig2_other");

    // Get all participant public keys
    let my_pubkey = key_manager
        .derive_keypair(BitcoinKeyType::P2wpkh, 0)
        .unwrap();

    let other_pubkey = other_key_manager
        .derive_keypair(BitcoinKeyType::P2wpkh, 0)
        .unwrap();

    // Step 1: Initialize MuSig2 session
    // Public keys must be in the same order for all participants
    let participant_pubkeys = vec![my_pubkey, other_pubkey];

    // Initialize a new MuSig2 session, it creates the aggregated public key
    let aggregated_pubkey =
        key_manager.new_musig2_session(participant_pubkeys.clone(), my_pubkey)?;
    println!("Aggregated public key: {:?}", aggregated_pubkey);

    // The other participant does the same, the aggregated public key is the same for all participants
    other_key_manager.new_musig2_session(participant_pubkeys.clone(), other_pubkey)?;

    // Step 2: Generate nonces for each message
    // Create a Message and id for the message and session, a session can have multiple messages.
    let message = "Hello, MuSig2!";
    let message_id = "msg_1";
    let session_id = "session_1";
    let tweak = None;

    // Generate a nonce for the message
    key_manager.generate_nonce(
        message_id,
        message.as_bytes().to_vec(),
        &aggregated_pubkey,
        session_id,
        tweak,
    )?;

    // Do the same for the other participant
    other_key_manager.generate_nonce(
        message_id,
        message.as_bytes().to_vec(),
        &aggregated_pubkey,
        session_id,
        tweak,
    )?;

    // Step 3: Exchange public nonces with other participants
    // Get the public nonces for the message
    let my_pub_nonces = key_manager.get_my_pub_nonces(&aggregated_pubkey, session_id)?;
    println!("My public nonces: {:?}", my_pub_nonces);

    let other_pub_nonces = other_key_manager.get_my_pub_nonces(&aggregated_pubkey, session_id)?;
    println!("Other public nonces: {:?}", other_pub_nonces);

    // Step 4: Aggregate nonces from all participants
    let mut nonces_map = HashMap::new();
    nonces_map.insert(other_pubkey, other_pub_nonces);
    key_manager.aggregate_nonces(&aggregated_pubkey, session_id, nonces_map)?;

    // Do the same for the other participant
    let mut nonces_map = HashMap::new();
    nonces_map.insert(my_pubkey.clone(), my_pub_nonces);
    other_key_manager.aggregate_nonces(&aggregated_pubkey, session_id, nonces_map)?;
    println!("Nonces aggregated");

    // Step 5: Create partial signatures
    // Get the partial signatures for the message
    let my_partial_sigs = key_manager.get_my_partial_signatures(&aggregated_pubkey, session_id)?;
    println!("My partial signatures: {:?}", my_partial_sigs);

    // Get the partial signatures for the message
    let other_partial_sigs =
        other_key_manager.get_my_partial_signatures(&aggregated_pubkey, session_id)?;
    println!("Other partial signatures: {:?}", other_partial_sigs);

    // Step 6: Exchange and save partial signatures
    let mut partial_sigs_map = HashMap::new();
    partial_sigs_map.insert(my_pubkey, my_partial_sigs.clone());
    partial_sigs_map.insert(other_pubkey, other_partial_sigs.clone());
    key_manager.save_partial_signatures(
        &aggregated_pubkey,
        session_id,
        partial_sigs_map.clone(),
    )?;

    // Do the same for the other participant
    let mut partial_sigs_map = HashMap::new();
    partial_sigs_map.insert(my_pubkey, my_partial_sigs);
    partial_sigs_map.insert(other_pubkey, other_partial_sigs);
    other_key_manager.save_partial_signatures(&aggregated_pubkey, session_id, partial_sigs_map)?;
    println!("Partial signatures saved");

    // Step 7: Get the aggregated signature
    let aggregated_signature =
        key_manager.get_aggregated_signature(&aggregated_pubkey, session_id, message_id)?;
    println!("Aggregated signature: {:?}", aggregated_signature);

    // Verify the final signature
    let verification = key_manager.verify_final_signature(
        message_id,
        aggregated_signature,
        aggregated_pubkey,
        session_id,
    );
    // True if the signature is valid otherwise error
    println!("Verification: {:?}", verification);
    if verification.is_err() {
        return Err(verification.unwrap_err());
    }

    Ok(())
}
