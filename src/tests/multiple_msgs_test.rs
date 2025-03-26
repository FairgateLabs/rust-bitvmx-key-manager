#[cfg(test)]
    mod tests {

    use std::{collections::HashMap, path::PathBuf, rc::Rc};
    use storage_backend::storage::Storage;

    use crate::{musig2::musig::{MuSig2Signer, MuSig2SignerApi}, tests::utils::helper::{clear_output, create_key_manager, create_pub_key}};

    #[test]
    fn test_multiple_messages() -> Result<(), anyhow::Error> {
        // Set up test environment
        let path = PathBuf::from(format!("test_output/test_multiple_messages"));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager = create_key_manager("test_output/keystore_10", store.clone())?;
        let pub_key_part_1 = create_pub_key(&key_manager)?;
        let pub_key_part_2 = create_pub_key(&key_manager)?;
        let musig = MuSig2Signer::new(store);
        let key_manager = Rc::new(key_manager);
        let musig_id_1 = "1";
        let musig_id_2 = "2"; // Use other id for testing porpouse

        let participant_pubkeys = vec![pub_key_part_1, pub_key_part_2];
        musig.init(musig_id_1, participant_pubkeys.clone(), pub_key_part_1)?;

        let aggregated_pub_key = key_manager.get_aggregated_pubkey(musig_id_1, None)?;

        let messages = vec!["1 test message", "2 test message", "3 test message"];

        // Generate pub nonces for all messages
        key_manager.generate_nonce(musig_id_1, messages[0], messages[0].as_bytes().to_vec(), None)?;
        key_manager.generate_nonce(musig_id_1, messages[1], messages[1].as_bytes().to_vec(), None)?;
        key_manager.generate_nonce(musig_id_1, messages[2], messages[2].as_bytes().to_vec(), None)?;

        musig.init(musig_id_2, participant_pubkeys.clone(), pub_key_part_2)?;

        let aggregated_pub_key_2 = key_manager.get_aggregated_pubkey(musig_id_2, None)?;

        // Generate pub nonces for all messages
        key_manager.generate_nonce(musig_id_2, messages[0], messages[0].as_bytes().to_vec(), None)?;
        key_manager.generate_nonce(musig_id_2, messages[1], messages[1].as_bytes().to_vec(), None)?;
        key_manager.generate_nonce(musig_id_2, messages[2], messages[2].as_bytes().to_vec(), None)?;

        // Check if the aggregated pub keys are the same
        assert_eq!(aggregated_pub_key, aggregated_pub_key_2);

        // Add nonces
        let nonces_1 = musig.get_my_pub_nonces(musig_id_1).unwrap();
        let nonces_2 = musig.get_my_pub_nonces(musig_id_2).unwrap();

        // Check that nonces length matches number of messages
        assert_eq!(nonces_1.len(), messages.len());
        assert_eq!(nonces_2.len(), messages.len());

        let mut nonces_map_1 = HashMap::new();
        let mut nonces_map_2 = HashMap::new();
        nonces_map_1.insert(pub_key_part_1, nonces_1);
        nonces_map_2.insert(pub_key_part_2, nonces_2);

        musig.aggregate_nonces(musig_id_1, nonces_map_2.clone())?;
        musig.aggregate_nonces(musig_id_2, nonces_map_1.clone())?;

        // Get partial signatures
        let my_partial_sigs_1 = key_manager.get_my_partial_signatures(musig_id_1).unwrap();
        let my_partial_sigs_2 = key_manager.get_my_partial_signatures(musig_id_2).unwrap();

        // Check that partial signatures length matches number of messages
        assert_eq!(my_partial_sigs_1.len(), messages.len());
        assert_eq!(my_partial_sigs_2.len(), messages.len());

        // let mut partial_sigs_1 = HashMap::new();
        // partial_sigs_1.insert(pub_key_part_1, my_partial_sigs_1);

        // let mut partial_sigs_2 = HashMap::new();
        // partial_sigs_2.insert(pub_key_part_2, my_partial_sigs_2);

        key_manager.save_partial_signatures(musig_id_1, pub_key_part_2, my_partial_sigs_2)?;
        key_manager.save_partial_signatures(musig_id_2, pub_key_part_1, my_partial_sigs_1)?;

        let signature_1 = musig.get_aggregated_signature(musig_id_1, &messages[0])?;
        let signature_2 = musig.get_aggregated_signature(musig_id_2, &messages[1])?;
        // Check that signatures length matches number of messages

        let verification_1 =
            musig.verify_final_signature(musig_id_1, &messages[0], signature_1, aggregated_pub_key)?;

        let verification_2 =
            musig.verify_final_signature(musig_id_2, &messages[1], signature_2, aggregated_pub_key)?;

        assert!(verification_1);
        assert!(verification_2);

        clear_output();

        Ok(())
    }
}