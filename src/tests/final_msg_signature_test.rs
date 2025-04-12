#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf, rc::Rc};

    use storage_backend::storage::Storage;

    use crate::{
        musig2::musig::{MuSig2Signer, MuSig2SignerApi},
        tests::utils::helper::{clear_output, create_key_manager, create_pub_key},
    };

    #[test]
    fn test_final_signature() -> Result<(), anyhow::Error> {
        // Set up test environment
        let path = PathBuf::from(format!("test_output/test_final_signature_1"));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager_1 = create_key_manager("test_output/keystore_1", store.clone())?;

        let pub_key_part_1 = create_pub_key(&key_manager_1)?;
        let musig_1 = MuSig2Signer::new(store);

        let path = PathBuf::from(format!("test_output/test_final_signature_2"));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager_2 = create_key_manager("test_output/keystore_2", store.clone())?;

        let pub_key_part_2 = create_pub_key(&key_manager_2)?;
        let musig_2 = MuSig2Signer::new(store);

        let participant_pubkeys = vec![pub_key_part_1, pub_key_part_2];
        let aggregated_pub_key_1 =
            musig_1.new_session(participant_pubkeys.clone(), pub_key_part_1)?;
        let aggregated_pub_key_2 =
            musig_2.new_session(participant_pubkeys.clone(), pub_key_part_2)?;

        key_manager_1.generate_nonce(
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pub_key_1,
            None,
        )?;
        key_manager_2.generate_nonce(
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pub_key_2,
            None,
        )?;

        // Check if the aggregated pub keys are the same
        assert_eq!(aggregated_pub_key_1, aggregated_pub_key_2);

        // Add nonces
        let nonces_1 = musig_1.get_my_pub_nonces(&aggregated_pub_key_1).unwrap();
        let nonces_2 = musig_2.get_my_pub_nonces(&aggregated_pub_key_2).unwrap();
        let mut nonces_map_1 = HashMap::new();
        let mut nonces_map_2 = HashMap::new();
        nonces_map_1.insert(pub_key_part_1, nonces_1);
        nonces_map_2.insert(pub_key_part_2, nonces_2);

        musig_1.aggregate_nonces(&aggregated_pub_key_1, nonces_map_2.clone())?;
        musig_2.aggregate_nonces(&aggregated_pub_key_2, nonces_map_1.clone())?;

        // Get partial signatures
        let my_partial_sigs_1 = key_manager_1.get_my_partial_signatures(&aggregated_pub_key_1)?;
        let my_partial_sigs_2 = key_manager_2.get_my_partial_signatures(&aggregated_pub_key_2)?;

        key_manager_1.save_partial_signatures(
            &aggregated_pub_key_1,
            pub_key_part_2,
            my_partial_sigs_2,
        )?;
        key_manager_2.save_partial_signatures(
            &aggregated_pub_key_2,
            pub_key_part_1,
            my_partial_sigs_1,
        )?;

        let signature_1 = musig_1.get_aggregated_signature(&aggregated_pub_key_1, "message_1")?;
        let signature_2 = musig_2.get_aggregated_signature(&aggregated_pub_key_2, "message_1")?;

        let verification_1 =
            musig_1.verify_final_signature(&"message_1", signature_1, aggregated_pub_key_1)?;

        let verification_2 =
            musig_2.verify_final_signature(&"message_1", signature_2, aggregated_pub_key_2)?;

        assert!(verification_1);
        assert!(verification_2);

        clear_output();

        Ok(())
    }
}
