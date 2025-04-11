#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf, rc::Rc};

    use bitcoin::PublicKey;
    use storage_backend::storage::Storage;

    use crate::{
        musig2::{
            errors::Musig2SignerError,
            musig::{MuSig2Signer, MuSig2SignerApi},
        },
        tests::utils::helper::{clear_output, create_key_manager, create_pub_key},
    };

    #[test]
    fn test_get_partial_signatures() -> Result<(), anyhow::Error> {
        // Set up test environment
        let path = PathBuf::from(format!("test_output/test_partial_1"));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager = create_key_manager("test_output/keystore_partial_1", store.clone())?;
        let participant_2 = create_pub_key(&key_manager)?;

        let musig = MuSig2Signer::new(store);
        let key_manager = Rc::new(key_manager);

        let participant_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();
        let participant_pubkeys = vec![participant_1, participant_2];

        let aggregated_pubkey = musig
            .new_session(participant_pubkeys.clone(), participant_2)
            .expect("Failed to initialize MuSig session");

        let index = musig.get_index(&aggregated_pubkey)?;
        let public_key = musig.my_public_key(&aggregated_pubkey)?;

        let nonce_seed: [u8; 32] = key_manager
            .generate_nonce_seed(index, public_key)
            .map_err(|_| Musig2SignerError::NonceSeedError)?;

        musig.generate_nonce(
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            None,
            nonce_seed,
        )?;

        musig.get_my_pub_nonces(&aggregated_pubkey).unwrap();

        let result = key_manager.get_my_partial_signatures(&aggregated_pubkey);
        assert!(matches!(
            result,
            Err(Musig2SignerError::IncompleteParticipantNonces)
        ));

        // Use same nonces for both participants

        let mut nonces_map = HashMap::new();
        nonces_map.insert(
            participant_1,
            musig.get_my_pub_nonces(&aggregated_pubkey).unwrap(),
        );

        musig
            .aggregate_nonces(&aggregated_pubkey, nonces_map)
            .unwrap();

        // Test getting partial signatures
        let result = key_manager.get_my_partial_signatures(&aggregated_pubkey);
        assert!(result.is_ok());

        // Test getting partial signatures for non-existent ID
        let result = key_manager.get_my_partial_signatures(&public_key);
        assert!(matches!(result, Err(Musig2SignerError::MuSig2IdNotFound)));

        clear_output();

        Ok(())
    }

    /*
    //TODO: FIX TESTS

    #[test]
    fn test_add_partial_signatures() -> Result<(), anyhow::Error> {
        // Set up test environment
        let path = PathBuf::from(format!("test_output/test_partial_2"));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager = create_key_manager("test_output/keystore_partial_2", store.clone())?;

        let pub_key_part_1 = create_pub_key(&key_manager)?;
        let pub_key_part_2 = create_pub_key(&key_manager)?;

        let musig = MuSig2Signer::new(store);
        let key_manager = Rc::new(key_manager);

        let musig_id_1 = "1";
        let musig_id_2 = "2";

        let participant_pubkeys = vec![pub_key_part_1, pub_key_part_2];

        // Initialize MuSig2 session 1 with two participants
        let aggregated_pubkey =
            musig.new_session(musig_id_1, participant_pubkeys.clone(), pub_key_part_1)?;
        key_manager.generate_nonce(
            musig_id_1,
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            None,
        )?;

        // Create nonces for pub_key_part_1
        let mut nonce_part_1 = HashMap::new();
        let nonces = musig.get_my_pub_nonces(musig_id_1).unwrap();
        nonce_part_1.insert(pub_key_part_1, nonces);

        // Initialize MuSig2 session 2 with the same two participants
        let aggregated_pubkey =
            musig.new_session(musig_id_2, participant_pubkeys.clone(), pub_key_part_2)?;
        key_manager.generate_nonce(
            musig_id_2,
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            None,
        )?;

        // Create nonces for pub_key_part_2
        let mut nonce_part_2 = HashMap::new();
        let nonces = musig.get_my_pub_nonces(musig_id_2).unwrap();
        nonce_part_2.insert(pub_key_part_2, nonces);

        musig.aggregate_nonces(musig_id_1, nonce_part_2).unwrap();
        musig.aggregate_nonces(musig_id_2, nonce_part_1).unwrap();

        let partial_sig_part_2 = key_manager.get_my_partial_signatures(musig_id_2).unwrap();
        let partial_sig_part_1 = key_manager.get_my_partial_signatures(musig_id_1).unwrap();

        // Test adding partial signatures with invalid public key
        let mut partial_sigs_2 = HashMap::new();
        partial_sigs_2.insert(pub_key_part_2, partial_sig_part_2.clone());
        partial_sigs_2.insert(pub_key_part_1, partial_sig_part_1.clone());

        let result = musig.save_partial_signatures(musig_id_1, partial_sigs_2.clone());
        assert!(matches!(result, Ok(_)));

        //Test adding duplicate partial signatures
        let result = musig.save_partial_signatures(musig_id_1, partial_sigs_2);
        assert!(matches!(
            result,
            Err(Musig2SignerError::PartialSignatureAlreadyExists)
        ));

        // Test adding partial signatures for non-existent ID
        let result = musig.save_partial_signatures("non_existent_id", HashMap::new());
        assert!(matches!(result, Err(Musig2SignerError::MuSig2IdNotFound)));

        clear_output();

        Ok(())
    }

    #[test]
    fn test_verify_invalid_partial_signature() -> Result<(), anyhow::Error> {
        let path = PathBuf::from(format!("test_output/test_partial_3"));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager = create_key_manager("test_output/keystore_partial_3", store.clone())?;
        let pub_key_part_2 = create_pub_key(&key_manager)?;
        let pub_key_part_3 = create_pub_key(&key_manager)?;

        let musig = MuSig2Signer::new(store);
        let key_manager = Rc::new(key_manager);

        let musig_id = "1234567890";

        // Initialize with two participants
        let pub_key_part_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();

        let participant_pubkeys = vec![pub_key_part_1, pub_key_part_2];

        let aggregated_pubkey =
            musig.new_session(musig_id, participant_pubkeys.clone(), pub_key_part_2)?;

        key_manager.generate_nonce(
            musig_id,
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            None,
        )?;

        let mut nonces_part_1 = HashMap::new();
        let nonce = musig.get_my_pub_nonces(musig_id).unwrap();
        nonces_part_1.insert(pub_key_part_1, nonce);

        musig
            .aggregate_nonces(musig_id, nonces_part_1.clone())
            .unwrap();

        let other_musig_id = "other_musig_id";
        let participant_pubkeys = vec![pub_key_part_1, pub_key_part_3];

        let aggregated_pubkey =
            musig.new_session(other_musig_id, participant_pubkeys.clone(), pub_key_part_3)?;

        key_manager.generate_nonce(
            other_musig_id,
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            None,
        )?;

        musig.get_my_pub_nonces(&other_musig_id).unwrap();

        musig
            .aggregate_nonces(other_musig_id, nonces_part_1)
            .unwrap();

        // The only way to add the message.
        musig.get_my_pub_nonces(&other_musig_id).unwrap();

        let other_partial_signature = key_manager
            .get_my_partial_signatures(other_musig_id)
            .unwrap();

        // Add partial signature for participant 1 which is not a correct partial signature (belongs to participant 1 and 2)
        let result = musig.save_partial_signatures(
            musig_id,
            HashMap::from([
                (pub_key_part_1, other_partial_signature.clone()),
                (pub_key_part_2, other_partial_signature),
            ]),
        );
        assert!(matches!(
            result,
            Err(Musig2SignerError::InvalidPartialSignature)
        ));

        clear_output();

        Ok(())
    }

    #[test]
    fn test_verify_partial_signature() -> Result<(), anyhow::Error> {
        let path = PathBuf::from(format!("test_output/test_partial_4"));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager = create_key_manager("test_output/keystore_partial_4", store.clone())?;
        let my_pub_key = create_pub_key(&key_manager)?;

        let musig = MuSig2Signer::new(store);
        let key_manager = Rc::new(key_manager);

        let musig_id = "1234567890";

        // Initialize with two participants
        let participant_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();

        let participant_pubkeys = vec![participant_1, my_pub_key];

        let aggregated_pubkey = musig
            .new_session(musig_id, participant_pubkeys.clone(), my_pub_key)
            .expect("Failed to initialize MuSig session");

        key_manager.generate_nonce(
            musig_id,
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            None,
        )?;

        // Add nonce for participant 1, are a copy of nonces of participant 2
        let mut nonces_map = HashMap::new();
        let nonces = musig.get_my_pub_nonces(musig_id).unwrap();
        nonces_map.insert(participant_1, nonces);

        musig.aggregate_nonces(musig_id, nonces_map).unwrap();

        let partial_signatures = key_manager.get_my_partial_signatures(musig_id).unwrap();

        // Test verifying partial signature for non-existent ID
        let result = musig.verify_partial_signatures(
            "non_existent_id",
            participant_1,
            partial_signatures.clone(),
        );
        assert!(matches!(result, Err(Musig2SignerError::MuSig2IdNotFound)));

        // Test verifying invalid partial signature
        let result =
            musig.verify_partial_signatures(musig_id, participant_1, partial_signatures.clone());
        assert!(matches!(
            result,
            Err(Musig2SignerError::InvalidPartialSignature)
        ));

        // Test verifying valid partial signature
        let is_valid = musig.verify_partial_signatures(musig_id, my_pub_key, partial_signatures)?;
        assert!(is_valid);

        clear_output();

        Ok(())
    }
    */
}
