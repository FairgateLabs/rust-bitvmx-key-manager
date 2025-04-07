#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf, rc::Rc};

    use bitcoin::PublicKey;
    use storage_backend::storage::Storage;

    use crate::{musig2::{errors::Musig2SignerError, musig::{MuSig2Signer, MuSig2SignerApi}}, tests::utils::helper::{clear_output, create_key_manager}};

    #[test]
    fn test_get_nonces() -> Result<(), anyhow::Error> {
        let path = PathBuf::from(format!("test_output/test_nonce_1"));
        let store = Rc::new(Storage::new_with_path(&path)?);
        let key_manager = create_key_manager("test_output/keystore_nonce_1", store.clone())?;
        let mut rng = bitcoin::key::rand::thread_rng();
        let my_pubkey = key_manager.generate_keypair(&mut rng)?;

        let musig = MuSig2Signer::new(store);
        let key_manager = Rc::new(key_manager);

        let musig_id = "1234567890";

        let participant_pubkeys = vec![
            "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
                .parse::<PublicKey>()
                .unwrap(),
            my_pubkey,
        ];

        let aggregated_pubkey = musig.new_session(musig_id, participant_pubkeys.clone(), my_pubkey)?;

        key_manager.generate_nonce(musig_id, "message_1", "message_1".as_bytes().to_vec(), &aggregated_pubkey, None)?;

        // Test getting nonces returns expected number
        let pub_nonces = musig.get_my_pub_nonces(musig_id);
        assert!(pub_nonces.is_ok());

        // Test getting nonces for non-existent id fails
        let result = musig.get_my_pub_nonces("non_existent_id");
        assert!(matches!(result, Err(Musig2SignerError::MuSig2IdNotFound)));

        clear_output();

        Ok(())
    }

    #[test]
    fn test_add_nonces() -> Result<(), anyhow::Error> {
        let path = PathBuf::from(format!("test_output/test_nonce_2"));
        let store = Rc::new(Storage::new_with_path(&path)?);
        let key_manager = create_key_manager("test_output/keystore_nonce_2", store.clone())?;
        let mut rng = bitcoin::key::rand::thread_rng();
        let participant_2 = key_manager.generate_keypair(&mut rng)?;
        let musig = MuSig2Signer::new(store);
        let key_manager = Rc::new(key_manager);

        let musig_id = "1234567890";

        let participant_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();

        let participant_pubkeys = vec![participant_1, participant_2];

        let aggregated_pubkey = musig.new_session(musig_id, participant_pubkeys.clone(), participant_2)?;

        //For now we use the same nonces that we get from the first participant.
        let nonces = musig.get_my_pub_nonces(musig_id);

        // Test getting nonces before adding any messages returns error
        assert!(matches!(nonces, Err(Musig2SignerError::NoncesNotGenerated)));

        key_manager.generate_nonce(musig_id, "message_1", "message_1".as_bytes().to_vec(), &aggregated_pubkey, None)?;

        let nonces = musig.get_my_pub_nonces(musig_id).unwrap();

        // Create nonces map for second participant
        let mut pub_nonces_map = HashMap::new();
        pub_nonces_map.insert(participant_2, nonces.clone());

        // Test adding nonces for non-existent id fails
        let result = musig.aggregate_nonces("non_existent_id", pub_nonces_map.clone());
        assert!(matches!(result, Err(Musig2SignerError::MuSig2IdNotFound)));

        let result = musig.aggregate_nonces(musig_id, pub_nonces_map.clone());
        assert!(matches!(result, Err(Musig2SignerError::InvalidPublicKey)));

        let mut pub_nonces_map = HashMap::new();
        pub_nonces_map.insert(participant_1, nonces.clone());

        // Test adding duplicate nonces fails
        musig.aggregate_nonces(musig_id, pub_nonces_map.clone())?;
        let result = musig.aggregate_nonces(musig_id, pub_nonces_map.clone());
        println!("result: {:?}", result);

        assert!(matches!(result, Err(Musig2SignerError::NonceAlreadyExists)));

        clear_output();

        Ok(())
    }

    #[test]
    /// This test verifies that:
    /// 1. Nonces are deterministic - requesting a nonce multiple times for the same musig session and message returns the same nonce
    /// 2. Nonces are unique across different musig sessions - requesting a nonce for a different musig session with the same message returns a different nonce
    fn test_nonce_generation() -> Result<(), anyhow::Error> {
        // Set up test environment with storage and key manager
        let path = PathBuf::from(format!("test_output/test_nonce_3"));
        let store = Rc::new(Storage::new_with_path(&path)?);
        let key_manager = create_key_manager("test_output/keystore_nonce_3", store.clone())?;
        let mut rng = bitcoin::key::rand::thread_rng();
        let participant_2 = key_manager.generate_keypair(&mut rng)?;
        let musig = MuSig2Signer::new(store);
        let key_manager = Rc::new(key_manager);

        let musig_id = "1234567890";

        // Set up participants
        let participant_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();
        let participant_pubkeys = vec![participant_1, participant_2];

        // Initialize first musig session
        let aggregated_pubkey = musig.new_session(musig_id, participant_pubkeys.clone(), participant_2)?;
        key_manager.generate_nonce(musig_id, "message_1", "message_1".as_bytes().to_vec(), &aggregated_pubkey, None)?;
        // Test nonce determinism - same session and message should give same nonce
        let my_pub_nonce = musig.get_my_pub_nonces(musig_id).unwrap();
        let my_pub_nonce_again = musig.get_my_pub_nonces(musig_id).unwrap();
        assert_eq!(my_pub_nonce, my_pub_nonce_again);

        // Test nonce uniqueness - different session should give different nonce
        let other_musig_id = "other_musig_id";
        let aggregated_pubkey = musig.new_session(other_musig_id, participant_pubkeys.clone(), participant_2)?;
        key_manager.generate_nonce(other_musig_id, "message_1", "message_1".as_bytes().to_vec(), &aggregated_pubkey, None)?;
        let my_pub_nonce_again = musig.get_my_pub_nonces(other_musig_id).unwrap();
        assert_ne!(my_pub_nonce, my_pub_nonce_again);

        clear_output();

        Ok(())
    }
}