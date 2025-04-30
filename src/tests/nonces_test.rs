#[cfg(test)]
mod tests {
    use crate::{
        musig2::{errors::Musig2SignerError, musig::MuSig2SignerApi},
        tests::utils::helper::{clear_output, mock_data},
    };
    use std::collections::HashMap;

    #[test]
    fn test_get_nonces() -> Result<(), anyhow::Error> {
        let (key_manager, participant_1, musig) = mock_data()?;
        let (_, participant_2, _) = mock_data()?;
        let participant_pubkeys = vec![participant_1, participant_2];

        let id = "test_id";
        let aggregated_pubkey =
            musig.new_session(participant_pubkeys.clone(), id, participant_1)?;

        key_manager.generate_nonce(
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            id,
            None,
        )?;

        // Test getting nonces returns expected number
        let pub_nonces = musig.get_my_pub_nonces(&aggregated_pubkey, id);
        assert!(pub_nonces.is_ok());

        // Test getting nonces for non-existent id fails
        let result = musig.get_my_pub_nonces(&participant_1, id);
        assert!(matches!(
            result,
            Err(Musig2SignerError::AggregatedPubkeyNotFound)
        ));

        clear_output();

        Ok(())
    }

    #[test]
    fn test_add_nonces() -> Result<(), anyhow::Error> {
        let (key_manager, participant_1, musig) = mock_data()?;
        let (_, participant_2, _) = mock_data()?;
        let participant_pubkeys = vec![participant_2, participant_1];

        let id = "test_id";
        let aggregated_pubkey =
            musig.new_session(participant_pubkeys.clone(), id, participant_1)?;

        //For now we use the same nonces that we get from the first participant.
        let nonces = musig.get_my_pub_nonces(&aggregated_pubkey, id);

        // Test getting nonces before adding any messages returns error
        assert!(matches!(nonces, Err(Musig2SignerError::NoncesNotGenerated)));

        key_manager.generate_nonce(
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            id,
            None,
        )?;

        let nonces = musig.get_my_pub_nonces(&aggregated_pubkey, id).unwrap();

        // Create nonces map for second participant
        let mut pub_nonces_map = HashMap::new();
        pub_nonces_map.insert(participant_1, nonces.clone());

        // Test adding nonces for non-existent id fails
        let result = musig.aggregate_nonces(&participant_2, id, pub_nonces_map.clone());
        assert!(matches!(
            result,
            Err(Musig2SignerError::AggregatedPubkeyNotFound)
        ));

        let result = musig.aggregate_nonces(&aggregated_pubkey, id, pub_nonces_map.clone());
        assert!(matches!(result, Err(Musig2SignerError::InvalidPublicKey)));

        let mut pub_nonces_map = HashMap::new();
        pub_nonces_map.insert(participant_2, nonces.clone());

        // Test adding duplicate nonces fails
        musig.aggregate_nonces(&aggregated_pubkey, id, pub_nonces_map.clone())?;
        let result = musig.aggregate_nonces(&aggregated_pubkey, id, pub_nonces_map.clone());

        assert!(matches!(result, Err(Musig2SignerError::NonceAlreadyExists)));

        clear_output();

        Ok(())
    }

    #[test]
    /// This test verifies that:
    /// 1. Nonces are deterministic - requesting a nonce multiple times for the same musig session and message returns the same nonce
    /// 2. Nonces are unique across different musig sessions - requesting a nonce for a different musig session with the same message returns a different nonce
    fn test_nonce_generation() -> Result<(), anyhow::Error> {
        let (key_manager, participant_1, musig) = mock_data()?;
        let (key_manager2, participant_2, musig2) = mock_data()?;
        let (_, participant_3, _) = mock_data()?;

        let participant_pubkeys = vec![participant_1, participant_2];

        // Initialize first musig session
        let id = "test_id";
        let aggregated_pubkey =
            musig.new_session(participant_pubkeys.clone(), id, participant_1)?;

        key_manager.generate_nonce(
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            id,
            None,
        )?;

        // Test nonce determinism - same session and message should give same nonce
        let my_pub_nonce = musig.get_my_pub_nonces(&aggregated_pubkey, id).unwrap();
        let my_pub_nonce_again = musig.get_my_pub_nonces(&aggregated_pubkey, id).unwrap();
        assert_eq!(my_pub_nonce, my_pub_nonce_again);

        // Test nonce uniqueness - different session should give different nonce
        let participant_pubkeys = vec![participant_3, participant_2];
        let aggregated_pubkey =
            musig2.new_session(participant_pubkeys.clone(), id, participant_2)?;
        key_manager2.generate_nonce(
            "message_1",
            "message_1".as_bytes().to_vec(),
            &aggregated_pubkey,
            id,
            None,
        )?;

        let my_pub_nonce_again = musig2.get_my_pub_nonces(&aggregated_pubkey, id).unwrap();
        assert_ne!(my_pub_nonce, my_pub_nonce_again);

        clear_output();

        Ok(())
    }
}
