#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        errors::KeyManagerError,
        musig2::{errors::Musig2SignerError, musig::MuSig2SignerApi},
        tests::utils::helper::{clear_output, mock_data},
    };

    #[test]
    fn test_get_partial_signatures() -> Result<(), anyhow::Error> {
        // Set up test environment
        let (key_manager, participant_1, musig) = mock_data()?;
        let (_, participant_2, _) = mock_data()?;
        let participant_pubkeys = vec![participant_1, participant_2];

        let id = "test_id";
        let aggregated_pubkey = musig
            .new_session(participant_pubkeys.clone(), participant_1)
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
            id,
            None,
            nonce_seed,
        )?;

        musig.get_my_pub_nonces(&aggregated_pubkey, id)?;

        let result = key_manager.get_my_partial_signatures(&aggregated_pubkey, id);
        assert!(matches!(
            result,
            Err(KeyManagerError::Musig2SignerError(
                Musig2SignerError::IncompleteParticipantNonces
            ))
        ));

        // Use same nonces for both participants

        let mut nonces_map = HashMap::new();
        let mypub_nonces = musig.get_my_pub_nonces(&aggregated_pubkey, id)?;
        nonces_map.insert(participant_2, mypub_nonces);
        musig.aggregate_nonces(&aggregated_pubkey, id, nonces_map)?;

        // Test getting partial signatures
        let result = key_manager.get_my_partial_signatures(&aggregated_pubkey, id);
        assert!(result.is_ok());

        // Test getting partial signatures for non-existent ID
        let result = key_manager.get_my_partial_signatures(&public_key, id);
        assert!(matches!(
            result,
            Err(KeyManagerError::Musig2SignerError(
                Musig2SignerError::AggregatedPubkeyNotFound
            ))
        ));

        clear_output();

        Ok(())
    }
}
