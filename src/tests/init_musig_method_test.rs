#[cfg(test)]
mod tests {
    use crate::{
        musig2::{errors::Musig2SignerError, musig::MuSig2SignerApi},
        tests::utils::helper::{clear_output, mock_data},
    };

    #[test]
    fn test_init_musig_method() -> Result<(), anyhow::Error> {
        let (_, my_pub_key, musig) = mock_data()?;
        let (_, my_pub_key2, _) = mock_data()?;
        let (_, my_pub_key3, _) = mock_data()?;

        let participant_pubkeys = vec![my_pub_key, my_pub_key2, my_pub_key3];
        let _aggregated_pubkey = musig.new_session(participant_pubkeys.clone(), my_pub_key)?;

        clear_output();

        Ok(())
    }

    #[test]
    fn test_init_musig_invalid_participants() -> Result<(), anyhow::Error> {
        let (_, my_pub_key, musig) = mock_data()?;
        let participant_pubkeys = vec![my_pub_key];
        let result = musig.new_session(participant_pubkeys.clone(), my_pub_key);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Musig2SignerError::InvalidNumberOfParticipants
        ));

        clear_output();

        Ok(())
    }

    #[test]
    fn test_init_musig_invalid_participant_key_no_current_pub_key() -> Result<(), anyhow::Error> {
        let (_, my_pub_key, musig) = mock_data()?;
        let (_, my_pub_key2, _) = mock_data()?;
        let (_, my_pub_key3, _) = mock_data()?;
        let participant_pubkeys = vec![my_pub_key, my_pub_key2];
        let result = musig.new_session(participant_pubkeys.clone(), my_pub_key3);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Musig2SignerError::InvalidNumberOfParticipants
        ));

        clear_output();

        Ok(())
    }

    #[test]
    fn test_init_musig_unsort_pub_keys() -> Result<(), anyhow::Error> {
        let (_, participant_1, musig) = mock_data()?;
        let (_, participant_2, _) = mock_data()?;
        let (_, participant_3, _) = mock_data()?;

        let participant_pubkeys = vec![participant_1, participant_2, participant_3];
        let aggregated_pub_key = musig
            .new_session(participant_pubkeys.clone(), participant_1)
            .unwrap();

        let participant_pubkeys = vec![participant_3, participant_1, participant_2];

        let aggregated_pub_key_2 = musig
            .new_session(participant_pubkeys.clone(), participant_1)
            .unwrap();

        // Check if the aggregated pub keys are the same
        assert_eq!(aggregated_pub_key, aggregated_pub_key_2);

        clear_output();

        Ok(())
    }
}
