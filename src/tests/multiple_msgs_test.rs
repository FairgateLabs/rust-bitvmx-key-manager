#[cfg(test)]
mod tests {

    use crate::{
        musig2::musig::MuSig2SignerApi,
        tests::utils::helper::{clear_output, mock_data},
    };
    use std::collections::HashMap;

    // This test verifies the MuSig2 protocol's ability to handle multiple messages in a single session.
    // We use two separate MuSig2 signers (musig and musig2) to simulate different participants
    // in a multi-signature scheme. Each participant generates nonces for multiple messages,
    // exchanges them, and then creates partial signatures that can be aggregated into a final
    // signature. This tests the protocol's functionality when dealing with multiple messages
    // that need to be signed by the same set of participants.
    #[test]
    fn test_multiple_messages() -> Result<(), anyhow::Error> {
        let (key_manager, pub_key_part_1, musig) = mock_data()?;
        let (key_manager2, pub_key_part_2, musig2) = mock_data()?;
        let participant_pubkeys = vec![pub_key_part_1, pub_key_part_2];

        let aggregated_pub_key = musig.new_session(participant_pubkeys.clone(), pub_key_part_1)?;
        let messages = ["1 test message", "2 test message", "3 test message"];

        // Generate pub nonces for all messages
        key_manager.generate_nonce(
            messages[0],
            messages[0].as_bytes().to_vec(),
            &aggregated_pub_key,
            None,
        )?;

        key_manager.generate_nonce(
            messages[1],
            messages[1].as_bytes().to_vec(),
            &aggregated_pub_key,
            None,
        )?;

        key_manager.generate_nonce(
            messages[2],
            messages[2].as_bytes().to_vec(),
            &aggregated_pub_key,
            None,
        )?;

        let aggregated_pub_key_2 =
            musig2.new_session(participant_pubkeys.clone(), pub_key_part_2)?;

        key_manager2.generate_nonce(
            messages[0],
            messages[0].as_bytes().to_vec(),
            &aggregated_pub_key,
            None,
        )?;

        key_manager2.generate_nonce(
            messages[1],
            messages[1].as_bytes().to_vec(),
            &aggregated_pub_key,
            None,
        )?;

        key_manager2.generate_nonce(
            messages[2],
            messages[2].as_bytes().to_vec(),
            &aggregated_pub_key,
            None,
        )?;

        // Check if the aggregated pub keys are the same
        assert_eq!(aggregated_pub_key, aggregated_pub_key_2);
        // Add nonces
        let nonces_1 = musig.get_my_pub_nonces(&aggregated_pub_key).unwrap();
        let nonces_2 = musig2.get_my_pub_nonces(&aggregated_pub_key_2).unwrap();
        // Check that nonces length matches number of messages
        assert_eq!(nonces_1.len(), messages.len());
        assert_eq!(nonces_2.len(), messages.len());
        let mut nonces_map_1 = HashMap::new();
        nonces_map_1.insert(pub_key_part_1, nonces_1);
        let mut nonces_map_2 = HashMap::new();
        nonces_map_2.insert(pub_key_part_2, nonces_2);

        musig.aggregate_nonces(&aggregated_pub_key, nonces_map_2.clone())?;
        musig2.aggregate_nonces(&aggregated_pub_key_2, nonces_map_1.clone())?;

        // Get partial signatures
        let my_partial_sigs_1 = key_manager
            .get_my_partial_signatures(&aggregated_pub_key)
            .unwrap();
        let my_partial_sigs_2 = key_manager2
            .get_my_partial_signatures(&aggregated_pub_key_2)
            .unwrap();

        // Check that partial signatures length matches number of messages
        assert_eq!(my_partial_sigs_1.len(), messages.len());
        assert_eq!(my_partial_sigs_2.len(), messages.len());

        key_manager.save_partial_signatures(
            &aggregated_pub_key,
            pub_key_part_2,
            my_partial_sigs_2,
        )?;

        key_manager2.save_partial_signatures(
            &aggregated_pub_key_2,
            pub_key_part_1,
            my_partial_sigs_1,
        )?;

        let signature_1 = musig.get_aggregated_signature(&aggregated_pub_key, messages[0])?;
        let signature_2 = musig2.get_aggregated_signature(&aggregated_pub_key_2, messages[1])?;
        // Check that signatures length matches number of messages

        let verification_1 =
            musig.verify_final_signature(messages[0], signature_1, aggregated_pub_key)?;

        let verification_2 =
            musig2.verify_final_signature(messages[1], signature_2, aggregated_pub_key)?;

        assert!(verification_1);
        assert!(verification_2);

        clear_output();

        Ok(())
    }
}
