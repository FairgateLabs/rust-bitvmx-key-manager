#[cfg(test)]
mod tests {

    use bitcoin::PublicKey;
    use std::{path::PathBuf, rc::Rc};
    use storage_backend::storage::Storage;

    use crate::{
        musig2::{
            errors::Musig2SignerError,
            musig::{MuSig2Signer, MuSig2SignerApi},
        },
        tests::utils::helper::{clear_output, create_key_manager, create_pub_key},
    };

    #[test]
    fn test_init_musig_method() -> Result<(), anyhow::Error> {
        let path = PathBuf::from(format!("test_output/test_init_musig_method"));
        let store = Rc::new(Storage::new_with_path(&path)?);
        let key_manager = create_key_manager("test_output/keystore_1", store.clone())?;
        let my_pub_key = create_pub_key(&key_manager)?;
        let musig = MuSig2Signer::new(store);

        let participant_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();
        let participant_2 = "02f3b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b"
            .parse::<PublicKey>()
            .unwrap();

        let participant_pubkeys = vec![participant_1, participant_2, my_pub_key];

        let _aggregated_pubkey = musig.new_session(participant_pubkeys.clone(), my_pub_key)?;

        clear_output();

        Ok(())
    }

    #[test]
    fn test_init_musig_invalid_participants() -> Result<(), anyhow::Error> {
        let path = PathBuf::from(format!("test_output/test_init_musig_invalid_participants"));

        let store = Rc::new(Storage::new_with_path(&path).unwrap());

        let musig = MuSig2Signer::new(store);

        let participant_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();
        let participant_pubkeys = vec![participant_1];

        let result = musig.new_session(participant_pubkeys.clone(), participant_1);

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
        let path = PathBuf::from(format!(
            "test_output/test_init_musig_invalid_participant_key_no_current_pub_key"
        ));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager = create_key_manager("test_output/keystore_3", store.clone())?;
        let my_pub_key = create_pub_key(&key_manager)?;
        let musig = MuSig2Signer::new(store);

        let participant_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();
        let participant_2 = "02f3b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b"
            .parse::<PublicKey>()
            .unwrap();

        let participant_pubkeys = vec![participant_1, participant_2];

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
    fn test_init_musig_unsort_pub_keys() -> Result<(), anyhow::Error> {
        let path = PathBuf::from(format!("test_output/test_init_musig_unsort_pub_keys"));
        let store = Rc::new(Storage::new_with_path(&path).unwrap());
        let key_manager = create_key_manager("test_output/keystore_4", store.clone())?;
        let my_pub_key = create_pub_key(&key_manager)?;
        let musig = MuSig2Signer::new(store);

        let participant_1 = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
            .parse::<PublicKey>()
            .unwrap();
        let participant_2 = "02f3b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b"
            .parse::<PublicKey>()
            .unwrap();

        let participant_pubkeys = vec![participant_1, participant_2, my_pub_key];

        let aggregated_pub_key = musig
            .new_session(participant_pubkeys.clone(), my_pub_key)
            .unwrap();

        let participant_pubkeys = vec![participant_2, my_pub_key, participant_1];

        let aggregated_pub_key_2 = musig
            .new_session(participant_pubkeys.clone(), my_pub_key)
            .unwrap();

        // Check if the aggregated pub keys are the same
        assert_eq!(aggregated_pub_key, aggregated_pub_key_2);

        clear_output();

        Ok(())
    }
}
