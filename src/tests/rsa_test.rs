#[cfg(test)]
mod rsa_tests {
    use crate::{
        errors::KeyManagerError,
        rsa::RSAKeyPair,
        tests::utils::helper::{clear_output, create_key_manager},
        verifier::SignatureVerifier,
    };
    use bitcoin::key::rand::RngCore;
    use bitcoin::secp256k1::rand::thread_rng;

    fn random_bytes() -> Vec<u8> {
        let mut buf = [0u8; 32];
        thread_rng().fill_bytes(&mut buf);
        buf.to_vec()
    }

    #[test]
    fn test_sign_and_verify() {
        let key_manager = create_key_manager("test_output/rsa_sign_verify", None).unwrap();
        let pubkey_pem = key_manager.generate_rsa_keypair(&mut thread_rng()).unwrap();
        let message = random_bytes();
        let signature = key_manager.sign_rsa_message(&message, &pubkey_pem).unwrap();

        let verifier = SignatureVerifier::new();
        assert!(verifier
            .verify_rsa_signature(&signature, &message, &pubkey_pem)
            .unwrap());
        clear_output();
    }

    #[test]
    fn test_signature_rejects_tampered_message() {
        let key_manager = create_key_manager("test_output/rsa_tampered_msg", None).unwrap();
        let pubkey_pem = key_manager.generate_rsa_keypair(&mut thread_rng()).unwrap();
        let mut message = random_bytes();
        let signature = key_manager.sign_rsa_message(&message, &pubkey_pem).unwrap();

        message[0] ^= 0xFF;
        let verifier = SignatureVerifier::new();
        assert!(!verifier
            .verify_rsa_signature(&signature, &message, &pubkey_pem)
            .unwrap());
        clear_output();
    }

    #[test]
    fn test_signature_does_not_verify_with_different_key() {
        let key_manager = create_key_manager("test_output/rsa_wrong_key", None).unwrap();
        let mut rng = thread_rng();
        let pubkey_pem_a = key_manager.generate_rsa_keypair(&mut rng).unwrap();
        let pubkey_pem_b = key_manager.generate_rsa_keypair(&mut rng).unwrap();
        let message = random_bytes();
        let signature = key_manager
            .sign_rsa_message(&message, &pubkey_pem_a)
            .unwrap();

        let verifier = SignatureVerifier::new();
        assert!(!verifier
            .verify_rsa_signature(&signature, &message, &pubkey_pem_b)
            .unwrap());
        clear_output();
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key_manager = create_key_manager("test_output/rsa_enc_dec", None).unwrap();
        let pubkey_pem = key_manager.generate_rsa_keypair(&mut thread_rng()).unwrap();
        let message = random_bytes();

        let encrypted = key_manager
            .encrypt_rsa_message(&message, &pubkey_pem)
            .unwrap();
        let decrypted = key_manager
            .decrypt_rsa_message(&encrypted, &pubkey_pem)
            .unwrap();
        assert_eq!(message, decrypted);
        clear_output();
    }

    #[test]
    fn test_sign_with_unknown_key_returns_not_found() {
        let key_manager = create_key_manager("test_output/rsa_unknown_sign", None).unwrap();
        let other = create_key_manager("test_output/rsa_unknown_sign_other", None).unwrap();
        let foreign_pubkey_pem = other.generate_rsa_keypair(&mut thread_rng()).unwrap();

        let result = key_manager.sign_rsa_message(&random_bytes(), &foreign_pubkey_pem);
        assert!(matches!(result, Err(KeyManagerError::RsaKeyNotFound)));
        clear_output();
    }

    #[test]
    fn test_decrypt_with_unknown_key_returns_not_found() {
        let key_manager = create_key_manager("test_output/rsa_unknown_dec", None).unwrap();
        let pem = key_manager.generate_rsa_keypair(&mut thread_rng()).unwrap();
        let encrypted = key_manager
            .encrypt_rsa_message(&random_bytes(), &pem)
            .unwrap();

        let other = create_key_manager("test_output/rsa_unknown_dec_other", None).unwrap();
        let foreign_pubkey_pem = other.generate_rsa_keypair(&mut thread_rng()).unwrap();

        let result = key_manager.decrypt_rsa_message(&encrypted, &foreign_pubkey_pem);
        assert!(matches!(result, Err(KeyManagerError::RsaKeyNotFound)));
        clear_output();
    }

    #[test]
    fn test_generate_custom_key_below_minimum_size_returns_error() {
        let key_manager = create_key_manager("test_output/rsa_custom_too_small", None).unwrap();

        let result = key_manager.generate_rsa_keypair_custom(&mut thread_rng(), 1024);
        assert!(matches!(result, Err(KeyManagerError::InvalidRSAKeySize(_))));
        clear_output();
    }

    #[test]
    fn test_import_key_below_minimum_size_returns_error() {
        let key_manager = create_key_manager("test_output/rsa_import_too_small", None).unwrap();
        let small_key_pem = RSAKeyPair::new(&mut thread_rng(), 1024)
            .unwrap()
            .export_private_pem()
            .unwrap();

        let result = key_manager.import_rsa_private_key(&small_key_pem);
        assert!(matches!(result, Err(KeyManagerError::InvalidRSAKeySize(_))));
        clear_output();
    }

    #[test]
    fn test_import_key_above_maximum_size_returns_error() {
        let key_manager = create_key_manager("test_output/rsa_import_too_large", None).unwrap();
        // Just above the 4096-bit maximum, larger keys are slow to generate
        let large_key_pem = RSAKeyPair::new(&mut thread_rng(), 4160)
            .unwrap()
            .export_private_pem()
            .unwrap();

        let result = key_manager.import_rsa_private_key(&large_key_pem);
        assert!(matches!(result, Err(KeyManagerError::InvalidRSAKeySize(_))));
        clear_output();
    }
}
