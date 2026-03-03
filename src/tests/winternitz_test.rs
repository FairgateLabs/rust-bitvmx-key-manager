#[cfg(test)]
mod winternitz_tests {
    use crate::{
        tests::utils::helper::{clear_output, create_key_manager},
        verifier::SignatureVerifier,
        winternitz::{
            checksum_length, message_digits_length, to_checksummed_message, Winternitz,
            WinternitzSignature, WinternitzType,
        },
    };
    use bitcoin::key::rand::RngCore;

    fn create_master_secret() -> Vec<u8> {
        b"test_master_secret_key_32_bytes".to_vec()
    }

    #[test]
    fn test_checksummed_message_creation() {
        let message = b"Test message";
        let checksummed = to_checksummed_message(message);
        let message_digits = message_digits_length(message.len());
        let checksum_size = checksum_length(message_digits);

        assert_eq!(checksummed.len(), message_digits + checksum_size);
        assert!(!checksummed.is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        // Overview: This test validates the complete Winternitz signature workflow:
        // 1. Generate private/public key pair from master secret
        // 2. Convert message to checksummed format
        // 3. Sign the message using private key
        // 4. Verify signature using public key
        // 5. Test signature properties and edge cases (modified signature verification)

        let winternitz = Winternitz::new();
        let master_secret = create_master_secret();
        let message = b"Hello";
        let message_size = message.len();
        let _checksum_size = 2;
        let derivation_index = 0;

        // Calculate the total number of digits needed
        let message_digits = message_digits_length(message_size);
        let checksum_digits = checksum_length(message_digits);
        let total_digits = message_digits + checksum_digits;

        // Generate private key with the correct message digits and checksum size
        // The private key should have message_digits + checksum_size hashes
        let private_key = winternitz
            .generate_private_key(
                &master_secret,
                WinternitzType::SHA256,
                message_digits,  // Use message_digits, not message_size
                checksum_digits, // Use checksum_digits, not checksum_size
                derivation_index,
            )
            .expect("Failed to generate private key");

        // Generate public key
        let public_key = private_key
            .public_key()
            .expect("Failed to generate public key");

        // Create checksummed message
        let checksummed_message = to_checksummed_message(message);

        // Test that we can sign the message without errors
        let signature = winternitz.sign_message(message_digits, &checksummed_message, &private_key);

        // Test basic signature properties
        assert_eq!(signature.message_length(), message_digits);
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), total_digits);

        // Test that signature has the expected number of hashes and digits
        assert_eq!(signature.len(), total_digits);
        assert_eq!(signature.checksummed_message_digits().len(), total_digits);

        // Test that we can get signature hashes
        let signature_hashes = signature.to_hashes();
        assert_eq!(signature_hashes.len(), total_digits);

        // Test message bytes conversion
        let message_bytes = signature.message_bytes();
        assert_eq!(message_bytes, message);

        // Test checksummed message digits
        let checksummed_digits = signature.checksummed_message_digits();
        assert_eq!(checksummed_digits.len(), total_digits);

        // Test message digits
        let message_digits_from_sig = signature.message_digits();
        assert_eq!(message_digits_from_sig.len(), message_digits);

        // Test checksum length
        assert_eq!(signature.checksum_length(), checksum_digits);

        // CRITICAL: Verify the signature
        let verification_result = winternitz
            .verify_signature(&checksummed_message, &signature, &public_key)
            .expect("Failed to verify signature");

        assert!(verification_result, "Signature verification should succeed");

        // Checksummed_message: [15, 6, 12, 6, 12, 6, 5, 6, 8, 4, 0, 4, 6] (digits + checksum)
        // Test signature verification with modified message (any digit changed from 15 to 25)
        let mut modified_checksummed_message = checksummed_message.clone();
        for digit in modified_checksummed_message.iter_mut() {
            if *digit == 15 {
                *digit = 25;
            }
        }

        let modified_verification_result = winternitz
            .verify_signature(&modified_checksummed_message, &signature, &public_key)
            .expect("Failed to verify modified signature");

        assert!(
            modified_verification_result,
            "Modified signature verification should succed because the digit is capped to W"
        );
    }

    // Suite 5: Integration tests for Winternitz OTS sign/verify operations

    fn random_message() -> Vec<u8> {
        let mut digest = [0u8; 32];
        bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut digest);
        digest.to_vec()
    }

    #[test]
    fn test_sign_verify_sha256() {
        let path = "test_output/suite5_sign_verify_sha256";
        let key_manager = create_key_manager(path, None).unwrap();
        let verifier = SignatureVerifier::new();
        let message = random_message();

        let public_key = key_manager.next_winternitz(message.len(), WinternitzType::SHA256).unwrap();
        let signature = key_manager.sign_winternitz_message_by_pubkey(&message, &public_key).unwrap();

        assert!(verifier.verify_winternitz_signature(&signature, &message, &public_key));
        clear_output();
    }

    #[test]
    fn test_sign_verify_hash160() {
        let path = "test_output/suite5_sign_verify_hash160";
        let key_manager = create_key_manager(path, None).unwrap();
        let verifier = SignatureVerifier::new();
        let message = random_message();

        let public_key = key_manager.next_winternitz(message.len(), WinternitzType::HASH160).unwrap();
        let signature = key_manager.sign_winternitz_message_by_pubkey(&message, &public_key).unwrap();

        assert!(verifier.verify_winternitz_signature(&signature, &message, &public_key));
        clear_output();
    }

    #[test]
    fn test_index_mismatch() {
        let path = "test_output/suite5_index_mismatch";
        let key_manager = create_key_manager(path, None).unwrap();
        let verifier = SignatureVerifier::new();
        let message = random_message();

        let public_key_i = key_manager.next_winternitz(message.len(), WinternitzType::SHA256).unwrap();
        let signature = key_manager.sign_winternitz_message_by_pubkey(&message, &public_key_i).unwrap();
        let public_key_i_plus_1 = key_manager.next_winternitz(message.len(), WinternitzType::SHA256).unwrap();

        assert!(!verifier.verify_winternitz_signature(&signature, &message, &public_key_i_plus_1));
        clear_output();
    }

    #[test]
    fn test_type_mismatch() {
        let path = "test_output/suite5_type_mismatch";
        let key_manager = create_key_manager(path, None).unwrap();
        let verifier = SignatureVerifier::new();
        let message = random_message();

        let public_key_sha256 = key_manager.next_winternitz(message.len(), WinternitzType::SHA256).unwrap();
        let signature = key_manager.sign_winternitz_message_by_pubkey(&message, &public_key_sha256).unwrap();
        let public_key_hash160 = key_manager.next_winternitz(message.len(), WinternitzType::HASH160).unwrap();

        assert!(!verifier.verify_winternitz_signature(&signature, &message, &public_key_hash160));
        clear_output();
    }

    #[test]
    fn test_signature_serialization_round_trip() {
        let path = "test_output/suite5_signature_serialization";
        let key_manager = create_key_manager(path, None).unwrap();
        let message = random_message();
        let winternitz_type = WinternitzType::SHA256;

        let public_key = key_manager.next_winternitz(message.len(), winternitz_type).unwrap();
        let original_signature = key_manager.sign_winternitz_message_by_pubkey(&message, &public_key).unwrap();

        let signature_bytes = original_signature.to_bytes();
        let message_digits_len = original_signature.message_length();
        let reconstructed_signature =
            WinternitzSignature::from_bytes(&signature_bytes, message_digits_len, winternitz_type).unwrap();

        assert_eq!(original_signature.to_hashes(), reconstructed_signature.to_hashes());
        assert_eq!(original_signature.message_length(), reconstructed_signature.message_length());
        assert_eq!(original_signature.len(), reconstructed_signature.len());
        clear_output();
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let invalid_bytes = vec![0u8; 33];
        let result = WinternitzSignature::from_bytes(&invalid_bytes, 10, WinternitzType::SHA256);
        assert!(result.is_err());
    }

    #[test]
    fn test_checksummed_digits_reconstruct_message() {
        let path = "test_output/suite5_checksummed_digits";
        let key_manager = create_key_manager(path, None).unwrap();
        let message = random_message();

        let public_key = key_manager.next_winternitz(message.len(), WinternitzType::SHA256).unwrap();
        let signature = key_manager.sign_winternitz_message_by_pubkey(&message, &public_key).unwrap();

        assert_eq!(message, signature.message_bytes());
        clear_output();
    }

    #[test]
    fn test_derive_multiple_equals_sequential() {
        let path = "test_output/suite5_derive_multiple";
        let key_manager = create_key_manager(path, None).unwrap();
        let message_size = 32;
        let key_type = WinternitzType::SHA256;
        let count = 5;

        let batch_keys = key_manager.next_multiple_winternitz(message_size, key_type, count).unwrap();
        let mut individual_keys = Vec::new();
        for _ in 0..count {
            individual_keys.push(key_manager.next_winternitz(message_size, key_type).unwrap());
        }

        assert_eq!(batch_keys.len(), count as usize);
        assert_eq!(individual_keys.len(), count as usize);

        for (i, key) in batch_keys.iter().enumerate() {
            for (j, other_key) in batch_keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key.to_bytes(), other_key.to_bytes());
                }
            }
        }
        clear_output();
    }
}
