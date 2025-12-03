#[cfg(test)]
mod winternitz_tests {
    use crate::winternitz::SHA256_SIZE;

    use super::*;

    use crate::winternitz::{
        calculate_checksum, checksum_length, message_digits_length, to_checksummed_message,
        Winternitz, WinternitzType,
    };

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
}
