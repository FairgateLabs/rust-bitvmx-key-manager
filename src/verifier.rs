use crate::{
    errors::KeyManagerError,
    rsa::{RSAKeyPair, Signature},
    winternitz::{to_checksummed_message, Winternitz, WinternitzPublicKey, WinternitzSignature},
};
use bitcoin::{
    secp256k1::{self, All},
    PublicKey,
};

pub struct SignatureVerifier {
    secp: secp256k1::Secp256k1<All>,
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureVerifier {
    pub fn new() -> Self {
        let secp = secp256k1::Secp256k1::new();
        SignatureVerifier { secp }
    }

    pub fn verify_ecdsa_signature(
        &self,
        signature: &secp256k1::ecdsa::Signature,
        message: &secp256k1::Message,
        public_key: PublicKey,
    ) -> bool {
        self.secp
            .verify_ecdsa(message, signature, &public_key.inner)
            .is_ok()
    }

    pub fn verify_schnorr_signature(
        &self,
        signature: &secp256k1::schnorr::Signature,
        message: &secp256k1::Message,
        public_key: PublicKey,
    ) -> bool {
        let xonly_public_key = public_key.into();
        self.secp
            .verify_schnorr(signature, message, &xonly_public_key)
            .is_ok()
    }

    pub fn verify_winternitz_signature(
        &self,
        signature: &WinternitzSignature,
        message_bytes: &[u8],
        public_key: &WinternitzPublicKey,
    ) -> bool {
        let checksummed_message = to_checksummed_message(message_bytes);

        let winternitz = Winternitz::new();
        winternitz
            .verify_signature(&checksummed_message, signature, public_key)
            .unwrap_or(false)

        // verification && (my_msg_with_checksum == message_with_checksum)
    }

    pub fn verify_rsa_signature(
        &self,
        signature: &Signature,
        message: &[u8],
        public_key: &String, // PEM format
    ) -> Result<bool, KeyManagerError> {
        let verify = RSAKeyPair::verify(message, public_key, signature)?;
        Ok(verify)
    }
}
