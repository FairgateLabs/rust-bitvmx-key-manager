use bitcoin::{secp256k1::{self, All}, PublicKey};

use crate::winternitz::{add_checksum, calculate_checksum_length, Winternitz, WinternitzPublicKey, WinternitzSignature, W};

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
        SignatureVerifier { 
            secp,
        }
    }

    pub fn verify_ecdsa_signature(&self, signature: &secp256k1::ecdsa::Signature, message: &secp256k1::Message, public_key: PublicKey) -> bool {
        self.secp.verify_ecdsa(message, signature,&public_key.inner).is_ok()
    }

    pub fn verify_schnorr_signature(&self, signature: &secp256k1::schnorr::Signature, message: &secp256k1::Message, public_key: PublicKey) -> bool {
        let xonly_public_key = public_key.into();
        self.secp.verify_schnorr(signature,message, &xonly_public_key).is_ok()
    }

    pub fn verify_winternitz_signature(&self, signature: &WinternitzSignature, message_bytes: &[u8], public_key: &WinternitzPublicKey) -> bool {
        let winternitz = Winternitz::new();

        let message_len = message_bytes.len();
        let message_with_checksum = add_checksum(message_bytes, W);

        let my_msg_with_checksum = add_checksum(&message_with_checksum[..message_len], W);
        let message_pad_len = calculate_checksum_length(message_len, W) + message_len - message_with_checksum.len();
        let message_with_checksum_pad = [message_with_checksum.as_slice(), &vec![0u8; message_pad_len]].concat(); 
        
        let verification = winternitz.verify_signature(&message_with_checksum_pad, signature, public_key).is_ok();

        verification && (my_msg_with_checksum == message_with_checksum)
    }
}
