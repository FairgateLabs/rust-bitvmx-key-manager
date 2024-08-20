use bitcoin::{hashes::{ripemd160, sha256, Hash}, secp256k1::{self, All}, PublicKey};

use crate::winternitz::{add_checksum, calculate_checksum_length, split_byte, WinternitzType, W};

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

    pub fn verify_winternitz_signature(&self, signature: &[Vec<u8>], msg_with_checksum: &[u8], msg_len_bytes: usize, public_key: &[Vec<u8>], key_type: WinternitzType) -> bool {
        let mut generated_public_key = Vec::new();

        let my_msg_with_checksum = add_checksum(&msg_with_checksum[..msg_len_bytes], W);
        let msg_pad_len = calculate_checksum_length(msg_len_bytes, W) + msg_len_bytes - msg_with_checksum.len();
        let msg_with_checksum_pad = [msg_with_checksum, &vec![0u8; msg_pad_len]].concat(); 
        
        for (i, byte) in msg_with_checksum_pad.iter().enumerate() {
            let (high_nibble, low_nibble) = split_byte(*byte);

            let mut hashed_val = signature[2 * i].clone();
            for _ in 0..(high_nibble as usize) {
                hashed_val = match key_type {
                    WinternitzType::WSHA256 => sha256::Hash::hash(&hashed_val).as_byte_array().to_vec(),
                    WinternitzType::WRIPEMD160 => ripemd160::Hash::hash(&hashed_val).as_byte_array().to_vec(),                  
                }
            }
            generated_public_key.push(hashed_val);

            let mut hashed_val = signature[2 * i + 1].clone();
            for _ in 0..(low_nibble as usize) {
                hashed_val = match key_type {
                    WinternitzType::WSHA256 => sha256::Hash::hash(&hashed_val).as_byte_array().to_vec(),
                    WinternitzType::WRIPEMD160 => ripemd160::Hash::hash(&hashed_val).as_byte_array().to_vec(),                    
                }
            }
            generated_public_key.push(hashed_val);
        }

        (generated_public_key == public_key) && (my_msg_with_checksum == msg_with_checksum)
    }
}
