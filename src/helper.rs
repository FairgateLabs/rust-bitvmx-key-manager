use bitcoin::{hashes::FromSliceError, secp256k1};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("Secure storage error")]
    SecureStorageError(#[from] SecureStorageError),

    #[error("Invalid private key: {0}")]
    PrivKeySliceError(#[from] bitcoin::key::FromWifError),

    #[error("Failed to create DerivationPath, Xpriv or ChildNumber: {0}")]
    Bip32Error(#[from] bitcoin::bip32::Error),

    #[error("Index overflow: cannot generate more keys")]
    IndexOverflow,

    #[error("Entry not found for public key")]
    EntryNotFound,
}

#[derive(Error, Debug)]
pub enum SecureStorageError {
    #[error("Failed to access secure storage")]
    StorageError(#[from] std::io::Error),

    #[error("Failed to decode data")]
    FailedToDecodeData(#[from] FromSliceError),

    #[error("Failed to decode private key")]
    FailedToDecodePrivateKey(#[from] secp256k1::Error),

    #[error("Failed to decode public key")]
    FailedToDecodePublicKey(#[from] bitcoin::key::FromSliceError),

    #[error("Failed to encrypt data")]
    FailedToEncryptData {
        error: cocoon::Error,
    },

    #[error("Failed to decrypt data")]
    FailedToDecryptData {
        error: cocoon::Error,
    },

    #[error("Failed to convert data to byte array")]
    CorruptedData
}

pub fn add_checksum(message: &[u8], w: usize) -> Vec<u8> {
    let mut message = message.to_vec();
    let checksum = calculate_checksum(&message, w);
    message.extend_from_slice(&checksum);
    message
}

pub fn calculate_checksum(message: &[u8], w: usize) -> Vec<u8> {
    let mut checksum: u32 = 0;

    for byte in message.iter() {
        let (high_nibble, low_nibble) = split_byte(*byte);
        checksum += (w as u32 - 1 - high_nibble as u32) + (w as u32 - 1 - low_nibble as u32);
    }

    let mut checksum_bytes = Vec::new();
    let mut temp = checksum;

    while temp > 0 {
        checksum_bytes.push((temp % 256) as u8);
        temp /= 256;
    }
    checksum_bytes.reverse();
    checksum_bytes
}

pub fn calculate_checksum_length(message_length_bytes: usize, w: usize) -> usize {
    let l1 = 2 * message_length_bytes;
    let l2 = ((l1 * (w-1)) as f64).log2() / 4.0; //log16(x) = log2(x) / 4
    (l2 / 2.0).ceil() as usize //checksum length in bytes
}

pub fn split_byte(byte: u8) -> (u8, u8) {
    let high_nibble: u8 = (byte & 0xF0) >> 4;
    let low_nibble: u8 = byte & 0x0F;
    (high_nibble, low_nibble)
}
