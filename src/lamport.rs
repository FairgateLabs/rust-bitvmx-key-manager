use core::fmt;
use std::str::FromStr;

use bitcoin::hashes::{ripemd160, sha256, Hash, HashEngine, Hmac, HmacEngine};
use serde::{Deserialize, Serialize};
use tracing::warn;
// use zeroize::Zeroize;

use crate::errors::LamportError;

pub const SHA256_SIZE: usize = 32;
pub const RIPEMD160_SIZE: usize = 20;

/// Lamport signature hash function types
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LamportType {
    // Based on some bitcoin script hash functions, but can be extended in the future if needed
    // If needed HASH256 (two times sha256) or RIPMED160 (without sha256) could be added here as well
    SHA256,
    HASH160,
}

pub trait HashFunction {
    fn hash(&self, data: &[u8]) -> LamportHash;
    fn hash_size(&self) -> usize;
}

impl HashFunction for LamportType {
    fn hash(&self, data: &[u8]) -> LamportHash {
        let hash = match self {
            LamportType::SHA256 => {
                LamportHash::new(sha256::Hash::hash(data).as_byte_array().to_vec())
            }
            LamportType::HASH160 => {
                let sha256 = sha256::Hash::hash(data);
                let hash160 = ripemd160::Hash::hash(sha256.as_byte_array());
                LamportHash::new(hash160.as_byte_array().to_vec())
            }
        };
        hash
    }

    fn hash_size(&self) -> usize {
        match self {
            LamportType::SHA256 => SHA256_SIZE,
            LamportType::HASH160 => RIPEMD160_SIZE,
        }
    }
}

impl fmt::Display for LamportType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl FromStr for LamportType {
    type Err = LamportError;

    fn from_str(input: &str) -> Result<LamportType, Self::Err> {
        match input.to_uppercase().as_str() {
            "SHA256" => Ok(LamportType::SHA256),
            "HASH160" => Ok(LamportType::HASH160),
            _ => Err(LamportError::InvalidLamportType(input.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportHash {
    hash: Vec<u8>,
}

// TODO do we want zeroize private key on drop? or left responsibility to the caller?
// impl Zeroize for LamportHash {
//     fn zeroize(&mut self) {
//         self.hash.zeroize();
//     }
// }

impl LamportHash {
    pub fn new(hash: Vec<u8>) -> Self {
        LamportHash { hash }
    }

    pub fn len(&self) -> usize {
        self.hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hash.is_empty()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.hash.clone()
    }

    pub fn to_array(&self) -> Result<[u8; 32], LamportError> {
        if self.hash.len() != 32 {
            return Err(LamportError::InvalidHashSize(self.hash.len(), 32));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&self.hash);
        Ok(array)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.hash)
    }
}

/// Lamport signature containing the revealed private key fragments
/// For each bit in the message:
///   - If bit is 0, reveal private_key_0
///   - If bit is 1, reveal private_key_1
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportSignature {
    /// The revealed private key hashes (one per bit in the message)
    revealed_keys: Vec<LamportHash>,
    /// The bit length of the original message
    message_bit_length: usize,
    /// The hash type used
    hash_type: LamportType,
}

impl LamportSignature {
    pub fn new(message_bit_length: usize, hash_type: LamportType) -> Self {
        LamportSignature {
            revealed_keys: Vec::with_capacity(message_bit_length),
            hash_type,
            message_bit_length,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for hash in self.revealed_keys.iter() {
            bytes.extend_from_slice(&hash.hash);
        }
        bytes
    }

    pub fn from_bytes(
        bytes: &[u8],
        message_bit_length: usize,
        hash_type: LamportType,
    ) -> Result<Self, LamportError> {
        let hash_size = hash_type.hash_size();

        if bytes.len() != message_bit_length * hash_size {
            return Err(LamportError::InvalidSignatureLength(
                bytes.len(),
                message_bit_length * hash_size,
            ));
        }

        let mut signature = LamportSignature::new(message_bit_length, hash_type);

        for i in 0..message_bit_length {
            let start = i * hash_size;
            let end = start + hash_size;
            let hash = LamportHash::new(bytes[start..end].to_vec());
            signature.push_revealed_key(hash)?;
        }

        Ok(signature)
    }

    pub fn to_hashes(&self) -> Vec<Vec<u8>> {
        self.revealed_keys
            .iter()
            .map(|hash| hash.to_bytes())
            .collect()
    }

    pub fn to_array_hashes(&self) -> Result<Vec<[u8; 32]>, LamportError> {
        self.revealed_keys
            .iter()
            .map(|hash| hash.to_array())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.revealed_keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revealed_keys.is_empty()
    }

    pub fn message_bit_length(&self) -> usize {
        self.message_bit_length
    }

    pub fn hash_type(&self) -> LamportType {
        self.hash_type
    }

    fn push_revealed_key(&mut self, hash: LamportHash) -> Result<(), LamportError> {
        if hash.len() != self.hash_type.hash_size() {
            return Err(LamportError::HashSizeMismatch(
                hash.len(),
                self.hash_type.hash_size(),
            ));
        }
        self.revealed_keys.push(hash);
        Ok(())
    }

    fn revealed_key_at(&self, index: usize) -> Result<&LamportHash, LamportError> {
        self.revealed_keys
            .get(index)
            .ok_or(LamportError::IndexOutOfBounds(index, self.revealed_keys.len()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraData {
    message_bit_length: usize,
    derivation_index: u32, // TODO what to use if the key was imported and not derived?
}

impl ExtraData {
    pub fn new(message_bit_length: usize, derivation_index: u32) -> Self {
        ExtraData {
            message_bit_length,
            derivation_index,
        }
    }

    pub fn message_bit_length(&self) -> usize {
        self.message_bit_length
    }

    pub fn derivation_index(&self) -> u32 {
        self.derivation_index
    }
}

/// Lamport public key containing two sets of hash values:
/// - public_key_0s: hashes for when the corresponding bit is 0
/// - public_key_1s: hashes for when the corresponding bit is 1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LamportPublicKey {
    public_key_0s: Vec<LamportHash>,
    public_key_1s: Vec<LamportHash>,
    hash_type: LamportType,
    extra_data: Option<ExtraData>,
}

impl LamportPublicKey {
    pub fn from(private_key: LamportPrivateKey) -> Result<Self, LamportError> {
        private_key.public_key()
    }

    pub fn new(hash_type: LamportType, extra_data: Option<ExtraData>) -> Self {
        LamportPublicKey {
            public_key_0s: Vec::new(),
            public_key_1s: Vec::new(),
            hash_type,
            extra_data,
        }
    }

    fn push_key_pair(
        &mut self,
        hash_0: LamportHash,
        hash_1: LamportHash,
    ) -> Result<(), LamportError> {
        if hash_0.len() != self.hash_type.hash_size() {
            return Err(LamportError::HashSizeMismatch(
                hash_0.len(),
                self.hash_type.hash_size(),
            ));
        }
        if hash_1.len() != self.hash_type.hash_size() {
            return Err(LamportError::HashSizeMismatch(
                hash_1.len(),
                self.hash_type.hash_size(),
            ));
        }

        self.public_key_0s.push(hash_0);
        self.public_key_1s.push(hash_1);

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize 0s
        for hash in self.public_key_0s.iter() {
            bytes.extend_from_slice(&hash.hash);
        }

        // Serialize 1s
        for hash in self.public_key_1s.iter() {
            bytes.extend_from_slice(&hash.hash);
        }

        bytes
    }

    pub fn from_bytes(
        bytes: &[u8],
        message_bit_length: usize,
        hash_type: LamportType,
    ) -> Result<Self, LamportError> {
        let hash_size = hash_type.hash_size();
        let expected_length = 2 * message_bit_length * hash_size;

        if bytes.len() != expected_length {
            return Err(LamportError::InvalidPublicKeyLength(
                bytes.len(),
                expected_length,
            ));
        }

        let mut public_key = LamportPublicKey::new(hash_type, None);

        // Split bytes into 0s and 1s sections
        let split_point = message_bit_length * hash_size;
        let bytes_0s = &bytes[..split_point];
        let bytes_1s = &bytes[split_point..];

        for i in 0..message_bit_length {
            let start = i * hash_size;
            let end = start + hash_size;

            let hash_0 = LamportHash::new(bytes_0s[start..end].to_vec());
            let hash_1 = LamportHash::new(bytes_1s[start..end].to_vec());

            public_key.push_key_pair(hash_0, hash_1)?;
        }

        Ok(public_key)
    }

    pub fn to_hashes(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let hashes_0s = self
            .public_key_0s
            .iter()
            .map(|hash| hash.to_bytes())
            .collect();
        let hashes_1s = self
            .public_key_1s
            .iter()
            .map(|hash| hash.to_bytes())
            .collect();
        (hashes_0s, hashes_1s)
    }

    pub fn to_array_hashes(&self) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), LamportError> {
        let hashes_0s: Result<Vec<[u8; 32]>, LamportError> =
            self.public_key_0s.iter().map(|hash| hash.to_array()).collect();
        let hashes_1s: Result<Vec<[u8; 32]>, LamportError> =
            self.public_key_1s.iter().map(|hash| hash.to_array()).collect();
        Ok((hashes_0s?, hashes_1s?))
    }

    pub fn to_hashes_string(&self) -> (Vec<String>, Vec<String>) {
        let hashes_0s = self.public_key_0s.iter().map(|hash| hash.to_hex()).collect();
        let hashes_1s = self.public_key_1s.iter().map(|hash| hash.to_hex()).collect();
        (hashes_0s, hashes_1s)
    }

    /// Defined as quantity of key pairs
    pub fn len(&self) -> usize {
        self.public_key_0s.len()
    }

    pub fn is_empty(&self) -> bool {
        self.public_key_0s.is_empty()
    }

    pub fn hash_size(&self) -> usize {
        self.hash_type.hash_size()
    }

    pub fn hash_type(&self) -> LamportType {
        self.hash_type
    }

    pub fn extra_data(&self) -> Option<ExtraData> {
        self.extra_data.clone()
    }

    pub fn message_bit_length(&self) -> Result<usize, LamportError> {
        let message_bit_length = self
            .extra_data
            .as_ref()
            .ok_or(LamportError::ExtraDataMissing(
                "message_bit_length".to_string(),
            ))?
            .message_bit_length;

        Ok(message_bit_length)
    }

    pub fn derivation_index(&self) -> Result<u32, LamportError> {
        let derivation_index = self
            .extra_data
            .as_ref()
            .ok_or(LamportError::ExtraDataMissing(
                "derivation_index".to_string(),
            ))?
            .derivation_index;

        Ok(derivation_index)
    }

    fn public_key_0_at(&self, index: usize) -> Result<&LamportHash, LamportError> {
        self.public_key_0s
            .get(index)
            .ok_or(LamportError::IndexOutOfBounds(index, self.public_key_0s.len()))
    }

    fn public_key_1_at(&self, index: usize) -> Result<&LamportHash, LamportError> {
        self.public_key_1s
            .get(index)
            .ok_or(LamportError::IndexOutOfBounds(index, self.public_key_1s.len()))
    }
}

/// Lamport private key containing two sets of secret values:
/// - private_key_0s: secrets for when the corresponding bit is 0
/// - private_key_1s: secrets for when the corresponding bit is 1
///
/// CRITICAL: Lamport signatures are ONE-TIME USE ONLY.
/// Revealing multiple signatures with the same key compromises security.
#[derive(Debug, Serialize, Deserialize)]
pub struct LamportPrivateKey {
    private_key_0s: Vec<LamportHash>,
    private_key_1s: Vec<LamportHash>,
    hash_type: LamportType,
    message_bit_length: usize,
    derivation_index: u32, // TODO what to use if the key was imported and not derived?
}

// TODO create from bytes or import method?
impl LamportPrivateKey {
    pub fn new(
        hash_type: LamportType,
        message_bit_length: usize,
        derivation_index: u32,
    ) -> Self {
        LamportPrivateKey {
            private_key_0s: Vec::with_capacity(message_bit_length),
            private_key_1s: Vec::with_capacity(message_bit_length),
            hash_type,
            message_bit_length,
            derivation_index,
        }
    }

    pub fn public_key(&self) -> Result<LamportPublicKey, LamportError> {
        let mut public_key = LamportPublicKey::new(
            self.hash_type,
            Some(ExtraData::new(self.message_bit_length, self.derivation_index)),
        );

        for i in 0..self.private_key_0s.len() {
            let pub_0 = self.hash_type.hash(&self.private_key_0s[i].to_bytes());
            let pub_1 = self.hash_type.hash(&self.private_key_1s[i].to_bytes());
            public_key.push_key_pair(pub_0, pub_1)?;
        }

        Ok(public_key)
    }

    pub fn to_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        let mut bytes_0s = Vec::new();
        let mut bytes_1s = Vec::new();

        for hash_0 in self.private_key_0s.iter() {
            bytes_0s.extend_from_slice(&hash_0.hash);
        }

        for hash_1 in self.private_key_1s.iter() {
            bytes_1s.extend_from_slice(&hash_1.hash);
        }

        (bytes_0s, bytes_1s)
    }

    pub fn to_hashes(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let hashes_0s = self
            .private_key_0s
            .iter()
            .map(|hash| hash.to_bytes())
            .collect();
        let hashes_1s = self
            .private_key_1s
            .iter()
            .map(|hash| hash.to_bytes())
            .collect();
        (hashes_0s, hashes_1s)
    }

    pub fn to_array_hashes(&self) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), LamportError> {
        let hashes_0s: Result<Vec<[u8; 32]>, LamportError> = self
            .private_key_0s
            .iter()
            .map(|hash| hash.to_array())
            .collect();
        let hashes_1s: Result<Vec<[u8; 32]>, LamportError> = self
            .private_key_1s
            .iter()
            .map(|hash| hash.to_array())
            .collect();
        Ok((hashes_0s?, hashes_1s?))
    }

    pub fn len(&self) -> usize {
        self.private_key_0s.len()
    }

    pub fn is_empty(&self) -> bool {
        self.private_key_0s.is_empty()
    }

    pub fn hash_size(&self) -> usize {
        self.hash_type.hash_size()
    }

    pub fn hash_type(&self) -> LamportType {
        self.hash_type
    }

    pub fn derivation_index(&self) -> u32 {
        self.derivation_index
    }

    pub fn message_bit_length(&self) -> usize {
        self.message_bit_length
    }

    fn push_key_pair(
        &mut self,
        hash_0: LamportHash,
        hash_1: LamportHash,
    ) -> Result<(), LamportError> {
        if hash_0.len() != self.hash_type.hash_size() {
            return Err(LamportError::HashSizeMismatch(
                hash_0.len(),
                self.hash_type.hash_size(),
            ));
        }
        if hash_1.len() != self.hash_type.hash_size() {
            return Err(LamportError::HashSizeMismatch(
                hash_1.len(),
                self.hash_type.hash_size(),
            ));
        }

        self.private_key_0s.push(hash_0);
        self.private_key_1s.push(hash_1);

        Ok(())
    }

    fn private_key_0_at(&self, index: usize) -> Result<&LamportHash, LamportError> {
        self.private_key_0s
            .get(index)
            .ok_or(LamportError::IndexOutOfBounds(index, self.private_key_0s.len()))
    }

    fn private_key_1_at(&self, index: usize) -> Result<&LamportHash, LamportError> {
        self.private_key_1s
            .get(index)
            .ok_or(LamportError::IndexOutOfBounds(index, self.private_key_1s.len()))
    }
}

// TODO do we want zeroize private key on drop? or left responsibility to the caller?
// impl Drop for LamportPrivateKey {
//     fn drop(&mut self) {
//         // Zeroize the private keys on drop
//         for hash in self.private_key_0s.iter_mut() {
//             hash.hash.zeroize();
//         }
//         for hash in self.private_key_1s.iter_mut() {
//             hash.hash.zeroize();
//         }
//     }
// }

/// Main Lamport signature scheme implementation
#[derive(Default)]
pub struct Lamport {}

impl Lamport {
    pub fn new() -> Self {
        Lamport {}
    }

    // TODO what deriv index to use if the key was imported and not derived?
    /// Generate a Lamport public key from a master secret
    ///
    /// # Arguments
    /// * `master_secret` - The master secret seed for key derivation
    /// * `hash_type` - The hash function to use (e.g., SHA256)
    /// * `message_bit_length` - The length of messages that can be signed (in bits)
    /// * `derivation_index` - The derivation index for this key (for HD derivation)
    ///
    /// # Returns
    /// The generated public key
    pub fn generate_public_key(
        &self,
        master_secret: &[u8],
        hash_type: LamportType,
        message_bit_length: usize,
        derivation_index: u32,
    ) -> Result<LamportPublicKey, LamportError> {
        let private_key =
            self.generate_private_key(master_secret, hash_type, message_bit_length, derivation_index)?;
        let public_key = LamportPublicKey::from(private_key)?;
        Ok(public_key)
    }

    // TODO what deriv index to use if the key was imported and not derived?
    // TODO do we know if it was already used when importing?
    /// Generate a Lamport private key from a master secret
    ///
    /// # Arguments
    /// * `master_secret` - The master secret seed for key derivation
    /// * `hash_type` - The hash function to use (e.g., SHA256)
    /// * `message_bit_length` - The length of messages that can be signed (in bits)
    /// * `derivation_index` - The derivation index for this key (for HD derivation)
    ///
    /// # Returns
    /// The generated private key
    ///
    /// # Security Note
    /// Store this key securely and mark it as used after signing to prevent reuse.
    pub fn generate_private_key(
        &self,
        master_secret: &[u8],
        hash_type: LamportType,
        message_bit_length: usize,
        derivation_index: u32,
    ) -> Result<LamportPrivateKey, LamportError> {
        derivation_index
            .checked_add(1)
            .ok_or(LamportError::IndexOverflow)?;

        let mut private_key =
            LamportPrivateKey::new(hash_type, message_bit_length, derivation_index);

        let hash_size = hash_type.hash_size();

        // Generate key pairs for each bit position
        for i in 0..message_bit_length {
            // Generate private key for bit value 0
            let priv_key_0 = self.generate_hash(master_secret, hash_size, derivation_index, i as u32, 0);

            // Generate private key for bit value 1
            let priv_key_1 = self.generate_hash(master_secret, hash_size, derivation_index, i as u32, 1);

            private_key.push_key_pair(priv_key_0, priv_key_1)?;
        }

        Ok(private_key)
    }


    // TODO Sing and Verify by message bits, and also by messages bytes, as for many cases using SHA256 as hash function will imply that the message is really the message digest, obtained by hashing also the message, so it willl be 32 exact bytes

    /// Sign a message using a Lamport private key
    ///
    /// # Arguments
    /// * `message_bits` - The message to sign as a vector of bits (0s and 1s)
    /// * `private_key` - The private key to use for signing
    ///
    /// # Returns
    /// The signature containing the revealed private key fragments
    ///
    /// # Security Critical
    /// After calling this function, the private key MUST be marked as used and never reused.
    /// Reusing a Lamport private key allows attackers to forge signatures.
    pub fn sign_message(
        &self,
        message_bits: &[u8], // TODO i prefer to be an array of booleans, as a bit is only 0 or 1
        private_key: &LamportPrivateKey,
    ) -> Result<LamportSignature, LamportError> {
        if message_bits.len() != private_key.message_bit_length() {
            return Err(LamportError::MessageLengthMismatch(
                message_bits.len(),
                private_key.message_bit_length(),
            ));
        }

        let mut signature = LamportSignature::new(message_bits.len(), private_key.hash_type());

        // For each bit, reveal the corresponding private key
        for (i, &bit) in message_bits.iter().enumerate() {
            let revealed_key = if bit == 1 {
                private_key.private_key_1_at(i)?.clone()
            } else if bit == 0 {
                private_key.private_key_0_at(i)?.clone()
            } else {
                return Err(LamportError::InvalidBitValue(bit));
            };

            signature.push_revealed_key(revealed_key)?;
        }

        Ok(signature)
    }

    /// Verify a Lamport signature
    ///
    /// # Arguments
    /// * `message_bits` - The message that was allegedly signed (as bits)
    /// * `signature` - The signature to verify
    /// * `public_key` - The public key to verify against
    ///
    /// # Returns
    /// True if the signature is valid, false otherwise
    pub fn verify_signature(
        &self,
        message_bits: &[u8], // TODO i prefer to be an array of booleans, as a bit is only 0 or 1
        signature: &LamportSignature,
        public_key: &LamportPublicKey,
    ) -> Result<bool, LamportError> {
        if message_bits.len() != signature.message_bit_length() {
            return Err(LamportError::MessageLengthMismatch(
                message_bits.len(),
                signature.message_bit_length(),
            ));
        }

        if message_bits.len() != public_key.len() {
            return Err(LamportError::MessageLengthMismatch(
                message_bits.len(),
                public_key.len(),
            ));
        }

        let hash_type = public_key.hash_type();

        // For each bit, verify the revealed key hashes to the correct public key
        for (i, &bit) in message_bits.iter().enumerate() {
            let revealed_key = signature.revealed_key_at(i)?;
            let hash_of_revealed = hash_type.hash(&revealed_key.to_bytes());

            let expected_public_key = if bit == 1 {
                public_key.public_key_1_at(i)?
            } else if bit == 0 {
                public_key.public_key_0_at(i)?
            } else {
                warn!("Invalid bit value: {} (expected 0 or 1)", bit);
                return Ok(false);
            };

            if hash_of_revealed != *expected_public_key {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Helper function to generate a hash using HMAC for key derivation
    fn generate_hash(
        &self,
        master_secret: &[u8],
        key_size: usize,
        derivation_index: u32,
        bit_index: u32,
        bit_value: u8, // 0 or 1
    ) -> LamportHash {
        let mut engine = HmacEngine::<sha256::Hash>::new(master_secret);
        let input = [
            derivation_index.to_le_bytes(),
            bit_index.to_le_bytes(),
            [bit_value, 0, 0, 0],
        ]
        .concat();
        engine.input(&input);

        let hash = Hmac::<sha256::Hash>::from_engine(engine);
        LamportHash::new(hash[..key_size].to_vec())
    }
}

// TODO padding should be added as a parameter, to know how many start 0s are not part of the message, for the funcs that call using exactly all the bits that fits in that bytes padding will be 0
/// Convert a byte array to a bit array
/// Each byte is expanded to 8 bits (MSB first)
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);

    for byte in bytes {
        for bit_index in 0..8 {
            let bit = (byte >> (7 - bit_index)) & 1;
            bits.push(bit);
        }
    }

    bits
}

// TODO padding should be added as a return value, to know how many start 0s of the 1st byte are not part of the message, for the cases converting bits mutiple of 8 the padding will be 0
/// Convert a bit array back to bytes
/// Every 8 bits are combined into one byte (MSB first)
pub fn bits_to_bytes(bits: &[u8]) -> Result<Vec<u8>, LamportError> {
    if bits.len() % 8 != 0 {
        return Err(LamportError::InvalidBitLength(bits.len()));
    }

    let mut bytes = Vec::with_capacity(bits.len() / 8);

    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit > 1 {
                return Err(LamportError::InvalidBitValue(bit));
            }
            byte |= bit << (7 - i);
        }
        bytes.push(byte);
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;


    // TODO in this test we assume we alsay have the hole byte filled with bits, we should create another tests, where we have 4 bits and padding, (filled with 0s at the begining) and 1 lonely bit with 7 0s as padding
    #[test]
    fn test_bytes_to_bits_and_back() {
        let original_bytes = vec![0b10110011, 0b01001100, 0xFF, 0x00];
        let bits = bytes_to_bits(&original_bytes);
        assert_eq!(bits.len(), 32);

        let reconstructed_bytes = bits_to_bytes(&bits).unwrap();
        assert_eq!(original_bytes, reconstructed_bytes);
    }

    #[test]
    fn test_lamport_keygen() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bit_length = 256; // 32 bytes

        let public_key = lamport
            .generate_public_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();

        assert_eq!(public_key.len(), message_bit_length);
        assert_eq!(public_key.hash_size(), SHA256_SIZE);
    }

    #[test]
    fn test_lamport_sign_and_verify() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bit_length = 256;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();

        let public_key = private_key.public_key().unwrap();

        // Create a test message
        let message_bytes = b"Hello, Lamport!"; // 15 bytes = 120 bits
        let message_bits = bytes_to_bits(message_bytes);

        // For this test, we need a key with the right bit length
        let private_key_120 = lamport
            .generate_private_key(master_secret, LamportType::SHA256, 120, 1)
            .unwrap();
        let public_key_120 = private_key_120.public_key().unwrap();

        let signature = lamport.sign_message(&message_bits, &private_key_120).unwrap();

        let is_valid = lamport
            .verify_signature(&message_bits, &signature, &public_key_120)
            .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_lamport_verify_fails_on_wrong_message() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bit_length = 120;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        let message_bytes = b"Hello, Lamport!";
        let message_bits = bytes_to_bits(message_bytes);

        let signature = lamport.sign_message(&message_bits, &private_key).unwrap();

        // Try to verify with a different message
        let wrong_message_bytes = b"Wrong message!!";
        let wrong_message_bits = bytes_to_bits(wrong_message_bytes);

        let is_valid = lamport
            .verify_signature(&wrong_message_bits, &signature, &public_key)
            .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_lamport_serialization() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bit_length = 256;

        let public_key = lamport
            .generate_public_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();

        let bytes = public_key.to_bytes();
        let reconstructed = LamportPublicKey::from_bytes(&bytes, message_bit_length, LamportType::SHA256).unwrap();

        assert_eq!(public_key.len(), reconstructed.len());
        assert_eq!(public_key.to_bytes(), reconstructed.to_bytes());
    }

    #[test]
    fn test_lamport_type_parsing() {
        assert_eq!(LamportType::from_str("SHA256").unwrap(), LamportType::SHA256);
        assert_eq!(LamportType::from_str("sha256").unwrap(), LamportType::SHA256);
        assert_eq!(LamportType::from_str("HASH160").unwrap(), LamportType::HASH160);
        assert_eq!(LamportType::from_str("hash160").unwrap(), LamportType::HASH160);
        assert!(LamportType::from_str("INVALID").is_err());
    }

    #[test]
    fn test_lamport_hash160_sign_and_verify() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bit_length = 160; // 20 bytes for HASH160

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::HASH160, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        assert_eq!(public_key.hash_size(), RIPEMD160_SIZE);

        // Create a test message
        let message_bytes = b"Hello, HASH160!"; // 15 bytes = 120 bits
        let message_bits = bytes_to_bits(message_bytes);

        let private_key_120 = lamport
            .generate_private_key(master_secret, LamportType::HASH160, 120, 1)
            .unwrap();
        let public_key_120 = private_key_120.public_key().unwrap();

        let signature = lamport.sign_message(&message_bits, &private_key_120).unwrap();

        let is_valid = lamport
            .verify_signature(&message_bits, &signature, &public_key_120)
            .unwrap();

        assert!(is_valid);
    }
}
