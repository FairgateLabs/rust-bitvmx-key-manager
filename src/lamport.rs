use core::fmt;
use std::str::FromStr;

use bitcoin::hashes::{ripemd160, sha256, Hash, HashEngine, Hmac, HmacEngine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::errors::LamportError;

pub const SHA256_SIZE: usize = 32;
pub const RIPEMD160_SIZE: usize = 20;

/// Maximum message bit length allowed to prevent DoS attacks with huge keys/signatures.
/// This limit supports up to 10x SHA256 size (256 bits * 10 = 2560 bits) with headroom.
/// At this limit, key size is approximately: 2 * 10000 * 32 bytes = 625 KB
pub const MAX_MESSAGE_BIT_LENGTH: usize = 10_000;

/// Maximum signature/key byte length, calculated as MAX_MESSAGE_BIT_LENGTH * max_hash_size * 2
/// This equals 10,000 * 32 * 2 = 640,000 bytes (~625 KB) for the largest hash type
pub const MAX_KEY_SIGNATURE_BYTE_LENGTH: usize = MAX_MESSAGE_BIT_LENGTH * SHA256_SIZE * 2;

/// Lamport signature hash function types
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LamportType {
    SHA256,
    RIPEMD160,
    HASH160, // RIPEMD160(SHA256(x))
    HASH256, // double SHA-256
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
            LamportType::RIPEMD160 => {
                LamportHash::new(ripemd160::Hash::hash(data).as_byte_array().to_vec())
            }
            LamportType::HASH160 => {
                let sha256 = sha256::Hash::hash(data);
                let hash160 = ripemd160::Hash::hash(sha256.as_byte_array());
                LamportHash::new(hash160.as_byte_array().to_vec())
            }
            LamportType::HASH256 => {
                let sha256_1 = sha256::Hash::hash(data);
                let sha256_2 = sha256::Hash::hash(sha256_1.as_byte_array());
                LamportHash::new(sha256_2.as_byte_array().to_vec())
            }
        };
        hash
    }

    fn hash_size(&self) -> usize {
        match self {
            LamportType::SHA256 => SHA256_SIZE,
            LamportType::RIPEMD160 => RIPEMD160_SIZE,
            LamportType::HASH160 => RIPEMD160_SIZE,
            LamportType::HASH256 => SHA256_SIZE,
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

impl Zeroize for LamportHash {
    fn zeroize(&mut self) {
        self.hash.zeroize();
    }
}

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
        validate_message_bit_length(message_bit_length)?;
        validate_byte_length(bytes.len())?;

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
            .ok_or(LamportError::IndexOutOfBounds(
                index,
                self.revealed_keys.len(),
            ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraData {
    message_bit_length: usize,
    derivation_index: Option<u32>,
}

impl ExtraData {
    pub fn new(message_bit_length: usize, derivation_index: Option<u32>) -> Self {
        ExtraData {
            message_bit_length,
            derivation_index,
        }
    }

    pub fn message_bit_length(&self) -> usize {
        self.message_bit_length
    }

    pub fn derivation_index(&self) -> Option<u32> {
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
    imported: bool, // if the key was imported or derived. imported = true, derive = false
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
            imported: false,
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

    // returns all bytes for 0s concatenated with bytes for 1s, in the order of the message bits
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

    // returns all bytes for 0s at 1st return param, bytes for 1s at the second, in the order of the message bits
    pub fn to_bytes_splitted(&self) -> (Vec<u8>, Vec<u8>) {
        let mut bytes_0s = Vec::new();
        let mut bytes_1s = Vec::new();

        // Serialize 0s
        for hash in self.public_key_0s.iter() {
            bytes_0s.extend_from_slice(&hash.hash);
        }

        // Serialize 1s
        for hash in self.public_key_1s.iter() {
            bytes_1s.extend_from_slice(&hash.hash);
        }

        (bytes_0s, bytes_1s)
    }

    pub fn from_bytes(
        bytes_0s_then_1s: &[u8],
        message_bit_length: usize,
        hash_type: LamportType,
        imported: bool,
        extra_data: Option<ExtraData>,
    ) -> Result<Self, LamportError> {
        validate_message_bit_length(message_bit_length)?;
        validate_byte_length(bytes_0s_then_1s.len())?;

        let hash_size = hash_type.hash_size();
        let expected_length = 2 * message_bit_length * hash_size;

        if bytes_0s_then_1s.len() != expected_length {
            return Err(LamportError::InvalidPublicKeyLength(
                bytes_0s_then_1s.len(),
                expected_length,
            ));
        }

        let mut public_key = LamportPublicKey::new(hash_type, extra_data);
        public_key.imported = imported;

        // Split bytes into 0s and 1s sections
        let split_point = message_bit_length * hash_size;
        let bytes_0s = &bytes_0s_then_1s[..split_point];
        let bytes_1s = &bytes_0s_then_1s[split_point..];

        for i in 0..message_bit_length {
            let start = i * hash_size;
            let end = start + hash_size;

            let hash_0 = LamportHash::new(bytes_0s[start..end].to_vec());
            let hash_1 = LamportHash::new(bytes_1s[start..end].to_vec());

            public_key.push_key_pair(hash_0, hash_1)?;
        }

        Ok(public_key)
    }

    pub fn from_bytes_splitted(
        bytes_0s: &[u8],
        bytes_1s: &[u8],
        message_bit_length: usize,
        hash_type: LamportType,
        imported: bool,
        extra_data: Option<ExtraData>,
    ) -> Result<Self, LamportError> {
        validate_message_bit_length(message_bit_length)?;
        let combined_length = bytes_0s.len().saturating_add(bytes_1s.len());
        validate_byte_length(combined_length)?;

        let hash_size = hash_type.hash_size();
        let expected_length = message_bit_length * hash_size;

        if bytes_0s.len() != expected_length {
            return Err(LamportError::InvalidPublicKeyLength(
                bytes_0s.len(),
                expected_length,
            ));
        }

        if bytes_1s.len() != expected_length {
            return Err(LamportError::InvalidPublicKeyLength(
                bytes_1s.len(),
                expected_length,
            ));
        }

        let mut public_key = LamportPublicKey::new(hash_type, extra_data);
        public_key.imported = imported;

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
        let hashes_0s: Result<Vec<[u8; 32]>, LamportError> = self
            .public_key_0s
            .iter()
            .map(|hash| hash.to_array())
            .collect();
        let hashes_1s: Result<Vec<[u8; 32]>, LamportError> = self
            .public_key_1s
            .iter()
            .map(|hash| hash.to_array())
            .collect();
        Ok((hashes_0s?, hashes_1s?))
    }

    pub fn to_hashes_string(&self) -> (Vec<String>, Vec<String>) {
        let hashes_0s = self
            .public_key_0s
            .iter()
            .map(|hash| hash.to_hex())
            .collect();
        let hashes_1s = self
            .public_key_1s
            .iter()
            .map(|hash| hash.to_hex())
            .collect();
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

    pub fn derivation_index(&self) -> Option<u32> {
        self.extra_data
            .as_ref()
            .and_then(|extra| extra.derivation_index)
    }

    pub fn imported(&self) -> bool {
        self.imported
    }

    fn public_key_0_at(&self, index: usize) -> Result<&LamportHash, LamportError> {
        self.public_key_0s
            .get(index)
            .ok_or(LamportError::IndexOutOfBounds(
                index,
                self.public_key_0s.len(),
            ))
    }

    fn public_key_1_at(&self, index: usize) -> Result<&LamportHash, LamportError> {
        self.public_key_1s
            .get(index)
            .ok_or(LamportError::IndexOutOfBounds(
                index,
                self.public_key_1s.len(),
            ))
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
    imported: bool, // if the key was imported or derived. imported = true, derive = false
    derivation_index: Option<u32>, // None if the key was imported and not derived
    spent: bool, // if the key was already used to sign. once spent = true, it should never be used again for signing
}

impl LamportPrivateKey {
    pub fn new(
        hash_type: LamportType,
        message_bit_length: usize,
        derivation_index: Option<u32>,
    ) -> Self {
        // Note: Validation is performed in generate_private_key and from_bytes methods
        LamportPrivateKey {
            private_key_0s: Vec::with_capacity(message_bit_length),
            private_key_1s: Vec::with_capacity(message_bit_length),
            hash_type,
            message_bit_length,
            imported: false,
            derivation_index,
            spent: false,
        }
    }

    pub fn public_key(&self) -> Result<LamportPublicKey, LamportError> {
        let mut public_key = LamportPublicKey::new(
            self.hash_type,
            Some(ExtraData::new(
                self.message_bit_length,
                self.derivation_index,
            )),
        );

        // Copy the imported flag from private key to public key
        public_key.imported = self.imported;

        for i in 0..self.private_key_0s.len() {
            let pub_0 = self.hash_type.hash(&self.private_key_0s[i].to_bytes());
            let pub_1 = self.hash_type.hash(&self.private_key_1s[i].to_bytes());
            public_key.push_key_pair(pub_0, pub_1)?;
        }

        Ok(public_key)
    }

    // returns all bytes for 0s concatenated with bytes for 1s, in the order of the message bits
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize 0s
        for hash in self.private_key_0s.iter() {
            bytes.extend_from_slice(&hash.hash);
        }

        // Serialize 1s
        for hash in self.private_key_1s.iter() {
            bytes.extend_from_slice(&hash.hash);
        }

        bytes
    }

    // returns all bytes for 0s at 1st return param, bytes for 1s at the second, in the order of the message bits
    pub fn to_bytes_splitted(&self) -> (Vec<u8>, Vec<u8>) {
        let mut bytes_0s = Vec::new();
        let mut bytes_1s = Vec::new();

        // Serialize 0s
        for hash in self.private_key_0s.iter() {
            bytes_0s.extend_from_slice(&hash.hash);
        }

        // Serialize 1s
        for hash in self.private_key_1s.iter() {
            bytes_1s.extend_from_slice(&hash.hash);
        }

        (bytes_0s, bytes_1s)
    }

    pub fn from_bytes(
        bytes_0s_then_1s: &[u8],
        message_bit_length: usize,
        hash_type: LamportType,
        derivation_index: Option<u32>,
    ) -> Result<Self, LamportError> {
        validate_message_bit_length(message_bit_length)?;
        validate_byte_length(bytes_0s_then_1s.len())?;

        let hash_size = hash_type.hash_size();
        let expected_length = 2 * message_bit_length * hash_size;

        if bytes_0s_then_1s.len() != expected_length {
            return Err(LamportError::InvalidPublicKeyLength(
                bytes_0s_then_1s.len(),
                expected_length,
            ));
        }

        let mut private_key =
            LamportPrivateKey::new(hash_type, message_bit_length, derivation_index);

        // Split bytes into 0s and 1s sections
        let split_point = message_bit_length * hash_size;
        let bytes_0s = &bytes_0s_then_1s[..split_point];
        let bytes_1s = &bytes_0s_then_1s[split_point..];

        for i in 0..message_bit_length {
            let start = i * hash_size;
            let end = start + hash_size;

            let hash_0 = LamportHash::new(bytes_0s[start..end].to_vec());
            let hash_1 = LamportHash::new(bytes_1s[start..end].to_vec());

            private_key.push_key_pair(hash_0, hash_1)?;
        }

        Ok(private_key)
    }

    pub fn from_bytes_splitted(
        bytes_0s: &[u8],
        bytes_1s: &[u8],
        message_bit_length: usize,
        hash_type: LamportType,
        derivation_index: Option<u32>,
    ) -> Result<Self, LamportError> {
        validate_message_bit_length(message_bit_length)?;
        let combined_length = bytes_0s.len().saturating_add(bytes_1s.len());
        validate_byte_length(combined_length)?;

        let hash_size = hash_type.hash_size();
        let expected_length = message_bit_length * hash_size;

        if bytes_0s.len() != expected_length {
            return Err(LamportError::InvalidPublicKeyLength(
                bytes_0s.len(),
                expected_length,
            ));
        }

        if bytes_1s.len() != expected_length {
            return Err(LamportError::InvalidPublicKeyLength(
                bytes_1s.len(),
                expected_length,
            ));
        }

        let mut private_key =
            LamportPrivateKey::new(hash_type, message_bit_length, derivation_index);

        for i in 0..message_bit_length {
            let start = i * hash_size;
            let end = start + hash_size;

            let hash_0 = LamportHash::new(bytes_0s[start..end].to_vec());
            let hash_1 = LamportHash::new(bytes_1s[start..end].to_vec());

            private_key.push_key_pair(hash_0, hash_1)?;
        }

        Ok(private_key)
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

    pub fn to_hashes_string(&self) -> (Vec<String>, Vec<String>) {
        let hashes_0s = self
            .private_key_0s
            .iter()
            .map(|hash| hash.to_hex())
            .collect();
        let hashes_1s = self
            .private_key_1s
            .iter()
            .map(|hash| hash.to_hex())
            .collect();
        (hashes_0s, hashes_1s)
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

    pub fn derivation_index(&self) -> Option<u32> {
        self.derivation_index
    }

    pub fn message_bit_length(&self) -> usize {
        self.message_bit_length
    }

    pub fn imported(&self) -> bool {
        self.imported
    }

    pub fn spent(&self) -> bool {
        self.spent
    }

    pub fn mark_spent(&mut self) {
        self.spent = true;
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
            .ok_or(LamportError::IndexOutOfBounds(
                index,
                self.private_key_0s.len(),
            ))
    }

    fn private_key_1_at(&self, index: usize) -> Result<&LamportHash, LamportError> {
        self.private_key_1s
            .get(index)
            .ok_or(LamportError::IndexOutOfBounds(
                index,
                self.private_key_1s.len(),
            ))
    }
}

impl Drop for LamportPrivateKey {
    fn drop(&mut self) {
        // Zeroize the private keys on drop
        for hash in self.private_key_0s.iter_mut() {
            hash.hash.zeroize();
        }
        for hash in self.private_key_1s.iter_mut() {
            hash.hash.zeroize();
        }
    }
}

// ========== Validation Helper Functions ==========

/// Validates that message bit length doesn't exceed the maximum to prevent DoS attacks
fn validate_message_bit_length(message_bit_length: usize) -> Result<(), LamportError> {
    if message_bit_length > MAX_MESSAGE_BIT_LENGTH {
        return Err(LamportError::MessageBitLengthExceedsMax(
            message_bit_length,
            MAX_MESSAGE_BIT_LENGTH,
        ));
    }
    Ok(())
}

/// Validates that byte length doesn't exceed the maximum to prevent DoS attacks
fn validate_byte_length(byte_length: usize) -> Result<(), LamportError> {
    if byte_length > MAX_KEY_SIGNATURE_BYTE_LENGTH {
        return Err(LamportError::ByteLengthExceedsMax(
            byte_length,
            MAX_KEY_SIGNATURE_BYTE_LENGTH,
        ));
    }
    Ok(())
}

// ========== Main Lamport Implementation ==========

/// Main Lamport signature scheme implementation
#[derive(Default)]
pub struct Lamport {}

impl Lamport {
    pub fn new() -> Self {
        Lamport {}
    }

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
        let private_key = self.generate_private_key(
            master_secret,
            hash_type,
            message_bit_length,
            derivation_index,
        )?;
        let public_key = LamportPublicKey::from(private_key)?;
        Ok(public_key)
    }

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
        validate_message_bit_length(message_bit_length)?;

        derivation_index
            .checked_add(1)
            .ok_or(LamportError::IndexOverflow)?;

        let mut private_key =
            LamportPrivateKey::new(hash_type, message_bit_length, Some(derivation_index));

        let hash_size = hash_type.hash_size();

        // Generate key pairs for each bit position
        for i in 0..message_bit_length {
            // Generate private key for bit value 0
            let priv_key_0 =
                self.generate_hash(master_secret, hash_size, derivation_index, i as u32, 0);

            // Generate private key for bit value 1
            let priv_key_1 =
                self.generate_hash(master_secret, hash_size, derivation_index, i as u32, 1);

            private_key.push_key_pair(priv_key_0, priv_key_1)?;
        }

        Ok(private_key)
    }

    /// Sign a message using a Lamport private key
    ///
    /// # Arguments
    /// * `message_bits` - The message to sign as a vector of bits (boolean array 0=false, 1=true)
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
        message_bits: &[bool],
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
            let revealed_key = if bit {
                private_key.private_key_1_at(i)?.clone()
            } else {
                private_key.private_key_0_at(i)?.clone()
            };

            signature.push_revealed_key(revealed_key)?;
        }

        Ok(signature)
    }

    /// Sign a message from bytes using a Lamport private key
    ///
    /// This is a convenience wrapper around `sign_message` that converts bytes to bits.
    /// For most use cases (e.g., signing SHA256 digests), this is the preferred method.
    ///
    /// # Arguments
    /// * `message_bytes` - The message to sign as bytes
    /// * `private_key` - The private key to use for signing
    ///
    /// # Returns
    /// The signature containing the revealed private key fragments
    ///
    /// # Security Critical
    /// After calling this function, the private key MUST be marked as used and never reused.
    /// Reusing a Lamport private key allows attackers to forge signatures.
    pub fn sign_message_bytes(
        &self,
        message_bytes: &[u8],
        private_key: &LamportPrivateKey,
    ) -> Result<LamportSignature, LamportError> {
        let message_bits = bytes_to_bits(message_bytes, 0);
        self.sign_message(&message_bits, private_key)
    }

    /// Sign a single bit using a Lamport private key
    ///
    /// This is a convenience wrapper around `sign_message` for signing individual bits.
    /// Commonly used for garbled circuits where wire labels need to be signed bit by bit.
    ///
    /// # Arguments
    /// * `message_bit` - The single bit to sign - bool representing a bit false = 0, true = 1
    /// * `private_key` - The private key to use for signing (must have message_bit_length = 1)
    ///
    /// # Returns
    /// The signature containing the revealed private key fragment
    ///
    /// # Security Critical
    /// After calling this function, the private key MUST be marked as used and never reused.
    /// Reusing a Lamport private key allows attackers to forge signatures.
    pub fn sign_message_bit(
        &self,
        message_bit: bool, // bool representing a bit false = 0, true = 1
        private_key: &LamportPrivateKey,
    ) -> Result<LamportSignature, LamportError> {
        let message_bits = [message_bit];
        self.sign_message(&message_bits, private_key)
    }

    /// Verify a Lamport signature
    ///
    /// # Arguments
    /// * `message_bits` - The message that was allegedly signed (as boolean array)
    /// * `signature` - The signature to verify
    /// * `public_key` - The public key to verify against
    ///
    /// # Returns
    /// True if the signature is valid, false otherwise
    pub fn verify_signature(
        &self,
        message_bits: &[bool],
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

            let expected_public_key = if bit {
                public_key.public_key_1_at(i)?
            } else {
                public_key.public_key_0_at(i)?
            };

            if hash_of_revealed != *expected_public_key {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify a Lamport signature from message bytes
    ///
    /// This is a convenience wrapper around `verify_signature` that converts bytes to bits.
    /// For most use cases (e.g., verifying SHA256 digests), this is the preferred method.
    ///
    /// # Arguments
    /// * `message_bytes` - The message that was allegedly signed
    /// * `signature` - The signature to verify
    /// * `public_key` - The public key to verify against
    ///
    /// # Returns
    /// True if the signature is valid, false otherwise
    pub fn verify_signature_bytes(
        &self,
        message_bytes: &[u8],
        signature: &LamportSignature,
        public_key: &LamportPublicKey,
    ) -> Result<bool, LamportError> {
        let message_bits = bytes_to_bits(message_bytes, 0);
        self.verify_signature(&message_bits, signature, public_key)
    }

    /// Verify a Lamport signature for a single bit
    ///
    /// This is a convenience wrapper around `verify_signature` for verifying individual bits.
    /// Commonly used for garbled circuits where wire labels are verified bit by bit.
    ///
    /// # Arguments
    /// * `message_bit` - The single bit that was allegedly signed
    /// * `signature` - The signature to verify
    /// * `public_key` - The public key to verify against (must have message_bit_length = 1)
    ///
    /// # Returns
    /// True if the signature is valid, false otherwise
    pub fn verify_signature_bit(
        &self,
        message_bit: bool,
        signature: &LamportSignature,
        public_key: &LamportPublicKey,
    ) -> Result<bool, LamportError> {
        let message_bits = [message_bit];
        self.verify_signature(&message_bits, signature, public_key)
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

/// Convert a byte array to a bit array
/// Each byte is expanded to 8 bits (MSB first)
///
/// # Arguments
/// * `bytes` - The byte array to convert
/// * `padding` - Number of leading bits to skip in the first byte (0-7)
///
/// # Returns
/// A vector of bools representing the bits, skipping the first `padding` bits
///
/// # Example
/// ```
/// // bytes = [0b00010110], padding = 3
/// // Result skips first 3 bits: [true, false, true, true, false] (the bits "10110")
/// ```
pub fn bytes_to_bits(bytes: &[u8], padding: usize) -> Vec<bool> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let total_bits = bytes.len() * 8;
    let mut bits = Vec::with_capacity(total_bits.saturating_sub(padding));
    let mut bits_to_skip = padding;

    for byte in bytes {
        for bit_index in 0..8 {
            if bits_to_skip > 0 {
                bits_to_skip -= 1;
                continue;
            }
            let bit = (byte >> (7 - bit_index)) & 1;
            bits.push(bit == 1);
            // Example extracting bits from byte 0b10110011 (179 in decimal):
            // bit_index=0: byte >> (7-0) = 0b10110011 >> 7 = 0b00000001, & 1 = 1 → bit = 1 (MSB, push true)
            // bit_index=1: byte >> (7-1) = 0b10110011 >> 6 = 0b00000010, & 1 = 0 → bit = 0 (push false)
            // ...
            // bit_index=7: byte >> (7-7) = 0b10110011 >> 0 = 0b10110011, & 1 = 1 → bit = 1 (push true, LSB)
            // Result: [true, false, true, true, false, false, true, true] representing bits from MSB to LSB
        }
    }

    bits
}

/// Convert a bit array back to bytes
/// Every 8 bits are combined into one byte (MSB first)
///
/// # Returns
/// A tuple containing:
/// * The byte vector
/// * The padding value (number of leading zeros added to make bits fit into bytes)
///
/// # Example
/// ```
/// // bits = [true, false, true, true, false] (5 bits: "10110")
/// // Padding = 3, result bytes = [0b00010110]
/// // Returns: (vec![0b00010110], 3)
/// ```
pub fn bits_to_bytes(bits: &[bool]) -> Result<(Vec<u8>, usize), LamportError> {
    if bits.is_empty() {
        return Ok((Vec::new(), 0));
    }

    // Calculate padding needed: how many zeros to prepend to make length a multiple of 8
    let padding = (8 - (bits.len() % 8)) % 8; // double % for the case 8 - 0 = 8 which should be 0 padding
    let total_bits = padding + bits.len();
    let mut bytes = Vec::with_capacity(total_bits / 8);

    let mut current_byte = 0u8;
    let mut bit_position = 0;

    // Add padding zeros
    for _ in 0..padding {
        // bit is 0, so we don't need to set it (current_byte starts as 0)
        bit_position += 1;
        if bit_position == 8 {
            bytes.push(current_byte);
            current_byte = 0;
            bit_position = 0;
        }
    }

    // Add actual bits
    for &bit in bits {
        if bit {
            current_byte |= 1 << (7 - bit_position);
            // Example building byte 0b10110011 from bits [true, false, true, true, false, false, true, true]:
            // bit_position=0, bit=true:  1 << (7-0) = 1 << 7 = 0b10000000, byte |= 0b10000000 → byte = 0b10000000
            // bit_position=1, bit=false: skipped (if bit is false, don't set the bit)
            // ...
            // bit_position=7, bit=true:  1 << (7-7) = 1 << 0 = 0b00000001, byte |= 0b00000001 → byte = 0b10110011
            // Result: byte = 0b10110011 (179 in decimal)
        }
        bit_position += 1;
        if bit_position == 8 {
            bytes.push(current_byte);
            current_byte = 0;
            bit_position = 0;
        }
    }

    Ok((bytes, padding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_bits_and_back() {
        // Test with no padding (full bytes)
        let original_bytes = vec![0b10110011, 0b01001100, 0xFF, 0x00];
        let bits = bytes_to_bits(&original_bytes, 0);
        assert_eq!(bits.len(), 32);

        let (reconstructed_bytes, padding) = bits_to_bytes(&bits).unwrap();
        assert_eq!(padding, 0);
        assert_eq!(original_bytes, reconstructed_bytes);
    }

    #[test]
    fn test_bytes_to_bits_with_padding() {
        // Test with 3 bits of padding
        // bytes = [0b00010110], padding = 3
        // Should skip first 3 bits and return the 5 bits: "10110"
        let bytes = vec![0b00010110];
        let bits = bytes_to_bits(&bytes, 3);
        assert_eq!(bits.len(), 5);
        assert_eq!(bits, vec![true, false, true, true, false]);

        // Test with 7 bits of padding (1 bit remaining)
        // bytes = [0b00000001], padding = 7
        // Should return just 1 bit: "1"
        let bytes = vec![0b00000001];
        let bits = bytes_to_bits(&bytes, 7);
        assert_eq!(bits.len(), 1);
        assert_eq!(bits, vec![true]);

        // Test with padding across multiple bytes
        // bytes = [0b00001011, 0b01110011], padding = 4
        // Should skip first 4 bits of first byte
        let bytes = vec![0b00001011, 0b01110011];
        let bits = bytes_to_bits(&bytes, 4);
        assert_eq!(bits.len(), 12);
        assert_eq!(
            bits,
            vec![true, false, true, true, false, true, true, true, false, false, true, true]
        );
    }

    #[test]
    fn test_bits_to_bytes_with_padding() {
        // Test with 5 bits (requires 3 bits of padding)
        // bits = [true, false, true, true, false] ("10110")
        // Should produce bytes = [0b00010110], padding = 3
        let bits = vec![true, false, true, true, false];
        let (bytes, padding) = bits_to_bytes(&bits).unwrap();
        assert_eq!(padding, 3);
        assert_eq!(bytes, vec![0b00010110]);

        // Test roundtrip
        let reconstructed_bits = bytes_to_bits(&bytes, padding);
        assert_eq!(bits, reconstructed_bits);

        // Test with 1 bit (requires 7 bits of padding)
        let bits = vec![true];
        let (bytes, padding) = bits_to_bytes(&bits).unwrap();
        assert_eq!(padding, 7);
        assert_eq!(bytes, vec![0b00000001]);

        // Test roundtrip
        let reconstructed_bits = bytes_to_bits(&bytes, padding);
        assert_eq!(bits, reconstructed_bits);

        // Test with 0 padding (exact byte boundary)
        let bits = vec![true, false, true, true, false, false, true, true];
        let (bytes, padding) = bits_to_bytes(&bits).unwrap();
        assert_eq!(padding, 0);
        assert_eq!(bytes, vec![0b10110011]);
    }

    #[test]
    fn test_bits_to_bytes_with_padding_zero() {
        // Test with 0 padding (exact byte boundary - 8 bits)
        let bits = vec![true, false, true, true, false, false, true, true];
        let (bytes, padding) = bits_to_bytes(&bits).unwrap();
        assert_eq!(padding, 0);
        assert_eq!(bytes, vec![0b10110011]);

        // Test roundtrip
        let reconstructed_bits = bytes_to_bits(&bytes, padding);
        assert_eq!(bits, reconstructed_bits);

        // Test with 0 padding (exact byte boundary - 16 bits)
        let bits = vec![
            true, false, true, true, false, false, true, true, false, true, false, false, true,
            true, false, false,
        ];
        let (bytes, padding) = bits_to_bytes(&bits).unwrap();
        assert_eq!(padding, 0);
        assert_eq!(bytes, vec![0b10110011, 0b01001100]);

        // Test roundtrip
        let reconstructed_bits = bytes_to_bits(&bytes, padding);
        assert_eq!(bits, reconstructed_bits);
    }

    #[test]
    fn test_padding_greater_than_8() {
        // Test with padding = 10 (spans across multiple bytes)
        // bytes = [0x00, 0x05] = [0b00000000, 0b00000101]
        // Skip first 10 bits: all 8 bits from first byte + 2 bits from second byte
        // Remaining 6 bits from second byte: "000101"
        let bytes = vec![0x00, 0x05];
        let bits = bytes_to_bits(&bytes, 10);
        assert_eq!(bits.len(), 6);
        assert_eq!(bits, vec![false, false, false, true, false, true]);

        // Test roundtrip
        let (reconstructed_bytes, padding) = bits_to_bytes(&bits).unwrap();
        assert_eq!(padding, 2); // 6 bits need 2 bits of padding to make 8
        assert_eq!(reconstructed_bytes, vec![0b00000101]);
        let final_bits = bytes_to_bits(&reconstructed_bytes, padding);
        assert_eq!(bits, final_bits);

        // Test with padding = 12 (1.5 bytes worth of padding)
        // bytes = [0xFF, 0xFF, 0xFF] = 24 bits total
        // Skip first 12 bits: all of first byte + half of second byte
        // Remaining 12 bits: second half of 2nd byte + all of 3rd byte
        let bytes = vec![0xFF, 0b11110101, 0xAA];
        let bits = bytes_to_bits(&bytes, 12);
        assert_eq!(bits.len(), 12);
        assert_eq!(
            bits,
            vec![
                false, true, false, true, // lower 4 bits of 0b11110101
                true, false, true, false, true, false, true, false // 0xAA
            ]
        );

        // Test with padding = 15 (almost 2 bytes)
        // bytes = [0x00, 0xFF, 0x01] = 24 bits total
        // Skip first 15 bits
        // Remaining 9 bits
        let bytes = vec![0x00, 0xFF, 0x01];
        let bits = bytes_to_bits(&bytes, 15);
        assert_eq!(bits.len(), 9);
        assert_eq!(
            bits,
            vec![true, false, false, false, false, false, false, false, true]
        );
    }

    #[test]
    fn test_large_value_with_leading_zeros() {
        // Simulate a u32 with value 5 (binary: 101)
        // When serialized: [0x00, 0x00, 0x00, 0x05]
        // That's 32 bits total, but only last 3 bits matter
        // padding = 29 to skip the leading zeros
        let value: u32 = 5;
        let bytes = value.to_be_bytes();
        let bits = bytes_to_bits(&bytes, 29);

        assert_eq!(bits.len(), 3);
        assert_eq!(bits, vec![true, false, true]); // "101" in binary

        // Test roundtrip
        let (reconstructed_bytes, padding) = bits_to_bytes(&bits).unwrap();
        assert_eq!(padding, 5); // 3 bits need 5 bits padding to make 8
        assert_eq!(reconstructed_bytes, vec![0b00000101]);
        let final_bits = bytes_to_bits(&reconstructed_bytes, padding);
        assert_eq!(bits, final_bits);

        // Test with u16 value 7 (binary: 111)
        let value: u16 = 7;
        let bytes = value.to_be_bytes();
        let bits = bytes_to_bits(&bytes, 13); // Skip 13 leading zeros

        assert_eq!(bits.len(), 3);
        assert_eq!(bits, vec![true, true, true]); // "111" in binary
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

        let _public_key = private_key.public_key().unwrap();

        // Create a test message
        let message_bytes = b"Hello, Lamport!"; // 15 bytes = 120 bits
        let message_bits = bytes_to_bits(message_bytes, 0);

        // For this test, we need a key with the right bit length
        let private_key_120 = lamport
            .generate_private_key(master_secret, LamportType::SHA256, 120, 1)
            .unwrap();
        let public_key_120 = private_key_120.public_key().unwrap();

        let signature = lamport
            .sign_message(&message_bits, &private_key_120)
            .unwrap();

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
        let message_bits = bytes_to_bits(message_bytes, 0);

        let signature = lamport.sign_message(&message_bits, &private_key).unwrap();

        // Try to verify with a different message
        let wrong_message_bytes = b"Wrong message!!";
        let wrong_message_bits = bytes_to_bits(wrong_message_bytes, 0);

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
        let reconstructed =
            LamportPublicKey::from_bytes(&bytes, message_bit_length, LamportType::SHA256, false, Some(ExtraData::new(message_bit_length, Some(0)))).unwrap();

        assert_eq!(public_key.len(), reconstructed.len());
        assert_eq!(public_key.to_bytes(), reconstructed.to_bytes());
    }

    #[test]
    fn test_lamport_type_parsing() {
        assert_eq!(
            LamportType::from_str("SHA256").unwrap(),
            LamportType::SHA256
        );
        assert_eq!(
            LamportType::from_str("sha256").unwrap(),
            LamportType::SHA256
        );
        assert_eq!(
            LamportType::from_str("HASH160").unwrap(),
            LamportType::HASH160
        );
        assert_eq!(
            LamportType::from_str("hash160").unwrap(),
            LamportType::HASH160
        );
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
        let message_bits = bytes_to_bits(message_bytes, 0);

        let private_key_120 = lamport
            .generate_private_key(master_secret, LamportType::HASH160, 120, 1)
            .unwrap();
        let public_key_120 = private_key_120.public_key().unwrap();

        let signature = lamport
            .sign_message(&message_bits, &private_key_120)
            .unwrap();

        let is_valid = lamport
            .verify_signature(&message_bits, &signature, &public_key_120)
            .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_lamport_sign_and_verify_bytes() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";

        // Sign a 32-byte SHA256 digest (common use case)
        let message_bytes = [0u8; 32]; // Example: a zero-filled digest
        let message_bit_length = 256;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();

        let is_valid = lamport
            .verify_signature_bytes(&message_bytes, &signature, &public_key)
            .unwrap();

        assert!(is_valid);

        // Verify that wrong message fails
        let wrong_message = [1u8; 32];
        let is_valid = lamport
            .verify_signature_bytes(&wrong_message, &signature, &public_key)
            .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_bytes_and_bits_methods_equivalent() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bytes = b"Test message";
        let message_bit_length = message_bytes.len() * 8;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        // Sign with bytes method
        let sig_bytes = lamport
            .sign_message_bytes(message_bytes, &private_key)
            .unwrap();

        // Verify bytes signature with bytes method
        assert!(lamport
            .verify_signature_bytes(message_bytes, &sig_bytes, &public_key)
            .unwrap());

        // Verify bytes signature with bits method (should also work)
        let message_bits = bytes_to_bits(message_bytes, 0);
        assert!(lamport
            .verify_signature(&message_bits, &sig_bytes, &public_key)
            .unwrap());
    }

    #[test]
    fn test_sign_bytes_various_lengths() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";

        // Test with various message lengths
        for byte_length in [1, 8, 16, 20, 32] {
            let message_bytes = vec![0xABu8; byte_length];
            let message_bit_length = byte_length * 8;

            let private_key = lamport
                .generate_private_key(
                    master_secret,
                    LamportType::SHA256,
                    message_bit_length,
                    byte_length as u32,
                )
                .unwrap();
            let public_key = private_key.public_key().unwrap();

            let signature = lamport
                .sign_message_bytes(&message_bytes, &private_key)
                .unwrap();

            let is_valid = lamport
                .verify_signature_bytes(&message_bytes, &signature, &public_key)
                .unwrap();

            assert!(is_valid, "Failed for byte_length={}", byte_length);
        }
    }

    #[test]
    fn test_verify_bytes_detects_tampering() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bytes = [0x42u8; 32];
        let message_bit_length = 256;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();

        // Original message should verify
        assert!(lamport
            .verify_signature_bytes(&message_bytes, &signature, &public_key)
            .unwrap());

        // Tampered message (single bit flip) should fail
        let mut tampered_message = message_bytes;
        tampered_message[0] = 0x43; // Change one byte
        assert!(!lamport
            .verify_signature_bytes(&tampered_message, &signature, &public_key)
            .unwrap());

        // Completely different message should fail
        let different_message = [0xFFu8; 32];
        assert!(!lamport
            .verify_signature_bytes(&different_message, &signature, &public_key)
            .unwrap());
    }

    #[test]
    fn test_sign_and_verify_single_bit() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";

        // Generate a key for signing single bits (message_bit_length = 1)
        let private_key_bit0 = lamport
            .generate_private_key(master_secret, LamportType::SHA256, 1, 0)
            .unwrap();
        let public_key_bit0 = private_key_bit0.public_key().unwrap();

        // Test signing bit value 0
        let signature_0 = lamport.sign_message_bit(false, &private_key_bit0).unwrap();
        assert!(lamport
            .verify_signature_bit(false, &signature_0, &public_key_bit0)
            .unwrap());
        assert!(!lamport
            .verify_signature_bit(true, &signature_0, &public_key_bit0)
            .unwrap());

        // Generate another key for signing bit value 1
        let private_key_bit1 = lamport
            .generate_private_key(master_secret, LamportType::SHA256, 1, 1)
            .unwrap();
        let public_key_bit1 = private_key_bit1.public_key().unwrap();

        // Test signing bit value 1
        let signature_1 = lamport.sign_message_bit(true, &private_key_bit1).unwrap();
        assert!(lamport
            .verify_signature_bit(true, &signature_1, &public_key_bit1)
            .unwrap());
        assert!(!lamport
            .verify_signature_bit(false, &signature_1, &public_key_bit1)
            .unwrap());
    }

    #[test]
    fn test_bit_methods_equivalent_to_array_methods() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, 1, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        // Sign using bit method
        let sig_bit = lamport.sign_message_bit(true, &private_key).unwrap();

        // Verify using array method
        let message_bits = [true];
        assert!(lamport
            .verify_signature(&message_bits, &sig_bit, &public_key)
            .unwrap());

        // Verify using bit method
        assert!(lamport
            .verify_signature_bit(true, &sig_bit, &public_key)
            .unwrap());
    }

    #[test]
    fn test_garbled_circuit_wire_label_scenario() {
        // Simulate a garbled circuit scenario where we need to sign individual wire labels
        let lamport = Lamport::new();
        let master_secret = b"garbled_circuit_master_secret_123456789";

        // Generate keys for multiple wire labels (each is 1 bit)
        let mut keys = Vec::new();
        let mut pubkeys = Vec::new();
        for i in 0..5 {
            let key = lamport
                .generate_private_key(master_secret, LamportType::SHA256, 1, i)
                .unwrap();
            let pubkey = key.public_key().unwrap();
            keys.push(key);
            pubkeys.push(pubkey);
        }

        // Simulate wire values: [true, false, true, true, false]
        let wire_values = [true, false, true, true, false];

        // Sign each wire value
        let mut signatures = Vec::new();
        for (i, &wire_value) in wire_values.iter().enumerate() {
            let sig = lamport.sign_message_bit(wire_value, &keys[i]).unwrap();
            signatures.push(sig);
        }

        // Verify each wire value
        for (i, &wire_value) in wire_values.iter().enumerate() {
            assert!(lamport
                .verify_signature_bit(wire_value, &signatures[i], &pubkeys[i])
                .unwrap());

            // Verify that wrong bit value fails
            assert!(!lamport
                .verify_signature_bit(!wire_value, &signatures[i], &pubkeys[i])
                .unwrap());
        }
    }

    // ========== Additional Hash Type Tests ==========

    #[test]
    fn test_lamport_ripemd160_sign_and_verify() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bit_length = 160; // 20 bytes for RIPEMD160

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::RIPEMD160, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        assert_eq!(public_key.hash_size(), RIPEMD160_SIZE);
        assert_eq!(public_key.hash_type(), LamportType::RIPEMD160);

        let message_bytes = [0x42u8; 20]; // Sign a 20-byte message
        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();

        assert!(lamport
            .verify_signature_bytes(&message_bytes, &signature, &public_key)
            .unwrap());

        // Test with wrong message
        let wrong_message = [0x43u8; 20];
        assert!(!lamport
            .verify_signature_bytes(&wrong_message, &signature, &public_key)
            .unwrap());
    }

    #[test]
    fn test_lamport_hash256_sign_and_verify() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret_12345678901234567890";
        let message_bit_length = 256; // 32 bytes for HASH256 (double SHA256)

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::HASH256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        assert_eq!(public_key.hash_size(), SHA256_SIZE);
        assert_eq!(public_key.hash_type(), LamportType::HASH256);

        let message_bytes = [0xAAu8; 32]; // Sign a 32-byte message
        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();

        assert!(lamport
            .verify_signature_bytes(&message_bytes, &signature, &public_key)
            .unwrap());

        // Test with wrong message
        let wrong_message = [0xBBu8; 32];
        assert!(!lamport
            .verify_signature_bytes(&wrong_message, &signature, &public_key)
            .unwrap());
    }

    #[test]
    fn test_all_hash_types_produce_correct_sizes() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";

        // Test each hash type
        let test_cases = vec![
            (LamportType::SHA256, SHA256_SIZE),
            (LamportType::RIPEMD160, RIPEMD160_SIZE),
            (LamportType::HASH160, RIPEMD160_SIZE),
            (LamportType::HASH256, SHA256_SIZE),
        ];

        for (hash_type, expected_size) in test_cases {
            let private_key = lamport
                .generate_private_key(master_secret, hash_type, 8, 0)
                .unwrap();
            let public_key = private_key.public_key().unwrap();

            assert_eq!(
                public_key.hash_size(),
                expected_size,
                "Hash type: {:?}",
                hash_type
            );
            assert_eq!(
                private_key.hash_size(),
                expected_size,
                "Hash type: {:?}",
                hash_type
            );
        }
    }

    // ========== Error Handling Tests ==========

    #[test]
    fn test_error_invalid_signature_length() {
        let bytes = vec![0u8; 100]; // Wrong length
        let result = LamportSignature::from_bytes(&bytes, 256, LamportType::SHA256);
        assert!(result.is_err());
        if let Err(LamportError::InvalidSignatureLength(got, expected)) = result {
            assert_eq!(got, 100);
            assert_eq!(expected, 256 * 32);
        } else {
            panic!("Expected InvalidSignatureLength error");
        }
    }

    #[test]
    fn test_error_invalid_public_key_length() {
        let bytes = vec![0u8; 100]; // Wrong length
        let result = LamportPublicKey::from_bytes(&bytes, 256, LamportType::SHA256, false, None);
        assert!(result.is_err());
        if let Err(LamportError::InvalidPublicKeyLength(got, expected)) = result {
            assert_eq!(got, 100);
            assert_eq!(expected, 2 * 256 * 32);
        } else {
            panic!("Expected InvalidPublicKeyLength error");
        }
    }

    #[test]
    fn test_error_message_length_mismatch() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, 128, 0)
            .unwrap();

        // Try to sign a message with wrong bit length
        let wrong_message_bits = vec![false; 256]; // 256 bits instead of 128
        let result = lamport.sign_message(&wrong_message_bits, &private_key);

        assert!(result.is_err());
        if let Err(LamportError::MessageLengthMismatch(got, expected)) = result {
            assert_eq!(got, 256);
            assert_eq!(expected, 128);
        } else {
            panic!("Expected MessageLengthMismatch error");
        }
    }

    #[test]
    fn test_error_hash_size_mismatch_in_to_array() {
        // Create a hash with size != 32
        let hash = LamportHash::new(vec![0u8; 20]);
        let result = hash.to_array();

        assert!(result.is_err());
        if let Err(LamportError::InvalidHashSize(got, expected)) = result {
            assert_eq!(got, 20);
            assert_eq!(expected, 32);
        } else {
            panic!("Expected InvalidHashSize error");
        }
    }

    #[test]
    fn test_error_extra_data_missing() {
        let public_key = LamportPublicKey::new(LamportType::SHA256, None);

        let result = public_key.message_bit_length();
        assert!(result.is_err());
        assert!(matches!(result, Err(LamportError::ExtraDataMissing(_))));

        let result = public_key.derivation_index();
        assert!(result.is_none());
    }

    #[test]
    fn test_error_index_overflow() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";

        // Try to use max u32 value, which would overflow when incremented
        let result = lamport.generate_private_key(master_secret, LamportType::SHA256, 8, u32::MAX);

        assert!(result.is_err());
        assert!(matches!(result, Err(LamportError::IndexOverflow)));
    }

    // ========== Serialization Tests ==========

    #[test]
    fn test_private_key_serialization_from_bytes() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 128;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();

        let bytes = private_key.to_bytes();
        let reconstructed =
            LamportPrivateKey::from_bytes(&bytes, message_bit_length, LamportType::SHA256, Some(0))
                .unwrap();

        assert_eq!(private_key.len(), reconstructed.len());
        assert_eq!(private_key.to_bytes(), reconstructed.to_bytes());
        assert_eq!(
            private_key.message_bit_length(),
            reconstructed.message_bit_length()
        );
        assert_eq!(
            private_key.derivation_index(),
            reconstructed.derivation_index()
        );
    }

    #[test]
    fn test_private_key_serialization_from_bytes_splitted() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 64;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::HASH160, message_bit_length, 5)
            .unwrap();

        let (bytes_0s, bytes_1s) = private_key.to_bytes_splitted();
        let reconstructed = LamportPrivateKey::from_bytes_splitted(
            &bytes_0s,
            &bytes_1s,
            message_bit_length,
            LamportType::HASH160,
            Some(5),
        )
        .unwrap();

        assert_eq!(private_key.to_bytes(), reconstructed.to_bytes());
        assert_eq!(
            private_key.derivation_index(),
            reconstructed.derivation_index()
        );
    }

    #[test]
    fn test_public_key_serialization_from_bytes_splitted() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 64;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 7)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        let (bytes_0s, bytes_1s) = public_key.to_bytes_splitted();
        let reconstructed = LamportPublicKey::from_bytes_splitted(
            &bytes_0s,
            &bytes_1s,
            message_bit_length,
            LamportType::SHA256,
            false,
            Some(ExtraData::new(message_bit_length, Some(7))),
        )
        .unwrap();

        assert_eq!(public_key.to_bytes(), reconstructed.to_bytes());
    }

    #[test]
    fn test_signature_serialization() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 128;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();

        let message_bytes = [0x42u8; 16]; // 128 bits
        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();

        let bytes = signature.to_bytes();
        let reconstructed =
            LamportSignature::from_bytes(&bytes, message_bit_length, LamportType::SHA256).unwrap();

        assert_eq!(signature.len(), reconstructed.len());
        assert_eq!(signature.to_bytes(), reconstructed.to_bytes());
        assert_eq!(
            signature.message_bit_length(),
            reconstructed.message_bit_length()
        );
    }

    // ========== Array Conversion Tests ==========

    #[test]
    fn test_to_array_hashes_private_key() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 16;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();

        let result = private_key.to_array_hashes();
        assert!(result.is_ok());

        let (hashes_0s, hashes_1s) = result.unwrap();
        assert_eq!(hashes_0s.len(), message_bit_length);
        assert_eq!(hashes_1s.len(), message_bit_length);
    }

    #[test]
    fn test_to_array_hashes_public_key() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 16;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        let result = public_key.to_array_hashes();
        assert!(result.is_ok());

        let (hashes_0s, hashes_1s) = result.unwrap();
        assert_eq!(hashes_0s.len(), message_bit_length);
        assert_eq!(hashes_1s.len(), message_bit_length);
    }

    #[test]
    fn test_to_array_hashes_signature() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 16;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();

        let message_bytes = [0x42u8; 2]; // 16 bits
        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();

        let result = signature.to_array_hashes();
        assert!(result.is_ok());

        let hashes = result.unwrap();
        assert_eq!(hashes.len(), message_bit_length);
    }

    #[test]
    fn test_to_hashes_methods() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 8;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        // Test private key to_hashes
        let (priv_0s, priv_1s) = private_key.to_hashes();
        assert_eq!(priv_0s.len(), message_bit_length);
        assert_eq!(priv_1s.len(), message_bit_length);

        // Test public key to_hashes
        let (pub_0s, pub_1s) = public_key.to_hashes();
        assert_eq!(pub_0s.len(), message_bit_length);
        assert_eq!(pub_1s.len(), message_bit_length);

        // Test signature to_hashes
        let message_bytes = [0x42u8; 1];
        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();
        let sig_hashes = signature.to_hashes();
        assert_eq!(sig_hashes.len(), message_bit_length);
    }

    #[test]
    fn test_to_hashes_string() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 8;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        let (priv_0s_str, priv_1s_str) = private_key.to_hashes_string();
        assert_eq!(priv_0s_str.len(), message_bit_length);
        assert_eq!(priv_1s_str.len(), message_bit_length);
        // Each should be a hex string (64 chars for SHA256)
        for hash_str in &priv_0s_str {
            assert_eq!(hash_str.len(), 64);
        }

        let (pub_0s_str, pub_1s_str) = public_key.to_hashes_string();
        assert_eq!(pub_0s_str.len(), message_bit_length);
        assert_eq!(pub_1s_str.len(), message_bit_length);
    }

    // ========== ExtraData Tests ==========

    #[test]
    fn test_extra_data_getters() {
        let extra_data = ExtraData::new(256, Some(42));

        assert_eq!(extra_data.message_bit_length(), 256);
        assert_eq!(extra_data.derivation_index(), Some(42));
    }

    #[test]
    fn test_public_key_extra_data() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 128;
        let derivation_index = 99;

        let private_key = lamport
            .generate_private_key(
                master_secret,
                LamportType::SHA256,
                message_bit_length,
                derivation_index,
            )
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        assert!(public_key.extra_data().is_some());
        assert_eq!(public_key.message_bit_length().unwrap(), message_bit_length);
        assert_eq!(public_key.derivation_index().unwrap(), derivation_index);
    }

    // ========== Cross-Hash-Type Validation Tests ==========

    #[test]
    fn test_cross_hash_type_verification_fails() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 128;

        // Sign with SHA256
        let private_key_sha256 = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let message_bytes = [0x42u8; 16];
        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key_sha256)
            .unwrap();

        // Try to verify with a HASH160 public key (different hash type)
        let private_key_hash160 = lamport
            .generate_private_key(master_secret, LamportType::HASH160, message_bit_length, 0)
            .unwrap();
        let public_key_hash160 = private_key_hash160.public_key().unwrap();

        // This should fail because hash types don't match
        let is_valid = lamport
            .verify_signature_bytes(&message_bytes, &signature, &public_key_hash160)
            .unwrap();
        assert!(!is_valid);
    }

    // ========== LamportHash Tests ==========

    #[test]
    fn test_lamport_hash_is_empty() {
        let empty_hash = LamportHash::new(vec![]);
        assert!(empty_hash.is_empty());
        assert_eq!(empty_hash.len(), 0);

        let non_empty_hash = LamportHash::new(vec![1, 2, 3]);
        assert!(!non_empty_hash.is_empty());
        assert_eq!(non_empty_hash.len(), 3);
    }

    #[test]
    fn test_lamport_hash_to_hex() {
        let hash = LamportHash::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(hash.to_hex(), "deadbeef");
    }

    #[test]
    fn test_lamport_hash_to_bytes() {
        let original_bytes = vec![1, 2, 3, 4, 5];
        let hash = LamportHash::new(original_bytes.clone());
        assert_eq!(hash.to_bytes(), original_bytes);
    }

    // ========== Edge Cases ==========

    #[test]
    fn test_empty_message_bits() {
        let (bytes, padding) = bits_to_bytes(&[]).unwrap();
        assert_eq!(bytes.len(), 0);
        assert_eq!(padding, 0);

        let bits = bytes_to_bits(&[], 0);
        assert_eq!(bits.len(), 0);
    }

    #[test]
    fn test_single_byte_edge_cases() {
        // Test all possible single byte values
        for byte_val in [0x00, 0xFF, 0x55, 0xAA, 0x01, 0x80] {
            let bytes = vec![byte_val];
            let bits = bytes_to_bits(&bytes, 0);
            let (reconstructed_bytes, padding) = bits_to_bytes(&bits).unwrap();
            assert_eq!(reconstructed_bytes, bytes);
            assert_eq!(padding, 0);
        }
    }

    #[test]
    fn test_signature_length_getters() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 64;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();

        let message_bytes = [0x42u8; 8];
        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();

        assert_eq!(signature.len(), message_bit_length);
        assert!(!signature.is_empty());
        assert_eq!(signature.message_bit_length(), message_bit_length);
        assert_eq!(signature.hash_type(), LamportType::SHA256);
    }

    #[test]
    fn test_private_key_length_getters() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 32;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::HASH160, message_bit_length, 7)
            .unwrap();

        assert_eq!(private_key.len(), message_bit_length);
        assert!(!private_key.is_empty());
        assert_eq!(private_key.message_bit_length(), message_bit_length);
        assert_eq!(private_key.derivation_index(), Some(7));
        assert_eq!(private_key.hash_type(), LamportType::HASH160);
    }

    #[test]
    fn test_public_key_length_getters() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 32;

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        assert_eq!(public_key.len(), message_bit_length);
        assert!(!public_key.is_empty());
        assert_eq!(public_key.hash_size(), SHA256_SIZE);
    }

    #[test]
    fn test_lamport_type_display() {
        assert_eq!(format!("{}", LamportType::SHA256), "SHA256");
        assert_eq!(format!("{}", LamportType::RIPEMD160), "RIPEMD160");
        assert_eq!(format!("{}", LamportType::HASH160), "HASH160");
        assert_eq!(format!("{}", LamportType::HASH256), "HASH256");
    }

    #[test]
    fn test_lamport_type_parsing_all_variants() {
        // Test case insensitivity
        assert_eq!(
            LamportType::from_str("SHA256").unwrap(),
            LamportType::SHA256
        );
        assert_eq!(
            LamportType::from_str("sha256").unwrap(),
            LamportType::SHA256
        );
        assert_eq!(
            LamportType::from_str("SHa256").unwrap(),
            LamportType::SHA256
        );

        assert_eq!(
            LamportType::from_str("HASH160").unwrap(),
            LamportType::HASH160
        );
        assert_eq!(
            LamportType::from_str("hash160").unwrap(),
            LamportType::HASH160
        );

        // Test invalid types
        assert!(LamportType::from_str("RIPEMD160").is_err());
        assert!(LamportType::from_str("HASH256").is_err());
        assert!(LamportType::from_str("MD5").is_err());
        assert!(LamportType::from_str("").is_err());
    }

    #[test]
    fn test_derive_multiple_keys_same_master_secret() {
        let lamport = Lamport::new();
        let master_secret = b"shared_master_secret";
        let message_bit_length = 64;

        // Generate multiple keys with different indices
        let mut keys = Vec::new();
        for i in 0..5 {
            let key = lamport
                .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, i)
                .unwrap();
            keys.push(key);
        }

        // Verify all keys are different
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].to_bytes(), keys[j].to_bytes());
            }
        }
    }

    #[test]
    fn test_deterministic_key_generation() {
        let lamport = Lamport::new();
        let master_secret = b"deterministic_secret";
        let message_bit_length = 128;
        let derivation_index = 42;

        // Generate the same key twice
        let key1 = lamport
            .generate_private_key(
                master_secret,
                LamportType::SHA256,
                message_bit_length,
                derivation_index,
            )
            .unwrap();
        let key2 = lamport
            .generate_private_key(
                master_secret,
                LamportType::SHA256,
                message_bit_length,
                derivation_index,
            )
            .unwrap();

        // They should be identical
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        let pub1 = key1.public_key().unwrap();
        let pub2 = key2.public_key().unwrap();
        assert_eq!(pub1.to_bytes(), pub2.to_bytes());
    }

    #[test]
    fn test_max_safe_derivation_index() {
        let lamport = Lamport::new();
        let master_secret = b"test_secret";

        // u32::MAX should fail
        let result = lamport.generate_private_key(master_secret, LamportType::SHA256, 8, u32::MAX);
        assert!(result.is_err());

        // u32::MAX - 1 should succeed
        let result =
            lamport.generate_private_key(master_secret, LamportType::SHA256, 8, u32::MAX - 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_message_bit_length() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";
        let message_bit_length = 1024; // Large message

        let private_key = lamport
            .generate_private_key(master_secret, LamportType::SHA256, message_bit_length, 0)
            .unwrap();
        let public_key = private_key.public_key().unwrap();

        assert_eq!(private_key.len(), message_bit_length);
        assert_eq!(public_key.len(), message_bit_length);

        // Sign and verify a large message
        let message_bytes = vec![0x42u8; 128]; // 1024 bits
        let signature = lamport
            .sign_message_bytes(&message_bytes, &private_key)
            .unwrap();
        assert!(lamport
            .verify_signature_bytes(&message_bytes, &signature, &public_key)
            .unwrap());
    }

    // ========== DoS Protection Tests ==========

    #[test]
    fn test_dos_protection_exceeds_max_message_bit_length() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";

        // Try to generate with message_bit_length exceeding MAX_MESSAGE_BIT_LENGTH
        let result = lamport.generate_private_key(
            master_secret,
            LamportType::SHA256,
            MAX_MESSAGE_BIT_LENGTH + 1,
            0,
        );

        assert!(result.is_err());
        match result {
            Err(LamportError::MessageBitLengthExceedsMax(actual, max)) => {
                assert_eq!(actual, MAX_MESSAGE_BIT_LENGTH + 1);
                assert_eq!(max, MAX_MESSAGE_BIT_LENGTH);
            }
            _ => panic!("Expected MessageBitLengthExceedsMax error"),
        }
    }

    #[test]
    fn test_dos_protection_at_max_message_bit_length() {
        let lamport = Lamport::new();
        let master_secret = b"test_master_secret";

        // Exactly at MAX_MESSAGE_BIT_LENGTH should succeed (might be slow, but validates the limit)
        let result = lamport.generate_private_key(
            master_secret,
            LamportType::SHA256,
            MAX_MESSAGE_BIT_LENGTH,
            0,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_dos_protection_public_key_from_bytes() {
        // Try to deserialize with excessive message_bit_length
        let result = LamportPublicKey::from_bytes(
            &[0u8; 100],
            MAX_MESSAGE_BIT_LENGTH + 1,
            LamportType::SHA256,
            false,
            None,
        );

        assert!(result.is_err());
        match result {
            Err(LamportError::MessageBitLengthExceedsMax(actual, max)) => {
                assert_eq!(actual, MAX_MESSAGE_BIT_LENGTH + 1);
                assert_eq!(max, MAX_MESSAGE_BIT_LENGTH);
            }
            _ => panic!("Expected MessageBitLengthExceedsMax error"),
        }
    }

    #[test]
    fn test_dos_protection_public_key_from_bytes_excessive_bytes() {
        // Create a huge byte array that exceeds MAX_KEY_SIGNATURE_BYTE_LENGTH
        // We don't actually allocate it, just pass the length check
        let large_vec = vec![0u8; 1000]; // Small allocation for the test

        // Try with a message_bit_length that would require more bytes than MAX
        let result =
            LamportPublicKey::from_bytes(&large_vec, MAX_MESSAGE_BIT_LENGTH, LamportType::SHA256, false, None);

        // Should fail because bytes length (1000) doesn't match expected (MAX_MESSAGE_BIT_LENGTH * 32 * 2)
        // but more importantly, it validates limits before trying to process
        assert!(result.is_err());
    }

    #[test]
    fn test_dos_protection_private_key_from_bytes() {
        // Try to deserialize with excessive message_bit_length
        let result = LamportPrivateKey::from_bytes(
            &[0u8; 100],
            MAX_MESSAGE_BIT_LENGTH + 1,
            LamportType::SHA256,
            Some(0),
        );

        assert!(result.is_err());
        match result {
            Err(LamportError::MessageBitLengthExceedsMax(actual, max)) => {
                assert_eq!(actual, MAX_MESSAGE_BIT_LENGTH + 1);
                assert_eq!(max, MAX_MESSAGE_BIT_LENGTH);
            }
            _ => panic!("Expected MessageBitLengthExceedsMax error"),
        }
    }

    #[test]
    fn test_dos_protection_signature_from_bytes() {
        // Try to deserialize with excessive message_bit_length
        let result = LamportSignature::from_bytes(
            &[0u8; 100],
            MAX_MESSAGE_BIT_LENGTH + 1,
            LamportType::SHA256,
        );

        assert!(result.is_err());
        match result {
            Err(LamportError::MessageBitLengthExceedsMax(actual, max)) => {
                assert_eq!(actual, MAX_MESSAGE_BIT_LENGTH + 1);
                assert_eq!(max, MAX_MESSAGE_BIT_LENGTH);
            }
            _ => panic!("Expected MessageBitLengthExceedsMax error"),
        }
    }

    #[test]
    fn test_dos_protection_from_bytes_splitted() {
        // Test both public and private key from_bytes_splitted methods
        let bytes_0s = vec![0u8; 100];
        let bytes_1s = vec![0u8; 100];

        // Test public key
        let result = LamportPublicKey::from_bytes_splitted(
            &bytes_0s,
            &bytes_1s,
            MAX_MESSAGE_BIT_LENGTH + 1,
            LamportType::SHA256,
            false,
            None,
        );
        assert!(result.is_err());

        // Test private key
        let result = LamportPrivateKey::from_bytes_splitted(
            &bytes_0s,
            &bytes_1s,
            MAX_MESSAGE_BIT_LENGTH + 1,
            LamportType::SHA256,
            Some(0),
        );
        assert!(result.is_err());
    }
}
