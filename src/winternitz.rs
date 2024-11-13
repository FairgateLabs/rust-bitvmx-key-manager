use core::fmt;
use std::{str::FromStr, vec};

use bitcoin::hashes::{ripemd160, sha256, Hash, HashEngine, Hmac, HmacEngine};
use serde::{Deserialize, Serialize};

use crate::errors::WinternitzError;

pub const NBITS: usize = 4; // Nibbles
pub const W: usize = 2usize.pow(NBITS as u32) -1; // Winternitz parameter (times to hash)
pub const SHA256_SIZE: usize = 32;
pub const RIPEMD160_SIZE: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum WinternitzType {
    SHA256,
    HASH160,
}

pub trait HashFunction {
    fn hash(&self, data: &WinternitzHash) -> WinternitzHash;
    fn hash_size(&self) -> usize;
}

impl HashFunction for WinternitzType {
    fn hash(&self, data: &WinternitzHash) -> WinternitzHash {
        let hash = match self {
            WinternitzType::SHA256 => WinternitzHash::new(sha256::Hash::hash(&data.to_bytes()).as_byte_array().to_vec()),
            WinternitzType::HASH160 => {
                let sha256 = sha256::Hash::hash(&data.to_bytes());
                let hash160 = ripemd160::Hash::hash(sha256.as_byte_array());
                WinternitzHash::new(hash160.as_byte_array().to_vec())
            }
        };

        hash
    }

    fn hash_size(&self) -> usize {
        match self {
            WinternitzType::SHA256 => SHA256_SIZE,
            WinternitzType::HASH160 => RIPEMD160_SIZE,
        }
    }
}

impl fmt::Display for WinternitzType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl FromStr for WinternitzType {
    type Err = WinternitzError;

    fn from_str(input: &str) -> Result<WinternitzType, Self::Err> {
        match input.to_uppercase().as_str() {
            "SHA256"  => Ok(WinternitzType::SHA256),
            "HASH160" => Ok(WinternitzType::HASH160),
            _         => Err(WinternitzError::InvalidWinternitzType(input.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinternitzHash {
    hash: Vec<u8>,
}

impl WinternitzHash {
    fn new(hash: Vec<u8>) -> Self {
        WinternitzHash {
            hash,
        }
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

    pub fn to_hex(&self) -> String {
        hex::encode(&self.hash)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinternitzSignature {
    hashes: Vec<WinternitzHash>,
    digits: Vec<u8>,
    message_length: usize,
}

impl WinternitzSignature {
    pub fn new(message_length: usize) -> Self {
        WinternitzSignature {
            hashes: vec![],
            digits: vec![],
            message_length,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for hash in self.hashes.iter() {
            bytes.extend_from_slice(&hash.hash);
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8], message_digits: usize, hash_type: WinternitzType) -> Result<Self, WinternitzError> {   
        let hash_size = hash_type.hash_size();

        if bytes.len() % hash_size != 0 {
            return Err(WinternitzError::InvalidSignatureLength(bytes.len(), hash_type.to_string()));
        }

        let mut signature = WinternitzSignature::new(message_digits);

        for i in 0..bytes.len() / hash_size {
            let start = i * hash_size;
            let end = start + hash_size;
            let hash = WinternitzHash::new(bytes[start..end].to_vec());
            signature.push_hash(hash);
        }

        Ok(signature)
    }

    pub fn from_hashes_and_digits(hashes: &[u8], checksummed_digits: &[u8], message_length: usize, hash_type: WinternitzType) -> Result<Self, WinternitzError> {   
        let hash_size = hash_type.hash_size();

        if hashes.len() % hash_size != 0 {
            return Err(WinternitzError::InvalidSignatureLength(hashes.len(), hash_type.to_string()));
        }

        let mut signature = WinternitzSignature::new(message_length);

        for i in 0..hashes.len() / hash_size {
            let start = i * hash_size;
            let end = start + hash_size;
            let hash = WinternitzHash::new(hashes[start..end].to_vec());
            signature.push_hash(hash);
        }

        for digit in checksummed_digits.iter() {
            signature.push_digit(*digit);
        }

        Ok(signature)
    }

    pub fn to_hashes(&self) -> Vec<Vec<u8>> {
        let mut hashes = vec![];

        for hash in self.hashes.iter() {
            hashes.push(hash.to_bytes());
        }

        hashes
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn checksummed_message_digits(&self) -> Vec<u8> {
        self.digits.clone()
    }

    pub fn message_length(&self) -> usize {
        self.message_length
    }

    pub fn checksum_length(&self) -> usize {
        self.digits.len() - self.message_length
    }

    pub fn message_digits(&self) -> Vec<u8> {
        let mut copy = self.digits.clone();
        copy.reverse();
        copy[self.message_length -1..].to_vec()
    }

    pub fn message_bytes(&self) -> Vec<u8> {
        from_message_digits(&self.message_digits())
    }

    fn push_hash(&mut self, hash: WinternitzHash) {
        self.hashes.push(hash);
    }

    fn hash_at(&self, index: usize) -> WinternitzHash {
        self.hashes[index].clone()
    }

    fn push_digit(&mut self, digit: u8) {
        self.digits.push(digit);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraData {
    message_size: usize,
    checksum_size: usize,
    derivation_index: u32,
}

impl ExtraData {
    fn new(message_size: usize, checksum_size: usize, derivation_index: u32) -> Self {
        ExtraData {
            message_size,
            checksum_size,
            derivation_index,
        }
    }

    pub fn message_size(&self) -> usize {
        self.message_size
    }

    pub fn checksum_size(&self) -> usize {
        self.checksum_size
    }

    pub fn derivation_index(&self) -> u32 {
        self.derivation_index
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinternitzPublicKey {
    hashes: Vec<WinternitzHash>,
    hash_type: WinternitzType,
    extra_data: Option<ExtraData>,
}

impl WinternitzPublicKey {
    pub fn from(private_key: WinternitzPrivateKey) -> Result<Self, WinternitzError> {
        private_key.public_key()
    }

    fn new(hash_type: WinternitzType, extra_data: Option<ExtraData>) -> Self {
        WinternitzPublicKey {
            hashes: Vec::new(),
            hash_type,
            extra_data,
        }
    }

    fn push_hash(&mut self, hash: WinternitzHash) -> Result<(), WinternitzError> {
        if hash.len() != self.hash_type.hash_size() {
            return Err(WinternitzError::HashSizeMissmatch(hash.len(), self.hash_type.to_string()));
        }

        self.hashes.push(hash);

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for hash in self.hashes.iter() {
            bytes.extend_from_slice(&hash.hash);
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8], hash_type: WinternitzType) -> Result<Self, WinternitzError> {   
        let hash_size = hash_type.hash_size();

        if bytes.len() % hash_size != 0 {
            return Err(WinternitzError::InvalidPublicKeyLength(bytes.len(), hash_type.to_string()));
        }

        let mut public_key = WinternitzPublicKey::new(hash_type, None);

        for i in 0..bytes.len() / hash_size {
            let start = i * hash_size;
            let end = start + hash_size;
            let hash = WinternitzHash::new(bytes[start..end].to_vec());
            public_key.push_hash(hash)?;
        }

        Ok(public_key)
    }

    pub fn to_hashes(&self) -> Vec<Vec<u8>> {
        let mut hashes = vec![];

        for hash in self.hashes.iter() {
            hashes.push(hash.to_bytes());
        }

        hashes
    }

    pub fn total_len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn hash_size(&self) -> usize {
        self.hash_type.hash_size()
    }

    pub fn key_type(&self) -> WinternitzType {
        self.hash_type
    }

    pub fn extra_data(&self) -> Option<ExtraData> {
        self.extra_data.clone()
    }

    pub fn message_size(&self) -> Result<usize, WinternitzError> {
        let message_size = self.extra_data.as_ref().ok_or(
            WinternitzError::ExtraDataMissing("message_size".to_string())
        )?.message_size;

        Ok(message_size)
    }

    pub fn checksum_size(&self) -> Result<usize, WinternitzError> {
        let checksum_size = self.extra_data.as_ref().ok_or(
            WinternitzError::ExtraDataMissing("checksum_size".to_string())
        )?.checksum_size;
        
        Ok(checksum_size)
    }

    pub fn derivation_index(&self) -> Result<u32, WinternitzError> {
        let derivation_index = self.extra_data.as_ref().ok_or(
            WinternitzError::ExtraDataMissing("derivation_index".to_string())
        )?.derivation_index;
        
        Ok(derivation_index)
    }

    pub fn base(&self) -> usize {
        W
    }
    
    pub fn bits_per_digit(&self) -> u32 {
        NBITS as u32
    }
}

pub struct WinternitzPrivateKey {
    hashes: Vec<WinternitzHash>,
    hash_type: WinternitzType,
    message_size: usize,
    checksum_size: usize,
    derivation_index: u32,
}

impl WinternitzPrivateKey {
    pub fn new(hash_type: WinternitzType, derivation_index: u32, message_size: usize, checksum_size: usize) -> Self {
        WinternitzPrivateKey {
            hashes: Vec::new(),
            hash_type,
            message_size,
            checksum_size,
            derivation_index,
        }
    }

    pub fn public_key(&self) -> Result<WinternitzPublicKey, WinternitzError> {
        let mut public_key = WinternitzPublicKey::new(
            self.hash_type, 
            Some(ExtraData::new(self.message_size, self.checksum_size, self.derivation_index)
        ));

        for h in self.hashes.iter() {
            let mut hashed_pk = h.clone(); // Start with sks as hashed_pk
            
            for _ in 0..W {
                hashed_pk = self.hash_type.hash(&hashed_pk);
            }
           
            public_key.push_hash(hashed_pk)?;
        }  

        Ok(public_key)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for hash in self.hashes.iter() {
            bytes.extend_from_slice(&hash.hash);
        }
        bytes
    }

    pub fn to_hashes(&self) -> Vec<Vec<u8>> {
        let mut hashes = vec![];

        for hash in self.hashes.iter() {
            hashes.push(hash.to_bytes());
        }

        hashes
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn hash_size(&self) -> usize {
        self.hash_type.hash_size()
    }

    pub fn key_type(&self) -> WinternitzType {
        self.hash_type
    }

    pub fn derivation_index(&self) -> u32 {
        self.derivation_index
    }

    fn push_hash(&mut self, hash: WinternitzHash) -> Result<(), WinternitzError> {
        if hash.len() != self.hash_type.hash_size() {
            return Err(WinternitzError::HashSizeMissmatch(hash.len(), self.hash_type.to_string()));
        }

        self.hashes.push(hash);

        Ok(())
    }

    fn hash_at(&self, index: usize) -> WinternitzHash {
        self.hashes[index].clone()
    }
}

pub struct Winternitz {
}

impl Default for Winternitz {
    fn default() -> Self {
        Winternitz::new()
    }
}

impl Winternitz {
    pub fn new() -> Self {
        Winternitz {
        }
    }

    pub fn generate_public_key(&self, master_secret: &[u8], key_type: WinternitzType, message_size: usize, checksum_size: usize, derivation_index: u32) -> Result<WinternitzPublicKey, WinternitzError> {        
        let private_key = self.generate_private_key(master_secret, key_type, message_size, checksum_size, derivation_index)?;
        let public_key = WinternitzPublicKey::from(private_key)?;

        Ok(public_key)
    }

    pub fn generate_private_key(&self, master_secret: &[u8], key_type: WinternitzType, message_size: usize, checksum_size: usize, derivation_index: u32) -> Result<WinternitzPrivateKey, WinternitzError> {
        let private_key = self.generate_hashes(master_secret, key_type, message_size, checksum_size, derivation_index)?;
        
        Ok(private_key)
    }

    pub fn sign_message(&self, message_digits: usize, checksummed_message: &[u8], private_key: &WinternitzPrivateKey) -> WinternitzSignature {
        let mut signature = WinternitzSignature::new(message_digits);
        let key_type = private_key.key_type();
        
        for (i, digit) in checksummed_message.iter().enumerate() {
            let mut hashed_val = private_key.hash_at(i);
            for _ in 0..(W - (*digit as usize)) {
                hashed_val = key_type.hash(&hashed_val);
            }

            signature.push_hash(hashed_val);
            signature.push_digit(*digit);
        }   

        signature
    }

    pub fn verify_signature(&self, checksummed_message: &[u8], signature: &WinternitzSignature, public_key: &WinternitzPublicKey) -> Result<bool, WinternitzError> {
        let mut generated_public_key: WinternitzPublicKey = WinternitzPublicKey::new(
            public_key.key_type(),
            public_key.extra_data(),
        );

        let key_type = public_key.key_type();
        
        for (i, digit) in checksummed_message.iter().enumerate() {
            let mut hashed_val = signature.hash_at(i);
            for _ in 0..(*digit as usize) {
                hashed_val = key_type.hash(&hashed_val);
            }

            generated_public_key.push_hash(hashed_val)?;
        }

        Ok(generated_public_key == *public_key)
    }

    fn generate_hashes(&self, master_secret: &[u8], key_type: WinternitzType, message_size: usize, checksum_size: usize, derivation_index: u32)-> Result<WinternitzPrivateKey, WinternitzError>{
        derivation_index.checked_add(1).ok_or(WinternitzError::IndexOverflow)?;

        let mut private_key = WinternitzPrivateKey::new(key_type, derivation_index, message_size, checksum_size);

        for i in 0..message_size + checksum_size {
            let privk = self.generate_hash(master_secret, key_type.hash_size(), derivation_index, i as u32);
            private_key.push_hash(privk)?;
        }

        Ok(private_key)
    }

    fn generate_hash(&self, master_secret: &[u8], key_size: usize, index: u32, internal_index: u32)-> WinternitzHash {
        let mut engine = HmacEngine::<sha256::Hash>::new(master_secret);
        let input = [index.to_le_bytes(), internal_index.to_le_bytes()].concat();   
        engine.input(&input);

        let hash = Hmac::<sha256::Hash>::from_engine(engine);
        WinternitzHash::new(hash[..key_size].to_vec())
    }
}

pub fn to_checksummed_message(message_bytes: &[u8]) -> Vec<u8> {
    let mut message_digits = to_message_digits(message_bytes); 
    let mut checksummed = calculate_checksum(&message_digits);
    
    checksummed.append(&mut message_digits);
    checksummed.reverse();
    checksummed
}

pub fn calculate_checksum(message_digits: &[u8]) -> Vec<u8> {
    let mut sum: u32 = 0;
    for digit in message_digits {
        sum += *digit as u32;
    }

    let checksum = (W * message_digits.len() - sum as usize) as u32;
    let checksum_size = checksum_length(message_digits.len());
    to_digits(checksum, checksum_size)
}

pub fn checksum_length(message_digits_len: usize) -> usize {
    let log_digits_per_message:f32 = ((W * message_digits_len) as f32).log((W + 1) as f32).ceil() + 1.0;
    let digits_per_checksum: usize = usize::try_from(log_digits_per_message as u32).unwrap();
    digits_per_checksum
}

pub fn message_digits_length(message_size_in_bytes: usize) -> usize {
    message_size_in_bytes * 8 / NBITS
}

fn split_byte(byte: u8) -> (u8, u8) {
    let high_nibble: u8 = (byte & 0xF0) >> 4;
    let low_nibble: u8 = byte & 0x0F;
    (high_nibble, low_nibble)
}

fn to_message_digits(message_bytes: &[u8]) -> Vec<u8> {
    let mut message_digits = Vec::new();

    for byte in message_bytes.iter() {
        let (high_nibble, low_nibble) = split_byte(*byte);
        message_digits.push(high_nibble);
        message_digits.push(low_nibble);
    }

    message_digits
}

fn from_message_digits(message_digits: &[u8]) -> Vec<u8> {
    let mut message_bytes = Vec::new();

    for chunk in message_digits.chunks(2) {
        if let [high_nibble, low_nibble] = *chunk {
            // Combine the high and low nibbles into a single byte
            let byte = (high_nibble << 4) | low_nibble;
            message_bytes.push(byte);
        }
    }

    message_bytes
}

// Converts a number to an array of digits of size number_of_digits.
// If the number is smaller than the number of digits, the remaining digits are filled with 0.
fn to_digits(mut number: u32, number_of_digits: usize) -> Vec<u8> {
    let mut digits = Vec::with_capacity(number_of_digits);

    for _ in 0..number_of_digits {
        let digit = number % (W + 1) as u32;
        number /= (W + 1) as u32;
        digits.push(digit as u8);
    }

    digits.resize(number_of_digits, 0);
    digits
}
