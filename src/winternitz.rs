use core::fmt;
use std::vec;

use bitcoin::hashes::{ripemd160, sha256, Hash, HashEngine, Hmac, HmacEngine};

use crate::errors::WinternitzError;

pub const NBITS: usize = 4; // Nibbles
pub const W: usize = 2usize.pow(NBITS as u32); // Winternitz parameter (times to hash)
pub const SHA256_SIZE: usize = 32;
pub const RIPEMD160_SIZE: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WinternitzType {
    SHA256,
    RIPEMD160,
}

pub trait HashFunction {
    fn hash(&self, data: &WinternitzHash) -> WinternitzHash;
    fn hash_size(&self) -> usize;
}

impl HashFunction for WinternitzType {
    fn hash(&self, data: &WinternitzHash) -> WinternitzHash {
        let hash = match self {
            WinternitzType::SHA256 => WinternitzHash::new(sha256::Hash::hash(&data.to_bytes()).as_byte_array().to_vec()),
            WinternitzType::RIPEMD160 => WinternitzHash::new(ripemd160::Hash::hash(&data.to_bytes()).as_byte_array().to_vec())
        };

        hash
    }

    fn hash_size(&self) -> usize {
        match self {
            WinternitzType::SHA256 => SHA256_SIZE,
            WinternitzType::RIPEMD160 => RIPEMD160_SIZE,
        }
    }
}

impl fmt::Display for WinternitzType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
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
}

#[derive(Clone)]
pub struct WinternitzSignature {
    hashes: Vec<WinternitzHash>,
}

impl Default for WinternitzSignature {
    fn default() -> Self {
        WinternitzSignature::new()
    }
}

impl WinternitzSignature {
    pub fn new() -> Self {
        WinternitzSignature {
            hashes: Vec::new(),
        }
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

        if bytes.len() % hash_size == 0 {
            return Err(WinternitzError::InvalidSignatureLength(bytes.len(), hash_type.to_string()));
        }

        let mut signature = WinternitzSignature::new();

        for i in 0..bytes.len() / hash_size {
            let start = i * hash_size;
            let end = start + hash_size;
            let hash = WinternitzHash::new(bytes[start..end].to_vec());
            signature.push_hash(hash);
        }

        Ok(signature)
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    fn push_hash(&mut self, hash: WinternitzHash) {
        self.hashes.push(hash);
    }

    fn hash_at(&self, index: usize) -> WinternitzHash {
        self.hashes[index].clone()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinternitzPublicKey {
    hashes: Vec<WinternitzHash>,
    hash_type: WinternitzType,
    message_size: usize,
    checksum_size: usize,
}

impl WinternitzPublicKey {
    pub fn from(private_key: WinternitzPrivateKey) -> Result<Self, WinternitzError> {
        private_key.public_key()
    }

    fn new(hash_type: WinternitzType, message_size: usize, checksum_size: usize) -> Self {
        WinternitzPublicKey {
            hashes: Vec::new(),
            hash_type,
            message_size,
            checksum_size,
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

    pub fn message_size(&self) -> usize {
        self.message_size
    }

    pub fn checksum_size(&self) -> usize {
        self.checksum_size
    }
}

pub struct WinternitzPrivateKey {
    hashes: Vec<WinternitzHash>,
    hash_type: WinternitzType,
    message_size: usize,
    checksum_size: usize,
}

impl WinternitzPrivateKey {
    pub fn new(hash_type: WinternitzType, message_size: usize, checksum_size: usize) -> Self {
        WinternitzPrivateKey {
            hashes: Vec::new(),
            hash_type,
            message_size,
            checksum_size,
        }
    }

    pub fn public_key(&self) -> Result<WinternitzPublicKey, WinternitzError> {
        let mut public_key = WinternitzPublicKey::new(self.hash_type, self.message_size, self.checksum_size);

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

    pub fn generate_public_key(&self, master_secret: &[u8], key_type: WinternitzType, message_size: usize, index: u32) -> Result<WinternitzPublicKey, WinternitzError> {
        let private_key = self.generate_private_key(master_secret, key_type, message_size, index)?;
        
        WinternitzPublicKey::from(private_key)
    }

    pub fn generate_private_key(&self, master_secret: &[u8], key_type: WinternitzType, message_size: usize, index: u32) -> Result<WinternitzPrivateKey, WinternitzError> {
        let checksum_size = calculate_checksum_length(message_size, W);
        let private_key = self.generate_hashes(master_secret, key_type, message_size, checksum_size, index)?;
        
        Ok(private_key)
    }

    pub fn sign_message(&self, msg_with_checksum_pad: &[u8], private_key: &WinternitzPrivateKey) -> WinternitzSignature {
        let mut signature = WinternitzSignature::new();
        let key_type = private_key.key_type();
        
        for (i, byte) in msg_with_checksum_pad.iter().enumerate() {
            let (high_nibble, low_nibble) = split_byte(*byte);

            let mut hashed_val = private_key.hash_at(2 * i);
            for _ in 0..(W - (high_nibble as usize)) {
                hashed_val = key_type.hash(&hashed_val);
            }

            signature.push_hash(hashed_val);

            let mut hashed_val = private_key.hash_at(2 * i + 1);
            for _ in 0..(W - (low_nibble as usize)) {
                hashed_val = key_type.hash(&hashed_val);
            }
        
            signature.push_hash(hashed_val);
        }   

        signature
    }

    pub fn verify_signature(&self, msg_with_checksum_pad: &[u8], signature: &WinternitzSignature, public_key: &WinternitzPublicKey) -> Result<bool, WinternitzError> {
        let mut generated_public_key: WinternitzPublicKey = WinternitzPublicKey::new(public_key.key_type(), public_key.message_size(), public_key.checksum_size());

        let key_type = public_key.key_type();
        
        for (i, byte) in msg_with_checksum_pad.iter().enumerate() {
            let (high_nibble, low_nibble) = split_byte(*byte);

            let mut hashed_val = signature.hash_at(2 * i);
            for _ in 0..(high_nibble as usize) {
                hashed_val = key_type.hash(&hashed_val);
            }

            generated_public_key.push_hash(hashed_val)?;

            let mut hashed_val = signature.hash_at(2 * i + 1);
            for _ in 0..(low_nibble as usize) {
                hashed_val = key_type.hash(&hashed_val);
            }

            generated_public_key.push_hash(hashed_val)?;
        }

        Ok(generated_public_key == *public_key)
    }

    fn generate_hashes(&self, master_secret: &[u8], key_type: WinternitzType, message_size: usize, checksum_size: usize, index: u32)-> Result<WinternitzPrivateKey, WinternitzError>{
        index.checked_add(1).ok_or(WinternitzError::IndexOverflow)?;

        let num_hashes = 2 * (message_size + checksum_size);

        let mut private_key = WinternitzPrivateKey::new(key_type, message_size, checksum_size);

        for i in 0..num_hashes {
            let privk = self.generate_hash(master_secret, key_type.hash_size(), index, i as u32);
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

pub fn calculate_checksum_length(message_size: usize, w: usize) -> usize {
    let l1 = 2 * message_size;
    let l2 = ((l1 * (w-1)) as f64).log2() / 4.0; //log16(x) = log2(x) / 4
    (l2 / 2.0).ceil() as usize //checksum length in bytes
}

pub fn split_byte(byte: u8) -> (u8, u8) {
    let high_nibble: u8 = (byte & 0xF0) >> 4;
    let low_nibble: u8 = byte & 0x0F;
    (high_nibble, low_nibble)
}
