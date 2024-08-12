use std::str::FromStr;

use bitcoin::{bip32::{ChildNumber, DerivationPath, Xpriv}, hashes::{Hash, HashEngine, Hmac, HmacEngine}, key::{rand::Rng, Keypair, TapTweak, TweakedKeypair}, secp256k1::{self, hashes::{ripemd160, sha256}, All, Message, SecretKey}, Network, PrivateKey, PublicKey};
use itertools::izip;
use secure_storage::SecureStorage;

mod helper;
use crate::helper::{KeyManagerError, add_checksum, calculate_checksum_length, split_byte};

pub mod secure_storage;

// For winternitz
const NBITS: usize = 4; // Nibbles
const W: usize = 2usize.pow(NBITS as u32); // Winternitz parameter (times to hash)
const SHA256_SIZE: usize = 32;
const RIPEMD160_SIZE: usize = 20;

/// This module provides a key manager for managing BitVMX keys and signatures.
/// It includes functionality for generating, importing, and deriving keys, as well as signing messages 
/// using ECDSA, Schnorr and Winternitz algorithms. The key manager uses a secure storage mechanism 
/// to store the keys.
pub struct KeyManager {
    secp: secp256k1::Secp256k1<All>,
    network: Network,
    master_xpriv: Xpriv, 
    next_normal: ChildNumber,
    key_derivation_path: String,
    storage: SecureStorage,
}

pub struct SignatureVerifier {
    secp: secp256k1::Secp256k1<All>,
}

#[derive(Clone)]
pub enum WinternitzType {
    WSHA256,
    WRIPEMD160,
}

impl KeyManager {
    // If master secret is provided, first one correspond to ecdsa_schnorr_generator and second one to winternitz_generator
    pub fn new<R: Rng + ?Sized>(network: Network, key_derivation_path: &str, storage_path: &str, password: Vec<u8>, seed:&[u8], winternitz_secret: Option<[u8; 32]>, rng: &mut R) -> Result<Self, KeyManagerError> {
        let secp = secp256k1::Secp256k1::new();
        
         let secret = match winternitz_secret {
            Some(secret) => secret,
            _ => {
                let mut secret= [0u8; 32];
                rng.fill_bytes(&mut secret);
                secret
            }
        };

        let storage = SecureStorage::new(storage_path, password, network)?;        
        storage.store_winternitz_secret(secret)?;

        let master_xpriv = Xpriv::new_master(network, seed)?;

        Ok(KeyManager { 
            secp,
            network,
            master_xpriv,
            next_normal: ChildNumber::Normal { index: 0 },
            key_derivation_path: key_derivation_path.to_string(),
            storage,
        })
    }

    pub fn import_private_key(&mut self, label: &str, private_key: &str)-> Result<(), KeyManagerError> {
        let private_key = PrivateKey::from_str(private_key)?;
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        self.storage.store_keypair(label, private_key, public_key)?;

        Ok(())
    }

    /*********************************/
    /******* Key Generation **********/
    /*********************************/
    pub fn generate_key<R: Rng + ?Sized>(&mut self, label: Option<String>, rng: &mut R) -> Result<PublicKey, KeyManagerError> {
        let private_key = self.generate_private_key(self.network, rng);
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);
        let label = label.unwrap_or_else(|| public_key.to_string());      
        
        self.storage.store_keypair(&label, private_key, public_key)?;

        Ok(public_key)
    }

    pub fn derive_bip32(& mut self, label: Option<String>) -> Result<PublicKey, KeyManagerError> {
        let derivation_path = DerivationPath::from_str(&format!("{}{}", self.key_derivation_path, self.next_normal))?;
        let xpriv = self.master_xpriv.derive_priv(&self.secp, &derivation_path)?;

        let internal_keypair = xpriv.to_keypair(&self.secp);
        let public_key = PublicKey::new(internal_keypair.public_key());
        let private_key = PrivateKey::new(internal_keypair.secret_key(), self.network);
        let label = label.unwrap_or_else(|| public_key.to_string());
        
        self.storage.store_keypair(&label, private_key, public_key)?;

        self.next_normal = self.next_normal.increment()?;

        Ok(public_key)
    }

    pub fn generate_winternitz_key(&mut self, msg_len_bytes: usize, key_type: WinternitzType, index: u32) -> Result<Vec<Vec<u8>>, KeyManagerError> {
        let checksum_len_bytes = calculate_checksum_length(msg_len_bytes, W);
        let private_keys = self.generate_winternitz_private_key(msg_len_bytes + checksum_len_bytes, key_type.clone(), index)?;
        let mut public_keys = Vec::new();
        for sks in private_keys.iter() {
            let mut hashed_pk = sks.clone(); // Start with sks as hashed_pk
            for _ in 0..W {
                hashed_pk = match key_type {
                    WinternitzType::WSHA256 => sha256::Hash::hash(&hashed_pk).as_byte_array().to_vec(),
                    WinternitzType::WRIPEMD160 => ripemd160::Hash::hash(&hashed_pk).as_byte_array().to_vec(),                  
                }
            }
            public_keys.push(hashed_pk);
        }  
       
        Ok(public_keys)
    }
        
    fn generate_private_key<R: Rng + ?Sized>(&self, network: Network, rng: &mut R) -> PrivateKey {
        let secret_key = SecretKey::new(rng);
        PrivateKey::new(secret_key, network)
    }

    fn generate_winternitz_private_key(& mut self, msg_len_bytes: usize, key_type: WinternitzType, index: u32) -> Result<Vec<Vec<u8>>, KeyManagerError> {
        let msg_len = 2 * msg_len_bytes;
        let key_size = match key_type {
            WinternitzType::WSHA256 => SHA256_SIZE,
            WinternitzType::WRIPEMD160 => RIPEMD160_SIZE,
        };

        let private_key = self.get_multiple_child_keys(key_size, msg_len, index)?;

        Ok(private_key)
    }

    fn get_child_key(&self, key_size: usize, index: u32, internal_index: u32, master_secret: &[u8])-> Vec<u8> {
        let mut engine = HmacEngine::<sha256::Hash>::new(master_secret);
        let input = [index.to_le_bytes(), internal_index.to_le_bytes()].concat();   
        engine.input(&input);

        let hash = Hmac::<sha256::Hash>::from_engine(engine);

        hash[..key_size].to_vec()
    }

    fn get_multiple_child_keys(&self, key_size: usize, num_keys: usize, index: u32)-> Result<Vec<Vec<u8>>, KeyManagerError>{

        index.checked_add(1).ok_or(KeyManagerError::IndexOverflow)?;
        let master_secret = self.storage.load_winternitz_secret().unwrap();

        let mut keys = Vec::new();
        for i in 0..num_keys {
            let privk = self.get_child_key(key_size, index, i as u32, &master_secret);
            keys.push(privk);
        }
        Ok(keys)
    }

    /*********************************/
    /*********** Signing *************/
    /*********************************/
    pub fn sign_ecdsa_message(&self, message: &Message, public_key: PublicKey) -> Result<secp256k1::ecdsa::Signature, KeyManagerError> {
        let (_, sk, _) = match self.storage.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };

        Ok(self.secp.sign_ecdsa(message, &sk.inner))
    }

    pub fn sign_ecdsa_messages(&self, messages: Vec<Message>, public_keys: Vec<PublicKey>) -> Result<Vec<secp256k1::ecdsa::Signature>, KeyManagerError> {
        let mut signatures = Vec::new();

        for (message, public_key) in izip!(
            messages.iter(),
            public_keys.iter(),
        ) {
            let signature = self.sign_ecdsa_message(message, public_key.to_owned())?;
            signatures.push(signature);
        }
    
        Ok(signatures)
    }

    // Use key_spend = true for taproot key spend, false for taproot script spend
    pub fn sign_schnorr_message(&self, message: &Message, public_key: &PublicKey, key_spend: bool) -> Result<(secp256k1::schnorr::Signature, Option<PublicKey>), KeyManagerError>{
        let (_, sk, _) = match self.storage.load_keypair(public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };
        
        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);
        
        let (signature, tweaked_pk) = match key_spend {
            true => {
                let tweaked: TweakedKeypair = keypair.tap_tweak(&self.secp, None);
                let kp = tweaked.to_inner();
                (self.secp.sign_schnorr(message, &kp), Some(PublicKey::new(kp.public_key())))
            },
            false => (self.secp.sign_schnorr(message, &keypair), None)
        };        

        Ok((signature, tweaked_pk))
    }

    // Use key_spend = true for taproot key spend, false for taproot script spend
    pub fn sign_schnorr_messages(&self, messages: Vec<Message>, public_keys: Vec<PublicKey>, key_spend: bool) -> Result<Vec<(secp256k1::schnorr::Signature, Option<PublicKey>)>, KeyManagerError> {
        let mut signatures = Vec::new();
        
        for (message, public_key) in izip!(
            messages.iter(),
            public_keys.iter(),
        ) {
            let signature = self.sign_schnorr_message(message, public_key, key_spend)?;
            signatures.push(signature);
        }
    
        Ok(signatures)
    }
    
    pub fn sign_winternitz_message(&self, msg_with_checksum: &[u8], msg_len_bytes: usize, index:u32, key_type: WinternitzType) -> Result<Vec<Vec<u8>>, KeyManagerError> {

        let mut signature = Vec::new();

        let key_size = match key_type {
            WinternitzType::WSHA256 => SHA256_SIZE,
            WinternitzType::WRIPEMD160 => RIPEMD160_SIZE,
        };

        let msg_pad_len = calculate_checksum_length(msg_len_bytes, W) + msg_len_bytes - msg_with_checksum.len();
        let msg_with_checksum_pad = [msg_with_checksum, &vec![0u8; msg_pad_len]].concat(); 

        let private_key = self.get_multiple_child_keys(key_size, msg_with_checksum_pad.len()*2, index)?;
        for (i, byte) in msg_with_checksum_pad.iter().enumerate() {
            let (high_nibble, low_nibble) = split_byte(*byte);

            let mut hashed_val = private_key[2 * i].clone();
            for _ in 0..(W - (high_nibble as usize)) {
                hashed_val = match key_type {
                    WinternitzType::WSHA256 => sha256::Hash::hash(&hashed_val).as_byte_array().to_vec(),
                    WinternitzType::WRIPEMD160 => ripemd160::Hash::hash(&hashed_val).as_byte_array().to_vec(),                    
                }
            }
            signature.push(hashed_val);

            let mut hashed_val = private_key[2 * i + 1].clone();
            for _ in 0..(W - (low_nibble as usize)) {
                hashed_val = match key_type {
                    WinternitzType::WSHA256 => sha256::Hash::hash(&hashed_val).as_byte_array().to_vec(),
                    WinternitzType::WRIPEMD160 => ripemd160::Hash::hash(&hashed_val).as_byte_array().to_vec(),               
                }
            }
            signature.push(hashed_val);
        }   

        Ok(signature)
    }
    
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


#[cfg(test)]
mod tests {
    use std::{env, panic, str::FromStr};

    use bitcoin::{hashes::{self, Hash}, key::rand::{self, RngCore}, secp256k1::{self, Message, SecretKey}, Network, PrivateKey, PublicKey};
    use crate::{add_checksum, calculate_checksum_length, secure_storage::SecureStorage, KeyManager, KeyManagerError, SignatureVerifier, WinternitzType, W};

    use rand::Rng;

    const DERIVATION_PATH: &str = "101/1/0/0/";
    const REGTEST: Network = Network::Regtest;

    #[test]
    fn test_sign_ecdsa_message() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();
        let mut rng = secp256k1::rand::thread_rng();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None, &mut rng).unwrap();
        let signature_verifier = SignatureVerifier::new();

        let pk = key_manager.generate_key(None, &mut rng).unwrap();
     
        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, pk).unwrap();

        println!("Message: {}", message);
        println!("Signature: {}", signature);

        assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));
    }

    #[test]
    fn test_sign_schnorr_message_script_spend() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();
        let mut rng = secp256k1::rand::thread_rng();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None, &mut rng).unwrap();
        let signature_verifier = SignatureVerifier::new();
        let pk = key_manager.generate_key(None, &mut rng).unwrap();
     
        let message = random_message();
        let (signature, _) = key_manager.sign_schnorr_message(&message, &pk, false).unwrap();

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk));  
    }

    #[test]
    fn test_sign_schnorr_message_key_spend() { 
        let seed = random_seed();
        let storage_password: Vec<u8> = b"secret password".to_vec();
        let mut rng = secp256k1::rand::thread_rng();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None, &mut rng).unwrap();
        let signature_verifier = SignatureVerifier::new();
        let pk = key_manager.generate_key(None, &mut rng).unwrap();
     
        let message = random_message();
        let (signature, tweaked_key) = key_manager.sign_schnorr_message(&message, &pk, true).unwrap();

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, tweaked_key.unwrap()));
    }

    #[test]
    fn test_sign_winternitz_message_sha256() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();
        let mut rng = secp256k1::rand::thread_rng();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None, &mut rng).unwrap();
        let signature_verifier = SignatureVerifier::new();

        let message = random_message();
        let msg_with_checksum = add_checksum(&message[..], W);

        let pk = key_manager.generate_winternitz_key( message[..].len(), WinternitzType::WSHA256, 0).unwrap();
        let signature = key_manager.sign_winternitz_message(&msg_with_checksum, message[..].len(), 0, WinternitzType::WSHA256).unwrap();

        assert!(signature_verifier.verify_winternitz_signature(&signature, &msg_with_checksum, message[..].len(), &pk, WinternitzType::WSHA256));
    }

    #[test]
    fn test_sign_winternitz_message_ripemd160() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();
        let mut rng = secp256k1::rand::thread_rng();

        let mut secret= [0u8; 32];
        rng.fill(&mut secret);

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, Some(secret), &mut rng).unwrap();
        let signature_verifier = SignatureVerifier::new();

        let digest: [u8; 32] = [0xFE; 32];
        let message = Message::from_digest(digest);

        let msg_with_checksum = add_checksum(&message[..], W);
        
        let pk = key_manager.generate_winternitz_key( message[..].len(), WinternitzType::WRIPEMD160, 0).unwrap();
        let signature = key_manager.sign_winternitz_message(&msg_with_checksum, message[..].len(), 0, WinternitzType::WRIPEMD160).unwrap();

        println!("Msg: {:?}", &message[..]);
        println!("Msg with checksum: {:?}", msg_with_checksum);
        println!("Msg_len: {} \nMsg_checksum_len: {} \nMsg_chacksum_max_len {} \nSignature_len: {}", message[..].len(), add_checksum(&message[..], W).len(), calculate_checksum_length(message[..].len(), W), signature.len());

        assert!(signature_verifier.verify_winternitz_signature(&signature, &msg_with_checksum, message[..].len(), &pk, WinternitzType::WRIPEMD160));
    }

    #[test]
    fn test_derive_key() { 
        let seed = random_seed();
        let storage_password: Vec<u8> = b"secret password".to_vec();
        let mut rng = secp256k1::rand::thread_rng();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None, &mut rng).unwrap();
        let signature_verifier = SignatureVerifier::new();
        let pk_1 = key_manager.derive_bip32(Some("pk_1".to_string())).unwrap();
        let pk_2 = key_manager.derive_bip32(Some("pk_2".to_string())).unwrap();

        assert_ne!(pk_1.to_string(), pk_2.to_string());
     
        let message = random_message();
        let signature_1 = key_manager.sign_ecdsa_message(&message, pk_1).unwrap();
        let signature_2 = key_manager.sign_ecdsa_message(&message, pk_2).unwrap();

        assert_ne!(signature_1.to_string(), signature_2.to_string());

        assert!(signature_verifier.verify_ecdsa_signature(&signature_1, &message, pk_1));
        assert!(signature_verifier.verify_ecdsa_signature(&signature_2, &message, pk_2));
    }

    #[test]
    fn test_key_generation() {  
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();
        let mut rng = secp256k1::rand::thread_rng();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None, &mut rng).unwrap();

        let message = random_message();
        let pk1 = key_manager.generate_winternitz_key(message[..].len(), WinternitzType::WSHA256, 0).unwrap();
        let pk2 = key_manager.generate_winternitz_key(message[..].len(), WinternitzType::WRIPEMD160, 8).unwrap();
        let pk3 = key_manager.generate_winternitz_key(message[..].len(), WinternitzType::WRIPEMD160, 8).unwrap();
        let pk4 = key_manager.generate_winternitz_key(message[..].len(), WinternitzType::WSHA256, 8).unwrap();
        let pk5 = key_manager.generate_key(None, &mut rng).unwrap();
        let pk6 = key_manager.generate_key(None, &mut rng).unwrap();


        assert!(pk1.len() == (calculate_checksum_length(message[..].len(), W) + message[..].len())*2);
        assert!(pk2.len() == (calculate_checksum_length(message[..].len(), W) + message[..].len())*2);
        assert!(pk1[0].len() == 32);
        assert!(pk2[0].len() == 20);
        assert!(pk5.to_bytes().len() == 33);
        assert!(pk1[0] != pk1[1]);

        assert!(pk1 != pk2);
        assert!(pk2 == pk3);
        assert!(pk2 != pk4);
        assert!(pk5 != pk6);
        
    }

    #[test]
    fn test_secure_storage() -> Result<(), KeyManagerError> { 
        let password = b"secret password".to_vec();
        let secp = secp256k1::Secp256k1::new();
        let secret = random_secret();

        let mut secure_storage = SecureStorage::new(&temp_storage(), password, Network::Regtest)?;
        secure_storage.store_winternitz_secret(secret)?;

        for i in 0..10 {
            let label_hash = hashes::sha256::Hash::hash(i.to_string().as_bytes()).to_string();
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            let private_key = PrivateKey::new(secret_key, Network::Regtest);
            let public_key = PublicKey::from_private_key(&secp, &private_key);
            
            secure_storage.store_keypair(&i.to_string(), private_key, public_key)?;
 
            let (restored_label, restored_sk, restored_pk) = match secure_storage.load_keypair_by_label(&i.to_string())? {
                Some(entry) => entry,
                None => panic!("Failed to find key"),
            };

            assert_eq!(restored_label, label_hash);
            assert_eq!(restored_sk.to_string(), private_key.to_string());
            assert_eq!(restored_pk.to_string(), public_key.to_string());

        }
        let loaded_secret = secure_storage.load_winternitz_secret().unwrap();
        assert!(loaded_secret == secret);

        Ok(())
    }

    #[test]
    fn test_secure_storage_indexes() -> Result<(), KeyManagerError>{ 
        let path = temp_storage();
        let password = b"secret password".to_vec();
        let secp = secp256k1::Secp256k1::new();
        let secret = random_secret();

        let mut secure_storage = SecureStorage::new(&path, password, Network::Regtest)?;
        secure_storage.store_winternitz_secret(secret)?;

        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, Network::Regtest);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let label = "my_key";

        secure_storage.store_keypair(label, private_key, public_key)?;

        let (_, _, recovered_public_key) = match secure_storage.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        assert_eq!(recovered_public_key.to_string(), public_key.to_string());

        // Create a second SecureStorage instance to test that the indexes are restored correctly by loading the same storage file        let password = b"secret password".to_vec();
        let password = b"secret password".to_vec();
        let secure_storage_2 = SecureStorage::new(&path, password, Network::Regtest)?;

        let (_, _, recovered_public_key_2) = match secure_storage_2.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        assert_eq!(recovered_public_key_2.to_string(), public_key.to_string());

        Ok(())
    }

    #[test]
    fn test_error_handling() {
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();
        let message = random_message();
        let mut rng = secp256k1::rand::thread_rng();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password.clone(), &seed, None, &mut rng).unwrap();

        // Case 1: Invalid private key string
        let result = key_manager.import_private_key("test_label", "invalid_key");
        assert!(matches!(result, Err(KeyManagerError::PrivKeySliceError(_))));

        // Case 2: Invalid derivation path
        let invalid_derivation_path = "m/44'/invalid'";
        key_manager.key_derivation_path = invalid_derivation_path.to_string();
        let result = key_manager.derive_bip32(None);
        assert!(matches!(result, Err(KeyManagerError::Bip32Error(_))));

        // Case 3: Storage error when creating storage (invalid path)
        let invalid_storage_path = "/invalid/path";
        let result = KeyManager::new(Network::Regtest, "m/44'/0'/0'", invalid_storage_path, storage_password, &seed, None, &mut rng);
        assert!(matches!(result, Err(KeyManagerError::SecureStorageError(_))));

        // Case 4: Index overflow when generating keys
        let result = key_manager.generate_winternitz_key( message[..].len(), WinternitzType::WRIPEMD160, u32::MAX);
        assert!(matches!(result, Err(KeyManagerError::IndexOverflow)));

        // Case 5: Entry not found for public key
        let fake_public_key = PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let result = key_manager.sign_ecdsa_message(&random_message(), fake_public_key);
        assert!(matches!(result, Err(KeyManagerError::EntryNotFound)));
    }

    fn random_message() -> Message {
        let mut digest = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut digest);
        Message::from_digest(digest)
    }

    fn random_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }

    fn random_secret() -> [u8; 32]{
        let mut rng = secp256k1::rand::thread_rng();
        let mut secret= [0u8; 32];
        rng.fill(&mut secret);
        secret
    }

    fn temp_storage() -> String {
        let dir = env::temp_dir();

        let mut rng = rand::thread_rng();
        let index = rng.next_u32();

        let storage_path = dir.join(format!("secure_storage_{}.db", index));
        storage_path.to_str().expect("Failed to get path to temp file").to_string()
    }
}
