use std::str::FromStr;

use bitcoin::{bip32::{ChildNumber, DerivationPath, Xpriv}, key::{Keypair, TapTweak, TweakedKeypair}, secp256k1::{self, All, Message, SecretKey, hashes::{sha256, ripemd160}}, hashes::{Hash, HashEngine, Hmac, HmacEngine}, Network, PrivateKey, PublicKey};
use itertools::izip;
use secure_storage::SecureStorage;
use rand::Rng;

pub mod secure_storage;

// For winternitz
const NBITS: usize = 4; // Nibbles
const W: usize = 2usize.pow(NBITS as u32); // Winternitz parameter (times to hash)

/// This module provides a key manager for managing BitVMX keys and signatures.
/// It includes functionality for generating, importing, and deriving keys, as well as signing 
/// messages using ECDSA and Schnorr algorithms. The key manager uses a secure storage mechanism 
/// to store the keys.
pub struct KeyManager {
    secp: secp256k1::Secp256k1<All>,
    network: Network,
    master_xpriv: Xpriv, 
    next_normal: ChildNumber,
    key_derivation_path: String,
    storage: SecureStorage,
    ecdsa_schnorr_generator: PrivkGenerator,
    winterintz_generator: PrivkGenerator
}

pub struct SignatureVerifier {
    secp: secp256k1::Secp256k1<All>,
}

struct PrivkGenerator{
    master_secret: [u8; 32],
    last_index: u32,
}

#[derive(Clone)]
pub enum WinternitzType {
    WSHA256,
    WRIPEMD160,
}

impl KeyManager {
    // If master secret is provided, first one correspond to ecdsa_schnorr_generator and second one to winternitz_generator
    pub fn new(network: Network, key_derivation_path: &str, storage_path: &str, password: Vec<u8>, seed:&[u8], master_secrets: Option<(Option<[u8; 32]>, Option<[u8; 32]>)>) -> Self {
        let secp = secp256k1::Secp256k1::new();
        
         let secret1 = match master_secrets {
            Some((Some(secret1), _)) => secret1,
            _ => {
                let mut rng = rand::thread_rng();
                let mut secret= [0u8; 32];
                rng.fill(&mut secret);
                secret
            }
        };

        let secret2 = match master_secrets {
            Some((_, Some(secret2))) => secret2,
            _ => {
                let mut rng = rand::thread_rng();
                let mut secret= [0u8; 32];
                rng.fill(&mut secret);
                secret
            }
        };

        KeyManager { 
            secp,
            network,
            master_xpriv: Xpriv::new_master(network, seed).expect("Failed to create master xpriv"),
            next_normal: ChildNumber::Normal { index: 0 },
            key_derivation_path: key_derivation_path.to_string(),
            storage: SecureStorage::new(storage_path, password, network),
            ecdsa_schnorr_generator: PrivkGenerator{master_secret: secret1, last_index: 0},
            winterintz_generator: PrivkGenerator{master_secret: secret2, last_index: 0}
        }
    }

    pub fn derive_bip32(& mut self, label: Option<String>) -> PublicKey {
        let derivation_path = DerivationPath::from_str(&format!("{}{}", self.key_derivation_path, self.next_normal)).expect("Failed to create derivation path");
        let xpriv = self.master_xpriv.derive_priv(&self.secp, &derivation_path).expect("Failed to derive xpriv");

        let internal_keypair = xpriv.to_keypair(&self.secp);
        let public_key = PublicKey::new(internal_keypair.public_key());
        let private_key = PrivateKey::new(internal_keypair.secret_key(), self.network);

        let label = label.unwrap_or_else(|| public_key.to_string());
        self.storage.store_entry(&label, private_key, public_key);

        self.next_normal = self.next_normal.increment().expect("Failed to increment next_normal");

        public_key
    }

    pub fn import_private_key(&mut self, label: &str, private_key: &str) {
        let private_key = PrivateKey::from_str(&private_key).unwrap();
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        self.storage.store_entry(label, private_key, public_key);
    }

    //TODO: add import key winternitz

    pub fn generate_key(&mut self, index: Option<u32>, label: Option<String>) -> PublicKey {
        let private_key = self.generate_private_key(self.network, index);
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        let label = label.unwrap_or_else(|| public_key.to_string());
        self.storage.store_entry(&label, private_key, public_key);

        public_key
    }

    pub fn generate_winternitz_key(&mut self, message: &Message, key_type: WinternitzType, index: Option<u32>, label: Option<String>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, u32) {
        let current_index = self.winterintz_generator.last_index;
        let private_keys = self.generate_winternitz_private_key(message, key_type.clone(), index);
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

        //TODO: Store private keys in secure storage 
        //let label = label.unwrap_or_else(|| public_key.to_string());
        //self.storage.store_entry(&label, private_key, public_key);
        
        (private_keys, public_keys, current_index) //return index and public key

    }

    fn generate_private_key(& mut self, network: Network, index: Option<u32>) -> PrivateKey {
         
        let (new_index, privk) = self.get_index_and_child_key(32, self.ecdsa_schnorr_generator.last_index, self.ecdsa_schnorr_generator.master_secret, index);
        self.ecdsa_schnorr_generator.last_index = new_index;
        
        let secret_key = SecretKey::from_slice(&privk).expect("Failed to create secret key");
        PrivateKey::new(secret_key, network)

    }

    fn generate_winternitz_private_key(& mut self, message: &Message, key_type: WinternitzType, index: Option<u32>) -> Vec<Vec<u8>> {
        let msg_with_checksum = add_checksum(&message[..]);
        let msg_len = 2 * msg_with_checksum.len();
        let key_size = match key_type {
            WinternitzType::WSHA256 => 32,  //TODO: no hardcoded values
            WinternitzType::WRIPEMD160 => 20,
        };

        let (new_index, private_key) = self.get_multiple_child_keys(key_size, msg_len.try_into().unwrap(), self.winterintz_generator.last_index, self.winterintz_generator.master_secret, index);
        self.winterintz_generator.last_index = new_index;

        private_key
    }

    fn get_index_and_child_key(&self, key_size: usize, last_index: u32, master_secret: [u8;32], index: Option<u32>)-> (u32, Vec<u8>) {
        let myindex = match index {
            Some(i) => i,
            None => last_index,
        };
        let mut engine = HmacEngine::<sha256::Hash>::new(&master_secret);
        engine.input(&myindex.to_le_bytes());
        let hash = Hmac::<sha256::Hash>::from_engine(engine);

        myindex.checked_add(1).expect("Index overflow: cannot generate more keys"); //TODO: handle overflow
        
        (myindex + 1 , hash[..key_size].to_vec())
    }

    fn get_multiple_child_keys(&self, key_size: usize, num_keys: u32, last_index: u32, master_secret: [u8;32], index: Option<u32>)-> (u32, Vec<Vec<u8>>){
        let myindex = match index {
            Some(i) => i,
            None => last_index,
        };
        
        let mut keys = Vec::new();
        for i in myindex..(myindex + num_keys) {
            let (_, privk) = self.get_index_and_child_key(key_size, i, master_secret, None);
            keys.push(privk);
        }
        (myindex + num_keys, keys)
    }

    pub fn sign_ecdsa_message(&self, message: &Message, public_key: PublicKey) -> secp256k1::ecdsa::Signature {
        let (_, sk, _) = match self.storage.entry_by_key(&public_key) {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        self.secp.sign_ecdsa(&message, &sk.inner)
    }

    pub fn sign_ecdsa_messages(&self, messages: Vec<Message>, public_keys: Vec<PublicKey>) -> Vec<secp256k1::ecdsa::Signature> {
        let mut signatures = Vec::new();

        for (message, public_key) in izip!(
            messages.iter(),
            public_keys.iter(),
        ) {
            let signature = self.sign_ecdsa_message(message, public_key.to_owned());
            signatures.push(signature);
        }
    
        signatures
    }

    // Use key_spend = true for taproot key spend, false for taproot script spend
    pub fn sign_schnorr_message(&self, message: &Message, public_key: &PublicKey, key_spend: bool) -> (secp256k1::schnorr::Signature, Option<PublicKey>){
        let (_, sk, _) = match self.storage.entry_by_key(public_key) {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };
        
        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);
        
        let (signature, tweaked_pk) = match key_spend {
            true => {
                let tweaked: TweakedKeypair = keypair.tap_tweak(&self.secp, None);
                let kp = tweaked.to_inner();
                (self.secp.sign_schnorr(message, &kp), Some(PublicKey::new(kp.public_key())))
            },
            false => (self.secp.sign_schnorr(&message, &keypair), None)
        };        

        (signature, tweaked_pk)
    }

    // Use key_spend = true for taproot key spend, false for taproot script spend
    pub fn sign_schnorr_messages(&self, messages: Vec<Message>, public_keys: Vec<PublicKey>, key_spend: bool) -> Vec<(secp256k1::schnorr::Signature, Option<PublicKey>)> {
        let mut signatures = Vec::new();
        
        for (message, public_key) in izip!(
            messages.iter(),
            public_keys.iter(),
        ) {
            let signature = self.sign_schnorr_message(message, public_key, key_spend);
            signatures.push(signature);
        }
    
        signatures
    }
    
    pub fn sign_winternitz_message(&self, message: &Message, private_key: &[Vec<u8>], key_type: WinternitzType) -> Vec<Vec<u8>> {
    //pub fn sign_winternitz_message(&self, message: &Message, public_key: &[Vec<u8>], key_type: WinternitzType) -> Vec<Vec<u8>> {
        //TODO: Implement: Pass the pubk and get the privk from secure storage
        // let (_, sk, _) = match self.storage.entry_by_key(&public_key) {
        //     Some(entry) => entry,
        //     None => panic!("Failed to find key"),
        // };

        let mut signature = Vec::new();
        let msg_with_checksum = add_checksum(&message[..]);

        for (i, byte) in msg_with_checksum.iter().enumerate() {
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

        signature
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
        self.secp.verify_ecdsa(message, &signature,&public_key.inner).is_ok()
    }

    pub fn verify_schnorr_signature(&self, signature: &secp256k1::schnorr::Signature, message: &secp256k1::Message, public_key: PublicKey) -> bool {
        let xonly_public_key = public_key.into();
        self.secp.verify_schnorr(&signature,&message, &xonly_public_key).is_ok()
    }

    pub fn verify_winternitz_signature(&self, signature: &[Vec<u8>], message: &secp256k1::Message, public_key: &[Vec<u8>], key_type: WinternitzType) -> bool {
        let mut generated_public_key = Vec::new();
        let msg_with_checksum = add_checksum(&message[..]);
        for (i, byte) in msg_with_checksum.iter().enumerate() {
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

        generated_public_key == public_key
    }
}



fn add_checksum(message: &[u8]) -> Vec<u8> {
    let mut message = message.to_vec();
    let checksum = calculate_checksum(&message);
    message.extend_from_slice(&checksum);
    message
}

fn calculate_checksum(message: &[u8]) -> Vec<u8> {
    let mut checksum: u32 = 0;

    for byte in message.iter() {
        let (high_nibble, low_nibble) = split_byte(*byte);
        checksum += (W as u32 - 1 - high_nibble as u32) + (W as u32 - 1 - low_nibble as u32);
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

fn split_byte(byte: u8) -> (u8, u8) {
    let high_nibble: u8 = (byte & 0xF0) >> 4;
    let low_nibble: u8 = byte & 0x0F;
    (high_nibble, low_nibble)
}

#[cfg(test)]
mod tests {
    use std::{env, u32, panic};

    use bitcoin::{hashes::{self, Hash}, key::rand::{self, RngCore}, secp256k1::{self, Message, SecretKey}, Network, PrivateKey, PublicKey};
    use crate::{secure_storage::SecureStorage, KeyManager, SignatureVerifier, WinternitzType, add_checksum};

    use rand::Rng;

    const DERIVATION_PATH: &str = "101/1/0/0/";
    const REGTEST: Network = Network::Regtest;

    #[test]
    fn test_sign_ecdsa_message() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None);
        let signature_verifier = SignatureVerifier::new();

        let pk = key_manager.generate_key(None, None);
     
        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, pk);

        println!("Message: {}", message);
        println!("Signature: {}", signature);

        assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));
    }

    #[test]
    fn test_sign_schnorr_message_script_spend() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None);
        let signature_verifier = SignatureVerifier::new();
        let pk = key_manager.generate_key(None, None);
     
        let message = random_message();
        let (signature, _) = key_manager.sign_schnorr_message(&message, &pk, false);

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk));  
    }

    #[test]
    fn test_sign_schnorr_message_key_spend() { 
        let seed = random_seed();
        let storage_password: Vec<u8> = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None);
        let signature_verifier = SignatureVerifier::new();
        let pk = key_manager.generate_key(None, None);
     
        let message = random_message();
        let (signature, tweaked_key) = key_manager.sign_schnorr_message(&message, &pk, true);

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, tweaked_key.unwrap()));
    }

    #[test]
    fn test_sign_winternitz_message_sha256() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None);
        let signature_verifier = SignatureVerifier::new();

        let message = random_message();
        let (privk, pk, _) = key_manager.generate_winternitz_key( &message, WinternitzType::WSHA256, None, None);
     
        let signature = key_manager.sign_winternitz_message(&message, &privk, WinternitzType::WSHA256);

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message, &pk, WinternitzType::WSHA256));
    }

    #[test]
    fn test_sign_winternitz_message_ripemd160() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();

        let mut rng = rand::thread_rng();
        let mut secret= [0u8; 32];
        rng.fill(&mut secret);

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, Some((Some(secret),None)));
        let signature_verifier = SignatureVerifier::new();

        let message = random_message();
        let (privk, pk, _) = key_manager.generate_winternitz_key(&message, WinternitzType::WRIPEMD160, None, None);
     
        let signature = key_manager.sign_winternitz_message(&message, &privk, WinternitzType::WRIPEMD160);

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message, &pk, WinternitzType::WRIPEMD160));
    }

    #[test]
    fn test_derive_key() { 
        let seed = random_seed();
        let storage_password: Vec<u8> = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None);
        let signature_verifier = SignatureVerifier::new();
        let pk_1 = key_manager.derive_bip32(Some("pk_1".to_string()));
        let pk_2 = key_manager.derive_bip32(Some("pk_2".to_string()));

        assert_ne!(pk_1.to_string(), pk_2.to_string());
     
        let message = random_message();
        let signature_1 = key_manager.sign_ecdsa_message(&message, pk_1);
        let signature_2 = key_manager.sign_ecdsa_message(&message, pk_2);

        assert_ne!(signature_1.to_string(), signature_2.to_string());

        assert!(signature_verifier.verify_ecdsa_signature(&signature_1, &message, pk_1));
        assert!(signature_verifier.verify_ecdsa_signature(&signature_2, &message, pk_2));
    }

    #[test]
    fn test_key_generation() {  
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed, None);

        let message = random_message();
        let (_, pk1, index1) = key_manager.generate_winternitz_key(&message, WinternitzType::WSHA256, None, None);
        let (_, pk2, index2) = key_manager.generate_winternitz_key(&message, WinternitzType::WRIPEMD160, None, None);
        let (_, pk3, index3) = key_manager.generate_winternitz_key(&message, WinternitzType::WRIPEMD160, Some(index2), None);
        let (_, pk4, index4) = key_manager.generate_winternitz_key(&message, WinternitzType::WSHA256, Some(index2), None);
        let pk5 = key_manager.generate_key(None, None);
        let pk6 = key_manager.generate_key(None, None);
        let pk7 = key_manager.generate_key(Some(0), None);
        let pk8 = key_manager.generate_key(Some(1), None);

        assert!(pk1.len() == add_checksum(&message[..]).len()*2);
        assert!(pk2.len() == add_checksum(&message[..]).len()*2);
        assert!(pk1[0].len() == 32);
        assert!(pk2[0].len() == 20);
        assert!(pk5.to_bytes().len() == 33);
        assert!(pk1[0] != pk1[1]);

        assert!(pk1 != pk2);
        assert!(pk5 != pk6);
        assert!(index1 == 0);
        assert!(index2 == index1 + (pk1.len() as u32));

        assert!(pk2 == pk3);
        assert!(pk2 != pk4);
        assert!(pk5 == pk7);
        assert!(pk6 == pk8);
        assert!(index3 == index4);

        let _ = key_manager.generate_key(Some(900), None);
        for _ in 0..10 {
            let _ = key_manager.generate_key(None, None);
        }
        assert!(key_manager.generate_key(None, None) == key_manager.generate_key(Some(911), None));

        let result = panic::catch_unwind(move || key_manager.generate_key(Some(u32::MAX), None));
        assert!(result.is_err()); 
 
    }
    #[test]
    fn test_secure_storage() { 
        let password = b"secret password".to_vec();
        let secp = secp256k1::Secp256k1::new();
        let mut secure_storage = SecureStorage::new(&temp_storage(), password, Network::Regtest);

        for i in 0..10 {
            let label_hash = hashes::sha256::Hash::hash(i.to_string().as_bytes()).to_string();
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            let private_key = PrivateKey::new(secret_key, Network::Regtest);
            let public_key = PublicKey::from_private_key(&secp, &private_key);
            
            secure_storage.store_entry(&i.to_string(), private_key, public_key);
 
            let (restored_label, restored_sk, restored_pk) = match secure_storage.entry_by_label(&i.to_string()) {
                Some(entry) => entry,
                None => panic!("Failed to find key"),
            };

            assert_eq!(restored_label, label_hash);
            assert_eq!(restored_sk.to_string(), private_key.to_string());
            assert_eq!(restored_pk.to_string(), public_key.to_string());
        }
    }

    #[test]
    fn test_secure_storage_indexes() { 
        let path = temp_storage();
        let password = b"secret password".to_vec();
        let secp = secp256k1::Secp256k1::new();
        let mut secure_storage = SecureStorage::new(&path, password, Network::Regtest);

        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, Network::Regtest);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let label = "my_key";

        secure_storage.store_entry(label, private_key, public_key);

        let (_, _, recovered_public_key) = match secure_storage.entry_by_key(&public_key) {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        assert_eq!(recovered_public_key.to_string(), public_key.to_string());

        // Create a second SecureStorage instance to test that the indexes are restored correctly by loading the same storage file        let password = b"secret password".to_vec();
        let password = b"secret password".to_vec();
        let secure_storage_2 = SecureStorage::new(&path, password, Network::Regtest);

        let (_, _, recovered_public_key_2) = match secure_storage_2.entry_by_key(&public_key) {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        assert_eq!(recovered_public_key_2.to_string(), public_key.to_string());
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

    fn temp_storage() -> String {
        let dir = env::temp_dir();

        let mut rng = rand::thread_rng();
        let index = rng.next_u32();

        let storage_path = dir.join(format!("secure_storage_{}.db", index));
        storage_path.to_str().expect("Failed to get path to temp file").to_string()
    }
}
