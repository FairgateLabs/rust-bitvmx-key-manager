use std::str::FromStr;

use bitcoin::{bip32::{ChildNumber, DerivationPath, Xpriv}, key::{Keypair, TapTweak, TweakedKeypair}, secp256k1::{self, All, Message, SecretKey}, Network, PrivateKey, PublicKey};
use itertools::izip;
use secure_storage::SecureStorage;

pub mod secure_storage;

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
}

pub struct SignatureVerifier {
    secp: secp256k1::Secp256k1<All>,
}

impl KeyManager {
    pub fn new(network: Network, key_derivation_path: &str, storage_path: &str, password: Vec<u8>, seed:&[u8]) -> Self {
        let secp = secp256k1::Secp256k1::new();
        KeyManager { 
            secp,
            network,
            master_xpriv: Xpriv::new_master(network, seed).expect("Failed to create master xpriv"),
            next_normal: ChildNumber::Normal { index: 0 },
            key_derivation_path: key_derivation_path.to_string(),
            storage: SecureStorage::new(storage_path, password, network),
        }
    }

    pub fn import_private_key(&mut self, label: &str, private_key: &str) {
        let private_key = PrivateKey::from_str(private_key).unwrap();
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        self.storage.store_entry(label, private_key, public_key);
    }

    pub fn generate_key(&mut self, label: Option<String>) -> PublicKey {
        let private_key = self.generate_private_key(self.network);
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        let label = label.unwrap_or_else(|| public_key.to_string());
        self.storage.store_entry(&label, private_key, public_key);

        public_key
    }

    pub fn derive_bip32(&mut self, label: Option<String>) -> PublicKey {
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

    fn generate_private_key(&self, network: Network) -> PrivateKey {
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        PrivateKey::new(secret_key, network)
    }

    pub fn sign_ecdsa_message(&self, message: &Message, public_key: PublicKey) -> secp256k1::ecdsa::Signature {
        let (_, sk, _) = match self.storage.entry_by_key(&public_key) {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        self.secp.sign_ecdsa(message, &sk.inner)
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
            false => (self.secp.sign_schnorr(message, &keypair), None)
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



    pub fn veriy_ecdsa_signature(&self, signature: &secp256k1::ecdsa::Signature, message: &secp256k1::Message, public_key: PublicKey) -> bool {
        self.secp.verify_ecdsa(message, signature,&public_key.inner).is_ok()
    }

    pub fn veriy_schnorr_signature(&self, signature: &secp256k1::schnorr::Signature, message: &secp256k1::Message, public_key: PublicKey) -> bool {
        let xonly_public_key = public_key.into();
        self.secp.verify_schnorr(signature, message, &xonly_public_key).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use bitcoin::{hashes::{self, Hash}, key::rand::{self, RngCore}, secp256k1::{self, Message, SecretKey}, Network, PrivateKey, PublicKey};
    use crate::{secure_storage::SecureStorage, KeyManager, SignatureVerifier};

    const DERIVATION_PATH: &str = "101/1/0/0/";
    const REGTEST: Network = Network::Regtest;

    #[test]
    fn test_sign_ecdsa_message() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed);
        let signature_verifier = SignatureVerifier::new();

        let pk = key_manager.generate_key(None);
     
        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, pk);

        assert!(signature_verifier.veriy_ecdsa_signature(&signature, &message, pk));
    }

    #[test]
    fn test_sign_schnorr_message_script_spend() { 
        let seed = random_seed();
        let storage_password = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed);
        let signature_verifier = SignatureVerifier::new();
        let pk = key_manager.generate_key(None);
     
        let message = random_message();
        let (signature, _) = key_manager.sign_schnorr_message(&message, &pk, false);

        assert!(signature_verifier.veriy_schnorr_signature(&signature, &message, pk));  
    }

    #[test]
    fn test_sign_schnorr_message_key_spend() { 
        let seed = random_seed();
        let storage_password: Vec<u8> = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed);
        let signature_verifier = SignatureVerifier::new();
        let pk = key_manager.generate_key(None);
     
        let message = random_message();
        let (signature, tweaked_key) = key_manager.sign_schnorr_message(&message, &pk, true);

        assert!(signature_verifier.veriy_schnorr_signature(&signature, &message, tweaked_key.unwrap()));
    }

    #[test]
    fn test_derive_key() { 
        let seed = random_seed();
        let storage_password: Vec<u8> = b"secret password".to_vec();

        let mut key_manager = KeyManager::new(REGTEST, DERIVATION_PATH,&temp_storage(), storage_password, &seed);
        let signature_verifier = SignatureVerifier::new();
        let pk_1 = key_manager.derive_bip32(Some("pk_1".to_string()));
        let pk_2 = key_manager.derive_bip32(Some("pk_2".to_string()));

        assert_ne!(pk_1.to_string(), pk_2.to_string());
     
        let message = random_message();
        let signature_1 = key_manager.sign_ecdsa_message(&message, pk_1);
        let signature_2 = key_manager.sign_ecdsa_message(&message, pk_2);

        assert_ne!(signature_1.to_string(), signature_2.to_string());

        assert!(signature_verifier.veriy_ecdsa_signature(&signature_1, &message, pk_1));
        assert!(signature_verifier.veriy_ecdsa_signature(&signature_2, &message, pk_2));
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
