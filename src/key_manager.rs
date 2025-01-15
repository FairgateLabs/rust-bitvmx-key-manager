use std::str::FromStr;

use bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    key::{rand::Rng, Keypair, TapTweak, TweakedKeypair},
    secp256k1::{self, All, Message, Scalar, SecretKey},
    Network, PrivateKey, PublicKey,
};
use itertools::izip;

use crate::{
    errors::KeyManagerError,
    keystorage::keystore::KeyStore,
    winternitz::{
        self, checksum_length, to_checksummed_message, WinternitzSignature, WinternitzType,
    },
};

/// This module provides a key manager for managing BitVMX keys and signatures.
/// It includes functionality for generating, importing, and deriving keys, as well as signing messages
/// using ECDSA, Schnorr and Winternitz algorithms. The key manager uses a secure storage mechanism
/// to store the keys.
pub struct KeyManager<K: KeyStore> {
    secp: secp256k1::Secp256k1<All>,
    network: Network,
    key_derivation_path: String,
    keystore: K,
}

impl<K: KeyStore> KeyManager<K> {
    pub fn new(
        network: Network,
        key_derivation_path: &str,
        key_derivation_seed: [u8; 32],
        winternitz_seed: [u8; 32],
        keystore: K,
    ) -> Result<Self, KeyManagerError> {
        let secp = secp256k1::Secp256k1::new();

        keystore.store_winternitz_seed(winternitz_seed)?;
        keystore.store_key_derivation_seed(key_derivation_seed)?;

        Ok(KeyManager {
            secp,
            network,
            key_derivation_path: key_derivation_path.to_string(),
            keystore,
        })
    }

    pub fn import_private_key(&self, private_key: &str) -> Result<PublicKey, KeyManagerError> {
        let private_key = PrivateKey::from_str(private_key)?;
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        self.keystore.store_keypair(private_key, public_key)?;

        Ok(public_key)
    }

    /*********************************/
    /******* Key Generation **********/
    /*********************************/
    pub fn generate_keypair<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<PublicKey, KeyManagerError> {
        let private_key = self.generate_private_key(self.network, rng);
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        self.keystore.store_keypair(private_key, public_key)?;

        Ok(public_key)
    }

    pub fn generate_master_xpub(&self) -> Result<Xpub, KeyManagerError> {
        let key_derivation_seed = self.keystore.load_key_derivation_seed()?;
        let master_xpriv = Xpriv::new_master(self.network, &key_derivation_seed)?;
        let master_xpub = Xpub::from_priv(&self.secp, &master_xpriv);

        Ok(master_xpub)
    }

    pub fn derive_keypair(&self, index: u32) -> Result<PublicKey, KeyManagerError> {
        let key_derivation_seed = self.keystore.load_key_derivation_seed()?;
        let master_xpriv = Xpriv::new_master(self.network, &key_derivation_seed)?;
        let derivation_path =
            DerivationPath::from_str(&format!("{}{}", self.key_derivation_path, index))?;
        let xpriv = master_xpriv.derive_priv(&self.secp, &derivation_path)?;

        let internal_keypair = xpriv.to_keypair(&self.secp);
        let public_key = PublicKey::new(internal_keypair.public_key());
        let private_key = PrivateKey::new(internal_keypair.secret_key(), self.network);

        self.keystore.store_keypair(private_key, public_key)?;

        Ok(public_key)
    }

    pub fn derive_public_key(
        &self,
        master_xpub: Xpub,
        index: u32,
    ) -> Result<PublicKey, KeyManagerError> {
        let secp = secp256k1::Secp256k1::new();
        let derivation_path =
            DerivationPath::from_str(&format!("{}{}", self.key_derivation_path, index))?;
        let xpub = master_xpub.derive_pub(&secp, &derivation_path)?;
        Ok(xpub.to_pub().into())
    }

    pub fn derive_winternitz(
        &self,
        message_size_in_bytes: usize,
        key_type: WinternitzType,
        index: u32,
    ) -> Result<winternitz::WinternitzPublicKey, KeyManagerError> {
        let message_digits_length = winternitz::message_digits_length(message_size_in_bytes);
        let checksum_size = checksum_length(message_digits_length);

        let master_secret = self.keystore.load_winternitz_seed()?;

        let winternitz = winternitz::Winternitz::new();
        let public_key = winternitz.generate_public_key(
            &master_secret,
            key_type,
            message_digits_length,
            checksum_size,
            index,
        )?;

        Ok(public_key)
    }

    fn generate_private_key<R: Rng + ?Sized>(&self, network: Network, rng: &mut R) -> PrivateKey {
        let secret_key = SecretKey::new(rng);
        PrivateKey::new(secret_key, network)
    }

    /*********************************/
    /*********** Signing *************/
    /*********************************/
    pub fn sign_ecdsa_message(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<secp256k1::ecdsa::Signature, KeyManagerError> {
        let (sk, _) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };

        Ok(self.secp.sign_ecdsa(message, &sk.inner))
    }

    pub fn sign_ecdsa_messages(
        &self,
        messages: Vec<Message>,
        public_keys: Vec<PublicKey>,
    ) -> Result<Vec<secp256k1::ecdsa::Signature>, KeyManagerError> {
        let mut signatures = Vec::new();

        for (message, public_key) in izip!(messages.iter(), public_keys.iter(),) {
            let signature = self.sign_ecdsa_message(message, public_key)?;
            signatures.push(signature);
        }

        Ok(signatures)
    }

    // For taproot script spend
    pub fn sign_schnorr_message(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<secp256k1::schnorr::Signature, KeyManagerError> {
        let (sk, _) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);

        Ok(self.secp.sign_schnorr(message, &keypair))
    }

    // For taproot key spend
    pub fn sign_schnorr_message_with_tap_tweak(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<(secp256k1::schnorr::Signature, PublicKey), KeyManagerError> {
        let (sk, _) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);

        let tweaked_keypair: TweakedKeypair = keypair.tap_tweak(&self.secp, None);
        let keypair = tweaked_keypair.to_inner();
        Ok((
            self.secp.sign_schnorr(message, &keypair),
            PublicKey::new(keypair.public_key()),
        ))
    }

    // For taproot key spend with tweak
    pub fn sign_schnorr_message_with_tweak(
        &self,
        message: &Message,
        public_key: &PublicKey,
        tweak: &Scalar,
    ) -> Result<(secp256k1::schnorr::Signature, PublicKey), KeyManagerError> {
        let (sk, _) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);
        let tweaked_keypair = keypair.add_xonly_tweak(&self.secp, tweak)?;

        Ok((
            self.secp.sign_schnorr(message, &tweaked_keypair),
            PublicKey::new(keypair.public_key()),
        ))
    }

    // For taproot script spend
    pub fn sign_schnorr_messages(
        &self,
        messages: Vec<Message>,
        public_keys: Vec<PublicKey>,
    ) -> Result<Vec<secp256k1::schnorr::Signature>, KeyManagerError> {
        let mut signatures = Vec::new();

        for (message, public_key) in izip!(messages.iter(), public_keys.iter(),) {
            let signature = self.sign_schnorr_message(message, public_key)?;
            signatures.push(signature);
        }

        Ok(signatures)
    }

    // For one-time winternitz keys
    pub fn sign_winternitz_message(
        &self,
        message_bytes: &[u8],
        key_type: WinternitzType,
        index: u32,
    ) -> Result<WinternitzSignature, KeyManagerError> {
        let message_digits_length = winternitz::message_digits_length(message_bytes.len());
        let checksummed_message = to_checksummed_message(message_bytes);
        let checksum_size = checksum_length(message_digits_length);
        let message_size = checksummed_message.len() - checksum_size;

        assert!(message_size == message_digits_length);

        let master_secret = self.keystore.load_winternitz_seed()?;
        let winternitz = winternitz::Winternitz::new();
        let private_key = winternitz.generate_private_key(
            &master_secret,
            key_type,
            message_size,
            checksum_size,
            index,
        )?;

        let signature =
            winternitz.sign_message(message_digits_length, &checksummed_message, &private_key);

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        key::rand::{self, RngCore},
        secp256k1::{self, Message, SecretKey},
        Network, PrivateKey, PublicKey,
    };
    use std::{env, panic, str::FromStr};

    use crate::{
        errors::{KeyManagerError, KeyStoreError, WinternitzError},
        keystorage::{database::DatabaseKeyStore, file::FileKeyStore, keystore::KeyStore},
        verifier::SignatureVerifier,
        winternitz::{to_checksummed_message, WinternitzType},
    };

    use super::KeyManager;

    const DERIVATION_PATH: &str = "m/101/1/0/0/";
    const REGTEST: Network = Network::Regtest;

    #[test]
    fn test_sign_ecdsa_message() -> Result<(), KeyManagerError> {
        let keystore = database_keystore(&temp_storage())?;

        let key_manager = test_key_manager(keystore)?;
        let signature_verifier = SignatureVerifier::new();

        let mut rng = secp256k1::rand::thread_rng();
        let pk = key_manager.generate_keypair(&mut rng)?;

        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, &pk)?;

        assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));

        Ok(())
    }

    #[test]
    fn test_sign_schnorr_message() -> Result<(), KeyManagerError> {
        let keystore = database_keystore(&temp_storage())?;
        let key_manager = test_key_manager(keystore)?;
        let signature_verifier = SignatureVerifier::new();

        let mut rng = secp256k1::rand::thread_rng();
        let pk = key_manager.generate_keypair(&mut rng)?;

        let message = random_message();
        let signature = key_manager.sign_schnorr_message(&message, &pk)?;

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk));

        Ok(())
    }

    #[test]
    fn test_sign_schnorr_message_with_tap_tweak() -> Result<(), KeyManagerError> {
        let keystore = database_keystore(&temp_storage())?;
        let key_manager = test_key_manager(keystore)?;
        let signature_verifier = SignatureVerifier::new();

        let mut rng = secp256k1::rand::thread_rng();
        let pk = key_manager.generate_keypair(&mut rng)?;

        let message = random_message();
        let (signature, tweaked_key) =
            key_manager.sign_schnorr_message_with_tap_tweak(&message, &pk)?;

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, tweaked_key));

        Ok(())
    }

    #[test]
    fn test_sign_winternitz_message_sha256() -> Result<(), KeyManagerError> {
        let keystore = database_keystore(&temp_storage())?;
        let key_manager = test_key_manager(keystore)?;
        let signature_verifier = SignatureVerifier::new();

        let message = random_message();

        let pk = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 0)?;
        let signature =
            key_manager.sign_winternitz_message(&message[..], WinternitzType::SHA256, 0)?;

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));
        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));

        Ok(())
    }

    #[test]
    fn test_sign_winternitz_message_ripemd160() -> Result<(), KeyManagerError> {
        let keystore = database_keystore(&temp_storage())?;
        let key_manager = test_key_manager(keystore)?;
        let signature_verifier = SignatureVerifier::new();

        let digest: [u8; 32] = [0xFE; 32];
        let message = Message::from_digest(digest);

        let pk = key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, 0)?;
        let signature =
            key_manager.sign_winternitz_message(&message[..], WinternitzType::HASH160, 0)?;

        println!("Pk size: {:?}", pk.total_len());
        println!("Msg: {:?}", &message[..]);

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));

        Ok(())
    }

    #[test]
    fn test_derive_key() -> Result<(), KeyManagerError> {
        let keystore = database_keystore(&temp_storage())?;
        let key_manager = test_key_manager(keystore)?;
        let signature_verifier = SignatureVerifier::new();

        let pk_1 = key_manager.derive_keypair(0)?;
        let pk_2 = key_manager.derive_keypair(1)?;

        assert_ne!(pk_1.to_string(), pk_2.to_string());

        let message = random_message();
        let signature_1 = key_manager.sign_ecdsa_message(&message, &pk_1)?;
        let signature_2 = key_manager.sign_ecdsa_message(&message, &pk_2)?;

        assert_ne!(signature_1.to_string(), signature_2.to_string());

        assert!(signature_verifier.verify_ecdsa_signature(&signature_1, &message, pk_1));
        assert!(signature_verifier.verify_ecdsa_signature(&signature_2, &message, pk_2));

        Ok(())
    }

    #[test]
    fn test_key_generation() -> Result<(), KeyManagerError> {
        let keystore = database_keystore(&temp_storage())?;
        let key_manager = test_key_manager(keystore)?;
        let mut rng = secp256k1::rand::thread_rng();

        let message = random_message();
        let checksummed = to_checksummed_message(&message[..]);

        let pk1 = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 0)?;
        let pk2 = key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, 8)?;
        let pk3 = key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, 8)?;
        let pk4 = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 8)?;
        let pk5 = key_manager.generate_keypair(&mut rng)?;
        let pk6 = key_manager.generate_keypair(&mut rng)?;

        assert!(pk1.total_len() == checksummed.len());
        assert!(pk2.total_len() == checksummed.len());
        assert!(pk1.hash_size() == 32);
        assert!(pk2.hash_size() == 20);
        assert!(pk5.to_bytes().len() == 33);

        assert!(pk1 != pk2);
        assert!(pk2 == pk3);
        assert!(pk2 != pk4);
        assert!(pk5 != pk6);

        Ok(())
    }

    #[test]
    fn test_keystore() -> Result<(), KeyManagerError> {
        let path = temp_storage();
        let password = b"secret password".to_vec();
        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = random_bytes();
        let key_derivation_seed = random_bytes();

        let keystore = FileKeyStore::new(path, password, Network::Regtest)?;
        keystore.store_winternitz_seed(winternitz_seed)?;
        keystore.store_key_derivation_seed(key_derivation_seed)?;

        for _ in 0..10 {
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            let private_key = PrivateKey::new(secret_key, Network::Regtest);
            let public_key = PublicKey::from_private_key(&secp, &private_key);

            keystore.store_keypair(private_key, public_key)?;

            let (restored_sk, restored_pk) = match keystore.load_keypair(&public_key)? {
                Some(entry) => entry,
                None => panic!("Failed to find key"),
            };

            assert_eq!(restored_sk.to_string(), private_key.to_string());
            assert_eq!(restored_pk.to_string(), public_key.to_string());
        }

        let loaded_winternitz_seed = keystore.load_winternitz_seed()?;
        assert!(loaded_winternitz_seed == winternitz_seed);

        let loaded_key_derivation_seed = keystore.load_key_derivation_seed()?;
        assert!(loaded_key_derivation_seed == key_derivation_seed);

        Ok(())
    }

    #[test]
    fn test_keystore_index() -> Result<(), KeyManagerError> {
        let path = temp_storage();
        let password = b"secret password".to_vec();
        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = random_bytes();
        let key_derivation_seed = random_bytes();

        let keystore = FileKeyStore::new(&path, password, Network::Regtest)?;
        keystore.store_winternitz_seed(winternitz_seed)?;
        keystore.store_key_derivation_seed(key_derivation_seed)?;

        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, Network::Regtest);
        let public_key = PublicKey::from_private_key(&secp, &private_key);

        keystore.store_keypair(private_key, public_key)?;

        let (_, recovered_public_key) = match keystore.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        assert_eq!(recovered_public_key.to_string(), public_key.to_string());

        // Create a second SecureStorage instance to test that the indexes are restored correctly by loading the same storage file        let password = b"secret password".to_vec();
        let password = b"secret password".to_vec();
        let keystore_2 = FileKeyStore::new(&path, password, Network::Regtest)?;

        let (_, recovered_public_key_2) = match keystore_2.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        assert_eq!(recovered_public_key_2.to_string(), public_key.to_string());

        Ok(())
    }

    #[test]
    fn test_error_handling() -> Result<(), KeyManagerError> {
        let message = random_message();

        let keystore = database_keystore(&temp_storage())?;
        let mut key_manager = test_key_manager(keystore)?;

        // Case 1: Invalid private key string
        let result = key_manager.import_private_key("invalid_key");
        assert!(matches!(
            result,
            Err(KeyManagerError::FailedToParsePrivateKey(_))
        ));

        // Case 2: Invalid derivation path
        let invalid_derivation_path = "m/44'/invalid'";
        key_manager.key_derivation_path = invalid_derivation_path.to_string();
        let result = key_manager.derive_keypair(0);
        assert!(matches!(result, Err(KeyManagerError::Bip32Error(_))));

        // Case 3 a: Storage error when creating file keystore (invalid path)
        let result = file_keystore("/invalid/path");
        assert!(matches!(result, Err(KeyStoreError::StorageError(_))));

        // Case 3 b: Write error when creating database keystore (invalid path)
        //TODO: FIX THIS TEST is not working in windows envs
        //let result = database_keystore("/invalid/path");
        //assert!(matches!(result, Err(KeyStoreError::WriteError(_))));

        // Case 4: Index overflow when generating keys
        let result =
            key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, u32::MAX);
        assert!(matches!(
            result,
            Err(KeyManagerError::WinternitzGenerationError(
                WinternitzError::IndexOverflow
            ))
        ));

        // Case 5: Entry not found for public key
        let fake_public_key = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )?;
        let result = key_manager.sign_ecdsa_message(&random_message(), &fake_public_key);
        assert!(matches!(result, Err(KeyManagerError::EntryNotFound)));

        Ok(())
    }

    #[test]
    fn test_signature_with_bip32_derivation() {
        let keystore = database_keystore(&temp_storage()).unwrap();
        let key_manager = test_key_manager(keystore).unwrap();

        let master_xpub = key_manager.generate_master_xpub().unwrap();

        for i in 0..5 {
            let pk1 = key_manager.derive_keypair(i).unwrap();
            let pk2 = key_manager.derive_public_key(master_xpub, i).unwrap();

            let signature_verifier = SignatureVerifier::new();
            let message = random_message();
            let signature = key_manager.sign_ecdsa_message(&message, &pk1).unwrap();

            assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk2));
        }

        let pk1 = key_manager.derive_keypair(10).unwrap();
        let pk2 = key_manager.derive_public_key(master_xpub, 11).unwrap();

        let signature_verifier = SignatureVerifier::new();
        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, &pk1).unwrap();

        assert!(!signature_verifier.verify_ecdsa_signature(&signature, &message, pk2));
    }

    #[test]
    fn test_schnorr_signature_with_bip32_derivation() {
        let keystore = database_keystore(&temp_storage()).unwrap();
        let key_manager = test_key_manager(keystore).unwrap();

        let master_xpub = key_manager.generate_master_xpub().unwrap();

        for i in 0..5 {
            let pk1 = key_manager.derive_keypair(i).unwrap();
            let pk2 = key_manager.derive_public_key(master_xpub, i).unwrap();

            let signature_verifier = SignatureVerifier::new();
            let message = random_message();
            let signature = key_manager.sign_schnorr_message(&message, &pk1).unwrap();

            assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk2));
        }

        let pk1 = key_manager.derive_keypair(10).unwrap();
        let pk2 = key_manager.derive_public_key(master_xpub, 11).unwrap();

        let signature_verifier = SignatureVerifier::new();
        let message = random_message();
        let signature = key_manager.sign_schnorr_message(&message, &pk1).unwrap();

        assert!(!signature_verifier.verify_schnorr_signature(&signature, &message, pk2));
    }

    #[test]
    fn test_key_derivation_from_xpub_in_different_key_manager() {
        let keystore = database_keystore(&temp_storage()).unwrap();
        let key_manager_1 = test_key_manager(keystore).unwrap();

        let keystore = database_keystore(&temp_storage()).unwrap();
        let key_manager_2 = test_key_manager(keystore).unwrap();

        for i in 0..5 {
            // Create master_xpub in key_manager_1 and derive public key in key_manager_2 for a given index
            let master_xpub = key_manager_1.generate_master_xpub().unwrap();
            let public_from_xpub = key_manager_2.derive_public_key(master_xpub, i).unwrap();

            // Derive keypair in key_manager_1 with the same index
            let public_from_xpriv = key_manager_1.derive_keypair(i).unwrap();

            // Both public keys must be equal
            assert_eq!(public_from_xpub.to_string(), public_from_xpriv.to_string());
        }
    }

    fn test_key_manager<K: KeyStore>(keystore: K) -> Result<KeyManager<K>, KeyManagerError> {
        let key_derivation_seed = random_bytes();
        let winternitz_seed = random_bytes();

        let key_manager = KeyManager::new(
            REGTEST,
            DERIVATION_PATH,
            key_derivation_seed,
            winternitz_seed,
            keystore,
        )?;

        Ok(key_manager)
    }

    fn file_keystore(storage_path: &str) -> Result<FileKeyStore, KeyStoreError> {
        let password = b"secret password".to_vec();
        FileKeyStore::new(storage_path, password, Network::Regtest)
    }

    fn database_keystore(storage_path: &str) -> Result<DatabaseKeyStore, KeyStoreError> {
        let password = b"secret password".to_vec();
        DatabaseKeyStore::new(storage_path, password, Network::Regtest)
    }

    fn random_message() -> Message {
        let mut digest = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut digest);
        Message::from_digest(digest)
    }

    fn random_bytes() -> [u8; 32] {
        let mut seed = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }

    fn temp_storage() -> String {
        let dir = env::temp_dir();

        let mut rng = rand::thread_rng();
        let index = rng.next_u32();

        let storage_path = dir.join(format!("keystore_{}.db", index));
        storage_path
            .to_str()
            .expect("Failed to get path to temp file")
            .to_string()
    }
}
