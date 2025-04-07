use std::{collections::HashMap, rc::Rc, str::FromStr};

use bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    hashes::{self, Hash},
    key::{rand::Rng, Keypair, Parity, TapTweak},
    secp256k1::{self, All, Message, Scalar, SecretKey},
    Network, PrivateKey, PublicKey, TapNodeHash,
};
use itertools::izip;
use storage_backend::storage::Storage;
use tracing::{debug, info};

use crate::{
    errors::KeyManagerError, keystorage::keystore::KeyStore, musig2::{errors::Musig2SignerError, musig::{MuSig2Signer, MuSig2SignerApi}, types::MessageId}, winternitz::{
        self, checksum_length, to_checksummed_message, WinternitzSignature, WinternitzType,
    }
};

use musig2::{sign_partial, AggNonce, PartialSignature, PubNonce, SecNonce};

/// This module provides a key manager for managing BitVMX keys and signatures.
/// It includes functionality for generating, importing, and deriving keys, as well as signing messages
/// using ECDSA, Schnorr and Winternitz algorithms. The key manager uses a secure storage mechanism
/// to store the keys.
pub struct KeyManager<K: KeyStore> {
    secp: secp256k1::Secp256k1<All>,
    network: Network,
    key_derivation_path: String,
    musig2: MuSig2Signer,
    keystore: K,
}

impl<K: KeyStore> KeyManager<K> {
    pub fn new(
        network: Network,
        key_derivation_path: &str,
        key_derivation_seed: [u8; 32],
        winternitz_seed: [u8; 32],
        keystore: K,
        store: Rc<Storage>,
    ) -> Result<Self, KeyManagerError> {
        let secp = secp256k1::Secp256k1::new();

        keystore.store_winternitz_seed(winternitz_seed)?;
        keystore.store_key_derivation_seed(key_derivation_seed)?;

        let musig2 = MuSig2Signer::new(store.clone());

        Ok(KeyManager {
            secp,
            network,
            key_derivation_path: key_derivation_path.to_string(),
            musig2,
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

        // For taproot keys
        let(public_key, private_key) = self.adjust_parity(internal_keypair);

        self.keystore.store_keypair(private_key, public_key)?;
        Ok(public_key)
    }

    // This method changes the parity of a keypair to be even, this is needed for Taproot.
    fn adjust_parity(&self, keypair: Keypair) -> (PublicKey, PrivateKey) {
        let (_, parity) = keypair.public_key().x_only_public_key();
        
        if parity == Parity::Odd {
            (PublicKey::new(keypair.public_key().negate(&self.secp)), PrivateKey::new(keypair.secret_key().negate(), self.network))
        } else {
            (PublicKey::new(keypair.public_key()), PrivateKey::new(keypair.secret_key(), self.network))
        }
    }

    // This method changes the parity of a public key to be even, this is needed for Taproot.
    fn adjust_public_key_only_parity(&self, public_key: PublicKey) -> PublicKey {
        let (_, parity) = public_key.inner.x_only_public_key();
        
        if parity == Parity::Odd {
            PublicKey::new(public_key.inner.negate(&self.secp))
        } else {
            public_key
        }
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

        Ok(self.adjust_public_key_only_parity(xpub.to_pub().into()))
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

    pub fn derive_multiple_winternitz(
        &self,
        message_size_in_bytes: usize,
        key_type: WinternitzType,
        initial_index: u32,
        number_of_keys: u32,
    ) -> Result<Vec<winternitz::WinternitzPublicKey>, KeyManagerError> {
        let message_digits_length = winternitz::message_digits_length(message_size_in_bytes);
        let checksum_size = checksum_length(message_digits_length);

        let master_secret = self.keystore.load_winternitz_seed()?;

        let mut public_keys = Vec::new();

        for index in initial_index..initial_index + number_of_keys {
            let winternitz = winternitz::Winternitz::new();
            let public_key = winternitz.generate_public_key(
                &master_secret,
                key_type,
                message_digits_length,
                checksum_size,
                index,
            )?;
            public_keys.push(public_key);
        }

        Ok(public_keys)
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
        merkle_root: Option<TapNodeHash>
    ) -> Result<(secp256k1::schnorr::Signature, PublicKey), KeyManagerError> {
        let (sk, _) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);

        let tweaked_keypair = keypair.tap_tweak(&self.secp, merkle_root);
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

    /*********************************/
    /*********** MuSig2 **************/
    /*********************************/

    pub fn sign_partial_message(
        &self,
        id: &str,
        my_public_key: PublicKey,
        secnonce: SecNonce,
        aggregated_nonce: AggNonce,
        tweak: Option<musig2::secp256k1::Scalar>,
        message: Vec<u8>,
    ) -> Result<PartialSignature, KeyManagerError> {
        let key_aggregation_context = self.musig2.get_key_agg_context(id, tweak).unwrap();

        let (private_key, _) = match self.keystore.load_keypair(&my_public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };

        let sk = musig2::secp256k1::SecretKey::from_slice(&private_key[..])
            .map_err(|_| KeyManagerError::InvalidPrivateKey)?;

        let result = sign_partial(&key_aggregation_context, sk, secnonce, &aggregated_nonce, message);

        match result {
            Ok(signature) => Ok(signature),
            Err(e) => {
                debug!("Failed to sign message: {:?}", e);
                return Err(KeyManagerError::FailedToSignMessage);
            }
        }
    }

    pub fn generate_nonce_seed(
        &self,
        index: u32,
        public_key: PublicKey,
    ) -> Result<[u8; 32], KeyManagerError> {
        let (sk, _) = match self.keystore.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => return Err(KeyManagerError::EntryNotFound),
        };

        let mut data = Vec::new();
        data.extend_from_slice(&sk.to_bytes());
        data.extend_from_slice(&index.to_le_bytes());

        let nonce_seed = hashes::sha256::Hash::hash(data.as_slice()).to_byte_array();

        Ok(nonce_seed)
    }

    pub fn new_musig2_session(
        &self,
        id: &str,
        participant_pubkeys: Vec<PublicKey>,
        my_pub_key: PublicKey,
    ) -> Result<PublicKey, Musig2SignerError> {
        self.musig2.new_session(id, participant_pubkeys, my_pub_key)
    }

    pub fn aggregate_nonces(
        &self,
        id: &str,
        pub_nonces_map: HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
    ) -> Result<(), Musig2SignerError> {
        self.musig2.aggregate_nonces(id, pub_nonces_map)
    }

    pub fn get_my_pub_nonces(&self, id: &str) -> Result<Vec<(MessageId, PubNonce)>, Musig2SignerError> {
        self.musig2.get_my_pub_nonces(id)
    }

    pub fn save_partial_signatures(
        &self,
        id: &str,
        other_public_key: PublicKey,
        other_partial_signatures: Vec<(MessageId, PartialSignature)>,
    ) -> Result<Vec<(MessageId, PartialSignature)>, Musig2SignerError> {
        let mut partial_signatures = HashMap::new();
        partial_signatures.insert(other_public_key, other_partial_signatures);

        let my_partial_signatures = self.get_my_partial_signatures(id)?;
        let my_pub_key = self.musig2.my_public_key(id)?;

        partial_signatures.insert(my_pub_key, my_partial_signatures.clone());

        self.musig2.save_partial_signatures(id, partial_signatures)?;

        Ok(my_partial_signatures)
    }

    pub fn get_my_partial_signatures(
        &self,
        id: &str,
    ) -> Result<Vec<(MessageId, PartialSignature)>, Musig2SignerError> {
        let mut my_partial_signatures = Vec::new();

        let data_to_iterate = self.musig2.get_data_for_partial_signatures(id)?;
        let my_pub_key = self.musig2.my_public_key(id)?;

        for (message_id, (message, sec_nonce, tweak,  aggregated_nonce)) in data_to_iterate.iter() {
            let sig = self
                .sign_partial_message(
                    id,
                my_pub_key,
                    sec_nonce.clone(),
                    aggregated_nonce.clone(),
                    tweak.clone(),
                    message.clone(),
                )
                .map_err(|_| Musig2SignerError::InvalidSignature)?;

            my_partial_signatures.push((message_id.clone(), sig));
        }

        Ok(my_partial_signatures)
    }

    pub fn get_aggregated_signature(
        &self,
        musig_id: &str,
        message_id: &str,
    ) -> Result<secp256k1::schnorr::Signature, Musig2SignerError> {
        self.musig2.get_aggregated_signature(musig_id, message_id)
    }

    pub fn generate_nonce(
        &self,
        musig_id: &str,
        message_id: &str,
        message: Vec<u8>,
        aggregated_pubkey: &PublicKey,
        tweak: Option<musig2::secp256k1::Scalar>,
    ) -> Result<(), Musig2SignerError> {

        let index = self.musig2.get_index(musig_id)?;
        let public_key = self.musig2.my_public_key(musig_id)?;

        let nonce_seed: [u8; 32] = self
            .generate_nonce_seed(index, public_key)
            .map_err(|_| Musig2SignerError::NonceSeedError)?;

        self.musig2.generate_nonce(musig_id, message_id, message, aggregated_pubkey, tweak, nonce_seed)
    }

    pub fn get_aggregated_pubkey(
        &self,
        id: &str,
    ) -> Result<PublicKey, Musig2SignerError> {
        self.musig2.get_aggregated_pubkey(id)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        hex::DisplayHex,
        key::rand::{self, rngs::mock::StepRng, RngCore},
        secp256k1::{self, Message, SecretKey},
        Network, PrivateKey, PublicKey,
    };
    use storage_backend::storage::Storage;
    use std::{env, fs, panic, path::PathBuf, rc::Rc, str::FromStr};

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
    fn test_generate_nonce_seed() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;
        
        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store)?;
        let mut rng = StepRng::new(1, 0);
        let pub_key: PublicKey = key_manager.generate_keypair(&mut rng)?;

        let mut rng = StepRng::new(2, 0);
        let pub_key2: PublicKey = key_manager.generate_keypair(&mut rng)?;

        // Small test to check that the nonce is deterministic with the same index and public key
        let nonce_seed = key_manager.generate_nonce_seed(0, pub_key)?;
        assert_eq!(
            nonce_seed.to_lower_hex_string(),
            "bb4f914ef003427e2eb5dd2547da171c130dfb09362e56033eaad94d81fe45a6"
        );
        let nonce_seed = key_manager.generate_nonce_seed(0, pub_key)?;
        assert_eq!(
            nonce_seed.to_lower_hex_string(),
            "bb4f914ef003427e2eb5dd2547da171c130dfb09362e56033eaad94d81fe45a6"
        );

        // Test that the nonce is different for different index
        let nonce_seed = key_manager.generate_nonce_seed(1, pub_key)?;
        assert_eq!(
            nonce_seed.to_lower_hex_string(),
            "30364fcd5b5dc41f5261219ed4db2c8b57e2a6b025852cda02e8718256661339"
        );
        let nonce_seed = key_manager.generate_nonce_seed(4, pub_key)?;
        assert_eq!(
            nonce_seed.to_lower_hex_string(),
            "335884b6a1febb486b546cd7fd64f262dab8f0577892a7dd2fe96b501c1e5139"
        );

        // Test that the nonce is different for different public key
        let nonce_seed = key_manager.generate_nonce_seed(0, pub_key2)?;
        assert_ne!(
            nonce_seed.to_lower_hex_string(),
            "bb4f914ef003427e2eb5dd2547da171c130dfb09362e56033eaad94d81fe45a6"
        );

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_sign_ecdsa_message() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store)?;
        let signature_verifier = SignatureVerifier::new();

        let mut rng = secp256k1::rand::thread_rng();
        let pk = key_manager.generate_keypair(&mut rng)?;

        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, &pk)?;

        assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_sign_schnorr_message() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store)?;
        let signature_verifier = SignatureVerifier::new();

        let mut rng = secp256k1::rand::thread_rng();
        let pk = key_manager.generate_keypair(&mut rng)?;

        let message = random_message();
        let signature = key_manager.sign_schnorr_message(&message, &pk)?;

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk));

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_sign_schnorr_message_with_tap_tweak() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store)?;
        let signature_verifier = SignatureVerifier::new();

        let mut rng = secp256k1::rand::thread_rng();
        let pk = key_manager.generate_keypair(&mut rng)?;

        let message = random_message();
        let (signature, tweaked_key) =
            key_manager.sign_schnorr_message_with_tap_tweak(&message, &pk, None)?;

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, tweaked_key));

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_sign_winternitz_message_sha256() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store)?;
        let signature_verifier = SignatureVerifier::new();

        let message = random_message();

        let pk = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 0)?;
        let signature =
            key_manager.sign_winternitz_message(&message[..], WinternitzType::SHA256, 0)?;

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));
        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_sign_winternitz_message_ripemd160() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store)?;
        let signature_verifier = SignatureVerifier::new();

        let digest: [u8; 32] = [0xFE; 32];
        let message = Message::from_digest(digest);

        let pk = key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, 0)?;
        let signature =
            key_manager.sign_winternitz_message(&message[..], WinternitzType::HASH160, 0)?;

        println!("Pk size: {:?}", pk.total_len());
        println!("Msg: {:?}", &message[..]);

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_derive_key() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store)?;
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

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_key_generation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store)?;
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

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_keystore() -> Result<(), KeyManagerError> {
        let path = temp_storage();
        let password = b"secret password".to_vec();
        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = random_bytes();
        let key_derivation_seed = random_bytes();

        let keystore = FileKeyStore::new(&path, password, Network::Regtest)?;
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

        cleanup_file_storage(&path);
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

        // Create a second SecureStorage instance to test that the indexes are restored correctly by loading the same storage file let password = b"secret password".to_vec();
        let password = b"secret password".to_vec();
        let keystore_2 = FileKeyStore::new(&path, password, Network::Regtest)?;

        let (_, recovered_public_key_2) = match keystore_2.load_keypair(&public_key)? {
            Some(entry) => entry,
            None => panic!("Failed to find key"),
        };

        assert_eq!(recovered_public_key_2.to_string(), public_key.to_string());

        cleanup_file_storage(&path);
        Ok(())
    }

    #[test]
    fn test_error_handling() -> Result<(), KeyManagerError> {
        let message = random_message();

        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let mut key_manager = test_key_manager(keystore, store)?;

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

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_signature_with_bip32_derivation() {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).unwrap();

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store).unwrap();

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

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
    }

    #[test]
    fn test_schnorr_signature_with_bip32_derivation() {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).unwrap();
        
        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store).unwrap();

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

        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
    }

    #[test]
    fn test_key_derivation_from_xpub_in_different_key_manager() {
        let keystore_path_1 = temp_storage();
        let keystore = database_keystore(&keystore_path_1).unwrap();

        let store_path_1 = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path_1.clone())).unwrap());

        let key_manager_1 = test_key_manager(keystore, store).unwrap();

        let keystore_path_2 = temp_storage();
        let keystore = database_keystore(&keystore_path_2).unwrap();

        let store_path_2 = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path_2.clone())).unwrap());

        let key_manager_2 = test_key_manager(keystore, store).unwrap();

        for i in 0..5 {
            // Create master_xpub in key_manager_1 and derive public key in key_manager_2 for a given index
            let master_xpub = key_manager_1.generate_master_xpub().unwrap();
            let public_from_xpub = key_manager_2.derive_public_key(master_xpub, i).unwrap();

            // Derive keypair in key_manager_1 with the same index
            let public_from_xpriv = key_manager_1.derive_keypair(i).unwrap();

            // Both public keys must be equal
            assert_eq!(public_from_xpub.to_string(), public_from_xpriv.to_string());
        }

        cleanup_storage(&keystore_path_1);
        cleanup_storage(&keystore_path_2);
        cleanup_storage(&store_path_1);
        cleanup_storage(&store_path_2);
    }

    #[test]
    fn test_derive_multiple_winternitz_gives_same_result_as_doing_one_by_one(){
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).unwrap();

        let store_path = temp_storage();
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(store_path.clone())).unwrap());

        let key_manager = test_key_manager(keystore, store).unwrap();

        let message_size_in_bytes = 32;
        let key_type = WinternitzType::SHA256;
        let initial_index = 0;
        let number_of_keys: u32 = 10;

        let public_keys = key_manager.derive_multiple_winternitz(
            message_size_in_bytes,
            key_type,
            initial_index,
            number_of_keys,
        ).unwrap();

        for i in 0..number_of_keys {
            let public_key = key_manager.derive_winternitz(
                message_size_in_bytes,
                key_type,
                initial_index + i,
            ).unwrap();

            assert_eq!(public_keys[i as usize], public_key);
        }
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
    }

    fn test_key_manager<K: KeyStore>(keystore: K, store: Rc<Storage>) -> Result<KeyManager<K>, KeyManagerError> {
        let key_derivation_seed = random_bytes();
        let winternitz_seed = random_bytes();

        let key_manager = KeyManager::new(
            REGTEST,
            DERIVATION_PATH,
            key_derivation_seed,
            winternitz_seed,
            keystore,
            store,
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

    fn cleanup_storage(path: &str) {
        fs::remove_dir_all(path).unwrap();
    }

    fn cleanup_file_storage(path: &str) {
        fs::remove_file(path).unwrap();
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
