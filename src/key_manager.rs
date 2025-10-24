use std::{collections::HashMap, rc::Rc, str::FromStr};

use bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    hashes::{self, Hash},
    key::{
        rand::{Rng, RngCore},
        Keypair, Parity, TapTweak,
    },
    secp256k1::{self, All, Message, Scalar, SecretKey},
    Network, PrivateKey, PublicKey, TapNodeHash,
};

use itertools::izip;
use storage_backend::storage::Storage;
use tracing::debug;

use crate::{
    errors::KeyManagerError,
    key_store::KeyStore,
    musig2::{
        errors::Musig2SignerError,
        musig::{MuSig2Signer, MuSig2SignerApi},
        types::MessageId,
    },
    rsa::{CryptoRng, OsRng, RSAKeyPair, Signature},
    winternitz::{
        self, checksum_length, to_checksummed_message, WinternitzSignature, WinternitzType,
    },
};

use musig2::{sign_partial, AggNonce, PartialSignature, PubNonce, SecNonce};

const RSA_BITS: usize = 2048; // RSA key size in bits

/// This module provides a key manager for managing BitVMX keys and signatures.
/// It includes functionality for generating, importing, and deriving keys, as well as signing messages
/// using ECDSA, Schnorr and Winternitz algorithms. The key manager uses a secure storage mechanism
/// to store the keys.
pub struct KeyManager {
    secp: secp256k1::Secp256k1<All>,
    network: Network,
    key_derivation_path: String,
    musig2: MuSig2Signer,
    keystore: KeyStore,
}

impl KeyManager {
    pub fn new(
        network: Network,
        key_derivation_path: &str,
        key_derivation_seed: Option<[u8; 32]>,
        winternitz_seed: Option<[u8; 32]>,
        keystore: KeyStore,
        store: Rc<Storage>,
    ) -> Result<Self, KeyManagerError> {
        if keystore.load_winternitz_seed().is_err() {
            match winternitz_seed {
                Some(seed) => keystore.store_winternitz_seed(seed)?,
                None => {
                    let mut seed = [0u8; 32];
                    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
                    keystore.store_winternitz_seed(seed)?;
                }
            }
        }

        if keystore.load_key_derivation_seed().is_err() {
            match key_derivation_seed {
                Some(seed) => keystore.store_key_derivation_seed(seed)?,
                None => {
                    let mut seed = [0u8; 32];
                    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
                    keystore.store_key_derivation_seed(seed)?;
                }
            }
        }

        let musig2 = MuSig2Signer::new(store.clone());
        let secp = secp256k1::Secp256k1::new();

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

    pub fn import_secret_key(
        &self,
        secret_key: &str,
        network: Network,
    ) -> Result<PublicKey, KeyManagerError> {
        let secret_key = SecretKey::from_str(secret_key)?;
        let private_key = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&self.secp, &private_key);

        self.keystore.store_keypair(private_key, public_key)?;
        Ok(public_key)
    }

    pub fn import_partial_secret_keys(
        &self,
        partial_keys: Vec<String>,
        network: Network,
    ) -> Result<PublicKey, KeyManagerError> {
        let partial_keys_bytes: Vec<Vec<u8>> = partial_keys
            .into_iter()
            .map(|key| SecretKey::from_str(&key).map(|sk| sk.secret_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;

        let (private_key, public_key) = self
            .musig2
            .aggregate_private_key(partial_keys_bytes, network)?;
        self.keystore.store_keypair(private_key, public_key)?;
        Ok(public_key)
    }

    pub fn import_partial_private_keys(
        &self,
        partial_keys: Vec<String>,
        network: Network,
    ) -> Result<PublicKey, KeyManagerError> {
        let partial_keys_bytes: Vec<Vec<u8>> = partial_keys
            .into_iter()
            .map(|key| PrivateKey::from_str(&key).map(|pk| pk.to_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?;

        let (private_key, public_key) = self
            .musig2
            .aggregate_private_key(partial_keys_bytes, network)?;
        self.keystore.store_keypair(private_key, public_key)?;
        Ok(public_key)
    }

    pub fn import_rsa_private_key(
        &self,
        private_key: &str, // PEM format
        index: usize,
    ) -> Result<String, KeyManagerError> {
        let rsa_keypair = RSAKeyPair::from_private_pem(private_key)?;
        self.keystore.store_rsa_key(rsa_keypair.clone(), index)?;
        let rsa_pubkey_pem = rsa_keypair.export_public_pem()?;
        Ok(rsa_pubkey_pem)
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
        let (public_key, private_key) = self.adjust_parity(internal_keypair);

        self.keystore.store_keypair(private_key, public_key)?;
        Ok(public_key)
    }

    // This method changes the parity of a keypair to be even, this is needed for Taproot.
    fn adjust_parity(&self, keypair: Keypair) -> (PublicKey, PrivateKey) {
        let (_, parity) = keypair.public_key().x_only_public_key();

        if parity == Parity::Odd {
            (
                PublicKey::new(keypair.public_key().negate(&self.secp)),
                PrivateKey::new(keypair.secret_key().negate(), self.network),
            )
        } else {
            (
                PublicKey::new(keypair.public_key()),
                PrivateKey::new(keypair.secret_key(), self.network),
            )
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

    pub fn generate_rsa_keypair<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        index: usize,
    ) -> Result<String, KeyManagerError> {
        let rsa_keypair = RSAKeyPair::new(rng, RSA_BITS)?;
        self.keystore.store_rsa_key(rsa_keypair.clone(), index)?;
        let rsa_pubkey_pem = rsa_keypair.export_public_pem()?;
        Ok(rsa_pubkey_pem)
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
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_ecdsa_message compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        Ok(self.secp.sign_ecdsa(message, &sk.inner))
    }

    pub fn sign_ecdsa_recoverable_message(
        &self,
        message: &Message,
        public_key: &PublicKey,
    ) -> Result<secp256k1::ecdsa::RecoverableSignature, KeyManagerError> {
        let (sk, _) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_ecdsa_recoverable_message compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        Ok(self.secp.sign_ecdsa_recoverable(message, &sk.inner))
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

    pub fn sign_ecdsa_recoverable_messages(
        &self,
        messages: Vec<Message>,
        public_keys: Vec<PublicKey>,
    ) -> Result<Vec<secp256k1::ecdsa::RecoverableSignature>, KeyManagerError> {
        let mut signatures = Vec::new();

        for (message, public_key) in izip!(messages.iter(), public_keys.iter(),) {
            let signature = self.sign_ecdsa_recoverable_message(message, public_key)?;
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
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_schnorr_message compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )));
            }
        };

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);

        Ok(self.secp.sign_schnorr(message, &keypair))
    }

    // For taproot key spend
    pub fn sign_schnorr_message_with_tap_tweak(
        &self,
        message: &Message,
        public_key: &PublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<(secp256k1::schnorr::Signature, PublicKey), KeyManagerError> {
        let (sk, _) = match self.keystore.load_keypair(public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_schnorr_message_with_tap_tweak compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        let keypair = Keypair::from_secret_key(&self.secp, &sk.inner);

        let tweaked_keypair = keypair.tap_tweak(&self.secp, merkle_root);
        let keypair = tweaked_keypair.into();
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
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_schnorr_message_with_tweak compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
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

    pub fn export_secret(&self, pubkey: &PublicKey) -> Result<PrivateKey, KeyManagerError> {
        match self.keystore.load_keypair(pubkey)? {
            Some(entry) => Ok(entry.0),
            None => Err(KeyManagerError::KeyPairNotFound(format!(
                "export_secret compressed {} public key: {:?}",
                pubkey.to_string(),
                pubkey
            ))),
        }
    }

    pub fn sign_rsa_message(
        &self,
        message: &[u8],
        index: usize,
    ) -> Result<Signature, KeyManagerError> {
        let rsa_key = self.keystore.load_rsa_key(index)?;
        match rsa_key {
            Some(rsa_key) => Ok(rsa_key.sign(message)),
            None => return Err(KeyManagerError::RsaKeyIndexNotFound(index)),
        }
    }

    pub fn encrypt_rsa_message(
        &self,
        message: &[u8],
        pub_key: String, // PEM format
    ) -> Result<Vec<u8>, KeyManagerError> {
        Ok(RSAKeyPair::encrypt(message, &pub_key, &mut OsRng)?)
    }

    pub fn decrypt_rsa_message(
        &self,
        encrypted_message: &[u8],
        index: usize,
    ) -> Result<Vec<u8>, KeyManagerError> {
        let rsa_key = self.keystore.load_rsa_key(index)?;
        match rsa_key {
            Some(rsa_key) => Ok(rsa_key.decrypt(encrypted_message)?),
            None => return Err(KeyManagerError::RsaKeyIndexNotFound(index)),
        }
    }

    /*********************************/
    /*********** MuSig2 **************/
    /*********************************/

    //TODO: Revisit this decision. The private key is used for the TOO protoocl.
    pub fn get_key_pair_for_too_insecure(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<(PrivateKey, PublicKey), KeyManagerError> {
        let my_pub_key = self.musig2.my_public_key(aggregated_pubkey).unwrap();

        match self.keystore.load_keypair(&my_pub_key)? {
            Some(entry) => Ok(entry),
            None => Err(KeyManagerError::KeyPairNotFound(format!(
                "get_key_pair_for_too_insecure compressed {} public key: {:?}",
                my_pub_key.to_string(),
                my_pub_key
            ))),
        }
    }

    pub fn sign_partial_message(
        &self,
        aggregated_pubkey: &PublicKey,
        my_public_key: PublicKey,
        secnonce: SecNonce,
        aggregated_nonce: AggNonce,
        tweak: Option<musig2::secp256k1::Scalar>,
        message: Vec<u8>,
    ) -> Result<PartialSignature, KeyManagerError> {
        let key_aggregation_context = self.musig2.get_key_agg_context(aggregated_pubkey, tweak)?;

        let (private_key, _) = match self.keystore.load_keypair(&my_public_key)? {
            Some(entry) => entry,
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "sign_partial_message compressed {} public key: {:?}",
                    my_public_key.to_string(),
                    my_public_key
                )))
            }
        };

        let sk = musig2::secp256k1::SecretKey::from_slice(&private_key[..])
            .map_err(|_| KeyManagerError::InvalidPrivateKey)?;

        let result = sign_partial(
            &key_aggregation_context,
            sk,
            secnonce,
            &aggregated_nonce,
            message,
        );

        match result {
            Ok(signature) => Ok(signature),
            Err(e) => {
                debug!("Failed to sign message: {:?}", e);
                Err(KeyManagerError::FailedToSignMessage)
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
            None => {
                return Err(KeyManagerError::KeyPairNotFound(format!(
                    "generate_nonce_seed compressed {} public key: {:?}",
                    public_key.to_string(),
                    public_key
                )))
            }
        };

        let mut data = Vec::new();
        data.extend_from_slice(&sk.to_bytes());
        data.extend_from_slice(&index.to_le_bytes());

        let nonce_seed = hashes::sha256::Hash::hash(data.as_slice()).to_byte_array();

        Ok(nonce_seed)
    }

    pub fn new_musig2_session(
        &self,
        participant_pubkeys: Vec<PublicKey>,
        my_pub_key: PublicKey,
    ) -> Result<PublicKey, KeyManagerError> {
        Ok(self.musig2.new_session(participant_pubkeys, my_pub_key)?)
    }

    pub fn get_my_public_key(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<PublicKey, KeyManagerError> {
        Ok(self.musig2.my_public_key(aggregated_pubkey)?)
    }

    pub fn get_pubkey(&self, aggregated_pubkey: &PublicKey) -> Result<PublicKey, KeyManagerError> {
        Ok(self.musig2.my_public_key(aggregated_pubkey)?)
    }

    pub fn aggregate_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        pub_nonces_map: HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
    ) -> Result<(), KeyManagerError> {
        Ok(self
            .musig2
            .aggregate_nonces(aggregated_pubkey, id, pub_nonces_map)?)
    }

    pub fn get_my_pub_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, PubNonce)>, KeyManagerError> {
        Ok(self.musig2.get_my_pub_nonces(aggregated_pubkey, id)?)
    }

    pub fn save_partial_signatures_multi(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        mut partial_signatures_mapping: HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
    ) -> Result<(), KeyManagerError> {
        //TODO: Fix this
        //this is a workaround bacause the as leader I got all the partial before sending mine
        //and therefore have it computed.
        //this should change in program
        let my_partial_signatures = self.get_my_partial_signatures(aggregated_pubkey, id)?;
        let my_pub_key = self.musig2.my_public_key(aggregated_pubkey)?;
        partial_signatures_mapping.insert(my_pub_key, my_partial_signatures.clone());

        Ok(self.musig2.save_partial_signatures(
            aggregated_pubkey,
            id,
            partial_signatures_mapping,
        )?)
    }

    pub fn save_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        other_public_key: PublicKey,
        other_partial_signatures: Vec<(MessageId, PartialSignature)>,
    ) -> Result<Vec<(MessageId, PartialSignature)>, KeyManagerError> {
        let mut partial_signatures = HashMap::new();
        partial_signatures.insert(other_public_key, other_partial_signatures);

        let my_partial_signatures = self.get_my_partial_signatures(aggregated_pubkey, id)?;
        let my_pub_key = self.musig2.my_public_key(aggregated_pubkey)?;

        partial_signatures.insert(my_pub_key, my_partial_signatures.clone());

        self.musig2
            .save_partial_signatures(aggregated_pubkey, id, partial_signatures)?;

        Ok(my_partial_signatures)
    }

    pub fn get_my_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, PartialSignature)>, KeyManagerError> {
        let mut my_partial_signatures = Vec::new();

        let data_to_iterate = self
            .musig2
            .get_data_for_partial_signatures(aggregated_pubkey, id)?;
        let my_pub_key = self.musig2.my_public_key(aggregated_pubkey)?;

        for (message_id, (message, sec_nonce, tweak, aggregated_nonce)) in data_to_iterate.iter() {
            let sig = self
                .sign_partial_message(
                    aggregated_pubkey,
                    my_pub_key,
                    sec_nonce.clone(),
                    aggregated_nonce.clone(),
                    *tweak,
                    message.clone(),
                )
                .map_err(|_| Musig2SignerError::InvalidSignature)?;

            my_partial_signatures.push((message_id.clone(), sig));
        }

        Ok(my_partial_signatures)
    }

    pub fn get_aggregated_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<secp256k1::schnorr::Signature, KeyManagerError> {
        Ok(self
            .musig2
            .get_aggregated_signature(aggregated_pubkey, id, message_id)?)
    }

    pub fn generate_nonce(
        &self,
        message_id: &str,
        message: Vec<u8>,
        aggregated_pubkey: &PublicKey,
        id: &str,
        tweak: Option<musig2::secp256k1::Scalar>,
    ) -> Result<(), KeyManagerError> {
        let index = self.musig2.get_index(aggregated_pubkey)?;
        let public_key = self.musig2.my_public_key(aggregated_pubkey)?;

        let nonce_seed: [u8; 32] = self
            .generate_nonce_seed(index, public_key)
            .map_err(|_| Musig2SignerError::NonceSeedError)?;

        Ok(self.musig2.generate_nonce(
            message_id,
            message,
            aggregated_pubkey,
            id,
            tweak,
            nonce_seed,
        )?)
    }

    /*pub fn get_aggregated_pubkey(&self, id: &str) -> Result<PublicKey, Musig2SignerError> {
        self.musig2.get_aggregated_pubkey(id)
    }*/
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        hex::DisplayHex,
        key::rand::{self, rngs::mock::StepRng, RngCore},
        secp256k1::{self, Message, SecretKey},
        Network, PrivateKey, PublicKey,
    };
    use std::{env, fs, panic, rc::Rc, str::FromStr};
    use storage_backend::{storage::Storage, storage_config::StorageConfig};

    use crate::{
        config::KeyManagerConfig, create_key_manager_from_config, errors::{KeyManagerError, WinternitzError}, key_store::KeyStore, verifier::SignatureVerifier, winternitz::{to_checksummed_message, WinternitzType}
    };

    use super::KeyManager;

    const DERIVATION_PATH: &str = "m/101/1/0/0/";
    const REGTEST: Network = Network::Regtest;

    #[test]
    fn test_generate_nonce_seed() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.to_string(), None);
        let store = Rc::new(Storage::new(&config)?);

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

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_sign_ecdsa_message() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let signature_verifier = SignatureVerifier::new();
            let mut rng = secp256k1::rand::thread_rng();
            let pk = key_manager.generate_keypair(&mut rng)?;
            let message = random_message();
            let signature = key_manager.sign_ecdsa_message(&message, &pk)?;
            
            assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));
            Ok(())
        })
    }

    #[test]
    fn test_sign_ecdsa_recoverable_message() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let signature_verifier = SignatureVerifier::new();
            let mut rng = secp256k1::rand::thread_rng();
            let pk = key_manager.generate_keypair(&mut rng)?;
            let message = random_message();
            let recoverable_signature = key_manager.sign_ecdsa_recoverable_message(&message, &pk)?;
            let signature = recoverable_signature.to_standard();
            
            assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, pk));
            Ok(())
        })
    }

    #[test]
    fn test_sign_schnorr_message() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let signature_verifier = SignatureVerifier::new();
            let mut rng = secp256k1::rand::thread_rng();
            let pk = key_manager.generate_keypair(&mut rng)?;
            let message = random_message();
            let signature = key_manager.sign_schnorr_message(&message, &pk)?;
            
            assert!(signature_verifier.verify_schnorr_signature(&signature, &message, pk));
            Ok(())
        })
    }

    #[test]
    fn test_sign_schnorr_message_with_tap_tweak() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.to_string(), None);
        let store = Rc::new(Storage::new(&config)?);

        let key_manager = test_key_manager(keystore, store)?;
        let signature_verifier = SignatureVerifier::new();

        let mut rng = secp256k1::rand::thread_rng();
        let pk = key_manager.generate_keypair(&mut rng)?;

        let message = random_message();
        let (signature, tweaked_key) =
            key_manager.sign_schnorr_message_with_tap_tweak(&message, &pk, None)?;

        assert!(signature_verifier.verify_schnorr_signature(&signature, &message, tweaked_key));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_sign_winternitz_message_sha256() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.to_string(), None);
        let store = Rc::new(Storage::new(&config)?);

        let key_manager = test_key_manager(keystore, store)?;
        let signature_verifier = SignatureVerifier::new();

        let message = random_message();

        let pk = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 0)?;
        let signature =
            key_manager.sign_winternitz_message(&message[..], WinternitzType::SHA256, 0)?;

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));
        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_sign_winternitz_message_ripemd160() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.to_string(), None);
        let store = Rc::new(Storage::new(&config)?);

        let key_manager = test_key_manager(keystore, store)?;
        let signature_verifier = SignatureVerifier::new();

        let digest: [u8; 32] = [0xFE; 32];
        let message = Message::from_digest(digest);

        let pk = key_manager.derive_winternitz(message[..].len(), WinternitzType::HASH160, 0)?;
        let signature =
            key_manager.sign_winternitz_message(&message[..], WinternitzType::HASH160, 0)?;

        assert!(signature_verifier.verify_winternitz_signature(&signature, &message[..], &pk));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_derive_key() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.to_string(), None);
        let store = Rc::new(Storage::new(&config)?);

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

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_key_generation() -> Result<(), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;

        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.to_string(), None);
        let store = Rc::new(Storage::new(&config)?);

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

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_keystore() -> Result<(), KeyManagerError> {
        let path = temp_storage();
        let password = "secret password".to_string();
        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = random_bytes();
        let key_derivation_seed = random_bytes();

        let config = StorageConfig::new(path.clone(), Some(password));
        let store = Rc::new(Storage::new(&config).unwrap());
        let keystore = KeyStore::new(store);
        keystore.store_winternitz_seed(winternitz_seed)?;
        keystore.store_key_derivation_seed(key_derivation_seed)?;

        for _ in 0..10 {
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            let private_key = PrivateKey::new(secret_key, Network::Regtest);
            let public_key = PublicKey::from_private_key(&secp, &private_key);

            keystore.store_keypair(private_key, public_key)?;

            let (restored_sk, restored_pk) = match keystore.load_keypair(&public_key)? {
                Some(entry) => entry,
                None => {
                    panic!("Failed to find key");
                }
            };

            assert_eq!(restored_sk.to_string(), private_key.to_string());
            assert_eq!(restored_pk.to_string(), public_key.to_string());
        }

        let loaded_winternitz_seed = keystore.load_winternitz_seed()?;
        assert!(loaded_winternitz_seed == winternitz_seed);

        let loaded_key_derivation_seed = keystore.load_key_derivation_seed()?;
        assert!(loaded_key_derivation_seed == key_derivation_seed);

        drop(keystore);
        cleanup_storage(&path);
        Ok(())
    }

    #[test]
    fn test_keystore_index() -> Result<(), KeyManagerError> {
        let path = temp_storage();
        let password = "secret password".to_string();
        let secp = secp256k1::Secp256k1::new();
        let winternitz_seed = random_bytes();
        let key_derivation_seed = random_bytes();

        let config = StorageConfig::new(path.clone(), Some(password.clone()));
        let store = Rc::new(Storage::new(&config)?);
        let keystore = KeyStore::new(store);
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

        drop(keystore);
        cleanup_storage(&path);
        Ok(())
    }

    #[test]
    fn test_error_handling() -> Result<(), KeyManagerError> {
        let message = random_message();
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config)?);

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
        assert!(matches!(result, Err(KeyManagerError::KeyPairNotFound(_))));

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        Ok(())
    }

    #[test]
    fn test_signature_with_bip32_derivation() {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).unwrap();

        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).unwrap());

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

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
    }

    #[test]
    fn test_schnorr_signature_with_bip32_derivation() {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).unwrap();

        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).unwrap());

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

        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
    }

    #[test]
    fn test_key_derivation_from_xpub_in_different_key_manager() {
        run_test_with_multiple_key_managers(2, |key_managers, _keystore_paths, _store_paths| {
            let key_manager_1 = &key_managers[0];
            let key_manager_2 = &key_managers[1];

            for i in 0..5 {
                // Create master_xpub in key_manager_1 and derive public key in key_manager_2 for a given index
                let master_xpub = key_manager_1.generate_master_xpub().unwrap();
                let public_from_xpub = key_manager_2.derive_public_key(master_xpub, i).unwrap();

                // Derive keypair in key_manager_1 with the same index
                let public_from_xpriv = key_manager_1.derive_keypair(i).unwrap();

                // Both public keys must be equal
                assert_eq!(public_from_xpub.to_string(), public_from_xpriv.to_string());
            }
            
            Ok(())
        }).unwrap();
    }

    #[test]
    fn test_derive_multiple_winternitz_gives_same_result_as_doing_one_by_one() {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).unwrap();
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).unwrap());
        let key_manager = test_key_manager(keystore, store).unwrap();

        let message_size_in_bytes = 32;
        let key_type = WinternitzType::SHA256;
        let initial_index = 0;
        let number_of_keys: u32 = 10;

        let public_keys = key_manager
            .derive_multiple_winternitz(
                message_size_in_bytes,
                key_type,
                initial_index,
                number_of_keys,
            )
            .unwrap();

        for i in 0..number_of_keys {
            let public_key = key_manager
                .derive_winternitz(message_size_in_bytes, key_type, initial_index + i)
                .unwrap();

            assert_eq!(public_keys[i as usize], public_key);
        }
        drop(key_manager);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
    }

    fn test_key_manager(
        keystore: KeyStore,
        store: Rc<Storage>,
    ) -> Result<KeyManager, KeyManagerError> {
        let key_derivation_seed = random_bytes();
        let winternitz_seed = random_bytes();

        let key_manager = KeyManager::new(
            REGTEST,
            DERIVATION_PATH,
            Some(key_derivation_seed),
            Some(winternitz_seed),
            keystore,
            store,
        )?;

        Ok(key_manager)
    }

    fn database_keystore(storage_path: &str) -> Result<KeyStore, KeyManagerError> {
        let password = "secret password".to_string();
        let config = StorageConfig::new(storage_path.to_string(), Some(password));
        let store = Rc::new(Storage::new(&config)?);
        Ok(KeyStore::new(store))
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
        println!("Cleaning up storage at: {}", path);
        fs::remove_dir_all(path).unwrap();
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

    fn setup_test_environment() -> Result<(KeyStore, Rc<Storage>, String, String), KeyManagerError> {
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path)?;
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config)?);
        
        Ok((keystore, store, keystore_path, store_path))
    }

    fn cleanup_test_environment(keystore_path: &str, store_path: &str) {
        cleanup_storage(keystore_path);
        cleanup_storage(store_path);
    }

    fn create_test_config_and_run_with_cleanup<F>(
        network: &str,
        key_derivation_seed: Option<String>,
        derivation_path: Option<String>,
        winternitz_seed: Option<String>,
        test_fn: F,
    ) -> Result<(), KeyManagerError>
    where
        F: FnOnce(&KeyManagerConfig, KeyStore, Rc<Storage>) -> Result<(), KeyManagerError>,
    {
        let (keystore, store, keystore_path, store_path) = setup_test_environment()?;
        
        let key_manager_config = KeyManagerConfig::new(
            network.to_string(),
            key_derivation_seed,
            derivation_path,
            winternitz_seed,
        );
        
        let result = test_fn(&key_manager_config, keystore, store);
        
        cleanup_test_environment(&keystore_path, &store_path);
        
        result
    }

    fn setup_test_key_manager() -> Result<(KeyManager, String, String), KeyManagerError> {
        let (keystore, store, keystore_path, store_path) = setup_test_environment()?;
        let key_manager = test_key_manager(keystore, store)?;
        Ok((key_manager, keystore_path, store_path))
    }

    fn run_test_with_key_manager<F, R>(test_fn: F) -> Result<R, KeyManagerError>
    where
        F: FnOnce(KeyManager) -> Result<R, KeyManagerError>,
    {
        let (key_manager, keystore_path, store_path) = setup_test_key_manager()?;
        let result = test_fn(key_manager);
        cleanup_test_environment(&keystore_path, &store_path);
        result
    }

    fn run_test_with_multiple_key_managers<F, R>(count: usize, test_fn: F) -> Result<R, KeyManagerError>
    where
        F: FnOnce(Vec<KeyManager>, Vec<String>, Vec<String>) -> Result<R, KeyManagerError>,
    {
        let mut key_managers = Vec::new();
        let mut keystore_paths = Vec::new();
        let mut store_paths = Vec::new();

        for _ in 0..count {
            let (key_manager, keystore_path, store_path) = setup_test_key_manager()?;
            key_managers.push(key_manager);
            keystore_paths.push(keystore_path);
            store_paths.push(store_path);
        }

        let result = test_fn(key_managers, keystore_paths.clone(), store_paths.clone());

        // Cleanup all storage
        for (keystore_path, store_path) in keystore_paths.iter().zip(store_paths.iter()) {
            cleanup_test_environment(keystore_path, store_path);
        }

        result
    }

    // Helper macro to reduce boilerplate for error test cases
    macro_rules! assert_config_error {
        ($network:expr, $key_derivation_seed:expr, $derivation_path:expr, $winternitz_seed:expr, $expected_error:pat) => {
            create_test_config_and_run_with_cleanup(
                $network,
                $key_derivation_seed,
                $derivation_path,
                $winternitz_seed,
                |config, keystore, store| {
                    let result = create_key_manager_from_config(config, keystore, store);
                    assert!(matches!(result, Err($expected_error)));
                    Ok(())
                },
            ).expect("Test case failed");
        };
    }

    #[test]
    pub fn test_rsa_signature() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let signature_verifier = SignatureVerifier::new();
            let mut rng = secp256k1::rand::thread_rng();
            let idx = 0;
            let pubkey = key_manager.generate_rsa_keypair(&mut rng, idx)?;
            let message = random_message().to_string().as_bytes().to_vec();
            let signature = key_manager.sign_rsa_message(&message, idx).unwrap();
            
            assert!(signature_verifier
                .verify_rsa_signature(&signature, &message, &pubkey)
                .unwrap());
            Ok(())
        })
    }

    #[test]
    pub fn test_rsa_encryption() -> Result<(), KeyManagerError> {
        run_test_with_key_manager(|key_manager| {
            let mut rng = secp256k1::rand::thread_rng();
            let idx = 0;
            let pubkey = key_manager.generate_rsa_keypair(&mut rng, idx)?;
            let message = random_message().to_string().as_bytes().to_vec();
            let encrypted_message = key_manager.encrypt_rsa_message(&message, pubkey).unwrap();
            let decrypted_message = key_manager.decrypt_rsa_message(&encrypted_message, idx).unwrap();
            
            assert_eq!(message, decrypted_message);
            Ok(())
        })
    }

        #[test]
    pub fn test_seed_decoding_success() {
        /* Objective: Verify 32-byte hex seeds decode and create a working KeyManager.
         * Preconditions: Valid Config with network set (e.g., regtest); temporary storage available.
         * Input / Test Data: winternitz_seed and key_derivation_seed as 64-hex-character strings.
         * Steps / Procedure: 1) Build Config with both seeds. 2) Call create_key_manager_from_config. 3) Read back seeds via KeyStore::load_winternitz_seed and load_key_derivation_seed.
         * Expected Result: Function succeeds; loaded seeds equal inputs; no errors.
        */
        
        // Generate 64-hex-character strings (32 bytes each)
        let winternitz_seed_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
        let key_derivation_seed_hex = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string();
        
        // Expected 32-byte arrays
        let expected_winternitz_seed = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        ];
        let expected_key_derivation_seed = [
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,
        ];
        
        // Step 1: Build Config with both seeds
        let key_manager_config = KeyManagerConfig::new(
            "regtest".to_string(),
            Some(key_derivation_seed_hex),
            Some("m/101/1/0/0/".to_string()),
            Some(winternitz_seed_hex),
        );
        
        // Set up temporary storage using helper function
        let (keystore, storage, keystore_path, store_path) = setup_test_environment()
            .expect("Failed to setup test environment");
        
        // Step 2: Call create_key_manager_from_config
        let key_manager = create_key_manager_from_config(&key_manager_config, keystore, storage)
            .expect("Failed to create key manager from config");
        
        // Step 3: Read back seeds via KeyStore methods
        let loaded_winternitz_seed = key_manager.keystore.load_winternitz_seed()
            .expect("Failed to load winternitz seed");
        let loaded_key_derivation_seed = key_manager.keystore.load_key_derivation_seed()
            .expect("Failed to load key derivation seed");
        
        // Expected Result: Loaded seeds equal inputs; no errors
        assert_eq!(loaded_winternitz_seed, expected_winternitz_seed, 
            "Winternitz seed mismatch");
        assert_eq!(loaded_key_derivation_seed, expected_key_derivation_seed, 
            "Key derivation seed mismatch");
        
        // Cleanup
        drop(key_manager);
        cleanup_test_environment(&keystore_path, &store_path);
    }

    #[test]
    pub fn test_seed_decoding_failure() {
        /*
        * Objective: Ensure invalid seeds are rejected with precise errors.
        * Preconditions: Valid base Config except seeds under test.
        * Input / Test Data: a) Non-hex; b) >32 bytes hex; c) empty string.
        * Steps / Procedure: For each bad input, invoke create_key_manager_from_config.
        * Expected Result: Returns ConfigError::InvalidWinternitzSeed or InvalidKeyDerivationSeed accordingly.
        */
        
        use crate::errors::ConfigError;
        
        // Valid seed for reference
        let valid_seed = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
        
        // Test Case 1: Non-hex winternitz_seed
        assert_config_error!(
            "regtest",
            Some(valid_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some("invalid_non_hex_string_here".to_string()), // Non-hex
            KeyManagerError::ConfigError(ConfigError::InvalidWinternitzSeed)
        );
        
        // Test Case 2: Non-hex key_derivation_seed
        assert_config_error!(
            "regtest",
            Some("not_a_hex_string".to_string()), // Non-hex
            Some("m/101/1/0/0/".to_string()),
            Some(valid_seed.clone()),
            KeyManagerError::ConfigError(ConfigError::InvalidKeyDerivationSeed)
        );
        
        // Test Case 3: Too long winternitz_seed (>32 bytes = >64 hex chars)
        let too_long_seed = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00".to_string(); // 66 chars
        create_test_config_and_run_with_cleanup(
            "regtest",
            Some(valid_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(too_long_seed),
            |config, keystore, store| {
                let result = create_key_manager_from_config(config, keystore, store);
                assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidWinternitzSeed))));
                Ok(())
            },
        ).expect("Test case failed");
        
        // Test Case 4: Too long key_derivation_seed (>32 bytes = >64 hex chars)
        let too_long_seed = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321ff".to_string(); // 66 chars
        create_test_config_and_run_with_cleanup(
            "regtest",
            Some(too_long_seed),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_seed.clone()),
            |config, keystore, store| {
                let result = create_key_manager_from_config(config, keystore, store);
                assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidKeyDerivationSeed))));
                Ok(())
            },
        ).expect("Test case failed");
        
        // Test Case 5: Empty winternitz_seed
        create_test_config_and_run_with_cleanup(
            "regtest",
            Some(valid_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some("".to_string()), // Empty string
            |config, keystore, store| {
                let result = create_key_manager_from_config(config, keystore, store);
                assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidWinternitzSeed))));
                Ok(())
            },
        ).expect("Test case failed");
        
        // Test Case 6: Empty key_derivation_seed
        create_test_config_and_run_with_cleanup(
            "regtest",
            Some("".to_string()), // Empty string
            Some("m/101/1/0/0/".to_string()),
            Some(valid_seed.clone()),
            |config, keystore, store| {
                let result = create_key_manager_from_config(config, keystore, store);
                assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidKeyDerivationSeed))));
                Ok(())
            },
        ).expect("Test case failed");
        
        // Test Case 7: Too short winternitz_seed (<32 bytes = <64 hex chars)
        let too_short_seed = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd".to_string(); // 62 chars
        create_test_config_and_run_with_cleanup(
            "regtest",
            Some(valid_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(too_short_seed),
            |config, keystore, store| {
                let result = create_key_manager_from_config(config, keystore, store);
                assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidWinternitzSeed))));
                Ok(())
            },
        ).expect("Test case failed");
        
        // Test Case 8: Too short key_derivation_seed (<32 bytes = <64 hex chars)
        let too_short_seed = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba09876543".to_string(); // 62 chars
        create_test_config_and_run_with_cleanup(
            "regtest",
            Some(too_short_seed),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_seed.clone()),
            |config, keystore, store| {
                let result = create_key_manager_from_config(config, keystore, store);
                assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidKeyDerivationSeed))));
                Ok(())
            },
        ).expect("Test case failed");
    }

    #[test]
    pub fn test_default_derivation_path_fallback(){
        /*
         * Objective: Confirm default path m/101/1/0/0/ is used when not provided.
         * Preconditions: key_derivation_path omitted in Config.
         * Input / Test Data: Valid seeds (or none); valid network.
         * Steps / Procedure: Create KeyManager from config; derive a key at index 0.
         * Expected Result: No error; derivation succeeds, implying the default path applied.
         */
        
        // Set up temporary storage using helper function
        let (keystore, store, keystore_path, store_path) = setup_test_environment()
            .expect("Failed to setup test environment");
        
        // Create config with key_derivation_path set to None (omitted)
        let key_manager_config = KeyManagerConfig::new(
            "regtest".to_string(),
            Some("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string()),
            None, // key_derivation_path omitted - should fall back to default
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()),
        );
        
        // Step: Create KeyManager from config - should use default path
        let key_manager = create_key_manager_from_config(&key_manager_config, keystore, store)
            .expect("Failed to create key manager from config with default derivation path");
        
        // Step: Derive a key at index 0 - should succeed if default path applied correctly
        let public_key = key_manager.derive_keypair(0)
            .expect("Failed to derive keypair - default derivation path may not have been applied");
        
        // Verify the derivation succeeded and we got a valid public key
        assert_eq!(public_key.to_bytes().len(), 33, "Generated public key should be 33 bytes");
        
        // Additional verification: derive master xpub and compare derived keys
        let master_xpub = key_manager.generate_master_xpub()
            .expect("Failed to generate master xpub");
        
        let public_key_from_xpub = key_manager.derive_public_key(master_xpub, 0)
            .expect("Failed to derive public key from xpub");
        
        // Both derivations should produce the same key if using the same default path
        assert_eq!(public_key.to_string(), public_key_from_xpub.to_string(), 
            "Keys derived with and without xpub should match when using default derivation path");
        
        // Verify that the KeyManager can sign with the derived key (further proof it works)
        let signature_verifier = SignatureVerifier::new();
        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, &public_key)
            .expect("Failed to sign with derived key");
        
        assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, public_key),
            "Signature verification should succeed for key derived using default path");
        
        // Cleanup
        drop(key_manager);
        cleanup_test_environment(&keystore_path, &store_path);
    }

    #[test]
    pub fn test_network_parsing(){
        /*
         * Objective: Validate network string parsing and error on invalid value.
         * Preconditions: Minimal Config with storage set.
         * Input / Test Data: network values: regtest, testnet, bitcoin, and invalid.
         * Steps / Procedure: Call create_key_manager_from_config for each network value.
         * Expected Result: Succeeds for valid networks; returns ConfigError::InvalidNetwork for invalid.
         */

        use crate::errors::ConfigError;
        
        // Valid seeds to use for all tests
        let valid_winternitz_seed = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
        let valid_key_derivation_seed = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string();
        
        // Test Case 1: Valid network "regtest"
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));
        
        let key_manager_config = KeyManagerConfig::new(
            "regtest".to_string(), // Valid network
            Some(valid_key_derivation_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_winternitz_seed.clone()),
        );
        
        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(result.is_ok(), "KeyManager creation should succeed for valid network 'regtest'");
        
        // Explicitly drop the KeyManager to release storage handles
        drop(result);
        
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        
        // Test Case 2: Valid network "testnet"
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));
        
        let key_manager_config = KeyManagerConfig::new(
            "testnet".to_string(), // Valid network
            Some(valid_key_derivation_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_winternitz_seed.clone()),
        );
        
        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(result.is_ok(), "KeyManager creation should succeed for valid network 'testnet'");
        
        // Explicitly drop the KeyManager to release storage handles
        drop(result);
        
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        
        // Test Case 3: Valid network "bitcoin" (mainnet)
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));
        
        let key_manager_config = KeyManagerConfig::new(
            "bitcoin".to_string(), // Valid network
            Some(valid_key_derivation_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_winternitz_seed.clone()),
        );
        
        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(result.is_ok(), "KeyManager creation should succeed for valid network 'bitcoin'");
        
        // Explicitly drop the KeyManager to release storage handles
        drop(result);
        
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        
        // Test Case 4: Valid network "signet"
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));
        
        let key_manager_config = KeyManagerConfig::new(
            "signet".to_string(), // Valid network
            Some(valid_key_derivation_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_winternitz_seed.clone()),
        );
        
        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(result.is_ok(), "KeyManager creation should succeed for valid network 'signet'");
        
        // Explicitly drop the KeyManager to release storage handles
        drop(result);
        
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        
        // Test Case 5: Invalid network value
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));
        
        let key_manager_config = KeyManagerConfig::new(
            "invalid_network".to_string(), // Invalid network
            Some(valid_key_derivation_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_winternitz_seed.clone()),
        );
        
        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidNetwork))),
            "KeyManager creation should fail with InvalidNetwork error for invalid network string");
        
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        
        // Test Case 6: Empty network string
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));
        
        let key_manager_config = KeyManagerConfig::new(
            "".to_string(), // Empty network string
            Some(valid_key_derivation_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_winternitz_seed.clone()),
        );
        
        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidNetwork))),
            "KeyManager creation should fail with InvalidNetwork error for empty network string");
        
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        
        // Test Case 7: Case sensitivity test (uppercase)
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));
        
        let key_manager_config = KeyManagerConfig::new(
            "REGTEST".to_string(), // Uppercase - should be invalid
            Some(valid_key_derivation_seed.clone()),
            Some("m/101/1/0/0/".to_string()),
            Some(valid_winternitz_seed.clone()),
        );
        
        let result = create_key_manager_from_config(&key_manager_config, keystore, store);
        assert!(matches!(result, Err(KeyManagerError::ConfigError(ConfigError::InvalidNetwork))),
            "KeyManager creation should fail with InvalidNetwork error for uppercase network string");
        
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
    }

    #[test]
    pub fn test_keystore_seed_bootstraping_provided_seeds(){
        /*
         * Objective: Ensure provided seeds are persisted and retrievable.
         * Preconditions: Fresh storage; both seeds in config.
         * Input / Test Data: Two 32-byte hex seeds.
         * Steps / Procedure: Initialize KeyManager; call KeyStore::load_winternitz_seed and load_key_derivation_seed.
         * Expected Result: Loaded seeds exactly match provided values.
         */
        
        // Set up temporary storage using helper function
        let (keystore, store, keystore_path, store_path) = setup_test_environment()
            .expect("Failed to setup test environment");
        
        // Define specific 32-byte seeds to provide
        let provided_winternitz_seed = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        ];
        
        let provided_key_derivation_seed = [
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21,
        ];
        
        // Step: Initialize KeyManager with provided seeds
        let key_manager = KeyManager::new(
            REGTEST,
            DERIVATION_PATH,
            Some(provided_key_derivation_seed),
            Some(provided_winternitz_seed),
            keystore,
            store,
        ).expect("Failed to create KeyManager with provided seeds");
        
        // Step: Load seeds from keystore and verify they match provided values
        let loaded_winternitz_seed = key_manager.keystore.load_winternitz_seed()
            .expect("Failed to load winternitz seed from keystore");
        
        let loaded_key_derivation_seed = key_manager.keystore.load_key_derivation_seed()
            .expect("Failed to load key derivation seed from keystore");
        
        // Expected Result: Loaded seeds exactly match provided values
        assert_eq!(loaded_winternitz_seed, provided_winternitz_seed,
            "Loaded winternitz seed should exactly match the provided seed");
        
        assert_eq!(loaded_key_derivation_seed, provided_key_derivation_seed,
            "Loaded key derivation seed should exactly match the provided seed");
        
        // Additional verification: Test that the seeds are actually being used for key derivation
        let public_key = key_manager.derive_keypair(0)
            .expect("Failed to derive keypair using stored seeds");
        
        // Verify the public key is valid
        assert_eq!(public_key.to_bytes().len(), 33, "Generated public key should be 33 bytes");
        
        // Test winternitz key generation as well
        let winternitz_public_key = key_manager.derive_winternitz(32, WinternitzType::SHA256, 0)
            .expect("Failed to derive winternitz key using stored seed");
        
        // Verify winternitz key was generated
        assert!(winternitz_public_key.total_len() > 0, "Winternitz public key should have non-zero length");
        
        // Test that we can create another KeyManager instance with same storage and seeds persist
        drop(key_manager);
        
        let keystore2 = database_keystore(&keystore_path).expect("Failed to create second keystore");
        let config2 = StorageConfig::new(store_path.clone(), None);
        let store2 = Rc::new(Storage::new(&config2).expect("Failed to create second storage"));
        
        // Create KeyManager without providing seeds - should load existing ones
        let key_manager2 = KeyManager::new(
            REGTEST,
            DERIVATION_PATH,
            None, // No seeds provided - should use existing ones
            None,
            keystore2,
            store2,
        ).expect("Failed to create second KeyManager");
        
        // Verify the seeds are still the same
        let loaded_winternitz_seed2 = key_manager2.keystore.load_winternitz_seed()
            .expect("Failed to load winternitz seed from second keystore");
        
        let loaded_key_derivation_seed2 = key_manager2.keystore.load_key_derivation_seed()
            .expect("Failed to load key derivation seed from second keystore");
        
        assert_eq!(loaded_winternitz_seed2, provided_winternitz_seed,
            "Seeds should persist across KeyManager instances");
        
        assert_eq!(loaded_key_derivation_seed2, provided_key_derivation_seed,
            "Seeds should persist across KeyManager instances");
        
        // Cleanup
        drop(key_manager2);
        cleanup_test_environment(&keystore_path, &store_path);
    }

    #[test]
    pub fn test_keystore_seed_bootstraping_generated_seeds(){
        /*
         * Objective: Ensure seeds are generated and stored if not provided.
         * Preconditions: Fresh storage; seeds omitted in config.
         * Input / Test Data: None beyond config.
         * Steps / Procedure: Initialize KeyManager; load seeds via KeyStore::load_*.
         * Expected Result: Both seeds load successfully as 32-byte arrays (non-zero, values unspecified).
         */
        
        // Set up temporary storage
        let keystore_path = temp_storage();
        let keystore = database_keystore(&keystore_path).expect("Failed to create keystore");
        let store_path = temp_storage();
        let config = StorageConfig::new(store_path.clone(), None);
        let store = Rc::new(Storage::new(&config).expect("Failed to create storage"));
        
        // Step: Initialize KeyManager without providing any seeds (should auto-generate)
        let key_manager = KeyManager::new(
            REGTEST,
            DERIVATION_PATH,
            None, // No key derivation seed provided - should be generated
            None, // No winternitz seed provided - should be generated
            keystore,
            store,
        ).expect("Failed to create KeyManager with auto-generated seeds");
        
        // Step: Load seeds from keystore to verify they were generated and stored
        let loaded_winternitz_seed = key_manager.keystore.load_winternitz_seed()
            .expect("Failed to load auto-generated winternitz seed from keystore");
        
        let loaded_key_derivation_seed = key_manager.keystore.load_key_derivation_seed()
            .expect("Failed to load auto-generated key derivation seed from keystore");
        
        // Expected Result: Both seeds load successfully as 32-byte arrays
        assert_eq!(loaded_winternitz_seed.len(), 32, 
            "Generated winternitz seed should be exactly 32 bytes");
        
        assert_eq!(loaded_key_derivation_seed.len(), 32, 
            "Generated key derivation seed should be exactly 32 bytes");
        
        // Verify seeds are non-zero (extremely unlikely to be all zeros by chance)
        let winternitz_all_zeros = loaded_winternitz_seed.iter().all(|&x| x == 0);
        let key_derivation_all_zeros = loaded_key_derivation_seed.iter().all(|&x| x == 0);
        
        assert!(!winternitz_all_zeros, 
            "Generated winternitz seed should not be all zeros");
        assert!(!key_derivation_all_zeros, 
            "Generated key derivation seed should not be all zeros");
        
        // Additional verification: Test that the generated seeds work for cryptographic operations
        let public_key = key_manager.derive_keypair(0)
            .expect("Failed to derive keypair using auto-generated seeds");
        
        // Verify the public key is valid
        assert_eq!(public_key.to_bytes().len(), 33, "Generated public key should be 33 bytes");
        
        // Test winternitz key generation as well
        let winternitz_public_key = key_manager.derive_winternitz(32, WinternitzType::SHA256, 0)
            .expect("Failed to derive winternitz key using auto-generated seed");
        
        // Verify winternitz key was generated successfully
        assert!(winternitz_public_key.total_len() > 0, "Winternitz public key should have non-zero length");
        
        // Test signing with auto-generated keys to prove they work
        let signature_verifier = SignatureVerifier::new();
        let message = random_message();
        let signature = key_manager.sign_ecdsa_message(&message, &public_key)
            .expect("Failed to sign with key derived from auto-generated seed");
        
        assert!(signature_verifier.verify_ecdsa_signature(&signature, &message, public_key),
            "Signature verification should succeed for key derived from auto-generated seed");
        
        // Test persistence: Create second KeyManager instance and verify seeds persist
        drop(key_manager);
        
        let keystore2 = database_keystore(&keystore_path).expect("Failed to create second keystore");
        let config2 = StorageConfig::new(store_path.clone(), None);
        let store2 = Rc::new(Storage::new(&config2).expect("Failed to create second storage"));
        
        // Create KeyManager without providing seeds - should load existing generated ones
        let key_manager2 = KeyManager::new(
            REGTEST,
            DERIVATION_PATH,
            None, // No seeds provided - should use existing generated ones
            None,
            keystore2,
            store2,
        ).expect("Failed to create second KeyManager");
        
        // Verify the seeds are the same as the first instance (persistence test)
        let loaded_winternitz_seed2 = key_manager2.keystore.load_winternitz_seed()
            .expect("Failed to load winternitz seed from second keystore");
        
        let loaded_key_derivation_seed2 = key_manager2.keystore.load_key_derivation_seed()
            .expect("Failed to load key derivation seed from second keystore");
        
        assert_eq!(loaded_winternitz_seed2, loaded_winternitz_seed,
            "Auto-generated seeds should persist across KeyManager instances");
        
        assert_eq!(loaded_key_derivation_seed2, loaded_key_derivation_seed,
            "Auto-generated seeds should persist across KeyManager instances");
        
        // Test uniqueness: Create a third KeyManager with fresh storage to verify different seeds are generated
        let keystore_path3 = temp_storage();
        let keystore3 = database_keystore(&keystore_path3).expect("Failed to create third keystore");
        let store_path3 = temp_storage();
        let config3 = StorageConfig::new(store_path3.clone(), None);
        let store3 = Rc::new(Storage::new(&config3).expect("Failed to create third storage"));
        
        let key_manager3 = KeyManager::new(
            REGTEST,
            DERIVATION_PATH,
            None, // Should generate new different seeds
            None,
            keystore3,
            store3,
        ).expect("Failed to create third KeyManager");
        
        let loaded_winternitz_seed3 = key_manager3.keystore.load_winternitz_seed()
            .expect("Failed to load winternitz seed from third keystore");
        
        let loaded_key_derivation_seed3 = key_manager3.keystore.load_key_derivation_seed()
            .expect("Failed to load key derivation seed from third keystore");
        
        // Verify that different KeyManager instances generate different seeds
        assert_ne!(loaded_winternitz_seed3, loaded_winternitz_seed,
            "Different KeyManager instances should generate different winternitz seeds");
        
        assert_ne!(loaded_key_derivation_seed3, loaded_key_derivation_seed,
            "Different KeyManager instances should generate different key derivation seeds");
        
        // Cleanup
        drop(key_manager2);
        drop(key_manager3);
        cleanup_storage(&keystore_path);
        cleanup_storage(&store_path);
        cleanup_storage(&keystore_path3);
        cleanup_storage(&store_path3);
    }
}
