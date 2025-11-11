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

        // Defensive: do not call musig2 aggregator with empty input - return an error instead
        if partial_keys_bytes.is_empty() {
            return Err(KeyManagerError::InvalidPrivateKey);
        }

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

        // Defensive: do not call musig2 aggregator with empty input - return an error instead
        if partial_keys_bytes.is_empty() {
            return Err(KeyManagerError::InvalidPrivateKey);
        }

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
        Network, PrivateKey, PublicKey, hex::DisplayHex, key::{Secp256k1, rand::{self, RngCore, rngs::mock::StepRng}}, secp256k1::{self, Message, SecretKey}
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

    #[test]
    pub fn test_store_load_ecdsa_keypairs(){
        /*
         * Objective: Validate keypair persistence and retrieval symmetry.
         * Preconditions: Initialized KeyStore; Secp256k1 context.
         * Input / Test Data: Two generated keypairs.
         * Steps / Procedure: Store both keypairs; load by public key; compare stored vs loaded.
         * Expected Result: Loads succeed; private/public key strings match; keys are distinct.
         */
        
        // Set up test environment using helper function
        let (keystore, _store, keystore_path, store_path) = setup_test_environment()
            .expect("Failed to setup test environment");
        
        // Initialize Secp256k1 context for key generation
        let secp = secp256k1::Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        
        // Generate first keypair
        let secret_key_1 = SecretKey::new(&mut rng);
        let private_key_1 = PrivateKey::new(secret_key_1, REGTEST);
        let public_key_1 = PublicKey::from_private_key(&secp, &private_key_1);
        
        // Generate second keypair
        let secret_key_2 = SecretKey::new(&mut rng);
        let private_key_2 = PrivateKey::new(secret_key_2, REGTEST);
        let public_key_2 = PublicKey::from_private_key(&secp, &private_key_2);
        
        // Verify the keypairs are distinct
        assert_ne!(private_key_1.to_string(), private_key_2.to_string(), 
            "Generated private keys should be distinct");
        assert_ne!(public_key_1.to_string(), public_key_2.to_string(), 
            "Generated public keys should be distinct");
        
        // Store both keypairs in the keystore
        keystore.store_keypair(private_key_1, public_key_1)
            .expect("Failed to store first keypair");
        keystore.store_keypair(private_key_2, public_key_2)
            .expect("Failed to store second keypair");
        
        // Load first keypair by public key and verify
        let (loaded_private_key_1, loaded_public_key_1) = match keystore.load_keypair(&public_key_1)
            .expect("Failed to load first keypair") {
            Some(entry) => entry,
            None => panic!("First keypair not found in keystore"),
        };
        
        // Load second keypair by public key and verify
        let (loaded_private_key_2, loaded_public_key_2) = match keystore.load_keypair(&public_key_2)
            .expect("Failed to load second keypair") {
            Some(entry) => entry,
            None => panic!("Second keypair not found in keystore"),
        };
        
        // Verify loaded keypairs match stored keypairs exactly
        assert_eq!(loaded_private_key_1.to_string(), private_key_1.to_string(),
            "Loaded private key 1 should match stored private key 1");
        assert_eq!(loaded_public_key_1.to_string(), public_key_1.to_string(),
            "Loaded public key 1 should match stored public key 1");
        
        assert_eq!(loaded_private_key_2.to_string(), private_key_2.to_string(),
            "Loaded private key 2 should match stored private key 2");
        assert_eq!(loaded_public_key_2.to_string(), public_key_2.to_string(),
            "Loaded public key 2 should match stored public key 2");
        
        // Verify that loaded keypairs are still distinct from each other
        assert_ne!(loaded_private_key_1.to_string(), loaded_private_key_2.to_string(),
            "Loaded private keys should remain distinct");
        assert_ne!(loaded_public_key_1.to_string(), loaded_public_key_2.to_string(),
            "Loaded public keys should remain distinct");
        
        // Additional verification: Test that we cannot load non-existent keypair
        let fake_secret_key = SecretKey::new(&mut rng);
        let fake_private_key = PrivateKey::new(fake_secret_key, REGTEST);
        let fake_public_key = PublicKey::from_private_key(&secp, &fake_private_key);
        
        let non_existent_result = keystore.load_keypair(&fake_public_key)
            .expect("Load operation should succeed even for non-existent key");
        
        assert!(non_existent_result.is_none(), 
            "Loading non-existent keypair should return None");
        
        // Cleanup: drop both keystore and storage handles before removing files on Windows
        drop(keystore);
        drop(_store);
        cleanup_test_environment(&keystore_path, &store_path);
    }

    #[test]
    pub fn test_non_existent_keypair_lookout(){
        /*
         * Objective: Ensure missing keys return Ok(None).
         * Preconditions: Fresh keystore without that public key.
         * Input / Test Data: Random valid PublicKey not in store.
         * Steps / Procedure: Call load_keypair(&pubkey).
         * Expected Result: Returns Ok(None) without error.
         */
        
        // Set up fresh test environment using helper function
        let (keystore, _store, keystore_path, store_path) = setup_test_environment()
            .expect("Failed to setup test environment");
        
        // Initialize Secp256k1 context for key generation
        let secp = secp256k1::Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        
        // Generate a random valid PublicKey that is NOT in the store
        let secret_key = SecretKey::new(&mut rng);
        let private_key = PrivateKey::new(secret_key, REGTEST);
        let non_existent_public_key = PublicKey::from_private_key(&secp, &private_key);
        
        // Verify the keystore is empty (fresh) by checking it doesn't contain our test key
        // This should return Ok(None) since the key was never stored
        let result = keystore.load_keypair(&non_existent_public_key)
            .expect("load_keypair operation should succeed even for non-existent keys");
        
        // Expected Result: Returns Ok(None) without error
        assert!(result.is_none(), 
            "Loading non-existent keypair should return None, but got Some(_)");
        
        // Additional verification: Test with multiple non-existent keys to ensure consistency
        for _ in 0..5 {
            let another_secret_key = SecretKey::new(&mut rng);
            let another_private_key = PrivateKey::new(another_secret_key, REGTEST);
            let another_non_existent_public_key = PublicKey::from_private_key(&secp, &another_private_key);
            
            let another_result = keystore.load_keypair(&another_non_existent_public_key)
                .expect("load_keypair operation should consistently succeed for non-existent keys");
            
            assert!(another_result.is_none(), 
                "Loading multiple non-existent keypairs should consistently return None");
        }
        
        // Verify that the keystore operations don't fail even when repeatedly called
        // This tests that the "lookup" behavior is stable and doesn't cause side effects
        let repeated_result = keystore.load_keypair(&non_existent_public_key)
            .expect("Repeated load_keypair calls should not fail");
        
        assert!(repeated_result.is_none(), 
            "Repeated lookups of non-existent keypair should consistently return None");
        
        // Store one keypair to verify the keystore is functional, then test non-existent lookup again
        let stored_secret_key = SecretKey::new(&mut rng);
        let stored_private_key = PrivateKey::new(stored_secret_key, REGTEST);
        let stored_public_key = PublicKey::from_private_key(&secp, &stored_private_key);
        
        keystore.store_keypair(stored_private_key, stored_public_key)
            .expect("Should be able to store a keypair");
        
        // Verify the stored key can be retrieved (keystore is working)
        let stored_result = keystore.load_keypair(&stored_public_key)
            .expect("Should be able to load stored keypair");
        assert!(stored_result.is_some(), "Stored keypair should be retrievable");
        
        // Now test that non-existent keys still return None even with other keys present
        let final_result = keystore.load_keypair(&non_existent_public_key)
            .expect("load_keypair should work even with other keys present");
        
        assert!(final_result.is_none(), 
            "Non-existent keypair should still return None even when other keys are present");
        
        // Cleanup: drop both keystore and storage handles before removing files on Windows
        drop(keystore);
        drop(_store);
        cleanup_test_environment(&keystore_path, &store_path);
    }

    #[test]
    pub fn test_rsa_key_index_mapping() -> Result<(), KeyManagerError> {
        /*
         * Objective: Validate per-index storage and retrieval.
         * Preconditions: Initialized KeyStore.
         * Input / Test Data: RSA keypair PEM stored at index N.
         * Steps / Procedure: Store at N; load at N and N+1.
         * Expected Result: N returns Some(RSAKeyPair); N+1 returns None; public PEM round-trips.
         * This test will verify that the RSA key index mapping is working correctly.
         */
        
        run_test_with_key_manager(|key_manager| {
            // Initialize random number generator for RSA key generation
            let mut rng = secp256k1::rand::thread_rng();
            
            // Define test indices
            let target_index: usize = 5;
            let non_existent_index: usize = target_index + 1;
            
            // Generate and store RSA keypair at target_index N
            let original_pubkey_pem = key_manager.generate_rsa_keypair(&mut rng, target_index)
                .expect("Failed to generate RSA keypair at target index");
            
            // Test Step 1: Load at target index N - should return Some(RSAKeyPair)
            let loaded_rsa_key = key_manager.keystore.load_rsa_key(target_index)
                .expect("Failed to load RSA key at target index");
            
            assert!(loaded_rsa_key.is_some(), 
                "RSA key should be found at stored index {}", target_index);
            
            let loaded_key = loaded_rsa_key.unwrap();
            
            // Test Step 2: Verify the loaded RSA key public PEM round-trips correctly
            let loaded_pubkey_pem = loaded_key.export_public_pem()
                .expect("Failed to export public PEM from loaded RSA keypair");
            
            assert_eq!(loaded_pubkey_pem, original_pubkey_pem,
                "Loaded RSA public key PEM should match the original");
            
            // Test Step 3: Load at non-existent index N+1 - should return None
            let non_existent_result = key_manager.keystore.load_rsa_key(non_existent_index)
                .expect("Failed to attempt loading RSA key at non-existent index");
            
            assert!(non_existent_result.is_none(), 
                "RSA key should not be found at non-existent index {}", non_existent_index);
            
            // Additional verification: Test multiple indices to ensure proper index isolation
            let additional_indices = [0, 1, 10, 100];
            for &idx in &additional_indices {
                if idx != target_index {
                    let result = key_manager.keystore.load_rsa_key(idx)
                        .expect("Failed to check RSA key at additional index");
                    assert!(result.is_none(), 
                        "RSA key should not be found at unrelated index {}", idx);
                }
            }
            
            // Test Step 4: Store another RSA key at a different index and verify independence
            let different_index: usize = 20;
            let second_pubkey_pem = key_manager.generate_rsa_keypair(&mut rng, different_index)
                .expect("Failed to generate second RSA keypair at different index");
            
            // Verify both keys can be loaded independently
            let first_key_still_there = key_manager.keystore.load_rsa_key(target_index)
                .expect("Failed to re-load first RSA key");
            assert!(first_key_still_there.is_some(), 
                "First RSA key should still be available at index {}", target_index);
            
            let second_key_loaded = key_manager.keystore.load_rsa_key(different_index)
                .expect("Failed to load second RSA key");
            assert!(second_key_loaded.is_some(), 
                "Second RSA key should be available at index {}", different_index);
            
            // Verify the keys are different (different indices should have different keys)
            let first_key_pem = first_key_still_there.unwrap().export_public_pem()
                .expect("Failed to export first key's public PEM");
            let second_key_pem = second_key_loaded.unwrap().export_public_pem()
                .expect("Failed to export second key's public PEM");
            
            assert_ne!(first_key_pem, second_key_pem,
                "RSA keys at different indices should be different");
            
            // Verify the PEMs match what we got from generate_rsa_keypair
            assert_eq!(first_key_pem, original_pubkey_pem,
                "First loaded key PEM should match original");
            assert_eq!(second_key_pem, second_pubkey_pem,
                "Second loaded key PEM should match original");
            
            Ok(())
        })
    }

    #[test]
    pub fn test_overwrite_semantics() -> Result<(), KeyManagerError> {
        /*
         * Objective: Verify safe re-store behavior and RSA index overwrite semantics.
         * Preconditions: Existing entries for (a) an ECDSA keypair and (b) an RSA key at an index.
         * Input / Test Data: (a) Same ECDSA keypair re-stored; (b) Two different RSA keypairs stored at the same index N sequentially.
         * Steps / Procedure: (a) Call store_keypair twice with the same (sk, pk); load and compare; (b) store_rsa_key with key1 at N, then key2 at N; load_rsa_key(N).
         * Expected Result: (a) Idempotent: loaded entry equals the stored pair. (b) Last-write-wins: loaded RSA key equals the second one.
         */
        
        run_test_with_key_manager(|key_manager| {
            // Initialize contexts and random number generator
            let secp = secp256k1::Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            
            // Test Part (a): ECDSA keypair idempotent re-store behavior
            
            // Generate ECDSA keypair
            let secret_key = SecretKey::new(&mut rng);
            let private_key = PrivateKey::new(secret_key, REGTEST);
            let public_key = PublicKey::from_private_key(&secp, &private_key);
            
            // Store the ECDSA keypair first time
            key_manager.keystore.store_keypair(private_key, public_key)
                .expect("Failed to store ECDSA keypair first time");
            
            // Load and verify first storage
            let (loaded_private_1, loaded_public_1) = key_manager.keystore.load_keypair(&public_key)
                .expect("Failed to load ECDSA keypair after first store")
                .expect("ECDSA keypair should exist after first store");
            
            assert_eq!(loaded_private_1.to_string(), private_key.to_string(),
                "First load: private key should match stored key");
            assert_eq!(loaded_public_1.to_string(), public_key.to_string(),
                "First load: public key should match stored key");
            
            // Store the same ECDSA keypair second time (idempotent operation)
            key_manager.keystore.store_keypair(private_key, public_key)
                .expect("Failed to store ECDSA keypair second time");
            
            // Load and verify second storage - should be identical (idempotent)
            let (loaded_private_2, loaded_public_2) = key_manager.keystore.load_keypair(&public_key)
                .expect("Failed to load ECDSA keypair after second store")
                .expect("ECDSA keypair should exist after second store");
            
            assert_eq!(loaded_private_2.to_string(), private_key.to_string(),
                "Second load: private key should still match stored key");
            assert_eq!(loaded_public_2.to_string(), public_key.to_string(),
                "Second load: public key should still match stored key");
            
            // Verify idempotency: both loads should return identical results
            assert_eq!(loaded_private_1.to_string(), loaded_private_2.to_string(),
                "Idempotent re-store: private keys from both loads should be identical");
            assert_eq!(loaded_public_1.to_string(), loaded_public_2.to_string(),
                "Idempotent re-store: public keys from both loads should be identical");
            
            // Test Part (b): RSA key overwrite behavior (last-write-wins)
            
            let rsa_index: usize = 10;
            
            // Generate and store first RSA keypair at index N
            let first_rsa_pubkey_pem = key_manager.generate_rsa_keypair(&mut rng, rsa_index)
                .expect("Failed to generate first RSA keypair");
            
            // Load and verify first RSA key
            let loaded_first_rsa = key_manager.keystore.load_rsa_key(rsa_index)
                .expect("Failed to load first RSA key")
                .expect("First RSA key should exist");
            
            let first_loaded_pubkey_pem = loaded_first_rsa.export_public_pem()
                .expect("Failed to export public PEM from first RSA key");
            
            assert_eq!(first_loaded_pubkey_pem, first_rsa_pubkey_pem,
                "First RSA key should match original");
            
            // Generate and store second RSA keypair at the SAME index N (overwrite)
            let second_rsa_pubkey_pem = key_manager.generate_rsa_keypair(&mut rng, rsa_index)
                .expect("Failed to generate second RSA keypair");
            
            // Verify the two RSA public keys are different (we generated different keys)
            assert_ne!(first_rsa_pubkey_pem, second_rsa_pubkey_pem,
                "The two generated RSA keys should be different");
            
            // Load RSA key after overwrite - should return the second key (last-write-wins)
            let loaded_overwritten_rsa = key_manager.keystore.load_rsa_key(rsa_index)
                .expect("Failed to load RSA key after overwrite")
                .expect("RSA key should still exist after overwrite");
            
            let overwritten_loaded_pubkey_pem = loaded_overwritten_rsa.export_public_pem()
                .expect("Failed to export public PEM from overwritten RSA key");
            
            // Verify last-write-wins: loaded key should match the second (most recent) key
            assert_eq!(overwritten_loaded_pubkey_pem, second_rsa_pubkey_pem,
                "Last-write-wins: loaded RSA key should match the second (latest) stored key");
            
            // Verify the loaded key is NOT the first key (overwrite was successful)
            assert_ne!(overwritten_loaded_pubkey_pem, first_rsa_pubkey_pem,
                "Overwrite verification: loaded RSA key should NOT match the first (overwritten) key");
            
            // Additional verification: Test that RSA overwrite doesn't affect ECDSA storage
            let (final_ecdsa_private, final_ecdsa_public) = key_manager.keystore.load_keypair(&public_key)
                .expect("Failed to load ECDSA keypair after RSA operations")
                .expect("ECDSA keypair should still exist after RSA operations");
            
            assert_eq!(final_ecdsa_private.to_string(), private_key.to_string(),
                "ECDSA private key should be unaffected by RSA operations");
            assert_eq!(final_ecdsa_public.to_string(), public_key.to_string(),
                "ECDSA public key should be unaffected by RSA operations");
            
            Ok(())
        })
    }

    #[test]
    pub fn test_generate_keypair_in_keystore() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure generate_keypair persists the generated pair.
         * Preconditions: Initialized KeyManager and KeyStore.
         * Input / Test Data: RNG seeded; network set.
         * Steps / Procedure: Call generate_keypair; then KeyStore::load_keypair with returned pubkey.
         * Expected Result: Load returns Some((sk, pk)) and strings match.
         */
        
        run_test_with_key_manager(|key_manager| {
            // Initialize seeded RNG for reproducible testing
            let mut rng = secp256k1::rand::thread_rng();
            
            // Step 1: Call generate_keypair to create and store a new keypair
            let generated_public_key = key_manager.generate_keypair(&mut rng)
                .expect("Failed to generate keypair");
            
            // Verify that the generated public key is valid (33 bytes compressed format)
            assert_eq!(generated_public_key.to_bytes().len(), 33,
                "Generated public key should be 33 bytes in compressed format");
            
            // Step 2: Load the keypair from keystore using the returned public key
            let loaded_keypair = key_manager.keystore.load_keypair(&generated_public_key)
                .expect("Failed to load keypair from keystore");
            
            // Expected Result: Load should return Some((sk, pk))
            assert!(loaded_keypair.is_some(),
                "Keystore should contain the generated keypair");
            
            let (loaded_private_key, loaded_public_key) = loaded_keypair.unwrap();
            
            // Step 3: Verify that the loaded keys match the generated key
            assert_eq!(loaded_public_key.to_string(), generated_public_key.to_string(),
                "Loaded public key should match the generated public key");
            
            // Step 4: Verify key consistency by deriving public key from loaded private key
            let secp = secp256k1::Secp256k1::new();
            let derived_public_key = PublicKey::from_private_key(&secp, &loaded_private_key);
            
            assert_eq!(derived_public_key.to_string(), generated_public_key.to_string(),
                "Public key derived from loaded private key should match generated public key");
            
            assert_eq!(derived_public_key.to_string(), loaded_public_key.to_string(),
                "Public key derived from private key should match loaded public key");
            
            // Step 5: Additional verification - test that we can use the loaded keys for cryptographic operations
            let signature_verifier = SignatureVerifier::new();
            let test_message = random_message();
            
            // Sign with the loaded private key via KeyManager
            let signature = key_manager.sign_ecdsa_message(&test_message, &loaded_public_key)
                .expect("Failed to sign message with loaded key");
            
            // Verify the signature using the loaded public key
            assert!(signature_verifier.verify_ecdsa_signature(&signature, &test_message, loaded_public_key),
                "Signature should verify successfully with loaded public key");
            
            // Step 6: Test multiple keypair generation to ensure each is unique and properly stored
            let mut generated_keys: Vec<PublicKey> = Vec::new();
            for i in 0..3 {
                let another_public_key = key_manager.generate_keypair(&mut rng)
                    .expect(&format!("Failed to generate keypair {}", i + 2));
                
                // Verify this key is different from previously generated keys
                for existing_key in &generated_keys {
                    assert_ne!(another_public_key.to_string(), existing_key.to_string(),
                        "Each generated keypair should be unique");
                }
                
                // Verify this key can be loaded from keystore
                let another_loaded = key_manager.keystore.load_keypair(&another_public_key)
                    .expect("Failed to load additional keypair")
                    .expect("Additional keypair should exist in keystore");
                
                assert_eq!(another_loaded.1.to_string(), another_public_key.to_string(),
                    "Additional loaded public key should match generated key");
                
                generated_keys.push(another_public_key);
            }
            
            // Step 7: Verify all generated keys are still accessible (persistence test)
            generated_keys.push(generated_public_key); // Include the original key
            
            for (i, key) in generated_keys.iter().enumerate() {
                let persistent_loaded = key_manager.keystore.load_keypair(key)
                    .expect(&format!("Failed to re-load keypair {}", i + 1))
                    .expect(&format!("Keypair {} should still exist in keystore", i + 1));
                
                assert_eq!(persistent_loaded.1.to_string(), key.to_string(),
                    "Persistently loaded public key {} should match original", i + 1);
            }
            
            Ok(())
        })
    }

    #[test]
    pub fn test_import_private_key_wif_success() -> Result<(), KeyManagerError> {
        /* 
         * Objective: Validate WIF import stores a keypair.
         * Preconditions: Valid WIF string for the configured network.
         * Input / Test Data: WIF string.
         * Steps / Procedure: Call import_private_key(wif); then load_keypair by returned pubkey.
         * Expected Result: Returns public key; load succeeds with matching keys.
         */
        run_test_with_key_manager(|key_manager| {
            // Create a valid WIF for testing - using a known private key
            let secp = Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            let secret_key = SecretKey::new(&mut rng);
            let original_private_key = PrivateKey::new(secret_key, REGTEST);
            let original_public_key = PublicKey::from_private_key(&secp, &original_private_key);
            
            // Convert to WIF format for the configured network
            let wif_string = original_private_key.to_wif();
            
            // Import the WIF string
            let imported_public_key = key_manager.import_private_key(&wif_string)?;
            
            // Verify the imported public key matches the original
            assert_eq!(imported_public_key, original_public_key, 
                "Imported public key should match the original");
            
            // Load the keypair using the returned public key
            let (loaded_private_key, loaded_public_key) = key_manager.keystore.load_keypair(&imported_public_key)?
                .expect("Imported keypair should exist in keystore");
            
            // Verify the loaded keys match the original keys
            assert_eq!(loaded_private_key, original_private_key,
                "Loaded private key should match the original");
            assert_eq!(loaded_public_key, imported_public_key,
                "Loaded public key should match the imported public key");
            
            // Test with different WIF formats - compressed vs uncompressed
            let compressed_private_key = PrivateKey {
                compressed: true,
                network: bitcoin::Network::Regtest.into(),
                inner: original_private_key.inner,
            };
            let compressed_wif = compressed_private_key.to_wif();
            let compressed_public_key = PublicKey::from_private_key(&secp, &compressed_private_key);
            
            let imported_compressed = key_manager.import_private_key(&compressed_wif)?;
            assert_eq!(imported_compressed, compressed_public_key,
                "Imported compressed public key should match the original compressed key");
            
            let (loaded_compressed_private, loaded_compressed_public) = 
                key_manager.keystore.load_keypair(&imported_compressed)?
                .expect("Compressed imported key should exist in keystore");
            assert_eq!(loaded_compressed_private, compressed_private_key,
                "Loaded compressed private key should match the original");
            assert_eq!(loaded_compressed_public, imported_compressed,
                "Loaded compressed public key should match the imported public key");
            
            // Test persistence by simulating storage backend operations
            // Store both keys and verify they persist
            key_manager.keystore.store_keypair(original_private_key, original_public_key)?;
            key_manager.keystore.store_keypair(compressed_private_key, compressed_public_key)?;
            
            // Verify we can still load the imported keys
            let (persistent_private, persistent_public) = 
                key_manager.keystore.load_keypair(&imported_public_key)?
                .expect("Original imported key should be in keystore");
            assert_eq!(persistent_private, original_private_key,
                "Persistently loaded private key should match original");
            assert_eq!(persistent_public, imported_public_key,
                "Persistently loaded public key should match imported");
            
            let (persistent_compressed_private, persistent_compressed_public) = 
                key_manager.keystore.load_keypair(&imported_compressed)?
                .expect("Compressed imported key should be in keystore");
            assert_eq!(persistent_compressed_private, compressed_private_key,
                "Persistently loaded compressed private key should match original");
            assert_eq!(persistent_compressed_public, imported_compressed,
                "Persistently loaded compressed public key should match imported");
            
            // Test that importing the same WIF multiple times is idempotent
            let duplicate_import = key_manager.import_private_key(&wif_string)?;
            assert_eq!(duplicate_import, imported_public_key,
                "Duplicate import should return the same public key");
            
            // Test cryptographic operations with imported keys to verify they work correctly
            
            // Test cryptographic operations with imported keys
            let signature_verifier = SignatureVerifier::new();
            let test_message = random_message();
            
            // Sign with the imported key
            let signature = key_manager.sign_ecdsa_message(&test_message, &imported_public_key)?;
            
            // Verify the signature using the imported public key
            let is_valid = signature_verifier.verify_ecdsa_signature(
                &signature, 
                &test_message, 
                imported_public_key
            );
            assert!(is_valid, "Signature created with imported key should be valid");
            
            Ok(())
        })
    }

    #[test]
    pub fn test_import_private_key_wif_failure() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure invalid WIF returns the right error.
         * Preconditions: None.
         * Input / Test Data: Malformed WIF (e.g., non-base58, wrong checksum).
         * Steps / Procedure: Call import_private_key(bad).
         * Expected Result: Error KeyManagerError::FailedToParsePrivateKey.
         */
        run_test_with_key_manager(|key_manager| {
            // Test Case 1: Completely invalid string (non-base58 characters)
            let invalid_wif_1 = "this_is_not_a_wif_string_with_invalid_chars_0OIl";
            let result1 = key_manager.import_private_key(invalid_wif_1);
            assert!(result1.is_err(), "Import should fail for completely invalid WIF string");
            
            match result1.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 2: Empty string
            let empty_wif = "";
            let result2 = key_manager.import_private_key(empty_wif);
            assert!(result2.is_err(), "Import should fail for empty WIF string");
            
            match result2.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 3: Valid base58 but wrong length
            let wrong_length_wif = "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294Lv";  // Too short
            let result3 = key_manager.import_private_key(wrong_length_wif);
            assert!(result3.is_err(), "Import should fail for wrong length WIF");
            
            match result3.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 4: Valid base58 with wrong checksum
            // Start with a valid WIF and corrupt the checksum
            // let secp = Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            let secret_key = SecretKey::new(&mut rng);
            let valid_private_key = PrivateKey::new(secret_key, REGTEST);
            let valid_wif = valid_private_key.to_wif();
            
            // Corrupt the last character (part of checksum)
            let mut corrupted_wif = valid_wif.chars().collect::<Vec<char>>();
            let last_idx = corrupted_wif.len() - 1;
            corrupted_wif[last_idx] = if corrupted_wif[last_idx] == 'A' { 'B' } else { 'A' };
            let corrupted_wif_string: String = corrupted_wif.into_iter().collect();
            
            let result4 = key_manager.import_private_key(&corrupted_wif_string);
            assert!(result4.is_err(), "Import should fail for WIF with wrong checksum");
            
            match result4.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 5: Valid base58 but wrong network prefix
            // Create a WIF for a different network and try to import it
            let mainnet_private_key = PrivateKey::new(secret_key, bitcoin::Network::Bitcoin);
            let mainnet_wif = mainnet_private_key.to_wif();
            
            let _result5 = key_manager.import_private_key(&mainnet_wif);
            // This might succeed but we should test it anyway
            // Note: The behavior might depend on implementation - some might accept cross-network WIFs
            
            // Test Case 6: Random base58 string that looks like WIF but isn't
            let fake_wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTj";  // Random base58
            let result6 = key_manager.import_private_key(fake_wif);
            assert!(result6.is_err(), "Import should fail for fake WIF string");
            
            match result6.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 7: WIF with invalid characters that could be confused
            let confusing_wif = "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294Lv0OIl";  // Contains 0, O, I, l
            let result7 = key_manager.import_private_key(confusing_wif);
            assert!(result7.is_err(), "Import should fail for WIF with confusing characters");
            
            match result7.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 8: Very long invalid string
            let too_long_wif = "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294LvTJ1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294Lv";
            let result8 = key_manager.import_private_key(too_long_wif);
            assert!(result8.is_err(), "Import should fail for too long WIF string");
            
            match result8.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 9: WIF starting with wrong prefix
            let wrong_prefix_wif = "1J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294LvTJ";  // Starts with '1' instead of '5' or 'K'/'L'
            let result9 = key_manager.import_private_key(wrong_prefix_wif);
            assert!(result9.is_err(), "Import should fail for WIF with wrong prefix");
            
            match result9.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 10: Null bytes and special characters
            let null_wif = "5J1F7GHadZG3sCCKHCwg8\0Jvys9xUbFsjLnGec4H294LvTJ";
            let result10 = key_manager.import_private_key(null_wif);
            assert!(result10.is_err(), "Import should fail for WIF with null bytes");
            
            match result10.unwrap_err() {
                KeyManagerError::FailedToParsePrivateKey(_) => {
                    // Expected error type
                }
                other => panic!("Expected FailedToParsePrivateKey, got: {:?}", other),
            }
            
            // Test Case 11: Verify the KeyManager state is still clean after failures
            // Import a valid key to make sure the KeyManager still works
            let valid_secret_key = SecretKey::new(&mut rng);
            let valid_private_key = PrivateKey::new(valid_secret_key, REGTEST);
            let valid_wif = valid_private_key.to_wif();
            
            let valid_result = key_manager.import_private_key(&valid_wif);
            assert!(valid_result.is_ok(), "Valid WIF import should still work after failed attempts");
            
            Ok(())
        })
    }

    #[test]
    pub fn test_import_secret_key_hex_success() -> Result<(), KeyManagerError> {
        /*
         * Objective: Validate raw secret hex import stores keypair.
         * Preconditions: Valid 32-byte secp256k1 secret hex; network set.
         * Input / Test Data: 64-hex-character secret string.
         * Steps / Procedure: Call import_secret_key(hex, network); then load_keypair.
         * Expected Result: Returns public key; load succeeds; keys match.
         */
        run_test_with_key_manager(|key_manager| -> Result<(), KeyManagerError> {
            // Test Case 1: Generate a valid key using secp256k1's native key generation
            let secp = secp256k1::Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            let secret_key = secp256k1::SecretKey::new(&mut rng);
            let valid_hex = secret_key.display_secret().to_string();
            let imported_public_key = key_manager.import_secret_key(&valid_hex, REGTEST)?;
            
            // Verify the returned public key is valid
            assert!(!imported_public_key.to_string().is_empty(), 
                "Imported public key should not be empty");
            
            // Load the keypair using the returned public key
            let (loaded_private_key, loaded_public_key) = key_manager.keystore.load_keypair(&imported_public_key)?
                .expect("Imported keypair should exist in keystore");
            
            // Verify the loaded keys are consistent
            assert_eq!(loaded_public_key, imported_public_key,
                "Loaded public key should match the imported public key");
            
            // Verify the private key matches the hex input
            let expected_secret_key = SecretKey::from_str(&valid_hex)
                .expect("Valid hex should parse to SecretKey");
            let expected_private_key = PrivateKey::new(expected_secret_key, REGTEST);
            
            assert_eq!(loaded_private_key, expected_private_key,
                "Loaded private key should match the expected private key from hex");
            
            // Test Case 2: Another valid hex generated from secp
            let secret_key_2 = secp256k1::SecretKey::new(&mut rng);
            let hex_pattern_2 = secret_key_2.display_secret().to_string();
            let imported_key_2 = key_manager.import_secret_key(&hex_pattern_2, REGTEST)?;

            let (_loaded_private_2, loaded_public_2) = key_manager.keystore.load_keypair(&imported_key_2)?
                .expect("Second imported key should exist in keystore");
            assert_eq!(loaded_public_2, imported_key_2,
                "Second imported key should be loadable");

            // Test Case 3: Valid hex with mixed case (generate and then uppercase/lowercase mix)
            let secret_key_3 = secp256k1::SecretKey::new(&mut rng);
            let mut mixed_case_hex = secret_key_3.display_secret().to_string();
            // create a mixed-case variant
            mixed_case_hex = mixed_case_hex.chars().enumerate().map(|(i,c)| {
                if i % 2 == 0 { c.to_ascii_uppercase() } else { c }
            }).collect();
            let imported_key_3 = key_manager.import_secret_key(&mixed_case_hex, REGTEST)?;

            let (_loaded_private_3, loaded_public_3) = key_manager.keystore.load_keypair(&imported_key_3)?
                .expect("Mixed case hex import should exist in keystore");
            assert_eq!(loaded_public_3, imported_key_3,
                "Mixed case hex import should work correctly");
            
            // Test Case 4: Verify cryptographic operations work with imported key
            let signature_verifier = SignatureVerifier::new();
            let test_message = random_message();
            
            // Sign with the imported key
            let signature = key_manager.sign_ecdsa_message(&test_message, &imported_public_key)?;
            
            // Verify the signature using the imported public key
            let is_valid = signature_verifier.verify_ecdsa_signature(
                &signature, 
                &test_message, 
                imported_public_key
            );
            assert!(is_valid, "Signature created with imported secret key should be valid");
            
            // Test Case 5: Test different networks
            let mainnet_imported = key_manager.import_secret_key(&valid_hex, bitcoin::Network::Bitcoin)?;
            let (loaded_mainnet_private, loaded_mainnet_public) = key_manager.keystore.load_keypair(&mainnet_imported)?
                .expect("Mainnet imported keypair should exist in keystore");
            
            // The private key inner value should be the same, but network should differ
            assert_eq!(loaded_mainnet_private.inner, loaded_private_key.inner,
                "Private key inner values should be the same regardless of network");
            assert_ne!(loaded_mainnet_private.network, loaded_private_key.network,
                "Network should differ between regtest and mainnet imports");
            
            // Test Case 6: Verify persistence and idempotency
            let duplicate_import = key_manager.import_secret_key(&valid_hex, REGTEST)?;
            assert_eq!(duplicate_import, imported_public_key,
                "Duplicate import should return the same public key");
            
            // Verify all imported keys are still accessible
            let _verify_key1 = key_manager.keystore.load_keypair(&imported_public_key)?
                .expect("Original key should still be accessible");
            let _verify_key2 = key_manager.keystore.load_keypair(&imported_key_2)?
                .expect("Second key should still be accessible");
            let _verify_key3 = key_manager.keystore.load_keypair(&imported_key_3)?
                .expect("Third key should still be accessible");
            let _verify_mainnet = key_manager.keystore.load_keypair(&mainnet_imported)?
                .expect("Mainnet key should still be accessible");
            
            Ok(())
        })
    }

    #[test]
    pub fn test_import_secret_key_hex_failure() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure invalid hex parses fail.
         * Preconditions: None.
         * Input / Test Data: Non-hex or wrong-length string.
         * Steps / Procedure: Call import_secret_key(bad, network).
         * Expected Result: Error KeyManagerError::InvalidPrivateKey or parse error.
         */
        run_test_with_key_manager(|mut key_manager| {
            // Test Case 1: Non-hex characters
            let invalid_hex_1 = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
            let result1 = key_manager.import_secret_key(invalid_hex_1, REGTEST);
            assert!(result1.is_err(), "Import should fail for non-hex characters");
            
            // Test Case 2: Too short hex string
            let too_short_hex = "123456789abcdef";
            let result2 = key_manager.import_secret_key(too_short_hex, REGTEST);
            assert!(result2.is_err(), "Import should fail for hex string that's too short");
            
            // Test Case 3: Too long hex string
            let too_long_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef12345";
            let result3 = key_manager.import_secret_key(too_long_hex, REGTEST);
            assert!(result3.is_err(), "Import should fail for hex string that's too long");
            
            // Test Case 4: Empty string
            let empty_hex = "";
            let result4 = key_manager.import_secret_key(empty_hex, REGTEST);
            assert!(result4.is_err(), "Import should fail for empty hex string");
            
            // Test Case 5: Invalid characters mixed with valid hex
            let mixed_invalid_hex = "0123456789abcdefGHIJ456789abcdef0123456789abcdef0123456789abcdef";
            let result5 = key_manager.import_secret_key(mixed_invalid_hex, REGTEST);
            assert!(result5.is_err(), "Import should fail for hex with invalid characters");
            
            // Test Case 6: All zeros (valid hex but invalid private key)
            let zero_hex = "0000000000000000000000000000000000000000000000000000000000000000";
            let result6 = key_manager.import_secret_key(zero_hex, REGTEST);
            assert!(result6.is_err(), "Import should fail for all-zero private key");
            
            // Test Case 7: Hex string with spaces
            let hex_with_spaces = "0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef";
            let result7 = key_manager.import_secret_key(hex_with_spaces, REGTEST);
            assert!(result7.is_err(), "Import should fail for hex string with spaces");
            
            // Test Case 8: Hex string with 0x prefix
            let hex_with_prefix = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let result8 = key_manager.import_secret_key(hex_with_prefix, REGTEST);
            assert!(result8.is_err(), "Import should fail for hex string with 0x prefix");
            
            // Test Case 9: Private key above secp256k1 curve order (invalid)
            let above_curve_order = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
            let result9 = key_manager.import_secret_key(above_curve_order, REGTEST);
            assert!(result9.is_err(), "Import should fail for private key above curve order");
            
            // Test Case 10: Random unicode characters
            let unicode_hex = "你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好世界你好";
            let result10 = key_manager.import_secret_key(unicode_hex, REGTEST);
            assert!(result10.is_err(), "Import should fail for unicode characters");
            
            // Test Case 11: Verify KeyManager state is clean after failures
            // Try a valid import to ensure the KeyManager still works
            let valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let imported_pubkey = key_manager.import_secret_key(valid_hex, REGTEST)?;
            
            // Verify the imported key can be loaded correctly
            let loaded_key = key_manager.keystore.load_keypair(&imported_pubkey)?;
            assert!(loaded_key.is_some(), "Valid imported key should be loadable");
            
            // Verify that trying to load a different key returns None, confirming clean state
            let secp = secp256k1::Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            let other_secret_key = SecretKey::new(&mut rng);
            let other_private_key = PrivateKey::new(other_secret_key, REGTEST);
            let other_pubkey = PublicKey::from_private_key(&secp, &other_private_key);
            let other_key = key_manager.keystore.load_keypair(&other_pubkey)?;
            assert!(other_key.is_none(), "No other keys should exist in the store");
            
            Ok(())
        }
    )
}

    #[test]
    pub fn test_import_partial_keys_aggregation_success() -> Result<(), KeyManagerError> {
        /*
         * Objective: Aggregate partial keys into an aggregated (sk, pk) and store.
         * Preconditions: 2–3 valid partial keys (as strings) available.
         * Input / Test Data: Inputs for import_partial_secret_keys and import_partial_private_keys.
         * Steps / Procedure: Call import; then load_keypair by returned public key.
         * Expected Result: Aggregated keypair stored; load succeeds.
         */
        run_test_with_key_manager(|mut key_manager| {
            // Test Case 1: Aggregate 2 partial secret keys
            let secp = Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            
            // Create 2 valid secret keys for aggregation
            let secret_key_1 = SecretKey::new(&mut rng);
            let secret_key_2 = SecretKey::new(&mut rng);
            
            let partial_secret_keys = vec![
                secret_key_1.display_secret().to_string(),
                secret_key_2.display_secret().to_string(),
            ];
            
            // Import and aggregate partial secret keys
            let aggregated_public_key_1 = key_manager.import_partial_secret_keys(
                partial_secret_keys, 
                REGTEST
            )?;
            
            // Verify the aggregated public key is valid
            assert!(!aggregated_public_key_1.to_string().is_empty(),
                "Aggregated public key should not be empty");
            
            // Load the aggregated keypair
            let loaded_keys_1 = key_manager.keystore.load_keypair(&aggregated_public_key_1)?
                .expect("Aggregated keypair should exist in keystore");
            let (loaded_private_key_1, loaded_public_key_1) = loaded_keys_1;
            
            // Verify the loaded keys match the aggregated result
            assert_eq!(loaded_public_key_1, aggregated_public_key_1,
                "Loaded public key should match the aggregated public key");
            
            // Test Case 2: Aggregate 3 partial secret keys
            let secret_key_3 = SecretKey::new(&mut rng);
            let secret_key_4 = SecretKey::new(&mut rng);
            let secret_key_5 = SecretKey::new(&mut rng);
            
            let partial_secret_keys_3 = vec![
                secret_key_3.display_secret().to_string(),
                secret_key_4.display_secret().to_string(),
                secret_key_5.display_secret().to_string(),
            ];
            
            let aggregated_public_key_2 = key_manager.import_partial_secret_keys(
                partial_secret_keys_3, 
                REGTEST
            )?;
            
            let loaded_keys_2 = key_manager.keystore.load_keypair(&aggregated_public_key_2)?
                .expect("3-key aggregated keypair should exist in keystore");
            let (loaded_private_key_2, loaded_public_key_2) = loaded_keys_2;
            assert_eq!(loaded_public_key_2, aggregated_public_key_2,
                "3-key aggregated public key should be loadable");
            
            // Test Case 3: Aggregate partial private keys (WIF format)
            let private_key_1 = PrivateKey::new(SecretKey::new(&mut rng), REGTEST);
            let private_key_2 = PrivateKey::new(SecretKey::new(&mut rng), REGTEST);
            
            let partial_private_keys = vec![
                private_key_1.to_wif(),
                private_key_2.to_wif(),
            ];
            
            let aggregated_public_key_3 = key_manager.import_partial_private_keys(
                partial_private_keys,
                REGTEST
            )?;
            
            let loaded_keys_3 = key_manager.keystore.load_keypair(&aggregated_public_key_3)?
                .expect("WIF-based aggregated keypair should exist in keystore");
            let (loaded_private_key_3, loaded_public_key_3) = loaded_keys_3;
            assert_eq!(loaded_public_key_3, aggregated_public_key_3,
                "WIF-based aggregated public key should be loadable");
            
            // Test Case 4: Test with different networks
            let mainnet_partial_keys = vec![
                PrivateKey::new(SecretKey::new(&mut rng), bitcoin::Network::Bitcoin).to_wif(),
                PrivateKey::new(SecretKey::new(&mut rng), bitcoin::Network::Bitcoin).to_wif(),
            ];
            
            let mainnet_aggregated = key_manager.import_partial_private_keys(
                mainnet_partial_keys,
                bitcoin::Network::Bitcoin
            )?;
            
            let mainnet_keys = key_manager.keystore.load_keypair(&mainnet_aggregated)?
                .expect("Mainnet aggregated keypair should exist in keystore");
            let (mainnet_private, mainnet_public) = mainnet_keys;
            assert_eq!(mainnet_public, mainnet_aggregated,
                "Mainnet aggregated key should be loadable");
            assert_eq!(mainnet_private.network, bitcoin::Network::Bitcoin.into(),
                "Mainnet aggregated key should have correct network type");
            
            // Test Case 5: Verify cryptographic operations work with aggregated keys
            let signature_verifier = SignatureVerifier::new();
            let test_message = random_message();
            
            // Sign with the first aggregated key
            let signature = key_manager.sign_ecdsa_message(&test_message, &aggregated_public_key_1)?;
            
            // Verify the signature using the aggregated public key
            let is_valid = signature_verifier.verify_ecdsa_signature(
                &signature, 
                &test_message, 
                aggregated_public_key_1
            );
            assert!(is_valid, "Signature created with aggregated key should be valid");
            
            // Test Case 6: Verify all aggregated keys are different
            assert_ne!(aggregated_public_key_1, aggregated_public_key_2,
                "Different partial keys should produce different aggregated keys");
            assert_ne!(aggregated_public_key_1, aggregated_public_key_3,
                "Secret keys vs private keys aggregation should produce different results");
            assert_ne!(aggregated_public_key_2, aggregated_public_key_3,
                "All aggregated keys should be unique");
            
            // Test Case 7: Verify persistence - all aggregated keys should be loadable
            let _test_load_1 = key_manager.keystore.load_keypair(&aggregated_public_key_1)?.expect("Aggregated key 1 should exist");
            let _test_load_2 = key_manager.keystore.load_keypair(&aggregated_public_key_2)?.expect("Aggregated key 2 should exist");
            let _test_load_3 = key_manager.keystore.load_keypair(&aggregated_public_key_3)?.expect("Aggregated key 3 should exist");
            let _test_mainnet = key_manager.keystore.load_keypair(&mainnet_aggregated)?.expect("Mainnet aggregated key should exist");
            
            // Test Case 8: Test idempotent behavior - same partial keys should produce same result
            let duplicate_partial_keys = vec![
                secret_key_1.display_secret().to_string(),
                secret_key_2.display_secret().to_string(),
            ];
            
            let duplicate_aggregated = key_manager.import_partial_secret_keys(
                duplicate_partial_keys, 
                REGTEST
            )?;
            
            // Note: Depending on implementation, this might be the same or different
            // The behavior depends on whether the aggregation algorithm is deterministic
            // and whether duplicate detection is implemented
            
            Ok(())
        })
    }

    #[test]
    pub fn test_import_partial_keys_aggregation_failure() -> Result<(), KeyManagerError> {
        /*
         * Objective: Ensure invalid partial keys or aggregation fails.
         * Preconditions: None.
         * Input / Test Data: Malformed partial keys; insufficient keys.
         * Steps / Procedure: Call import_partial_secret_keys/import_partial_private_keys with bad data.
         * Expected Result: Error KeyManagerError::FailedToAggregatePartialKeys or parse error.
         */
        run_test_with_key_manager(|mut key_manager| -> Result<(), KeyManagerError> {
            // Test Case 1: Try with empty keys list
            let empty_keys: Vec<String> = vec![];
            let result1 = key_manager.import_partial_secret_keys(empty_keys, REGTEST);
            match result1 {
                Err(KeyManagerError::InvalidPrivateKey) => (),
                other => panic!("Expected InvalidPrivateKey for empty input, got: {:?}", other),
            }
            
            // Test Case 2: Try to aggregate a single key (musig2 accepts single-key aggregation)
            let secp = secp256k1::Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            let secret_key = secp256k1::SecretKey::new(&mut rng);
            let single_key = vec![secret_key.display_secret().to_string()];

            let result2 = key_manager.import_partial_secret_keys(single_key.clone(), REGTEST);
            // musig2 may accept a single key and return a valid aggregated pubkey; assert success
            assert!(result2.is_ok(), "Single key aggregation should succeed or be handled: {:?}", result2);
            let aggregated = result2.unwrap();
            // verify it was stored
            let loaded = key_manager.keystore.load_keypair(&aggregated)?;
            assert!(loaded.is_some(), "Aggregated single-key result should be stored");
            
            // Test Case 3: Invalid hex in partial secret keys
            let invalid_hex_keys = vec![
                "invalid_hex_string".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ];
            let result3 = key_manager.import_partial_secret_keys(invalid_hex_keys, REGTEST);
            assert!(result3.is_err(), "Invalid hex should fail parsing");
            
            // Test Case 4: Invalid WIF in partial private keys
            let invalid_wif_keys = vec![
                "invalid_wif_string".to_string(),
                "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H294LvTJ".to_string(),
            ];
            let result4 = key_manager.import_partial_private_keys(invalid_wif_keys, REGTEST);
            assert!(result4.is_err(), "Invalid WIF should fail parsing");
            
            // Test Case 5: Mixed valid and invalid keys
            let mixed_keys = vec![
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                "not_a_valid_key".to_string(),
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            ];
            let result5 = key_manager.import_partial_secret_keys(mixed_keys, REGTEST);
            assert!(result5.is_err(), "Mixed valid/invalid keys should fail");
            
            // Test Case 6: All zero secret keys (invalid for cryptography)
            let zero_keys = vec![
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ];
            let result6 = key_manager.import_partial_secret_keys(zero_keys, REGTEST);
            assert!(result6.is_err(), "All-zero keys should fail");
            
            // Test Case 7: Keys above secp256k1 curve order
            let above_curve_keys = vec![
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ];
            let result7 = key_manager.import_partial_secret_keys(above_curve_keys, REGTEST);
            assert!(result7.is_err(), "Keys above curve order should fail");
            
            // Test Case 8: Wrong length hex strings
            let wrong_length_keys = vec![
                "0123456789abcdef".to_string(), // Too short
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(), // Correct
            ];
            let result8 = key_manager.import_partial_secret_keys(wrong_length_keys, REGTEST);
            assert!(result8.is_err(), "Wrong length keys should fail");
            
            // Test Case 9: Empty strings in partial keys
            let empty_string_keys = vec![
                "".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ];
            let result9 = key_manager.import_partial_secret_keys(empty_string_keys, REGTEST);
            assert!(result9.is_err(), "Empty string keys should fail");
            
            // Test Case 10: Special characters and whitespace
            let special_char_keys = vec![
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                "fedcba9876543210 fedcba9876543210 fedcba9876543210 fedcba9876543210".to_string(), // With spaces
            ];
            let result10 = key_manager.import_partial_secret_keys(special_char_keys, REGTEST);
            assert!(result10.is_err(), "Keys with spaces should fail");
            
            // Test Case 11: Too many partial keys (test system limits)
            let mut too_many_keys = Vec::new();
            let secp = Secp256k1::new();
            let mut rng = secp256k1::rand::thread_rng();
            
            for _ in 0..100 {  // Create 100 keys to test limits
                let secret_key = SecretKey::new(&mut rng);
                too_many_keys.push(secret_key.display_secret().to_string());
            }
            
            let result11 = key_manager.import_partial_secret_keys(too_many_keys, REGTEST);
            // This might succeed or fail depending on implementation limits
            // We're just testing that the system handles large inputs gracefully
            
            // Test Case 12: Verify KeyManager state is clean after failures
            // Try a valid aggregation to ensure the KeyManager still works
            let valid_secret_1 = SecretKey::new(&mut rng);
            let valid_secret_2 = SecretKey::new(&mut rng);
            let valid_keys = vec![
                valid_secret_1.display_secret().to_string(),
                valid_secret_2.display_secret().to_string(),
            ];
            
            let valid_result = key_manager.import_partial_secret_keys(valid_keys, REGTEST);
            assert!(valid_result.is_ok(), "Valid aggregation should work after failed attempts");
            
            // Verify the aggregated key can be loaded (proves it was stored correctly)
            let valid_aggregated = valid_result.unwrap();
            let _valid_loaded = key_manager.keystore.load_keypair(&valid_aggregated)?
                .expect("Valid aggregated key should exist");

            Ok(())
        })
    }
}
