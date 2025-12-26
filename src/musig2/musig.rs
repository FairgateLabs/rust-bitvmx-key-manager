use bitcoin::{
    secp256k1::{schnorr::Signature, SecretKey},
    Network, PrivateKey, PublicKey,
};
use musig2::{
    aggregate_partial_signatures, secp::Scalar, verify_partial, verify_single, AggNonce,
    CompactSignature, PartialSignature, SecNonce,
};
use std::{collections::HashMap, rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, error};
use zeroize::Zeroizing;

use musig2::{KeyAggContext, PubNonce};

use super::{
    errors::Musig2SignerError,
    helper::{to_bitcoin_pubkey, to_musig_pubkey},
    types::{MessageId, Musig2MessageData, Musig2SessionData},
};

/// Keys used for storing data in the key-value store
enum StoreKey {
    /// Stores the nonce index for a given public key
    IndexForNonceGeneration(PublicKey),
    MuSig2Session {
        aggregated_pubkey: String,
    },
    MuSig2ParticipantPubKeys {
        aggregated_pubkey: String,
    },
    MuSig2MyPublicKey {
        aggregated_pubkey: String,
    },
    MuSig2MessageIds {
        aggregated_pubkey: String,
        session_id: String,
    },
    MuSig2PubNonces {
        aggregated_pubkey: String,
        session_id: String,
        message_id: String,
    },
    MuSig2PubNonce {
        aggregated_pubkey: String,
        session_id: String,
        message_id: String,
        participant_pubkey: String,
    },
    MuSig2SecretNonce {
        aggregated_pubkey: String,
        session_id: String,
        message_id: String,
    },
    MuSig2Tweak {
        aggregated_pubkey: String,
        session_id: String,
        message_id: String,
    },
    MuSig2Message {
        aggregated_pubkey: String,
        session_id: String,
        message_id: String,
    },
    MuSig2PartialSignatures {
        aggregated_pubkey: String,
        session_id: String,
        message_id: String,
    },
    MuSig2PartialSignature {
        aggregated_pubkey: String,
        session_id: String,
        message_id: String,
        participant_pubkey: String,
    },
}

/// MuSig2Signer manages the multi-signature signing process.
///
/// The signing process follows these steps:
///
/// 1. Initialize a new signing session with `init_musig2()`
/// 2. Generate public nonces for each message using `generate_pub_nonce()`
/// 3. Get your public nonces with `get_my_pub_nonces()` to share with other participants
/// 4. Aggregate all participants' nonces with `aggregate_nonces()`
/// 5. Get your partial signatures with `get_my_partial_signatures()`
/// 6. Aggregate all partial signatures with `aggregate_partial_signatures()`
/// 7. Get final signature for a message with `get_aggregate_partial_signature()`
pub struct MuSig2Signer {
    store: Rc<Storage>,
}

pub type PartialSignatureData = HashMap<
    String,
    (
        Vec<u8>,
        SecNonce,
        Option<musig2::secp256k1::Scalar>,
        AggNonce,
    ),
>;

#[allow(dead_code)]
pub trait MuSig2SignerApi {
    /// Initializes a new MuSig2 signing session.
    ///
    /// # Arguments
    ///
    /// * `participant_pubkeys` - Public keys of all signing participants (will be sorted internally)
    /// * `my_pub_key` - Public key of the current participant
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if initialization succeeds, or an error if:
    /// - Less than 2 participants
    /// - Current participant's key not included
    fn new_session(
        &self,
        participant_pubkeys: Vec<PublicKey>,
        my_pub_key: PublicKey,
    ) -> Result<PublicKey, Musig2SignerError>;

    /// Aggregates public nonces from other participants.
    ///
    /// # Arguments
    ///
    /// * `id` - Session identifier
    /// * `pub_nonces_map` - Map of participant public keys to their public nonces with message IDs
    ///
    /// # Returns
    ///
    /// Ok if nonces are successfully aggregated, error if:
    /// - Session not found
    /// - Invalid public key
    /// - Nonce already exists
    fn aggregate_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        pub_nonces_map: HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
    ) -> Result<(), Musig2SignerError>;

    /// Gets this participant's public nonces for all messages.
    ///
    /// # Arguments
    ///
    /// * `id` - Session identifier
    ///
    /// # Returns
    ///
    /// Vector of message IDs and public nonces, or error if:
    /// - Session not found
    /// - Nonces not yet generated
    fn get_my_pub_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, PubNonce)>, Musig2SignerError>;

    fn get_my_pub_nonce(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<PubNonce, Musig2SignerError>;

    /// Aggregates partial signatures from other participants.
    ///
    /// # Arguments
    ///
    /// * `id` - Session identifier
    /// * `partial_signatures` - Map of participant public keys to their partial signatures with message IDs
    ///
    /// # Returns
    ///
    /// Ok if signatures are successfully aggregated, error if:
    /// - Session not found
    /// - Invalid public key
    /// - Invalid partial signature
    /// - Signature already exists
    fn save_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        partial_signatures: HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
    ) -> Result<(), Musig2SignerError>;

    /// Gets this participant's partial signatures for all messages.
    ///
    /// # Arguments
    ///
    /// * `id` - Session identifier
    ///
    /// # Returns
    ///
    /// Vector of message IDs and partial signatures, or error if:
    /// - Session not found
    /// - Incomplete participant nonces
    fn get_data_for_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<PartialSignatureData, Musig2SignerError>;

    fn get_data_for_partial_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<
        (
            Vec<u8>,
            SecNonce,
            Option<musig2::secp256k1::Scalar>,
            AggNonce,
        ),
        Musig2SignerError,
    >;

    /// Verifies partial signatures from a participant.
    ///
    /// # Arguments
    ///
    /// * `id` - Session identifier
    /// * `pubkey` - Public key of participant whose signatures to verify
    /// * `partial_signatures` - Vector of message IDs and partial signatures to verify
    ///
    /// # Returns
    ///
    /// True if all signatures are valid, error if:
    /// - Session not found
    /// - Invalid partial signature
    fn verify_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        pubkey: PublicKey,
        partial_signatures: Vec<(MessageId, PartialSignature)>,
    ) -> Result<bool, Musig2SignerError>;

    /// Verifies a final signature for a specific message.
    ///
    /// # Arguments
    ///
    /// * `id` - Session identifier
    /// * `message_id` - ID of message to verify signature for
    /// * `final_signature` - Final aggregated signature to verify
    /// * `aggregated_pubkey` - Aggregated public key from init_musig2
    ///
    /// # Returns
    ///
    /// True if signature is valid, error if:
    /// - Session not found
    /// - Invalid signature
    fn verify_final_signature(
        &self,
        message_id: &str,
        final_signature: Signature,
        aggregated_pubkey: PublicKey,
        id: &str,
    ) -> Result<bool, Musig2SignerError>;

    /*
    /// Computes the aggregated public key from participant public keys.
    ///
    /// # Arguments
    ///
    /// * `participant_pubkeys` - Vector of participant public keys to aggregate
    ///
    /// # Returns
    ///
    /// Aggregated public key, or error if:
    /// - Invalid public key format
    /// - Error during key aggregation
    /fn get_aggregated_pubkey(&self, session_id: &str) -> Result<PublicKey, Musig2SignerError>;*/

    /// Gets the final aggregated signature for a specific message.
    ///
    /// # Arguments
    ///
    /// * `musig_id` - Session identifier
    /// * `message_id` - ID of message to get signature for
    ///
    /// # Returns
    ///
    /// Final aggregated signature, or error if:
    /// - Session not found
    /// - Message not found
    /// - Missing partial signatures
    fn get_aggregated_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<Signature, Musig2SignerError>;
}

impl MuSig2SignerApi for MuSig2Signer {
    fn new_session(
        &self,
        participant_pubkeys: Vec<PublicKey>,
        my_pub_key: PublicKey,
    ) -> Result<PublicKey, Musig2SignerError> {
        if participant_pubkeys.len() < 2 {
            return Err(Musig2SignerError::InvalidNumberOfParticipants);
        }

        let participant_index: Option<usize> = participant_pubkeys
            .iter()
            .position(|&pubkey| pubkey == my_pub_key);

        if participant_index.is_none() {
            return Err(Musig2SignerError::InvalidNumberOfParticipants);
        }

        // Sort participants by public key
        let mut sorted_participants = participant_pubkeys.clone();
        sorted_participants.sort();

        let key_agg_context = self.get_key_agg_context_aux(sorted_participants.clone(), None)?;
        let aggregated_pubkey: musig2::secp256k1::PublicKey = key_agg_context.aggregated_pubkey();
        let aggregated_pubkey = to_bitcoin_pubkey(aggregated_pubkey)?;
        debug!(
            "Creating sessing for aggregated pubkey: {}",
            aggregated_pubkey.to_string()
        );

        let session_data = (aggregated_pubkey, sorted_participants, my_pub_key);

        self.save_musig_session_data(session_data)?;
        Ok(aggregated_pubkey)
    }

    fn get_my_pub_nonce(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<PubNonce, Musig2SignerError> {
        let my_pub_key = self.my_public_key(aggregated_pubkey)?;
        match self.get_pub_nonce(aggregated_pubkey, id, message_id, &my_pub_key)? {
            Some(pub_nonce) => Ok(pub_nonce),
            None => return Err(Musig2SignerError::NoncesNotGenerated),
        }
    }

    fn get_my_pub_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, PubNonce)>, Musig2SignerError> {
        let my_pub_key = self.my_public_key(aggregated_pubkey)?;
        let message_ids = self.get_message_ids(aggregated_pubkey, id);

        let message_ids = match message_ids {
            Ok(ids) => ids,
            Err(_) => {
                error!(
                    "Failed to get message IDs for aggregated pubkey: {}",
                    aggregated_pubkey.to_string()
                );
                return Err(Musig2SignerError::NoncesNotGenerated);
            }
        };

        let mut pub_nonces = Vec::new();

        for message_id in message_ids.iter() {
            let pub_nonce =
                match self.get_pub_nonce(aggregated_pubkey, id, message_id, &my_pub_key)? {
                    Some(pub_nonce) => pub_nonce,
                    None => return Err(Musig2SignerError::NoncesNotGenerated),
                };
            pub_nonces.push((message_id.clone(), pub_nonce));
        }

        Ok(pub_nonces)
    }

    fn aggregate_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        pub_nonces_map: HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
    ) -> Result<(), Musig2SignerError> {
        debug!(
            "Aggregating nonces for aggregated pubkey: {}
                with nonces: {:?}",
            aggregated_pubkey.to_string(),
            pub_nonces_map
        );

        let participant_pubkeys = self.get_participant_pub_keys(aggregated_pubkey)?;

        let my_pub_key = self.my_public_key(aggregated_pubkey)?;

        if pub_nonces_map.len() != (participant_pubkeys.len() - 1) {
            return Err(Musig2SignerError::InvalidParticipantNonces);
        }

        for pub_key in pub_nonces_map.keys() {
            if *pub_key == my_pub_key {
                return Err(Musig2SignerError::InvalidPublicKey);
            }
        }

        // Validate that all nonces are valid
        for (pub_key, nonces) in &pub_nonces_map {
            for (message_id_nonce, nonce) in nonces {
                let key = self.get_key(StoreKey::MuSig2PubNonce {
                    aggregated_pubkey: aggregated_pubkey.to_string(),
                    session_id: id.to_string(),
                    message_id: message_id_nonce.to_string(),
                    participant_pubkey: pub_key.to_string(),
                });
                let exist_nonce = self.store.has_key(&key)?;

                if exist_nonce {
                    return Err(Musig2SignerError::NonceAlreadyExists);
                } else {
                    // Save the public nonce
                    self.store.set(key, nonce.clone(), None)?;
                }
            }
        }

        Ok(())
    }

    fn get_data_for_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<
        HashMap<
            String,
            (
                Vec<u8>,
                SecNonce,
                Option<musig2::secp256k1::Scalar>,
                AggNonce,
            ),
        >,
        Musig2SignerError,
    > {
        let participant_pubkeys = self.get_participant_pub_keys(aggregated_pubkey)?;

        self.validate_partial_nonces(participant_pubkeys, aggregated_pubkey, id)?;

        let aggregated_nonces = self.get_aggregated_nonces(aggregated_pubkey, id)?;
        let message_ids = self.get_message_ids(aggregated_pubkey, id)?;

        let mut data_to_sign = HashMap::new();

        for message_id in message_ids.iter() {
            let aggregated_nonce = aggregated_nonces
                .iter()
                .find(|(msg_id, _)| msg_id == message_id)
                .ok_or_else(|| Musig2SignerError::MissingNonce(message_id.to_string()))?
                .1
                .clone();

            let message = self.get_message(aggregated_pubkey, id, message_id)?;
            let tweak = self.get_tweak(aggregated_pubkey, id, message_id)?;
            let secret_nonce = self.get_secret_nonce(aggregated_pubkey, id, message_id)?;

            data_to_sign.insert(
                message_id.clone(),
                (message, secret_nonce, tweak, aggregated_nonce),
            );
        }

        Ok(data_to_sign)
    }

    fn get_data_for_partial_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<
        (
            Vec<u8>,
            SecNonce,
            Option<musig2::secp256k1::Scalar>,
            AggNonce,
        ),
        Musig2SignerError,
    > {
        let participant_pubkeys = self.get_participant_pub_keys(aggregated_pubkey)?;

        self.validate_partial_nonces(participant_pubkeys, aggregated_pubkey, id)?;

        let aggregated_nonces = self.get_aggregated_nonces(aggregated_pubkey, id)?;
        let aggregated_nonce = aggregated_nonces
            .iter()
            .find(|(msg_id, _)| msg_id == message_id)
            .ok_or_else(|| Musig2SignerError::MissingNonce(message_id.to_string()))?
            .1
            .clone();

        let message = self.get_message(aggregated_pubkey, id, message_id)?;
        let tweak = self.get_tweak(aggregated_pubkey, id, message_id)?;
        let secret_nonce = self.get_secret_nonce(aggregated_pubkey, id, message_id)?;

        Ok((message, secret_nonce, tweak, aggregated_nonce))
    }

    fn save_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        partial_signatures_to_save: HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
    ) -> Result<(), Musig2SignerError> {
        debug!(
            "Saving partial signatures for aggregated pubkey: {}
                with partial signatures: {:?}",
            aggregated_pubkey.to_string(),
            partial_signatures_to_save
        );

        let participant_pubkeys = self.get_participant_pub_keys(aggregated_pubkey)?;

        // partial signatures store all the participants' partial signatures
        if partial_signatures_to_save.len() != participant_pubkeys.len() {
            return Err(Musig2SignerError::InvalidParticipantPartialSignatures);
        }

        let message_ids = self.get_message_ids(aggregated_pubkey, id)?;

        // Validate that all partial signatures were not already inserted, and that each partial signature has a valid message id
        for message_id in message_ids.iter() {
            let partial_signatures =
                self.get_partial_signatures(aggregated_pubkey, id, message_id)?;
            for (pub_key, signatures) in &partial_signatures_to_save {
                if signatures.iter().any(|(id, _)| id == message_id) {
                    if partial_signatures.contains_key(pub_key) {
                        return Err(Musig2SignerError::PartialSignatureAlreadyExists);
                    }
                } else {
                    return Err(Musig2SignerError::InvalidMessageId);
                }
            }
        }

        // Validate that all partial signatures are valid
        for (pubkey, partial_signatures) in partial_signatures_to_save.iter() {
            let valid = self.verify_partial_signatures(
                aggregated_pubkey,
                id,
                *pubkey,
                partial_signatures.clone(),
            );
            if valid.is_err() || !valid.unwrap() {
                return Err(Musig2SignerError::InvalidPartialSignature);
            }
        }

        // Save the partial signatures
        for (pubkey, sigs) in partial_signatures_to_save {
            for (message_id, sig) in sigs {
                self.store.set(
                    self.get_key(StoreKey::MuSig2PartialSignature {
                        aggregated_pubkey: aggregated_pubkey.to_string(),
                        session_id: id.to_string(),
                        message_id: message_id.to_string(),
                        participant_pubkey: pubkey.to_string(),
                    }),
                    sig,
                    None,
                )?;
            }
        }

        Ok(())
    }

    fn get_aggregated_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<Signature, Musig2SignerError> {
        let participant_pubkeys = self.get_participant_pub_keys(aggregated_pubkey)?;

        let quantity_of_pub_nonces =
            self.quantity_of_pub_nonces(aggregated_pubkey, id, message_id)?;

        let partial_signatures = self.get_partial_signatures(aggregated_pubkey, id, message_id)?;

        let message = self.get_message(aggregated_pubkey, id, message_id)?;

        if quantity_of_pub_nonces != participant_pubkeys.len() {
            error!(
                "Participant pub nonces count mismatch: expected {}, got {}",
                participant_pubkeys.len(),
                quantity_of_pub_nonces
            );
            error!(
                "Aggregated pubkey: {}, session id: {}, message id: {}",
                aggregated_pubkey.to_string(),
                id,
                message_id
            );
            return Err(Musig2SignerError::IncompleteParticipantNonces);
        }

        if partial_signatures.len() != participant_pubkeys.len() {
            return Err(Musig2SignerError::InvalidParticipantPartialSignatures);
        }

        let tweak = self.get_tweak(aggregated_pubkey, id, message_id)?;
        let key_agg_ctx = self.get_key_agg_context(aggregated_pubkey, tweak)?;
        let aggregated_nonce = self.get_aggregated_nonce(aggregated_pubkey, id, message_id)?;

        let mut partial_signatures_vec = Vec::new();

        for pubkey in participant_pubkeys.iter() {
            let part_sigs = partial_signatures.get(pubkey).unwrap();
            partial_signatures_vec.push(*part_sigs);
        }

        let aggregated_signature: Vec<u8> = aggregate_partial_signatures(
            &key_agg_ctx,
            &aggregated_nonce,
            partial_signatures_vec,
            &message,
        )
        .map_err(|_| Musig2SignerError::InvalidSignature)?;

        let signature = Signature::from_slice(&aggregated_signature)
            .map_err(|_| Musig2SignerError::InvalidSignature)?;

        Ok(signature)
    }

    fn verify_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        pubkey: PublicKey,
        partial_signatures: Vec<(String, PartialSignature)>,
    ) -> Result<bool, Musig2SignerError> {
        let participant_pubkeys = self.get_participant_pub_keys(aggregated_pubkey)?;

        let message_ids = self.get_message_ids(aggregated_pubkey, id)?;

        if !participant_pubkeys.contains(&pubkey) {
            return Err(Musig2SignerError::InvalidPublicKey);
        }

        let mut data_to_iterate = HashMap::new();

        for message_id in message_ids.iter() {
            let message = self.get_message(aggregated_pubkey, id, message_id)?;
            let aggregated_nonce = self.get_aggregated_nonce(aggregated_pubkey, id, message_id)?;
            let tweak = self.get_tweak(aggregated_pubkey, id, message_id)?;
            let pub_nonce = self.get_pub_nonce(aggregated_pubkey, id, message_id, &pubkey)?;

            data_to_iterate.insert(
                message_id.clone(),
                (message, aggregated_nonce, pub_nonce.unwrap(), tweak),
            );
        }

        let individual_pubkey = to_musig_pubkey(pubkey)?;

        for (message_id, partial_signature) in partial_signatures {
            let (message, aggregated_nonce, individual_pubnonce, tweak) = data_to_iterate
                .get(&message_id)
                .ok_or(Musig2SignerError::InvalidMessageId)?;

            let key_agg_ctx = self.get_key_agg_context(aggregated_pubkey, *tweak)?;

            let result = verify_partial(
                &key_agg_ctx,
                partial_signature,
                aggregated_nonce,
                individual_pubkey,
                individual_pubnonce,
                message.clone(),
            );

            if result.is_err() {
                return Err(Musig2SignerError::InvalidPartialSignature);
            }
        }

        Ok(true)
    }

    fn verify_final_signature(
        &self,
        message_id: &str,
        final_signature: Signature,
        aggregated_pubkey: PublicKey,
        id: &str,
    ) -> Result<bool, Musig2SignerError> {
        const SIGNATURE_LENGTH: usize = 64;

        let message = self.get_message(&aggregated_pubkey, id, message_id)?;

        if final_signature.serialize().len() != SIGNATURE_LENGTH {
            return Err(Musig2SignerError::InvalidSignatureLength);
        }

        let aggregated_pubkey = to_musig_pubkey(aggregated_pubkey)?;

        let signature: CompactSignature =
            CompactSignature::from_bytes(&final_signature.serialize())
                .map_err(|_| Musig2SignerError::InvalidSignature)?;

        let result = verify_single(aggregated_pubkey, signature, message);

        if result.is_err() {
            return Err(Musig2SignerError::InvalidFinalSignature);
        }

        Ok(true)
    }
}

impl MuSig2Signer {
    pub fn new(store: Rc<Storage>) -> Self {
        Self { store }
    }

    pub fn generate_nonce(
        &self,
        message_id: &str,
        message: Vec<u8>,
        aggregated_pubkey: &PublicKey,
        id: &str,
        tweak: Option<musig2::secp256k1::Scalar>,
        nonce_seed: Zeroizing<[u8; 32]>,
    ) -> Result<(), Musig2SignerError> {
        match self.check_musig_data(aggregated_pubkey)? {
            true => {}
            false => return Err(Musig2SignerError::AggregatedPubkeyNotFound),
        }

        // If message exists then nonces are already generated
        if self.store.has_key(&self.get_key(StoreKey::MuSig2Message {
            aggregated_pubkey: aggregated_pubkey.to_string(),
            session_id: id.to_string(),
            message_id: message_id.to_string(),
        }))? {
            return Ok(());
        }

        let sec_nonce = musig2::SecNonceBuilder::new(*nonce_seed)
            .with_pubkey(to_musig_pubkey(*aggregated_pubkey)?)
            .with_message(&message)
            .build();

        let pub_nonce = sec_nonce.public_nonce();

        let mut pub_nonces = HashMap::new();
        let my_pub_key = self.my_public_key(aggregated_pubkey)?;
        pub_nonces.insert(my_pub_key, pub_nonce);

        let data = (message, pub_nonces, sec_nonce, tweak);

        self.save_musig_message_data(message_id, aggregated_pubkey, id, data)?;
        Ok(())
    }

    fn save_musig_message_data(
        &self,
        message_id: &str,
        aggregated_pubkey: &PublicKey,
        id: &str,
        data: Musig2MessageData,
    ) -> Result<(), Musig2SignerError> {
        #[cfg(feature = "transactional")]
        let transaction_id = Some(self.store.begin_transaction());
        #[cfg(not(feature = "transactional"))]
        let transaction_id = None;

        self.store.set(
            self.get_key(StoreKey::MuSig2Message {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
                message_id: message_id.to_string(),
            }),
            data.0,
            transaction_id,
        )?;
        for (pub_key, pub_nonce) in data.1.iter() {
            self.store.set(
                self.get_key(StoreKey::MuSig2PubNonce {
                    aggregated_pubkey: aggregated_pubkey.to_string(),
                    session_id: id.to_string(),
                    message_id: message_id.to_string(),
                    participant_pubkey: pub_key.to_string(),
                }),
                pub_nonce.clone(),
                transaction_id,
            )?;
        }
        self.store.set(
            self.get_key(StoreKey::MuSig2SecretNonce {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
                message_id: message_id.to_string(),
            }),
            data.2,
            transaction_id,
        )?;
        if let Some(tweak_value) = data.3 {
            self.store.set(
                self.get_key(StoreKey::MuSig2Tweak {
                    aggregated_pubkey: aggregated_pubkey.to_string(),
                    session_id: id.to_string(),
                    message_id: message_id.to_string(),
                }),
                tweak_value.to_be_bytes(),
                transaction_id,
            )?;
        }
        let message_ids =
            self.store
                .get::<String, Vec<MessageId>>(self.get_key(StoreKey::MuSig2MessageIds {
                    aggregated_pubkey: aggregated_pubkey.to_string(),
                    session_id: id.to_string(),
                }))?;

        let mut message_ids = message_ids.unwrap_or(Vec::new());
        message_ids.push(message_id.to_string());
        self.store.set(
            self.get_key(StoreKey::MuSig2MessageIds {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
            }),
            message_ids,
            transaction_id,
        )?;

        #[cfg(feature = "transactional")]
        self.store.commit_transaction(transaction_id.unwrap())?;

        Ok(())
    }

    fn get_aggregated_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<(MessageId, AggNonce)>, Musig2SignerError> {
        let mut aggregated_nonces: Vec<(MessageId, AggNonce)> = Vec::new();
        let message_ids = self.get_message_ids(aggregated_pubkey, id)?;

        for message_id in message_ids.iter() {
            aggregated_nonces.push((
                message_id.clone(),
                self.get_aggregated_nonce(aggregated_pubkey, id, message_id)?,
            ));
        }

        Ok(aggregated_nonces)
    }

    fn get_aggregated_nonce(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<AggNonce, Musig2SignerError> {
        let participant_pubkeys = self.get_participant_pub_keys(aggregated_pubkey)?;

        let mut ordered_pub_nonces = Vec::new();

        for participant_key in participant_pubkeys.iter() {
            if let Some(nonce) =
                self.get_pub_nonce(aggregated_pubkey, id, message_id, participant_key)?
            {
                ordered_pub_nonces.push(nonce);
            }
        }

        let aggregated_nonce = AggNonce::sum(ordered_pub_nonces);

        Ok(aggregated_nonce)
    }

    pub fn get_index(&self, aggregated_pubkey: &PublicKey) -> Result<u32, Musig2SignerError> {
        let my_pub_key = self.my_public_key(aggregated_pubkey)?;
        let key_index_used_by_me = self.get_key(StoreKey::IndexForNonceGeneration(my_pub_key));

        // Atomic transaction: increment and return nonce index, using a closure just for readability
        let new_index = {
            #[cfg(feature = "transactional")]
            let db_tx_id = Some(self.store.begin_transaction());
            #[cfg(not(feature = "transactional"))]
            let db_tx_id = None;

            let current_index = self
                .store
                .get::<String, u32>(key_index_used_by_me.clone())?;
            let new_index = current_index.map_or(0, |idx| idx + 1);
            self.store.set(key_index_used_by_me, new_index, db_tx_id)?;

            #[cfg(feature = "transactional")]
            self.store.commit_transaction(db_tx_id.unwrap())?;

            new_index
        };

        Ok(new_index)
    }

    pub fn my_public_key(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<PublicKey, Musig2SignerError> {
        match self.store.get(self.get_key(StoreKey::MuSig2MyPublicKey {
            aggregated_pubkey: aggregated_pubkey.to_string(),
        }))? {
            Some(result) => Ok(result),
            None => Err(Musig2SignerError::AggregatedPubkeyNotFound),
        }
    }

    pub fn get_participant_pub_keys(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<Vec<PublicKey>, Musig2SignerError> {
        match self
            .store
            .get(self.get_key(StoreKey::MuSig2ParticipantPubKeys {
                aggregated_pubkey: aggregated_pubkey.to_string(),
            }))? {
            Some(result) => Ok(result),
            None => Err(Musig2SignerError::AggregatedPubkeyNotFound),
        }
    }

    fn get_tweak(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<Option<musig2::secp256k1::Scalar>, Musig2SignerError> {
        match self
            .store
            .get::<String, [u8; 32]>(self.get_key(StoreKey::MuSig2Tweak {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
                message_id: message_id.to_string(),
            }))? {
            Some(result) => {
                let tweak = musig2::secp256k1::Scalar::from_be_bytes(result)?;
                Ok(Some(tweak))
            }
            None => Ok(None),
        }
    }

    fn get_secret_nonce(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<SecNonce, Musig2SignerError> {
        match self
            .store
            .get::<String, SecNonce>(self.get_key(StoreKey::MuSig2SecretNonce {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
                message_id: message_id.to_string(),
            }))? {
            Some(result) => Ok(result),
            None => Err(Musig2SignerError::InvalidMessageId),
        }
    }

    fn get_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<HashMap<PublicKey, PartialSignature>, Musig2SignerError> {
        let mut partial_signatures = HashMap::new();
        let result =
            self.store
                .partial_compare(&self.get_key(StoreKey::MuSig2PartialSignatures {
                    aggregated_pubkey: aggregated_pubkey.to_string(),
                    session_id: id.to_string(),
                    message_id: message_id.to_string(),
                }))?;

        for (key, value) in result {
            let pubkey_str = key.split('/').last().unwrap_or("");
            let pubkey = PublicKey::from_str(pubkey_str)
                .map_err(|_| Musig2SignerError::CantReconstructValue("PublicKey".to_string()))?;
            let partial_signature: PartialSignature =
                serde_json::from_str(&value).map_err(|_| {
                    Musig2SignerError::CantReconstructValue("PartialSignature".to_string())
                })?;
            partial_signatures.insert(pubkey, partial_signature);
        }

        Ok(partial_signatures)
    }

    fn get_message(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<Vec<u8>, Musig2SignerError> {
        match self
            .store
            .get::<String, Vec<u8>>(self.get_key(StoreKey::MuSig2Message {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
                message_id: message_id.to_string(),
            }))? {
            Some(result) => Ok(result),
            None => Err(Musig2SignerError::InvalidMessageId),
        }
    }

    fn get_pub_nonce(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
        participant_pubkey: &PublicKey,
    ) -> Result<Option<PubNonce>, Musig2SignerError> {
        match self
            .store
            .get::<String, PubNonce>(self.get_key(StoreKey::MuSig2PubNonce {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
                message_id: message_id.to_string(),
                participant_pubkey: participant_pubkey.to_string(),
            }))? {
            Some(result) => Ok(Some(result)),
            None => Ok(None),
        }
    }

    fn quantity_of_pub_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
        message_id: &str,
    ) -> Result<usize, Musig2SignerError> {
        let result = self
            .store
            .partial_compare(&self.get_key(StoreKey::MuSig2PubNonces {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
                message_id: message_id.to_string(),
            }))?;

        Ok(result.len())
    }

    fn get_message_ids(
        &self,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<Vec<MessageId>, Musig2SignerError> {
        match self.store.get::<String, Vec<MessageId>>(self.get_key(
            StoreKey::MuSig2MessageIds {
                aggregated_pubkey: aggregated_pubkey.to_string(),
                session_id: id.to_string(),
            },
        ))? {
            Some(ids) => Ok(ids),
            None => Err(Musig2SignerError::IdNotFound),
        }
    }

    fn validate_partial_nonces(
        &self,
        participant_pubkeys: Vec<PublicKey>,
        aggregated_pubkey: &PublicKey,
        id: &str,
    ) -> Result<(), Musig2SignerError> {
        let message_ids = self.get_message_ids(aggregated_pubkey, id)?;

        for participant_key in participant_pubkeys.iter() {
            for message_id in message_ids.iter() {
                if !self.store.has_key(&self.get_key(StoreKey::MuSig2PubNonce {
                    aggregated_pubkey: aggregated_pubkey.to_string(),
                    session_id: id.to_string(),
                    message_id: message_id.to_string(),
                    participant_pubkey: participant_key.to_string(),
                }))? {
                    error!(
                        "Participant {} is missing pub nonce for message {}",
                        participant_key, message_id
                    );
                    return Err(Musig2SignerError::IncompleteParticipantNonces);
                }
            }
        }
        Ok(())
    }

    fn save_musig_session_data(
        &self,
        musig2_data: Musig2SessionData,
    ) -> Result<(), Musig2SignerError> {
        debug!(
            "Saving musig session data for aggregated pubkey: {} {:?}",
            musig2_data.0.to_string(),
            musig2_data
        );

        #[cfg(feature = "transactional")]
        let transaction_id = Some(self.store.begin_transaction());
        #[cfg(not(feature = "transactional"))]
        let transaction_id = None;

        self.store.set(
            self.get_key(StoreKey::MuSig2ParticipantPubKeys {
                aggregated_pubkey: musig2_data.0.to_string(),
            }),
            musig2_data.1,
            transaction_id,
        )?;
        self.store.set(
            self.get_key(StoreKey::MuSig2MyPublicKey {
                aggregated_pubkey: musig2_data.0.to_string(),
            }),
            musig2_data.2,
            transaction_id,
        )?;

        #[cfg(feature = "transactional")]
        self.store.commit_transaction(transaction_id.unwrap())?;
        Ok(())
    }

    pub fn get_key_agg_context_aux(
        &self,
        participant_pubkeys: Vec<PublicKey>,
        tweak: Option<musig2::secp256k1::Scalar>,
    ) -> Result<KeyAggContext, Musig2SignerError> {
        let participant_pubkeys = participant_pubkeys
            .iter()
            .map(|pubkey| to_musig_pubkey(*pubkey))
            .collect::<Result<Vec<_>, _>>()?;
        match tweak {
            Some(tweak) => {
                let key_agg_context = KeyAggContext::new(participant_pubkeys)
                    .unwrap()
                    .with_tweak(tweak, true)
                    .map_err(|_| Musig2SignerError::InvalidPublicKey)?;

                Ok(key_agg_context)
            }
            None => {
                let key_agg_context = KeyAggContext::new(participant_pubkeys)
                    .map_err(|_| Musig2SignerError::InvalidPublicKey)?;

                Ok(key_agg_context)
            }
        }
    }

    pub fn get_key_agg_context(
        &self,
        aggregated_pubkey: &PublicKey,
        tweak: Option<musig2::secp256k1::Scalar>,
    ) -> Result<KeyAggContext, Musig2SignerError> {
        let participant_pubkeys = self.get_participant_pub_keys(aggregated_pubkey)?;
        self.get_key_agg_context_aux(participant_pubkeys, tweak)
    }

    fn get_key(&self, key: StoreKey) -> String {
        let prefix = "musig2";
        match key {
            StoreKey::IndexForNonceGeneration(pubkey) => {
                format!("{prefix}/index_for_nonce_generation/{pubkey}")
            }
            StoreKey::MuSig2Session { aggregated_pubkey } => {
                format!("{prefix}/session/{aggregated_pubkey}")
            }
            StoreKey::MuSig2ParticipantPubKeys { aggregated_pubkey } => {
                format!("{prefix}/session/{aggregated_pubkey}/participant_pub_keys")
            }
            StoreKey::MuSig2MyPublicKey { aggregated_pubkey } => {
                format!("{prefix}/session/{aggregated_pubkey}/my_public_key")
            }
            StoreKey::MuSig2MessageIds {
                aggregated_pubkey,
                session_id,
            } => {
                format!("{prefix}/session/{aggregated_pubkey}/{session_id}/message_ids")
            }
            StoreKey::MuSig2PubNonces {
                aggregated_pubkey,
                session_id,
                message_id,
            } => {
                format!("{prefix}/session/{aggregated_pubkey}/{session_id}/{message_id}/pub_nonces")
            }
            StoreKey::MuSig2PubNonce {
                aggregated_pubkey,
                session_id,
                message_id,
                participant_pubkey,
            } => {
                format!("{prefix}/session/{aggregated_pubkey}/{session_id}/{message_id}/pub_nonces/{participant_pubkey}")
            }
            StoreKey::MuSig2SecretNonce {
                aggregated_pubkey,
                session_id,
                message_id,
            } => {
                format!(
                    "{prefix}/session/{aggregated_pubkey}/{session_id}/{message_id}/secret_nonce"
                )
            }
            StoreKey::MuSig2Tweak {
                aggregated_pubkey,
                session_id,
                message_id,
            } => {
                format!("{prefix}/session/{aggregated_pubkey}/{session_id}/{message_id}/tweak")
            }
            StoreKey::MuSig2Message {
                aggregated_pubkey,
                session_id,
                message_id,
            } => {
                format!("{prefix}/session/{aggregated_pubkey}/{session_id}/{message_id}/message")
            }
            StoreKey::MuSig2PartialSignatures {
                aggregated_pubkey,
                session_id,
                message_id,
            } => {
                format!("{prefix}/session/{aggregated_pubkey}/{session_id}/{message_id}/partial_signatures")
            }
            StoreKey::MuSig2PartialSignature {
                aggregated_pubkey,
                session_id,
                message_id,
                participant_pubkey,
            } => {
                format!("{prefix}/session/{aggregated_pubkey}/{session_id}/{message_id}/partial_signatures/{participant_pubkey}")
            }
        }
    }

    fn check_musig_data(&self, aggregated_pubkey: &PublicKey) -> Result<bool, Musig2SignerError> {
        let result = self
            .store
            .partial_compare_keys(&self.get_key(StoreKey::MuSig2Session {
                aggregated_pubkey: aggregated_pubkey.to_string(),
            }))?;
        if result.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }

    pub(crate) fn aggregate_private_key(
        &self,
        partial_keys_bytes: Zeroizing<Vec<Vec<u8>>>,
        network: Network,
    ) -> Result<(PrivateKey, PublicKey), Musig2SignerError> {
        let secp = musig2::secp256k1::Secp256k1::new();
        let mut partial_secret_keys: Vec<Scalar> = Vec::new(); // Note: Scalar type is responsible for its own memory safety
        let mut partial_public_keys: Vec<musig2::secp256k1::PublicKey> = Vec::new();

        for partial_key_bytes in partial_keys_bytes.iter() {
            let scalar = Scalar::from_slice(partial_key_bytes)?;
            let public_key = musig2::secp256k1::PublicKey::from_secret_key(&secp, scalar.as_ref());
            partial_secret_keys.push(scalar);
            partial_public_keys.push(public_key);
        }

        let ctx = KeyAggContext::new(partial_public_keys)?;
        let aggregated_secret_key: musig2::secp256k1::SecretKey =
            ctx.aggregated_seckey(partial_secret_keys)?;
        let aggregated_public_key = to_bitcoin_pubkey(aggregated_secret_key.public_key(&secp))?;

        // Zeroize the string representation of the secret key after use
        let secret_display = Zeroizing::new(aggregated_secret_key.display_secret().to_string());
        let aggregated_seckey = SecretKey::from_str(&secret_display)?;
        let aggregated_private_key = PrivateKey::new(aggregated_seckey, network);

        Ok((aggregated_private_key, aggregated_public_key))
    }
}
