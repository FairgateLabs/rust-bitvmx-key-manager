use bitcoin::{secp256k1::schnorr::Signature, PublicKey};
use musig2::{
    aggregate_partial_signatures, verify_partial, verify_single, AggNonce, CompactSignature,
    PartialSignature, SecNonce,
};
use std::{collections::HashMap, rc::Rc};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, error};

use musig2::{KeyAggContext, PubNonce};

use super::{
    errors::Musig2SignerError,
    helper::{to_bitcoin_pubkey, to_musig_pubkey},
    types::{MessageId, MuSig2Session, Musig2Data},
};

/// Keys used for storing data in the key-value store
enum StoreKey {
    /// Stores the nonce index for a given public key
    IndexForNonceGeneration(PublicKey),
    /// Stores the MuSig2 session data for a given session ID
    MuSig2Session(String),
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
    ) -> Result<Vec<(MessageId, PubNonce)>, Musig2SignerError>;

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

        let musig = MuSig2Session::new(
            aggregated_pubkey.to_string(),
            sorted_participants,
            my_pub_key,
        );

        self.save_musig_data(&musig)?;
        Ok(aggregated_pubkey)
    }

    //fn get_aggregated_pubkey(&self, session_id: &str) -> Result<PublicKey, Musig2SignerError> {
    // // Sort participants by public key
    // let mut sorted_participants = participant_pubkeys.clone();
    // sorted_participants.sort();

    //

    fn get_my_pub_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<Vec<(MessageId, PubNonce)>, Musig2SignerError> {
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        let mut pub_nonces = Vec::new();

        for (message_id, data) in musig_data.data.iter() {
            pub_nonces.push((
                message_id.clone(),
                data.pub_nonces.get(&musig_data.my_pub_key).unwrap().clone(),
            ));
        }

        if pub_nonces.is_empty() {
            return Err(Musig2SignerError::NoncesNotGenerated);
        }

        Ok(pub_nonces)
    }

    fn aggregate_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
        pub_nonces_map: HashMap<PublicKey, Vec<(MessageId, PubNonce)>>,
    ) -> Result<(), Musig2SignerError> {
        debug!(
            "Aggregating nonces for aggregated pubkey: {} 
                with nonces: {:?}",
            aggregated_pubkey.to_string(),
            pub_nonces_map
        );
        let mut musig_session =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        if pub_nonces_map.len() != (musig_session.participant_pub_keys.len() - 1) {
            return Err(Musig2SignerError::InvalidParticipantNonces);
        }

        for pub_key in pub_nonces_map.keys() {
            if *pub_key == musig_session.my_pub_key {
                return Err(Musig2SignerError::InvalidPublicKey);
            }
        }

        // Validate that all nonces are valid
        for (pub_key, nonces) in &pub_nonces_map {
            for (message_id_nonce, nonce) in nonces {
                let message_data = musig_session
                    .data
                    .get_mut(message_id_nonce)
                    .ok_or(Musig2SignerError::InvalidMessageId)?;

                let exist_nonce = message_data.pub_nonces.get(pub_key);

                if exist_nonce.is_some() {
                    return Err(Musig2SignerError::NonceAlreadyExists);
                } else {
                    message_data.pub_nonces.insert(*pub_key, nonce.clone());
                }
            }
        }

        self.save_musig_data(&musig_session)?;

        Ok(())
    }

    fn get_data_for_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
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
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        for participant_key in musig_data.participant_pub_keys.iter() {
            for (_, data) in musig_data.data.iter() {
                if !data.pub_nonces.contains_key(participant_key) {
                    error!(
                        "Participant {} is missing pub nonce for message {:?}",
                        participant_key, data.pub_nonces
                    );
                    return Err(Musig2SignerError::IncompleteParticipantNonces);
                }
            }
        }

        let aggregated_nonces = self.get_aggregated_nonces(aggregated_pubkey)?;
        let mut data_to_sign: HashMap<
            String,
            (
                Vec<u8>,
                SecNonce,
                Option<musig2::secp256k1::Scalar>,
                AggNonce,
            ),
        > = HashMap::new();

        for (message_id, data) in musig_data.data.iter() {
            let aggregated_nonce = aggregated_nonces
                .iter()
                .find(|(msg_id, _)| msg_id == message_id)
                .unwrap()
                .1
                .clone();

            data_to_sign.insert(
                message_id.clone(),
                (
                    data.message.clone(),
                    data.secret_nonce.clone(),
                    data.tweak(),
                    aggregated_nonce,
                ),
            );
        }

        Ok(data_to_sign)
    }

    fn save_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        partial_signatures: HashMap<PublicKey, Vec<(MessageId, PartialSignature)>>,
    ) -> Result<(), Musig2SignerError> {
        debug!(
            "Saving partial signatures for aggregated pubkey: {} 
                with partial signatures: {:?}",
            aggregated_pubkey.to_string(),
            partial_signatures
        );
        let mut musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        // partial signatures store all the participants' partial signatures
        if partial_signatures.len() != musig_data.participant_pub_keys.len() {
            return Err(Musig2SignerError::InvalidParticipantPartialSignatures);
        }

        // Validate that all partial signatures were not already inserted, and that each partial signature has a valid message id
        for (message_id, data) in musig_data.data.iter() {
            for (pub_key, signatures) in &partial_signatures {
                if let Some(_sig) = signatures.iter().find(|(id, _)| id == message_id) {
                    if data.partial_signatures.contains_key(pub_key) {
                        return Err(Musig2SignerError::PartialSignatureAlreadyExists);
                    }
                } else {
                    return Err(Musig2SignerError::InvalidMessageId);
                }
            }
        }

        // Validate that all partial signatures are valid
        for (pubkey, partial_signatures) in partial_signatures.iter() {
            let valid = self.verify_partial_signatures(
                aggregated_pubkey,
                *pubkey,
                partial_signatures.clone(),
            );
            if valid.is_err() || !valid.unwrap() {
                return Err(Musig2SignerError::InvalidPartialSignature);
            }
        }

        // Save the partial signatures
        for (pubkey, sigs) in partial_signatures {
            for (message_id, sig) in sigs {
                musig_data
                    .data
                    .get_mut(&message_id)
                    .unwrap()
                    .partial_signatures
                    .insert(pubkey, sig);
            }
        }

        self.save_musig_data(&musig_data)?;
        Ok(())
    }

    fn get_aggregated_signature(
        &self,
        aggregated_pubkey: &PublicKey,
        message_id: &str,
    ) -> Result<Signature, Musig2SignerError> {
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        let data = musig_data
            .data
            .get(message_id)
            .ok_or(Musig2SignerError::InvalidMessageId)?;

        if data.pub_nonces.len() != musig_data.participant_pub_keys.len() {
            error!(
                "Nonces: {:?}
                    Participant: {:?} ",
                data.pub_nonces, musig_data.participant_pub_keys
            );
            return Err(Musig2SignerError::IncompleteParticipantNonces);
        }

        if data.partial_signatures.len() != musig_data.participant_pub_keys.len() {
            return Err(Musig2SignerError::InvalidParticipantPartialSignatures);
        }

        let key_agg_ctx = self.get_key_agg_context(aggregated_pubkey, data.tweak())?;
        let aggregated_nonce = self.get_aggregated_nonce(aggregated_pubkey, message_id)?;

        let mut partial_signatures = Vec::new();

        for pubkey in musig_data.participant_pub_keys.iter() {
            let part_sigs = data.partial_signatures.get(pubkey).unwrap();
            partial_signatures.push(*part_sigs);
        }

        let aggregated_signature: Vec<u8> = aggregate_partial_signatures(
            &key_agg_ctx,
            &aggregated_nonce,
            partial_signatures,
            &data.message,
        )
        .map_err(|_| Musig2SignerError::InvalidSignature)?;

        let signature = Signature::from_slice(&aggregated_signature)
            .map_err(|_| Musig2SignerError::InvalidSignature)?;

        Ok(signature)
    }

    fn verify_partial_signatures(
        &self,
        aggregated_pubkey: &PublicKey,
        pubkey: PublicKey,
        partial_signatures: Vec<(String, PartialSignature)>,
    ) -> Result<bool, Musig2SignerError> {
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        if !musig_data.participant_pub_keys.contains(&pubkey) {
            return Err(Musig2SignerError::InvalidPublicKey);
        }

        let mut data_to_iterate: HashMap<
            MessageId,
            (
                Vec<u8>,
                AggNonce,
                PubNonce,
                Option<musig2::secp256k1::Scalar>,
            ),
        > = HashMap::new();

        for (message_id, data) in musig_data.data.iter() {
            let aggregated_nonce = self.get_aggregated_nonce(aggregated_pubkey, message_id)?;

            data_to_iterate.insert(
                message_id.clone(),
                (
                    data.message.clone(),
                    aggregated_nonce.clone(),
                    data.pub_nonces.get(&pubkey).unwrap().clone(),
                    data.tweak(),
                ),
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
    ) -> Result<bool, Musig2SignerError> {
        const SIGNATURE_LENGTH: usize = 64;

        let musig_data =
            self.get_musig_data(&aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        let data = musig_data
            .data
            .get(message_id)
            .ok_or(Musig2SignerError::InvalidMessageId)?;

        if final_signature.serialize().len() != SIGNATURE_LENGTH {
            return Err(Musig2SignerError::InvalidSignatureLength);
        }

        let aggregated_pubkey = to_musig_pubkey(aggregated_pubkey)?;

        let signature: CompactSignature =
            CompactSignature::from_bytes(&final_signature.serialize())
                .map_err(|_| Musig2SignerError::InvalidSignature)?;

        let result = verify_single(aggregated_pubkey, signature, data.message.clone());

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
        tweak: Option<musig2::secp256k1::Scalar>,
        nonce_seed: [u8; 32],
    ) -> Result<(), Musig2SignerError> {
        let mut musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        // If message exists then nonces are already generated
        let data = musig_data.data.get(message_id);
        if data.is_some() {
            return Ok(());
        }

        // let key_agg_context = self.get_key_agg_context(session_id, tweak)?;
        // let aggregated_pubkey: musig2::secp256k1::PublicKey = key_agg_context.aggregated_pubkey();

        let sec_nonce = musig2::SecNonceBuilder::new(nonce_seed)
            .with_pubkey(to_musig_pubkey(*aggregated_pubkey)?)
            .with_message(&message)
            .build();

        let pub_nonce = sec_nonce.public_nonce();

        let mut pub_nonces = HashMap::new();
        pub_nonces.insert(musig_data.my_pub_key, pub_nonce);

        let data = Musig2Data::new(message, pub_nonces, sec_nonce, tweak);
        musig_data.data.insert(message_id.to_string(), data);

        self.save_musig_data(&musig_data)?;

        Ok(())
    }

    fn get_aggregated_nonces(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<Vec<(MessageId, AggNonce)>, Musig2SignerError> {
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        let mut aggregated_nonces: Vec<(MessageId, AggNonce)> = Vec::new();

        for (message_id, _) in musig_data.data.iter() {
            aggregated_nonces.push((
                message_id.clone(),
                self.get_aggregated_nonce(aggregated_pubkey, message_id)?,
            ));
        }

        Ok(aggregated_nonces)
    }

    fn get_aggregated_nonce(
        &self,
        aggregated_pubkey: &PublicKey,
        message_id: &str,
    ) -> Result<AggNonce, Musig2SignerError> {
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        let mut ordered_pub_nonces = Vec::new();

        for participant_key in musig_data.participant_pub_keys.iter() {
            if let Some(nonce) = musig_data
                .data
                .get(message_id)
                .unwrap()
                .pub_nonces
                .get(participant_key)
            {
                ordered_pub_nonces.push(nonce);
            }
        }

        let aggregated_nonce = AggNonce::sum(ordered_pub_nonces);

        Ok(aggregated_nonce)
    }

    pub fn get_index(&self, aggregated_pubkey: &PublicKey) -> Result<u32, Musig2SignerError> {
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        let key_index_used_by_me =
            self.get_key(StoreKey::IndexForNonceGeneration(musig_data.my_pub_key));

        let index_used_by_me = self
            .store
            .get::<String, u32>(key_index_used_by_me.clone())?;

        let new_index = match index_used_by_me {
            Some(index_used) => index_used + 1,
            None => 0,
        };

        // Update the index used by the participant
        self.store.set(key_index_used_by_me, new_index, None)?;

        Ok(new_index)
    }

    pub fn my_public_key(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<PublicKey, Musig2SignerError> {
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        Ok(musig_data.my_pub_key)
    }

    pub fn get_participant_pub_keys(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<Vec<PublicKey>, Musig2SignerError> {
        let musig_data =
            self.get_musig_data(aggregated_pubkey)?
                .ok_or(Musig2SignerError::MuSig2IdNotFound(
                    aggregated_pubkey.to_string(),
                ))?;

        Ok(musig_data.participant_pub_keys)
    }

    fn get_musig_data(
        &self,
        aggregated_pubkey: &PublicKey,
    ) -> Result<Option<MuSig2Session>, Musig2SignerError> {
        debug!(
            "Triying to get musig data for aggregated pubkey: {:?}",
            aggregated_pubkey.to_string()
        );
        let musig_data: Option<MuSig2Session> = self.store.get::<String, MuSig2Session>(
            self.get_key(StoreKey::MuSig2Session(aggregated_pubkey.to_string())),
        )?;
        debug!(
            "Get musig data for aggregated pubkey: {} {:?}",
            aggregated_pubkey.to_string(),
            musig_data
        );
        Ok(musig_data)
    }

    fn save_musig_data(&self, musig_data: &MuSig2Session) -> Result<(), Musig2SignerError> {
        debug!(
            "Saving musig data for aggregated pubkey: {} {:?}",
            musig_data.id, musig_data
        );
        self.store.set(
            self.get_key(StoreKey::MuSig2Session(musig_data.id.clone())),
            musig_data,
            None,
        )?;
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
        //.into_iter()
        //.map(to_musig_pubkey)
        //.collect::<Result<Vec<_>, _>>()?;
        self.get_key_agg_context_aux(participant_pubkeys, tweak)
    }

    fn get_key(&self, key: StoreKey) -> String {
        let prefix = "musig2";
        match key {
            StoreKey::IndexForNonceGeneration(pubkey) => {
                format!("{prefix}/index_for_nonce_generation/{pubkey}")
            }
            StoreKey::MuSig2Session(id) => format!("{prefix}/session/{id}"),
        }
    }
}
