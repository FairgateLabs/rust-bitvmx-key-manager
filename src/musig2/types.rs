use bitcoin::{PublicKey, TapNodeHash};
use musig2::{PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct MuSig2Session {
    /// Musig ID
    pub id: String,

    pub my_pub_key: PublicKey,

    /// Public keys of all participants including the current one for each message
    pub participant_pub_keys: Vec<PublicKey>,

    // Data of the current session
    pub data: HashMap<MessageId, Musig2Data>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Musig2Data {
    /// Public nonces of all participants
    pub pub_nonces: HashMap<PublicKey, PubNonce>,

    /// Partial signatures of all participants
    pub partial_signatures: HashMap<PublicKey, PartialSignature>,

    /// Secret nonce of the current participant
    pub secret_nonce: SecNonce,

    /// Message to be signed
    pub message: Vec<u8>,

    pub tweak: Option<TapNodeHash>,
}

impl Musig2Data {
    pub fn new(
        message: Vec<u8>,
        pub_nonces: HashMap<PublicKey, PubNonce>,
        secret_nonce: SecNonce,
        tweak: Option<TapNodeHash>,
    ) -> Self {
        Self {
            message,
            pub_nonces,
            partial_signatures: HashMap::new(),
            secret_nonce,
            tweak,
        }
    }
}

impl MuSig2Session {
    pub fn new(id: String, participant_pubkeys: Vec<PublicKey>, my_pub_key: PublicKey) -> Self {
        Self {
            id,
            participant_pub_keys: participant_pubkeys,
            data: HashMap::new(),
            my_pub_key,
        }
    }
}

pub type MessageId = String;
