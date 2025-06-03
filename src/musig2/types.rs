// use bitcoin::PublicKey;
// use musig2::{PartialSignature, PubNonce, SecNonce};
// use serde::{Deserialize, Serialize};
// use std::collections::HashMap;

// #[derive(Serialize, Deserialize, Debug)]
// pub struct MuSig2Session {
//     pub aggregated_pubkey_id: String,

//     pub my_pub_key: PublicKey,

//     pub participant_pubkeys: Vec<PublicKey>,

//     pub data: HashMap<String, HashMap<MessageId, Musig2Data>>,
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct Musig2Data {
//     /// Public nonces of all participants
//     pub pub_nonces: HashMap<PublicKey, PubNonce>,

//     /// Partial signatures of all participants
//     pub partial_signatures: HashMap<PublicKey, PartialSignature>,

//     /// Secret nonce of the current participant
//     pub secret_nonce: SecNonce,

//     /// Message to be signed
//     pub message: Vec<u8>,

//     /// Tweak to be applied to the message
//     tweak: Option<[u8; 32]>,
// }

// impl Musig2Data {
//     pub fn new(
//         message: Vec<u8>,
//         pub_nonces: HashMap<PublicKey, PubNonce>,
//         secret_nonce: SecNonce,
//         tweak: Option<musig2::secp256k1::Scalar>,
//     ) -> Self {
//         let tweak_bytes: Option<[u8; 32]> = tweak.map(|t| {
//             let mut bytes = [0; 32];
//             bytes.copy_from_slice(&t.to_be_bytes());
//             bytes
//         });

//         Self {
//             message,
//             pub_nonces,
//             partial_signatures: HashMap::new(),
//             secret_nonce,
//             tweak: tweak_bytes,
//         }
//     }

//     pub fn tweak(&self) -> Option<musig2::secp256k1::Scalar> {
//         self.tweak
//             .map(|t| musig2::secp256k1::Scalar::from_be_bytes(t).unwrap())
//     }
// }

// impl MuSig2Session {
//     pub fn new(
//         aggregated_pubkey_id: PublicKey,
//         participant_pubkeys: Vec<PublicKey>,
//         my_pub_key: PublicKey,
//     ) -> Self {
//         Self {
//             aggregated_pubkey_id: aggregated_pubkey_id.to_string(),
//             participant_pubkeys,
//             data: HashMap::new(),
//             my_pub_key,
//         }
//     }
// }

use bitcoin::PublicKey;

pub type MessageId = String;
pub type Musig2Session = (PublicKey, Vec<PublicKey>, PublicKey);
