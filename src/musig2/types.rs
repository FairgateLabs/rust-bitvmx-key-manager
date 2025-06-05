use std::collections::HashMap;
use bitcoin::PublicKey;
use musig2::{secp256k1::Scalar, PubNonce, SecNonce};

pub type MessageId = String;
pub type Musig2SessionData = (PublicKey, Vec<PublicKey>, PublicKey);
pub type Musig2MessageData = (Vec<u8>, HashMap<PublicKey, PubNonce>, SecNonce, Option<Scalar>);
