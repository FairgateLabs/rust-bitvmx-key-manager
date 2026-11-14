use bitcoin::PublicKey;
use musig2::{secp256k1::Scalar, PubNonce, SecNonce};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub type MessageId = String;
pub type Musig2SessionData = (PublicKey, Vec<PublicKey>, PublicKey);
pub type Musig2MessageData = (
    Vec<u8>,
    HashMap<PublicKey, PubNonce>,
    SecNonce,
    Option<Scalar>,
);

/// One message to commit to a nonce for: its id, the message itself,
/// and the tweak the signature over it will be made under.
///
/// What `KeyManager::generate_nonces` takes one of per message.
pub type NonceRequest = (MessageId, Vec<u8>, Option<Scalar>);

/// A [`NonceRequest`] with the seed its nonce is to be derived from.
///
/// The seed is added by `KeyManager`, which is the half that holds the
/// keystore; `MuSig2Signer::generate_nonces` takes these.
pub type SeededNonceRequest = (MessageId, Vec<u8>, Option<Scalar>, Zeroizing<[u8; 32]>);
