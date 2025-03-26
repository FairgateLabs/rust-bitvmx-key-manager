use bitcoin::PublicKey;

use std::str::FromStr;

use super::errors::Musig2SignerError;

/// Converts a Bitcoin public key to a MuSig2 public key
///
/// # Arguments
/// * `pubkey` - The Bitcoin public key to convert
///
/// # Returns
/// * `Result<musig2::secp256k1::PublicKey, Musig2SignerError>` - The converted MuSig2 public key
pub fn to_musig_pubkey(
    pubkey: PublicKey,
) -> Result<musig2::secp256k1::PublicKey, Musig2SignerError> {
    let my_pub_key = musig2::secp256k1::PublicKey::from_str(&pubkey.to_string())
        .map_err(|_| Musig2SignerError::ConvertionPublicKeyError)?;
    Ok(my_pub_key)
}

/// Converts a MuSig2 public key to a Bitcoin public key
///
/// # Arguments
/// * `pubkey` - The MuSig2 public key to convert
///
/// # Returns
/// * `Result<PublicKey, Musig2SignerError>` - The converted Bitcoin public key
pub fn to_bitcoin_pubkey(
    pubkey: musig2::secp256k1::PublicKey,
) -> Result<PublicKey, Musig2SignerError> {
    let my_pub_key = PublicKey::from_str(&pubkey.to_string())
        .map_err(|_| Musig2SignerError::ConvertionPublicKeyError)?;
    Ok(my_pub_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_conversions() -> Result<(), Musig2SignerError> {
        // Test multiple different public keys
        let test_pubkeys = [
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
            "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
            "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a",
            "03074e234239757332de164b2f8a7790f73cfb8b3182fed1d90719aaa8fe5af08a",
        ];

        for pubkey_str in test_pubkeys.iter() {
            let bitcoin_pubkey = PublicKey::from_str(pubkey_str).unwrap();

            // Convert Bitcoin -> MuSig2
            let musig_pubkey = to_musig_pubkey(bitcoin_pubkey)?;
            assert_eq!(musig_pubkey.to_string(), *pubkey_str);

            // Convert MuSig2 -> Bitcoin
            let converted_bitcoin_pubkey = to_bitcoin_pubkey(musig_pubkey)?;

            assert_eq!(converted_bitcoin_pubkey.to_string(), *pubkey_str);

            // Verify round-trip conversion preserves the key
            assert_eq!(bitcoin_pubkey, converted_bitcoin_pubkey);
        }
        Ok(())
    }
}
