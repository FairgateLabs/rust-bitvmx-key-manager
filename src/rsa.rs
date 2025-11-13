pub use rsa::{
    pkcs1v15::Signature,
    rand_core::{CryptoRng, OsRng},
};
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    pkcs8::{spki, DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    rand_core::RngCore,
    signature::{SignerMut, Verifier},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RSAError {
    #[error("RSA Error: {0}")]
    RsaError(#[from] rsa::Error),

    #[error("Invalid pubkey for PEM {0}")]
    InvalidPublicKey(#[from] spki::Error),

    #[error("Invalid private key for PEM {0}")]
    InvalidPrivateKey(#[from] rsa::pkcs8::Error),
}

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

impl RSAKeyPair {
    /// Generate a new RSA key pair
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, bits: usize) -> Result<Self, RSAError> {
        let private_key = RsaPrivateKey::new(rng, bits)?;
        Ok(Self::from_private_key(private_key))
    }
    /// Import private key from PEM (PKCS#8)
    pub fn from_private_pem(pem: &str) -> Result<Self, RSAError> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Create directly from a private key
    pub fn from_private_key(private_key: RsaPrivateKey) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    /// Sign a message using PKCS#1 v1.5 with SHA-256
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut signer = SigningKey::<Sha256>::new_unprefixed(self.private_key.clone());
        signer.sign(message)
    }

    /// Verify a signature using the public key
    pub fn verify(
        message: &[u8],
        public_key: &str, // PEM format public key
        signature: &Signature,
    ) -> Result<bool, RSAError> {
        let pubk = RsaPublicKey::from_public_key_pem(public_key)?;
        let verifier = VerifyingKey::<Sha256>::new_unprefixed(pubk);
        Ok(verifier.verify(message, signature).is_ok())
    }

    /// Encrypt a message using RSA
    pub fn encrypt<R: RngCore + CryptoRng>(
        message: &[u8],
        public_key: &str,
        rng: &mut R,
    ) -> Result<Vec<u8>, RSAError> {
        let pubk = RsaPublicKey::from_public_key_pem(public_key)?;
        let encrypt = pubk.encrypt(rng, Pkcs1v15Encrypt, message).unwrap();
        Ok(encrypt)
    }

    /// Decrypt a message using RSA
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RSAError> {
        let decrypt = self
            .private_key
            .decrypt(Pkcs1v15Encrypt, ciphertext)
            .unwrap();
        Ok(decrypt)
    }

    /// Export public key as PEM
    pub fn export_public_pem(&self) -> Result<String, RSAError> {
        let pem = self.public_key.to_public_key_pem(Default::default())?;
        Ok(pem)
    }

    /// Export public key as PEM
    pub fn export_public_pem_from_pubk(pubkey: RsaPublicKey) -> Result<String, RSAError> {
        let pem = pubkey.to_public_key_pem(Default::default())?;
        Ok(pem)
    }

    /// Export private key as PEM (PKCS#8)
    pub fn export_private_pem(&self) -> Result<String, RSAError> {
        let priv_pem = self
            .private_key
            .to_pkcs8_pem(Default::default())?
            .to_string();
        Ok(priv_pem)
    }

    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    /// RsaPublicKey form PEM public key
    pub fn pubkey_from_public_key_pem(public_key: &str) -> Result<RsaPublicKey, RSAError> {
        Ok(RsaPublicKey::from_public_key_pem(public_key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_keypair() {
        let mut rng = OsRng;
        let keypair = RSAKeyPair::from_private_key(RsaPrivateKey::new(&mut rng, 2048).unwrap());
        let keypair2 = RSAKeyPair::from_private_key(RsaPrivateKey::new(&mut rng, 2048).unwrap());

        let message = b"Hello, RSA!";
        let signature = keypair.sign(message);
        assert!(
            RSAKeyPair::verify(message, &keypair.export_public_pem().unwrap(), &signature).unwrap()
        );

        let ciphertext = RSAKeyPair::encrypt(
            &message[..],
            &keypair2.export_public_pem().unwrap(),
            &mut rng,
        )
        .unwrap();
        let decrypted_message = keypair2.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted_message, message);
    }
}
