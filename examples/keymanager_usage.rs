use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self, Message, Scalar},
    Network,
};

use key_manager::{
    key_manager::KeyManager, verifier::SignatureVerifier, winternitz::WinternitzType, key_type::BitcoinKeyType
};
use storage_backend::storage_config::StorageConfig;

fn main() {
    // --- Creating a KeyManager

    let network = Network::Regtest;
    let keystore_path = "./examples/storage/examples-keystore.db".to_string();
    let password = "secret password".to_string();
    let key_derivation_seed = random_bytes();

    let storage_config = StorageConfig::new(keystore_path, Some(password));

    let key_manager = KeyManager::new(
        network,
        Some(key_derivation_seed),
        storage_config,
    )
    .unwrap();

    // --- ------------------------ --- //

    // --- Key importing
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::PrivateKey;
    let secret_key = SecretKey::from_slice(&random_bytes()).unwrap();
    let private_key = PrivateKey::new(secret_key, network);
    let pubkey = key_manager
        .import_private_key(&private_key.to_wif())
        .unwrap();
    println!("Imported public key: {}", pubkey);

    let secret_key2 = SecretKey::from_slice(&random_bytes()).unwrap();
    let private_key2 = PrivateKey::new(secret_key2, network);

    let private_keys: Vec<String> =
        vec![private_key.to_wif().clone(), private_key2.to_wif().clone()];
    let pubkey = key_manager
        .import_partial_private_keys(private_keys, network)
        .unwrap();
    println!(
        "Imported partial aggregated public key from private keys: {}",
        pubkey
    );

    let secret_keys: Vec<String> = vec![
        secret_key.display_secret().to_string(),
        secret_key2.display_secret().to_string(),
    ];
    let pubkey = key_manager
        .import_partial_secret_keys(secret_keys, network)
        .unwrap();
    println!(
        "Imported partial aggregated public key from secret keys: {}",
        pubkey
    );

    // --- ------------------------ --- //

    // --- Key generation & Derivation

    // Internally the key manager generates a key pair,
    // stores the private key and the corresponding public key in the encrypted keystore.
    // The public key is later used to select the corresponding private key for signing.

    // Derive a child keypair (e.g., for indexed wallets)
    let derived_0_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0).unwrap();
    println!("derived_0_pubkey: {}", derived_0_pubkey);

    // Generate a master extended x public key
    let account_xpub = key_manager.generate_account_xpub(BitcoinKeyType::P2tr).unwrap();

    // Derive public key only
    let pubkey = key_manager.derive_public_key_from_account_xpub(account_xpub, BitcoinKeyType::P2tr, 1).unwrap();
    println!("Derived pubkey from xpub: {}", pubkey);

    // OR ...
    let same_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 1).unwrap();
    println!("Derived pubkey using derive_keypair: {}", same_pubkey);
    assert_eq!(pubkey, same_pubkey);

    // --- ------------------------ --- //

    // --- Signing and verifying a message using ECDSA

    let mut rng = secp256k1::rand::thread_rng();

    // Create a random Message.
    let mut digest = [0u8; 32];
    rng.fill_bytes(&mut digest);
    let message = Message::from_digest(digest);

    // Create a key pair
    let public_key = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0).unwrap();

    // Create an ECDSA signature of the random Message by selecting the private associated to the public key passed as parameter
    let signature = key_manager
        .sign_ecdsa_message(&message, &public_key)
        .unwrap();

    // Verify the signature
    let signature_verifier = SignatureVerifier::new();
    let sig_ok = signature_verifier.verify_ecdsa_signature(&signature, &message, public_key);
    println!("Signature valid: {}", sig_ok);

    // Recover signature
    let _recoverable_sig = key_manager
        .sign_ecdsa_recoverable_message(&message, &public_key)
        .unwrap();

    // --- ------------------------ --- //

    // --- Signing and verifying a message using Schnorr

    let mut rng = secp256k1::rand::thread_rng();

    // Create a random Message.
    let mut digest = [0u8; 32];
    rng.fill_bytes(&mut digest);
    let message = Message::from_digest(digest);

    // Create a key pair
    let public_key = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0).unwrap();

    // Create a Schnorr signature of the random Message by selecting the private associated to the public key passed as parameter
    let signature = key_manager
        .sign_schnorr_message(&message, &public_key)
        .unwrap();

    // Verify the signature
    let signature_verifier = SignatureVerifier::new();
    let sig_ok = signature_verifier.verify_schnorr_signature(&signature, &message, public_key);
    println!("Signature valid: {}", sig_ok);

    // --- ------------------------ --- //

    // --- Schnorr & Taproot Signatures

    // Sign with Taproot Script Path
    let signature = key_manager
        .sign_schnorr_message(&message, &public_key)
        .unwrap();
    println!("Schnorr signature: {}", signature);

    // Sign with Taproot Key Spend (Optional Merkle Root)
    let merkle_root = None;
    let (sig, tweaked_pubkey) = key_manager
        .sign_schnorr_message_with_tap_tweak(&message, &public_key, merkle_root)
        .unwrap();
    println!("Taproot Key Spend signature: {}", sig);
    println!("Taproot Key Spend tweaked pubkey: {}", tweaked_pubkey);

    // Sign with Custom Tweak
    let tweak: Scalar = Scalar::ZERO; // Example tweak, replace with actual tweak value
    let (sig, tweaked_pubkey) = key_manager
        .sign_schnorr_message_with_tweak(&message, &public_key, &tweak)
        .unwrap();
    println!("Taproot custom tweak Key Spend signature: {}", sig);
    println!(
        "Taproot custom tweak Key Spend tweaked pubkey: {}",
        tweaked_pubkey
    );

    // --- ------------------------ --- //

    // --- Winternitz ---

    // --- Deriving Winternitz OTS keys

    let mut rng = secp256k1::rand::thread_rng();

    // Key size in bytes. A Winternitz key needs to be of the same size as the message that will be signed with it.
    let key_size = 32;
    let winternitz_key = key_manager
        .derive_winternitz(key_size, WinternitzType::SHA256, 0)
        .unwrap();
    println!(
        "Winternitz public key: {:?}",
        hex::encode(winternitz_key.to_bytes())
    );
    let _ = winternitz_key.checksum_size();

    // --- Signing and verifying a message using Winternitz

    // Create a random Message.
    let mut digest = [0u8; 32];
    rng.fill_bytes(&mut digest);
    let message = Message::from_digest(digest);
    println!("Message: {:?}", message);

    // Create a Winternitz signature. Internally a Winternitz key pair for the derivation index 0 is created using the SHA-256 hash function
    let signature = key_manager
        .sign_winternitz_message(&message[..], WinternitzType::SHA256, 0)
        .unwrap();
    println!(
        "Winternitz signature: {:?}",
        hex::encode(signature.to_bytes())
    );

    // Get the Winternitz public key for the index 0 using the SHA-256 hash function
    let winternitz_key = key_manager
        .derive_winternitz(message[..].len(), WinternitzType::SHA256, 0)
        .unwrap();

    // Verify the signature
    let signature_verifier = SignatureVerifier::new();
    let is_valid =
        signature_verifier.verify_winternitz_signature(&signature, &message[..], &winternitz_key);
    println!("Is signature valid: {:?}", is_valid);
}

fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}
