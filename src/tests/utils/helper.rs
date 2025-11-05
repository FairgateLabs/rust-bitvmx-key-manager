use crate::key_manager::{self, KeyManager};
use crate::key_type::BitcoinKeyType;
use bip39::Mnemonic;
use bitcoin::key::rand;
use bitcoin::{key::rand::RngCore, secp256k1, PublicKey};
use rand::Rng;
use storage_backend::storage_config::StorageConfig;

pub fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}

pub fn create_key_manager(
    store_keystore_path: &str,
    encrypt: Option<String>,
) -> Result<KeyManager, anyhow::Error> {
    let random_mnemonic: Mnemonic = Mnemonic::from_entropy(&random_bytes()).unwrap();

    let config = StorageConfig::new(store_keystore_path.to_string(), encrypt);

    let key_manager =
        key_manager::KeyManager::new(bitcoin::Network::Regtest, Some(random_mnemonic), config)?;

    Ok(key_manager)
}

pub fn clear_output() {
    let _ = std::fs::remove_dir_all("test_output");
}

pub fn generate_random_string() -> String {
    let mut rng = rand::thread_rng();
    (0..10).map(|_| rng.gen_range('a'..='z')).collect()
}

pub fn mock_data() -> Result<(KeyManager, PublicKey), anyhow::Error> {
    let path = format!("test_output/{}", generate_random_string());
    let ket_manager_key = path;
    let password = "secret password".to_string();
    let key_manager = create_key_manager(ket_manager_key.as_str(), Some(password))?;
    let pub_key = key_manager.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;

    Ok((key_manager, pub_key))
}
