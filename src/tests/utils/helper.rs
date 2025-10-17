use crate::key_manager::{self, KeyManager};
use bitcoin::key::rand;
use bitcoin::{
    key::rand::{thread_rng, RngCore},
    secp256k1, PublicKey,
};
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
    let key_derivation_seed = random_bytes();
    let winternitz_seed = random_bytes();

    let derivation_path = format!("m/101/1/0/0/{}", generate_random_string());
    let config = StorageConfig::new(store_keystore_path.to_string(), encrypt);

    let key_manager = key_manager::KeyManager::new(
        bitcoin::Network::Regtest,
        derivation_path.as_str(),
        Some(key_derivation_seed),
        Some(winternitz_seed),
        config,
    )?;

    Ok(key_manager)
}

pub fn create_pub_key(key_manager: &KeyManager) -> Result<PublicKey, anyhow::Error> {
    let mut rng = thread_rng();
    let pub_key: PublicKey = key_manager.generate_keypair(&mut rng)?;
    Ok(pub_key)
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
    // let password = "secret password".to_string();
    let key_manager = create_key_manager(ket_manager_key.as_str(), None)?;
    let pub_key = create_pub_key(&key_manager)?;

    Ok((key_manager, pub_key))
}
