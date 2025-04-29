use std::path::PathBuf;
use std::rc::Rc;

use bitcoin::key::rand;
use bitcoin::{
    key::rand::{thread_rng, RngCore},
    secp256k1, PublicKey,
};
use rand::Rng;
use storage_backend::storage::Storage;

use crate::musig2::musig::MuSig2Signer;
use crate::{
    key_manager::{self, KeyManager},
    keystorage::{self, database::DatabaseKeyStore},
};

pub fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}

pub fn create_key_manager(
    store_keystore_path: &str,
    store: Rc<Storage>,
) -> Result<KeyManager<DatabaseKeyStore>, anyhow::Error> {
    let key_derivation_seed = random_bytes();
    let winternitz_seed = random_bytes();

    let derivation_path = format!("m/101/1/0/0/{}", generate_random_string());
    let password = b"secret password".to_vec();
    let storage_path = std::path::PathBuf::from(store_keystore_path);
    let keystore = keystorage::database::DatabaseKeyStore::new(
        storage_path,
        password,
        bitcoin::Network::Regtest,
    )?;

    let key_manager = key_manager::KeyManager::new(
        bitcoin::Network::Regtest,
        derivation_path.as_str(),
        key_derivation_seed,
        winternitz_seed,
        keystore,
        store,
    )?;

    Ok(key_manager)
}

pub fn create_pub_key(
    key_manager: &KeyManager<DatabaseKeyStore>,
) -> Result<PublicKey, anyhow::Error> {
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

pub fn mock_data() -> Result<(KeyManager<DatabaseKeyStore>, PublicKey, MuSig2Signer), anyhow::Error>
{
    let path = PathBuf::from(format!("test_output/{}", generate_random_string()));
    let store = Rc::new(Storage::new_with_path(&path)?);
    let ket_manager_key = format!("test_output/{}", generate_random_string());
    let key_manager = create_key_manager(ket_manager_key.as_str(), store.clone())?;
    let pub_key = create_pub_key(&key_manager)?;
    let musig = MuSig2Signer::new(store.clone());

    Ok((key_manager, pub_key, musig))
}
