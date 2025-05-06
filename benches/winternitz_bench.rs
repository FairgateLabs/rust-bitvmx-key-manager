use std::{env, fs, path::PathBuf, rc::Rc, time::Duration};

use bitcoin::{key::rand::RngCore, secp256k1, Network};
use criterion::{criterion_group, criterion_main, Criterion};
use key_manager::{
    errors::{KeyManagerError, KeyStoreError},
    key_manager::KeyManager,
    keystorage::{database::DatabaseKeyStore, keystore::KeyStore},
    winternitz::WinternitzType,
};
use storage_backend::storage::Storage;
const DERIVATION_PATH: &str = "m/101/1/0/0/";
const REGTEST: Network = Network::Regtest;

fn test_key_manager<K: KeyStore>(
    keystore: K,
    store: Rc<Storage>,
) -> Result<KeyManager<K>, KeyManagerError> {
    let key_derivation_seed = random_bytes();
    let winternitz_seed = random_bytes();

    let key_manager = KeyManager::new(
        REGTEST,
        DERIVATION_PATH,
        key_derivation_seed,
        winternitz_seed,
        keystore,
        store,
    )?;

    Ok(key_manager)
}

fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}

fn temp_storage() -> String {
    let dir = env::temp_dir();
    let mut rng = secp256k1::rand::thread_rng();
    let index = rng.next_u32();
    dir.join(format!("storage_{}.db", index))
        .to_str()
        .unwrap()
        .to_string()
}

fn database_keystore(storage_path: &str) -> Result<DatabaseKeyStore, KeyStoreError> {
    let password = b"secret password".to_vec();
    DatabaseKeyStore::new(storage_path, password, Network::Regtest)
}

fn criterion_benchmark(_c: &mut Criterion) {
    let storage_path = temp_storage();
    let keystore = database_keystore(&storage_path).unwrap();

    let store_path = PathBuf::from("/tmp/key_manager_storage".to_string());
    let store = Rc::new(Storage::new_with_path(&store_path).unwrap());

    let key_manager = test_key_manager(keystore, store).unwrap();

    let mut criterion = Criterion::default().measurement_time(Duration::from_secs(40));
    let numbers_of_keys_to_hash = vec![2, 4, 6, 8, 10, 12, 14, 16];

    for number_of_keys in numbers_of_keys_to_hash {
        criterion.bench_function(
            &format!(
                "Hashing {} Winternitz keys calling everytime the Winternitz Secret",
                number_of_keys
            ),
            |b| {
                b.iter(|| {
                    for i in 0..number_of_keys {
                        key_manager
                            .derive_winternitz(32, WinternitzType::HASH160, i)
                            .unwrap();
                    }
                })
            },
        );

        criterion.bench_function(
            &format!(
                "Hashing {} Winternitz keys calling the Winternitz Secret only once",
                number_of_keys
            ),
            |b| {
                b.iter(|| {
                    key_manager.derive_multiple_winternitz(
                        32,
                        WinternitzType::HASH160,
                        0,
                        number_of_keys,
                    )
                })
            },
        );
    }

    fs::remove_dir_all(storage_path).unwrap();
    fs::remove_dir_all(store_path).unwrap();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
