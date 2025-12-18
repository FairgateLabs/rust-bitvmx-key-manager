use std::{env, fs, time::Duration};

use bip39::Mnemonic;
use bitcoin::{key::rand::RngCore, secp256k1, Network};
use criterion::{criterion_group, criterion_main, Criterion};
use key_manager::{errors::KeyManagerError, key_manager::KeyManager, winternitz::WinternitzType};
use redact::Secret;
use storage_backend::storage_config::StorageConfig;
const REGTEST: Network = Network::Regtest;

fn test_key_manager(storage_config: StorageConfig) -> Result<KeyManager, KeyManagerError> {
    let random_mnemonic: Mnemonic = Mnemonic::from_entropy(&random_bytes()).unwrap();

    let key_manager = KeyManager::new(REGTEST, Some(random_mnemonic), None, &storage_config)?;

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

fn criterion_benchmark(_c: &mut Criterion) {
    let storage_path = temp_storage();
    let config_storage = StorageConfig::new(
        storage_path.clone(),
        Some(Secret::new("secret password_123__ABC".to_string())),
    );
    let key_manager = test_key_manager(config_storage).unwrap();

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
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
