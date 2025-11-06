mod create;

use bitcoin::Network;
use create::{create_key_manager_example, random_bytes};

fn main() {
    // see function code, main is just a wrapper to run the example
    import_key_to_key_manager_example();
}

pub fn import_key_to_key_manager_example() {
    let network = Network::Regtest;
    let key_manager = create_key_manager_example();

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
}
