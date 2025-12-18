mod create;

use bitcoin::Network;
use create::{create_key_manager_example, random_bytes};
use key_manager::key_type::BitcoinKeyType;

fn main() {
    // see function code, main is just a wrapper to run the example
    import_key_to_key_manager_example();
}

pub fn import_key_to_key_manager_example() {
    let network = Network::Regtest;
    let key_manager = create_key_manager_example("key_import");

    // --- Key importing
    // Note that it is responsibility of the caller to zeroize private keys after use, and they in memory lifespan management
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::PrivateKey;
    use zeroize::Zeroizing;

    // -- Importing a single private key without typing it (internally its type 'unknown')
    let random_bytes_z = Zeroizing::new(random_bytes()); // adds automatic zeroization on drop
    let secret_key = SecretKey::from_slice(&*random_bytes_z).unwrap();
    let private_key = PrivateKey::new(secret_key, network);
    let private_key_wif_z = Zeroizing::new(private_key.to_wif()); // adds automatic zeroization on drop

    let pubkey = key_manager.import_private_key(&*private_key_wif_z).unwrap();
    println!("Imported public key: {}", pubkey);

    // -- Importing a single private key with type specified
    let random_bytes2_z = Zeroizing::new(random_bytes()); // adds automatic zeroization on drop
                                                          // In this case we are using random bytes for the sake of this example simplicity,
                                                          // but in real use cases the bytes should come from a secure source following BIP-39 derivation path for the desired key type
    let secret_key2 = SecretKey::from_slice(&*random_bytes2_z).unwrap();
    let private_key2 = PrivateKey::new(secret_key2, network);
    let private_key_wif2_z = Zeroizing::new(private_key2.to_wif()); // adds automatic zeroization on drop

    // The key type could be any of the supported BitcoinKeyType variants (P2pkh, P2shP2wpkh, P2wpkh, P2tr)
    let key2_type = BitcoinKeyType::P2tr;
    let pubkey = key_manager
        .import_private_key_typed(&*private_key_wif2_z, Some(key2_type))
        .unwrap();
    println!("Imported public key 2: {} of type {:?}", pubkey, key2_type);

    let private_keys: Zeroizing<Vec<String>> = Zeroizing::new(vec![
        (*private_key_wif_z).clone(),
        (*private_key_wif2_z).clone(),
    ]);

    let pubkey = key_manager
        .import_partial_private_keys(private_keys, network)
        .unwrap();
    println!(
        "Imported partial aggregated public key from private keys: {}",
        pubkey
    );

    let secret_keys: Zeroizing<Vec<String>> = Zeroizing::new(vec![
        secret_key.display_secret().to_string(),
        secret_key2.display_secret().to_string(),
    ]);

    let pubkey = key_manager
        .import_partial_secret_keys(secret_keys, network)
        .unwrap();
    println!(
        "Imported partial aggregated public key from secret keys: {}",
        pubkey
    );
}
