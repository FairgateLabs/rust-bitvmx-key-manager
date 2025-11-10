mod create;

use create::create_key_manager_example;
use key_manager::key_type::BitcoinKeyType;

fn main() {
    // see function code, main is just a wrapper to run the example
    key_generation_example();
}

fn key_generation_example() {
    let key_manager = create_key_manager_example("key_gen");

    // --- Key generation & Derivation

    // Internally the key manager generates a key pair,
    // stores the private key and the corresponding public key in the encrypted keystore.
    // The public key is later used to select the corresponding private key for signing.

    // next_keypair is always the preferred way to get a new keypair, as it manages the derivation index automatically.

    let next_p2tr_keypair_pubkey = key_manager.next_keypair(BitcoinKeyType::P2tr).unwrap();
    println!("Next p2tr keypair public key: {}", next_p2tr_keypair_pubkey);

    let next_p2pkh_keypair_pubkey = key_manager.next_keypair(BitcoinKeyType::P2pkh).unwrap();
    println!("Next p2pkh keypair public key: {}", next_p2pkh_keypair_pubkey);

    let next_p2sh_p2wpkh_keypair_pubkey = key_manager.next_keypair(BitcoinKeyType::P2shP2wpkh).unwrap();
    println!("Next p2sh_p2wpkh keypair public key: {}", next_p2sh_p2wpkh_keypair_pubkey);

    let next_p2wpkh_keypair_pubkey = key_manager.next_keypair(BitcoinKeyType::P2wpkh).unwrap();
    println!("Next p2wpkh keypair public key: {}", next_p2wpkh_keypair_pubkey);

    // Derive a child keypair (e.g., for indexed wallets)
    let derived_0_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 0).unwrap();
    println!("derived_0_pubkey: {}", derived_0_pubkey);

    // Generate a master extended x public key
    let account_xpub = key_manager
        .generate_account_xpub(BitcoinKeyType::P2tr)
        .unwrap();

    // Derive public key only
    let pubkey = key_manager
        .derive_public_key_from_account_xpub(account_xpub, BitcoinKeyType::P2tr, 1)
        .unwrap();
    println!("Derived pubkey from xpub: {}", pubkey);

    // OR ...
    let same_pubkey = key_manager.derive_keypair(BitcoinKeyType::P2tr, 1).unwrap();
    println!("Derived pubkey using derive_keypair: {}", same_pubkey);
    assert_eq!(pubkey, same_pubkey);
}
