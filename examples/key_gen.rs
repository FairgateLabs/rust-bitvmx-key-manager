mod create;

use create::create_key_manager_example;
use key_manager::key_type::BitcoinKeyType;


fn main () {
    // see function code, main is just a wrapper to run the example
    key_generation_example();
}

fn key_generation_example() {
    let key_manager = create_key_manager_example();

    // --- Key generation & Derivation

    // Internally the key manager generates a key pair,
    // stores the private key and the corresponding public key in the encrypted keystore.
    // The public key is later used to select the corresponding private key for signing.

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
