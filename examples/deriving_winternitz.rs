mod create;

use create::create_key_manager_example;

use key_manager::winternitz::WinternitzType;

fn main() {
    // see function code, main is just a wrapper to run the example
    key_gen_winternitz_example();
}

fn key_gen_winternitz_example() {
    let key_manager = create_key_manager_example("deriving_winternitz");
    // --- Deriving Winternitz OTS keys

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
}
