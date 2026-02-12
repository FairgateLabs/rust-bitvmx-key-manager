mod create;

use create::create_key_manager_example;

use key_manager::lamport::LamportType;

fn main() {
    // see function code, main is just a wrapper to run the example
    key_gen_lamport_example();
}

fn key_gen_lamport_example() {
    let key_manager = create_key_manager_example("deriving_lamport");
    // --- Deriving Lamport OTS keys

    // using 1 bit to mimic a garbled circuit wire value
    let message_bit_length = 1;
    let lamport_pubkey = key_manager
        .next_lamport(message_bit_length, LamportType::SHA256)
        .unwrap();
    println!(
        "Lamport public key: {:?}",
        hex::encode(lamport_pubkey.to_bytes())
    );
}
