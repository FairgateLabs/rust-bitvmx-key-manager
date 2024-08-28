pub const NBITS: usize = 4; // Nibbles
pub const W: usize = 2usize.pow(NBITS as u32); // Winternitz parameter (times to hash)
pub const SHA256_SIZE: usize = 32;
pub const RIPEMD160_SIZE: usize = 20;

#[derive(Clone, Copy)]
pub enum WinternitzType {
    WSHA256,
    WRIPEMD160,
}

pub fn add_checksum(message: &[u8], w: usize) -> Vec<u8> {
    let mut message = message.to_vec();
    let checksum = calculate_checksum(&message, w);
    message.extend_from_slice(&checksum);
    message
}

pub fn calculate_checksum(message: &[u8], w: usize) -> Vec<u8> {
    let mut checksum: u32 = 0;

    for byte in message.iter() {
        let (high_nibble, low_nibble) = split_byte(*byte);
        checksum += (w as u32 - 1 - high_nibble as u32) + (w as u32 - 1 - low_nibble as u32);
    }

    let mut checksum_bytes = Vec::new();
    let mut temp = checksum;

    while temp > 0 {
        checksum_bytes.push((temp % 256) as u8);
        temp /= 256;
    }
    checksum_bytes.reverse();
    checksum_bytes
}

pub fn calculate_checksum_length(message_length_bytes: usize, w: usize) -> usize {
    let l1 = 2 * message_length_bytes;
    let l2 = ((l1 * (w-1)) as f64).log2() / 4.0; //log16(x) = log2(x) / 4
    (l2 / 2.0).ceil() as usize //checksum length in bytes
}

pub fn split_byte(byte: u8) -> (u8, u8) {
    let high_nibble: u8 = (byte & 0xF0) >> 4;
    let low_nibble: u8 = byte & 0x0F;
    (high_nibble, low_nibble)
}
