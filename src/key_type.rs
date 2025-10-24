#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]

// TODO add winternitz
// TODO add musig2 ?
// TODO add RSA ?
pub enum KeyType {
    P2pkh,
    P2shP2wpkh,
    P2wpkh,
    P2tr,
}

impl KeyType {
    pub fn purpose_index(&self) -> u32 {
        match self {
            KeyType::P2pkh => 44,
            KeyType::P2shP2wpkh => 49,
            KeyType::P2wpkh => 84,
            KeyType::P2tr => 86,
        }
    }
}