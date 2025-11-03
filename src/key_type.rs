use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]

pub enum BitcoinKeyType {
    P2pkh,
    P2shP2wpkh,
    P2wpkh,
    P2tr,
}

impl BitcoinKeyType {
    pub fn purpose_index(&self) -> u32 {
        match self {
            BitcoinKeyType::P2pkh => 44,
            BitcoinKeyType::P2shP2wpkh => 49,
            BitcoinKeyType::P2wpkh => 84,
            BitcoinKeyType::P2tr => 86,
        }
    }
}