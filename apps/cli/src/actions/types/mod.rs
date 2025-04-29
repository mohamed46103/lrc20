use core::{fmt, fmt::Display};
use std::{ops::Deref, str::FromStr};

use bitcoin::{key::Parity, secp256k1::PublicKey};
use color_eyre::eyre::{self, bail};
use lrc20_receipts::TokenPubkey;

/// Enum that represents recipient's address type.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AddrType {
    /// Pay-to-Witness-Public-Key-Hash.
    P2WPKH,
    /// Pay-to-Taproot.
    P2TR,
}

impl Display for AddrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrType::P2WPKH => {
                write!(f, "P2WPKH")
            }
            AddrType::P2TR => {
                write!(f, "P2TR")
            }
        }
    }
}

impl FromStr for AddrType {
    type Err = eyre::Error;

    fn from_str(addr_type: &str) -> Result<Self, Self::Err> {
        match addr_type.to_lowercase().as_str() {
            "p2tr" => Ok(AddrType::P2TR),
            "p2wpkh" => Ok(AddrType::P2WPKH),
            _ => {
                bail!("Unsupported address type")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LRC20Pubkey(PublicKey);

impl Deref for LRC20Pubkey {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for LRC20Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for LRC20Pubkey {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(pubkey) = PublicKey::from_str(s) {
            return Ok(LRC20Pubkey::from(pubkey));
        }

        let token_pubkey_with_parity = s.split(":").collect::<Vec<_>>();
        let parity = if let Some(p) = token_pubkey_with_parity.get(1) {
            let parity_num = p.parse::<u8>()?;
            Some(Parity::from_u8(parity_num)?)
        } else {
            None
        };
        let token_pubkey = TokenPubkey::from_address(token_pubkey_with_parity[0], parity)?;

        Ok(LRC20Pubkey(*token_pubkey.pubkey()))
    }
}

impl From<PublicKey> for LRC20Pubkey {
    fn from(pubkey: PublicKey) -> Self {
        LRC20Pubkey(pubkey)
    }
}

impl From<LRC20Pubkey> for PublicKey {
    fn from(recipient: LRC20Pubkey) -> Self {
        recipient.0
    }
}

impl From<&LRC20Pubkey> for PublicKey {
    fn from(recipient: &LRC20Pubkey) -> Self {
        recipient.0
    }
}

impl From<LRC20Pubkey> for bitcoin::PublicKey {
    fn from(recipient: LRC20Pubkey) -> Self {
        bitcoin::PublicKey::from(recipient.0)
    }
}

impl From<LRC20Pubkey> for TokenPubkey {
    fn from(recipient: LRC20Pubkey) -> Self {
        recipient.0.into()
    }
}
