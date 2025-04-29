use core::fmt;
use core::{fmt::Display, mem::size_of, str::FromStr};

use crate::errors::{ReceiptParseError, TokenAmountParseError, TokenPubkeyParseError};
use bitcoin::address::Payload;
use bitcoin::key::constants::PUBLIC_KEY_SIZE;
use bitcoin::secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE;
use bitcoin::secp256k1::{Parity, PublicKey};
use bitcoin::{Address, Network, key::XOnlyPublicKey};
use bitcoin::{WitnessProgram, WitnessVersion};
use once_cell::sync::Lazy;
#[cfg(feature = "serde")]
mod deser;
#[cfg(feature = "serde")]
use crate::deserialize_public_key;

/// The size of the [`TokenAmount`] in bytes.
pub const TOKEN_AMOUNT_SIZE: usize = 32;

pub const AMOUNT_SIZE: usize = size_of::<u128>();

pub const BLINDING_FACTOR_SIZE: usize = TOKEN_AMOUNT_SIZE - AMOUNT_SIZE;

/// Size of serialized [`PublicKey`] under the hood.
pub const TOKEN_PUBKEY_SIZE: usize = PUBLIC_KEY_SIZE;

/// Result size of serialized [`Receipt`].
pub const RECEIPT_SIZE: usize = TOKEN_AMOUNT_SIZE + TOKEN_PUBKEY_SIZE;

pub const ZERO_PUBKEY_BYTES: &[u8] = &[0x02; 33];

pub static ZERO_PUBLIC_KEY: Lazy<PublicKey> =
    Lazy::new(|| PublicKey::from_slice(ZERO_PUBKEY_BYTES).expect("Pubkey should be valid"));

/// Represents amount of tokens in the [`Receipt`].
///
/// The result size is 256 bits. The first 64 are for token amount, another 192
/// bits will be used as _blinding factor_ for future features.
#[derive(Clone, Debug, Copy, Hash, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct TokenAmount {
    pub amount: u128,

    pub blinding_factor: [u8; BLINDING_FACTOR_SIZE],
}

impl From<u128> for TokenAmount {
    fn from(amount: u128) -> Self {
        Self {
            amount,
            ..Default::default()
        }
    }
}

impl From<[u8; TOKEN_AMOUNT_SIZE]> for TokenAmount {
    fn from(bytes: [u8; TOKEN_AMOUNT_SIZE]) -> Self {
        Self::from_array(bytes)
    }
}

impl TokenAmount {
    pub fn new(amount: u128, blinding_factor: [u8; BLINDING_FACTOR_SIZE]) -> Self {
        Self {
            amount,
            blinding_factor,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenAmountParseError> {
        if bytes.len() < TOKEN_AMOUNT_SIZE {
            return Err(TokenAmountParseError::InvalidSize(bytes.len()));
        }

        let bytes: [u8; TOKEN_AMOUNT_SIZE] = bytes[..TOKEN_AMOUNT_SIZE]
            .try_into()
            .expect("As we checked the bytes size, slice should always convert");

        Ok(Self::from_array(bytes))
    }

    pub fn from_array(bytes: [u8; TOKEN_AMOUNT_SIZE]) -> Self {
        // TODO(Velnbur): check if we want big-endian, or little-endian.
        let amount = u128::from_be_bytes(
            bytes[0..AMOUNT_SIZE]
                .try_into()
                .expect("Converting [u8; 32] to [u8; 16] should always success"),
        );

        let blinding_factor = bytes[AMOUNT_SIZE..]
            .try_into()
            .expect("Converting [u8; 32] to [u8; 16] should always success");

        Self {
            amount,
            blinding_factor,
        }
    }

    pub fn to_bytes(&self) -> [u8; TOKEN_AMOUNT_SIZE] {
        let mut buf: [u8; TOKEN_AMOUNT_SIZE] = [0u8; TOKEN_AMOUNT_SIZE];

        // TODO(Velnbur): check if want to use big-endian or little-endian.
        buf[..AMOUNT_SIZE].copy_from_slice(&self.amount.to_be_bytes());
        buf[AMOUNT_SIZE..].copy_from_slice(&self.blinding_factor);

        buf
    }
}

/// Represensts the asset type of the LRC20 token and is defined by X
/// coordinate of issuer's public key.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenPubkey(
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_public_key"))] PublicKey,
);

impl FromStr for TokenPubkey {
    type Err = TokenPubkeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pubkey = PublicKey::from_str(s)?;

        Ok(Self::new(pubkey))
    }
}

impl Display for TokenPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TokenPubkey {
    pub fn new(pubkey: PublicKey) -> Self {
        Self(pubkey)
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; TOKEN_PUBKEY_SIZE] {
        self.0.serialize()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenPubkeyParseError> {
        if bytes.len() < TOKEN_PUBKEY_SIZE {
            return Err(TokenPubkeyParseError::InvalidSize(bytes.len()));
        }

        Ok(Self(PublicKey::from_slice(bytes)?))
    }

    pub fn to_address(&self, network: Network) -> Address {
        let program = self.0.x_only_public_key().0.serialize();

        Address::new(
            network,
            Payload::WitnessProgram(
                WitnessProgram::new(WitnessVersion::V1, program.to_vec())
                    .expect("Should be valid program"),
            ),
        )
    }

    pub fn from_address(
        address: &str,
        parity: Option<Parity>,
    ) -> Result<Self, TokenPubkeyParseError> {
        let address =
            Address::from_str(address).map_err(|_| TokenPubkeyParseError::InvalidAddressType)?;

        let (version, program) = match &address.payload() {
            Payload::WitnessProgram(program) => (program.version(), program.program()),
            _ => return Err(TokenPubkeyParseError::InvalidAddressType),
        };

        if version != WitnessVersion::V1 {
            return Err(TokenPubkeyParseError::InvalidWitnessProgramVersion(version));
        }

        if program.len() != SCHNORR_PUBLIC_KEY_SIZE {
            return Err(TokenPubkeyParseError::InvalidWitnessProgramLength(
                program.len(),
            ));
        }

        let xonly = XOnlyPublicKey::from_slice(program.as_bytes())?;

        Ok(Self::new(xonly.public_key(parity.unwrap_or(Parity::Even))))
    }
}

impl From<PublicKey> for TokenPubkey {
    fn from(public_key: PublicKey) -> Self {
        Self(public_key)
    }
}

impl From<&PublicKey> for TokenPubkey {
    fn from(public_key: &PublicKey) -> Self {
        Self(*public_key)
    }
}

impl From<bitcoin::PublicKey> for TokenPubkey {
    fn from(public_key: bitcoin::PublicKey) -> Self {
        Self(public_key.inner)
    }
}

impl From<&bitcoin::PublicKey> for TokenPubkey {
    fn from(public_key: &bitcoin::PublicKey) -> Self {
        Self(public_key.inner)
    }
}

impl From<XOnlyPublicKey> for TokenPubkey {
    fn from(xonly: XOnlyPublicKey) -> Self {
        Self(xonly.public_key(Parity::Even))
    }
}

impl From<&XOnlyPublicKey> for TokenPubkey {
    fn from(xonly: &XOnlyPublicKey) -> Self {
        Self(xonly.public_key(Parity::Even))
    }
}

impl From<&TokenPubkey> for PublicKey {
    fn from(token_pubkey: &TokenPubkey) -> Self {
        token_pubkey.0
    }
}

impl From<TokenPubkey> for PublicKey {
    fn from(token_pubkey: TokenPubkey) -> Self {
        token_pubkey.0
    }
}

/// Receipt and it's data that participates in a transaction.
#[derive(Clone, Debug, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Receipt {
    pub token_amount: TokenAmount,
    pub token_pubkey: TokenPubkey,
}

impl Receipt {
    pub fn new(token_amount: impl Into<TokenAmount>, token_pubkey: impl Into<TokenPubkey>) -> Self {
        Self {
            token_amount: token_amount.into(),
            token_pubkey: token_pubkey.into(),
        }
    }

    pub fn empty() -> Self {
        let zero_pubkey = PublicKey::from_slice(ZERO_PUBKEY_BYTES).expect("Pubkey should be valid");

        Self::new(0, zero_pubkey)
    }

    pub fn to_bytes(&self) -> [u8; RECEIPT_SIZE] {
        let mut buf = [0u8; RECEIPT_SIZE];

        buf[..TOKEN_AMOUNT_SIZE].copy_from_slice(&self.token_amount.to_bytes());
        buf[TOKEN_AMOUNT_SIZE..RECEIPT_SIZE].copy_from_slice(&self.token_pubkey.to_bytes());

        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReceiptParseError> {
        if bytes.len() < RECEIPT_SIZE {
            return Err(ReceiptParseError::IncorrectSize(bytes.len()));
        }

        let token_amount = TokenAmount::from_bytes(&bytes[0..TOKEN_AMOUNT_SIZE])?;
        let token_pubkey = TokenPubkey::from_bytes(&bytes[TOKEN_AMOUNT_SIZE..RECEIPT_SIZE])?;

        Ok(Self {
            token_amount,
            token_pubkey,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use once_cell::sync::Lazy;

    use super::*;

    static X_ONLY_PUBKEY: Lazy<XOnlyPublicKey> = Lazy::new(|| {
        XOnlyPublicKey::from_str("0677b5829356bb5e0c0808478ac150a500ceab4894d09854b0f75fbe7b4162f8")
            .expect("Should be valid address")
    });

    #[test]
    fn test_token_amount_parsing() {
        let token_amount = TokenAmount::from(100);

        let token_amount_as_bytes = token_amount.to_bytes();

        assert_eq!(
            token_amount,
            TokenAmount::from_bytes(&token_amount_as_bytes).unwrap(),
            "Converting back and forth should work"
        );
    }

    #[test]
    fn test_token_pubkey_parsing_bytes() {
        let token_pubkey = TokenPubkey::from(*X_ONLY_PUBKEY);

        let token_pubkey_as_bytes = token_pubkey.to_bytes();

        assert_eq!(
            token_pubkey,
            TokenPubkey::from_bytes(&token_pubkey_as_bytes).unwrap(),
            "Converting back and forth should work"
        );
    }

    #[test]
    fn test_token_pubkey_parsing_address() {
        let token_pubkey = TokenPubkey::from(*X_ONLY_PUBKEY);

        let address = token_pubkey.to_address(Network::Bitcoin);

        assert_eq!(
            token_pubkey,
            TokenPubkey::from_address(&address.to_string(), None).unwrap(),
            "Converting back and forth should work"
        );
    }

    #[test]
    fn test_receipt_parsing() {
        let receipt = Receipt::new(100, *X_ONLY_PUBKEY);

        let receipt_as_bytes = receipt.to_bytes();

        assert_eq!(
            receipt,
            Receipt::from_bytes(&receipt_as_bytes).unwrap(),
            "Converting back and forth should work"
        );
    }
}
