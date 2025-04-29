use alloc::string::String;
use alloc::vec::Vec;

use bitcoin::OutPoint;
use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Script, ScriptBuf, script::PushBytesBuf};
use lrc20_receipts::TokenPubkey;

use core::fmt;

use super::freeze::pubkey::PubkeyFreezeAnnouncement;
use super::token_logo::{TokenLogoAnnouncement, TokenLogoAnnouncementParseError};
use super::token_pubkey::TokenPubkeyAnnouncementParseError;
use super::transfer_ownership::TransferOwnershipAnnouncement;
use crate::{
    announcements::{
        ParseOpReturnError, TokenPubkeyAnnouncement, TxFreezeAnnouncement,
        issue::IssueAnnouncement, parse_op_return_script,
    },
    network::Network,
};
use bitcoin::blockdata::opcodes::all::OP_RETURN;

#[cfg(feature = "consensus")]
use {
    crate::announcements::announcement_from_bytes,
    bitcoin::{consensus, consensus::encode::Error as ConsensusError},
    core2::io,
};

/// `b'lrc20'` - constant prefix to differentiate [`Announcement`]'s `OP_RETURN` from other protocols.
pub const ANNOUNCEMENT_PREFIX: [u8; 5] = [76, 82, 67, 50, 48];
/// The length of the [`announcement kind`] in bytes.
///
/// [`announcement kind`]: AnnouncementKind
pub const ANNOUNCEMENT_KIND_LENGTH: usize = 2;
/// The minimal length of the [`Announcement`] in bytes. It includes the
/// [`announcement prefix`] - 5 bytes, and [`announcement kind`] - 2 bytes.
///
/// [`announcement prefix`]: ANNOUNCEMENT_PREFIX
/// [`announcement kind`]: AnnouncementKind
pub const ANNOUNCEMENT_MINIMAL_LENGTH: usize = ANNOUNCEMENT_PREFIX.len() + ANNOUNCEMENT_KIND_LENGTH;
/// Number of instructions in announcement script.
pub const ANNOUNCEMENT_INSTRUCTION_NUMBER: usize = 3;

/// Two bytes that represent the type of an [`Announcement`].
///
/// It is used to differentiate between different types of announcements, e.g. the token_pubkey's initial
/// announcement has the kind `[0, 0]`.
pub type AnnouncementKind = [u8; ANNOUNCEMENT_KIND_LENGTH];

/// The announcement message is used to announce some information about the issuer or token. It can
/// be broadcasted to the Bitcoin network using the `OP_RETURN` output script by the Issuer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Announcement {
    TokenLogo(TokenLogoAnnouncement),
    TokenPubkey(TokenPubkeyAnnouncement),
    TxFreeze(TxFreezeAnnouncement),
    PubkeyFreeze(PubkeyFreezeAnnouncement),
    Issue(IssueAnnouncement),
    TransferOwnership(TransferOwnershipAnnouncement),
}

impl Announcement {
    /// Return the inner [`AnyAnnouncement`] type that can be used to use some general methods.
    pub fn inner(&self) -> &dyn AnyAnnouncement {
        match self {
            Self::TokenLogo(inner) => inner,
            Self::TokenPubkey(inner) => inner,
            Self::TxFreeze(inner) => inner,
            Self::PubkeyFreeze(inner) => inner,
            Self::Issue(inner) => inner,
            Self::TransferOwnership(inner) => inner,
        }
    }

    pub fn token_pubkey(&self) -> TokenPubkey {
        match self {
            Announcement::TokenLogo(token_logo_announcement) => {
                token_logo_announcement.token_pubkey
            }
            Announcement::TokenPubkey(token_pubkey_announcement) => {
                token_pubkey_announcement.token_pubkey
            }
            Announcement::TxFreeze(tx_freeze_announcement) => tx_freeze_announcement.token_pubkey,
            Announcement::PubkeyFreeze(pubkey_freeze_announcement) => {
                pubkey_freeze_announcement.token_pubkey
            }
            Announcement::Issue(issue_announcement) => issue_announcement.token_pubkey,
            Announcement::TransferOwnership(transfer_ownership_announcement) => {
                transfer_ownership_announcement.token_pubkey
            }
        }
    }

    /// Returns the kind of the [`AnyAnnouncement`].
    pub fn kind(&self) -> AnnouncementKind {
        self.inner().kind()
    }

    /// Return minimal block height for the announcement of this type.
    pub fn minimal_block_height(&self, network: Network) -> usize {
        self.inner().minimal_block_height(network)
    }

    /// Convert the announcement message to the Bitcoin [`ScriptBuf`] with [`OP_RETURN`].
    pub fn to_script(&self) -> ScriptBuf {
        self.inner().to_script()
    }

    /// Convert the announcement message to bytes.    
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner().to_bytes()
    }
}

// Convenience methods
impl Announcement {
    /// A wrapper to create a [`TokenPubkeyAnnouncement`] from the given arguments.
    pub fn token_pubkey_announcement(
        token_pubkey: impl Into<TokenPubkey>,
        name: String,
        symbol: String,
        decimal: u8,
        max_supply: u128,
        is_freezable: bool,
    ) -> Result<Self, TokenPubkeyAnnouncementParseError> {
        Ok(Self::TokenPubkey(TokenPubkeyAnnouncement::new(
            token_pubkey.into(),
            name,
            symbol,
            decimal,
            max_supply,
            is_freezable,
        )?))
    }

    /// A wrapper to create a [`TokenLogoAnnouncement`] from the given arguments.
    pub fn token_logo_announcement(
        token_pubkey: impl Into<TokenPubkey>,
        logo_url: String,
    ) -> Result<Self, TokenLogoAnnouncementParseError> {
        Ok(Self::TokenLogo(TokenLogoAnnouncement::new(
            token_pubkey.into(),
            logo_url,
        )?))
    }

    /// A wrapper to create a [`TransferOwnershipAnnouncement`] from the given arguments.
    pub fn transfer_ownership_announcement(
        token_pubkey: impl Into<TokenPubkey>,
        new_owner: ScriptBuf,
    ) -> Self {
        Self::TransferOwnership(TransferOwnershipAnnouncement::new(
            token_pubkey.into(),
            new_owner,
        ))
    }

    /// A wrapper to create a [`TxFreezeAnnouncement`] from the given arguments.
    pub fn tx_freeze_announcement(
        token_pubkey: impl Into<TokenPubkey>,
        outpoint: OutPoint,
    ) -> Self {
        Self::TxFreeze(TxFreezeAnnouncement::new(token_pubkey.into(), outpoint))
    }

    /// A wrapper to create a [`PubkeyFreezeAnnouncement`] from the given arguments.
    pub fn pubkey_freeze_announcement(
        token_pubkey: impl Into<TokenPubkey>,
        pubkey: PublicKey,
    ) -> Self {
        Self::PubkeyFreeze(PubkeyFreezeAnnouncement::new(token_pubkey.into(), pubkey))
    }
}

impl fmt::Display for Announcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenLogo(_) => write!(f, "TokenLogoAnnouncement"),
            Self::TokenPubkey(_) => write!(f, "TokenPubkeyAnnouncement"),
            Self::TxFreeze(_) => write!(f, "TxFreezeAnnouncement"),
            Self::PubkeyFreeze(_) => write!(f, "PubkeyFreezeAnnouncement"),
            Self::Issue(_) => write!(f, "IssueAnnouncement"),
            Self::TransferOwnership(_) => write!(f, "TransferOwnershipAnnouncement"),
        }
    }
}

#[cfg(feature = "consensus")]
impl consensus::Encodable for Announcement {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        writer.write(&self.inner().to_bytes())
    }
}

#[cfg(feature = "consensus")]
impl consensus::Decodable for Announcement {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ConsensusError> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let announcement = announcement_from_bytes(&buf)
            .map_err(|_| ConsensusError::Io(io::ErrorKind::InvalidData.into()))?;

        Ok(announcement)
    }
}

/// The trait contains general methods of the [`Announcement`]s.
///
/// # Note
///
/// If you introduce a new type of announcement, you should implement this trait for it.
/// Specificaly you need to implement only the `kind()` method that just returns a [kind] of your
/// announcement and the `from_announcement_data_bytes`, `to_announcement_data_bytes` methods
/// that are used to decode/encode the announcement data. Other methods are implemented
/// automatically.
///
/// [kind]: AnnouncementKind
#[allow(private_bounds)]
#[cfg_attr(feature = "serde", typetag::serde(tag = "type"))]
pub trait AnyAnnouncement {
    /// Return the two bytes that represent the [`announcement kind`].
    ///
    /// [`announcement kind`]: AnnouncementKind
    fn kind(&self) -> AnnouncementKind;

    /// Return minimal block height for the announcement of this type.
    fn minimal_block_height(&self, network: Network) -> usize;

    /// Parse the announcement data from bytes.
    fn from_announcement_data_bytes(data_raw: &[u8]) -> Result<Self, AnnouncementParseError>
    where
        Self: Sized;

    /// Convert the announcement data to bytes.
    fn to_announcement_data_bytes(&self) -> Vec<u8>;

    /// Parse the announcement message from the Bitcoin [`Script] with [`OP_RETURN`].
    fn from_script(script: &Script) -> Result<Self, ParseOpReturnError>
    where
        Self: Sized,
    {
        parse_op_return_script(script, Self::from_bytes)
    }

    /// Convert the announcement message to the Bitcoin [`ScriptBuf`] with [`OP_RETURN`].
    fn to_script(&self) -> ScriptBuf {
        let mut push_bytes = PushBytesBuf::new();
        push_bytes
            .extend_from_slice(&self.to_bytes())
            .expect("Should be valid script");

        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(push_bytes)
            .into_script()
    }

    /// Parse the announcement message from bytes from `OP_RETURN` Script.
    fn from_bytes(value: &[u8]) -> Result<Self, AnnouncementParseError>
    where
        Self: Sized,
    {
        if value.len() < ANNOUNCEMENT_MINIMAL_LENGTH {
            return Err(AnnouncementParseError::ShortLength);
        }

        let prefix = [value[0], value[1], value[2], value[3], value[4]];
        if prefix != ANNOUNCEMENT_PREFIX {
            return Err(AnnouncementParseError::InvalidPrefix);
        }

        let announcement =
            Self::from_announcement_data_bytes(&value[ANNOUNCEMENT_MINIMAL_LENGTH..])?;

        Ok(announcement)
    }

    /// Convert the announcement message to bytes.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ANNOUNCEMENT_MINIMAL_LENGTH);

        bytes.extend_from_slice(&ANNOUNCEMENT_PREFIX);
        bytes.extend_from_slice(&self.kind());
        bytes.extend_from_slice(&self.to_announcement_data_bytes());

        bytes
    }
}

/// Error that can occur when parsing an `AnnouncementMessage` from bytes.
#[derive(Debug)]
pub enum AnnouncementParseError {
    /// The length of the message is too short to parse. See [`ANNOUNCEMENT_MINIMAL_LENGTH`].
    ShortLength,
    /// The [announcement prefix] is invalid.
    ///
    /// [announcement prefix]: ANNOUNCEMENT_PREFIX
    InvalidPrefix,
    /// The [announcement kind] is unknown.
    ///
    /// [announcement kind]: AnnouncementKind`
    UnknownAnnouncementKind,
    /// Failed to decode the announcement data.
    InvalidAnnouncementData(String),
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for AnnouncementParseError {}

impl fmt::Display for AnnouncementParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortLength => write!(
                f,
                "the announcement data is too short, it must be at least {} bytes",
                ANNOUNCEMENT_MINIMAL_LENGTH
            ),
            Self::InvalidPrefix => write!(
                f,
                "invalid LRC20 announcement prefix, expected {:?}",
                ANNOUNCEMENT_PREFIX
            ),
            Self::UnknownAnnouncementKind => {
                write!(f, "unknown announcement kind")
            }
            Self::InvalidAnnouncementData(e) => {
                write!(f, "failed to decode the announcement data: {}", e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::AnyAnnouncement;
    use crate::announcements::{AnnouncementKind, AnnouncementParseError};
    use alloc::vec;
    use alloc::vec::Vec;
    use bitcoin::ScriptBuf;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    struct TestAnnouncement(Vec<u8>);

    #[cfg_attr(feature = "serde", typetag::serde(name = "token_pubkey_announcement"))]
    impl AnyAnnouncement for TestAnnouncement {
        fn kind(&self) -> AnnouncementKind {
            [0xff, 0xff]
        }

        fn minimal_block_height(&self, _network: crate::network::Network) -> usize {
            0
        }

        fn from_announcement_data_bytes(data_raw: &[u8]) -> Result<Self, AnnouncementParseError> {
            Ok(Self(Vec::from(data_raw)))
        }

        fn to_announcement_data_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }
    }

    #[test]
    fn happy_path() {
        let bytes = [76, 82, 67, 50, 48, 0xff, 0xff, 0xaa, 0xbb, 0xcc];
        let result = TestAnnouncement::from_bytes(&bytes).unwrap();

        assert_eq!(result.kind(), [0xff, 0xff]);
        assert_eq!(result.to_bytes(), bytes.to_vec());
        assert_eq!(result.to_announcement_data_bytes(), vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(result.to_script(), ScriptBuf::new_op_return(bytes));
    }

    #[test]
    fn test_invalid_prefix() {
        let bytes = [76, 82, 67, 50, 49, 0xff, 0xff, 0xaa, 0xbb, 0xcc];
        let result = TestAnnouncement::from_bytes(&bytes);
        assert!(matches!(result, Err(AnnouncementParseError::InvalidPrefix)));
    }

    #[test]
    fn test_short_length() {
        let bytes = [76, 82, 67, 50, 48];
        let result = TestAnnouncement::from_bytes(&bytes);
        assert!(matches!(result, Err(AnnouncementParseError::ShortLength)));
    }
}
