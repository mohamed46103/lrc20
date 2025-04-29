use alloc::string::ToString;
use alloc::vec::Vec;
use bitcoin::{XOnlyPublicKey, key::constants::SCHNORR_PUBLIC_KEY_SIZE};

use core::fmt;
use core::mem::size_of;

use crate::{Announcement, AnyAnnouncement, network::Network};
use lrc20_receipts::{TOKEN_PUBKEY_SIZE, TokenPubkey, TokenPubkeyParseError};

#[cfg(feature = "consensus")]
use {
    crate::announcements::ANNOUNCEMENT_MINIMAL_LENGTH,
    bitcoin::{consensus, consensus::encode::Error as ConsensusError},
    core2::io,
};

use crate::announcements::{AnnouncementKind, AnnouncementParseError};

/// Two bytes that represent the [`IssueAnnouncement`]'s kind.
pub const ISSUE_ANNOUNCEMENT_KIND: AnnouncementKind = [0, 2];
/// The min size of issue announcement data in bytes.
pub const ISSUE_ANNOUNCEMENT_MIN_SIZE: usize = SCHNORR_PUBLIC_KEY_SIZE + size_of::<u128>();
/// The max size of issue announcement data in bytes.
pub const ISSUE_ANNOUNCEMENT_MAX_SIZE: usize = TOKEN_PUBKEY_SIZE + size_of::<u128>();

/// Issue announcement. This announcement is used to declare that in this transaction issuer has
/// issued tokens. The [Receipt proof] with exact amounts and address to whom the tokens are issued
/// should be provided to the LRC20 node.
///
/// # Structure
///
/// - `token_pubkey` - 32 bytes [`TokenPubkey`].
/// - `amount` - 16 bytes u128 amount of issued tokens in this transcation.
///
/// [Receipt proof]: lrc20_receipts::ReceiptProof
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IssueAnnouncement {
    /// TokenPubkey of the issued tokens.
    pub token_pubkey: TokenPubkey,
    /// The amount of issued tokens in this announcement.
    pub amount: u128,
}

impl IssueAnnouncement {
    /// Create a new issue announcement.
    pub fn new(token_pubkey: TokenPubkey, amount: u128) -> Self {
        Self {
            token_pubkey,
            amount,
        }
    }
}

#[cfg_attr(feature = "serde", typetag::serde(name = "issue_announcement"))]
impl AnyAnnouncement for IssueAnnouncement {
    fn kind(&self) -> AnnouncementKind {
        ISSUE_ANNOUNCEMENT_KIND
    }

    fn minimal_block_height(&self, _network: Network) -> usize {
        // For the default, innitial announcements, there is no minimal block height.
        0
    }

    fn from_announcement_data_bytes(data: &[u8]) -> Result<Self, AnnouncementParseError> {
        if data.len() < ISSUE_ANNOUNCEMENT_MIN_SIZE || data.len() > ISSUE_ANNOUNCEMENT_MAX_SIZE {
            return Err(IssueAnnouncementParseError::InvalidSize(data.len()))?;
        }

        let token_pubkey = match data.len() {
            ISSUE_ANNOUNCEMENT_MIN_SIZE => {
                let xonly = XOnlyPublicKey::from_slice(&data[..SCHNORR_PUBLIC_KEY_SIZE])
                    .map_err(|e| IssueAnnouncementParseError::InvalidTokenPubkey(e.into()))?;
                xonly.into()
            }
            _ => TokenPubkey::from_bytes(&data[..TOKEN_PUBKEY_SIZE])
                .map_err(IssueAnnouncementParseError::from)?,
        };

        let index = match data.len() {
            ISSUE_ANNOUNCEMENT_MIN_SIZE => SCHNORR_PUBLIC_KEY_SIZE,
            _ => TOKEN_PUBKEY_SIZE,
        };

        let amount = u128::from_le_bytes(data[index..].try_into().unwrap());

        Ok(Self {
            token_pubkey,
            amount,
        })
    }

    fn to_announcement_data_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ISSUE_ANNOUNCEMENT_MAX_SIZE);

        bytes.extend_from_slice(&self.token_pubkey.to_bytes());
        bytes.extend_from_slice(&self.amount.to_le_bytes());

        bytes
    }
}

#[cfg(feature = "consensus")]
impl consensus::Encodable for IssueAnnouncement {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        writer.write(&self.to_bytes())
    }
}

#[cfg(feature = "consensus")]
impl consensus::Decodable for IssueAnnouncement {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ConsensusError> {
        let mut buf = [0u8; ISSUE_ANNOUNCEMENT_MAX_SIZE + ANNOUNCEMENT_MINIMAL_LENGTH];
        reader.read_exact(&mut buf)?;

        let announcement = IssueAnnouncement::from_bytes(&buf)
            .map_err(|_| ConsensusError::Io(io::ErrorKind::InvalidData.into()))?;

        Ok(announcement)
    }
}

impl From<IssueAnnouncement> for Announcement {
    fn from(announcement: IssueAnnouncement) -> Self {
        Self::Issue(announcement)
    }
}

/// Errors that can occur when parsing [`IssueAnnouncement`].
#[derive(Debug)]
pub enum IssueAnnouncementParseError {
    InvalidSize(usize),
    InvalidTokenPubkey(TokenPubkeyParseError),
}

impl fmt::Display for IssueAnnouncementParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize(size) => write!(
                f,
                "invalid bytes size should be between {} and {}, got {}",
                ISSUE_ANNOUNCEMENT_MIN_SIZE, ISSUE_ANNOUNCEMENT_MAX_SIZE, size
            ),
            Self::InvalidTokenPubkey(e) => {
                write!(f, "invalid token_pubkey: {}", e)
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for IssueAnnouncementParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTokenPubkey(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TokenPubkeyParseError> for IssueAnnouncementParseError {
    fn from(err: TokenPubkeyParseError) -> Self {
        Self::InvalidTokenPubkey(err)
    }
}

impl From<IssueAnnouncementParseError> for AnnouncementParseError {
    fn from(err: IssueAnnouncementParseError) -> Self {
        AnnouncementParseError::InvalidAnnouncementData(err.to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::alloc::string::ToString;
    use crate::announcements::issue::{ISSUE_ANNOUNCEMENT_MAX_SIZE, ISSUE_ANNOUNCEMENT_MIN_SIZE};
    use crate::{
        Announcement, AnyAnnouncement,
        announcements::{
            AnnouncementParseError, IssueAnnouncement, announcement_from_bytes,
            announcement_from_script,
        },
    };
    use alloc::{format, string::String, vec, vec::Vec};
    use bitcoin::ScriptBuf;
    use lrc20_receipts::TokenPubkey;

    pub const TEST_TOKEN_PUBKEY: &str =
        "bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30";

    #[test]
    fn test_serialize_deserialize() {
        let test_announcements = vec![
            IssueAnnouncement {
                token_pubkey: TokenPubkey::from_address(TEST_TOKEN_PUBKEY, None)
                    .expect("valid token_pubkey"),
                amount: 10000,
            },
            IssueAnnouncement {
                token_pubkey: TokenPubkey::from_address(TEST_TOKEN_PUBKEY, None)
                    .expect("valid token_pubkey"),
                amount: 340282366920938463463374607431768211455,
            },
        ];

        for test_announcement in test_announcements {
            let data = test_announcement.to_announcement_data_bytes();

            match IssueAnnouncement::from_announcement_data_bytes(&data) {
                Ok(announcement) => {
                    assert_eq!(announcement, test_announcement);
                }
                Err(err) => {
                    panic!("Unexpected error: {}", err);
                }
            }

            let bytes = test_announcement.to_bytes();
            match IssueAnnouncement::from_bytes(&bytes) {
                Ok(announcement) => {
                    assert_eq!(announcement, test_announcement);
                    assert_eq!(Announcement::Issue(announcement).to_bytes(), bytes);
                }
                Err(err) => {
                    panic!("Unexpected error: {}", err);
                }
            }

            let announcement_script = test_announcement.to_script();
            match IssueAnnouncement::from_script(&announcement_script) {
                Ok(announcement) => {
                    assert_eq!(announcement, test_announcement);
                }
                Err(err) => {
                    panic!("Unexpected error: {}", err);
                }
            }

            match announcement_from_script(&announcement_script) {
                Ok(announcement) => {
                    assert_eq!(announcement, Announcement::Issue(test_announcement));
                    assert_eq!(announcement.to_script(), announcement_script);
                }
                Err(err) => {
                    panic!("Unexpected error: {}", err);
                }
            }
        }
    }

    #[test]
    fn parse_invalid_bytes() {
        struct TestData {
            bytes: Vec<u8>,
            err: String,
        }

        let test_vector = vec![
            TestData {
                bytes: vec![0],
                err: format!(
                    "invalid bytes size should be between {} and {}, got {}",
                    ISSUE_ANNOUNCEMENT_MIN_SIZE, ISSUE_ANNOUNCEMENT_MAX_SIZE, 1
                )
                .to_string(),
            },
            TestData {
                bytes: vec![0; ISSUE_ANNOUNCEMENT_MAX_SIZE],
                err: "invalid token_pubkey: Invalid public key structure: malformed public key"
                    .to_string(),
            },
        ];

        for test in test_vector {
            match IssueAnnouncement::from_announcement_data_bytes(&test.bytes) {
                Err(AnnouncementParseError::InvalidAnnouncementData(err)) => {
                    assert_eq!(err, test.err);
                }
                err => {
                    panic!("Unexpected result: {:?}", err);
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn test_backward_compatibility() {
        struct TestData {
            bytes: Vec<u8>,
            data_bytes: Vec<u8>,
            script: ScriptBuf,
        }

        let valid_announcements = vec![
            TestData {
                bytes: vec![76, 82, 67, 50, 48, 0, 2, 197, 21, 190, 150, 71, 80, 78, 148, 191, 220, 32, 196, 98, 152, 67, 216, 14, 226, 119, 119, 176, 101, 194, 175, 121, 250, 151, 204, 14, 255, 74, 35, 16, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                data_bytes: vec![113, 128, 188, 163, 232, 82, 234, 249, 5, 150, 157, 37, 7, 70, 36, 152, 160, 25, 195, 239, 213, 68, 75, 114, 164, 41, 27, 114, 180, 221, 38, 204, 16, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                script: ScriptBuf::from_hex("6a3579757600027180bca3e852eaf905969d2507462498a019c3efd5444b72a4291b72b4dd26cc10270000000000000000000000000000").unwrap(),
            },
            TestData {
                bytes: vec![76, 82, 67, 50, 48, 0, 2, 113, 128, 188, 163, 232, 82, 234, 249, 5, 150, 157, 37, 7, 70, 36, 152, 160, 25, 195, 239, 213, 68, 75, 114, 164, 41, 27, 114, 180, 221, 38, 204, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
                data_bytes: vec![113, 128, 188, 163, 232, 82, 234, 249, 5, 150, 157, 37, 7, 70, 36, 152, 160, 25, 195, 239, 213, 68, 75, 114, 164, 41, 27, 114, 180, 221, 38, 204, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255],
                script: ScriptBuf::from_hex("6a3579757600027180bca3e852eaf905969d2507462498a019c3efd5444b72a4291b72b4dd26ccffffffffffffffffffffffffffffffff").unwrap(),
            },
        ];

        for announcement in valid_announcements {
            assert!(announcement_from_script(&announcement.script).is_ok());
            assert!(announcement_from_bytes(&announcement.bytes).is_ok());
            assert!(IssueAnnouncement::from_bytes(&announcement.bytes).is_ok());
            assert!(
                IssueAnnouncement::from_announcement_data_bytes(&announcement.data_bytes).is_ok()
            );
            assert!(IssueAnnouncement::from_script(&announcement.script).is_ok());
        }
    }
}
