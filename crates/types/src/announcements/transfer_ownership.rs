use crate::{Announcement, AnyAnnouncement, network::Network};
use alloc::string::ToString;
use alloc::vec::Vec;
use bitcoin::{
    ScriptBuf, XOnlyPublicKey, consensus::encode, key::constants::SCHNORR_PUBLIC_KEY_SIZE,
};

use core::fmt;

use lrc20_receipts::{TOKEN_PUBKEY_SIZE, TokenPubkey, TokenPubkeyParseError};

use crate::announcements::{AnnouncementKind, AnnouncementParseError};

const MAINNET_MINIMAL_BLOCK: usize = 855_000;
const TESTNET_MINIMAL_BLOCK: usize = 2_830_000;
const MUTINY_MINIMAL_BLOCK: usize = 1_200_000;

/// Two bytes that represent the [`TransferOwnershipAnnouncement`]'s kind.
pub const TRANSFER_OWNERSHIP_ANNOUNCEMENT_KIND: AnnouncementKind = [0, 3];
/// Maximum script length in bytes, which is restricted by maximum `OP_RETURN` data size.
pub const MAX_SCRIPT_SIZE: usize = 48;
pub const MIN_SCRIPT_SIZE: usize = 16;
/// The max size of transfer ownership announcement data in bytes.
pub const TRANSFER_OWNERSHIP_ANNOUNCEMENT_MAX_SIZE: usize = TOKEN_PUBKEY_SIZE + MAX_SCRIPT_SIZE;
/// The min size of transfer ownership announcement data in bytes.
pub const TRANSFER_OWNERSHIP_ANNOUNCEMENT_MIN_SIZE: usize =
    SCHNORR_PUBLIC_KEY_SIZE + MIN_SCRIPT_SIZE;

/// Transfer ownership announcement from the current owner of the token_pubkey. It contains the token_pubkey
/// itself and the new owner.
///
/// # Structure
///
/// - `token_pubkey` - 32 bytes [`TokenPubkey`].
/// - `script` - 16 to 48 bytes [`ScriptBuf`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransferOwnershipAnnouncement {
    /// The token's [`TokenPubkey`].
    pub token_pubkey: TokenPubkey,
    /// New owner's Bitcoin address.
    pub new_owner: ScriptBuf,
}

impl TransferOwnershipAnnouncement {
    /// Create a new [`TransferOwnershipAnnouncement`].
    pub fn new(token_pubkey: TokenPubkey, new_owner: ScriptBuf) -> Self {
        Self {
            token_pubkey,
            new_owner,
        }
    }
}

#[cfg_attr(
    feature = "serde",
    typetag::serde(name = "transfer_ownership_announcement")
)]
impl AnyAnnouncement for TransferOwnershipAnnouncement {
    fn kind(&self) -> AnnouncementKind {
        TRANSFER_OWNERSHIP_ANNOUNCEMENT_KIND
    }

    fn minimal_block_height(&self, network: Network) -> usize {
        match network {
            Network::Bitcoin => MAINNET_MINIMAL_BLOCK,
            Network::Testnet => TESTNET_MINIMAL_BLOCK,
            Network::Mutiny => MUTINY_MINIMAL_BLOCK,
            _ => 0,
        }
    }

    fn from_announcement_data_bytes(data: &[u8]) -> Result<Self, AnnouncementParseError> {
        use TransferOwnershipAnnouncementParseError as Error;

        if data.len() < TRANSFER_OWNERSHIP_ANNOUNCEMENT_MIN_SIZE
            || data.len() > TRANSFER_OWNERSHIP_ANNOUNCEMENT_MAX_SIZE
        {
            return Err(Error::InvalidSize(data.len()))?;
        }

        let token_pubkey = TokenPubkey::from_bytes(&data[TOKEN_PUBKEY_SIZE..])
            .map_err(TransferOwnershipAnnouncementParseError::from)?;

        let index = TOKEN_PUBKEY_SIZE;

        let new_owner = ScriptBuf::from_bytes((data[index..]).to_vec());

        Ok(Self {
            token_pubkey,
            new_owner,
        })
    }

    fn to_announcement_data_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TRANSFER_OWNERSHIP_ANNOUNCEMENT_MAX_SIZE);

        bytes.extend_from_slice(&self.token_pubkey.to_bytes());
        bytes.extend_from_slice(&self.new_owner.to_bytes());

        bytes
    }
}

impl From<TransferOwnershipAnnouncement> for Announcement {
    fn from(value: TransferOwnershipAnnouncement) -> Self {
        Self::TransferOwnership(value)
    }
}

/// Errors that can occur when parsing [`TransferOwnershipAnnouncement`].
#[derive(Debug)]
pub enum TransferOwnershipAnnouncementParseError {
    InvalidSize(usize),
    InvalidTokenPubkey(TokenPubkeyParseError),
    MalformedScript(encode::Error),
}

impl fmt::Display for TransferOwnershipAnnouncementParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize(size) => write!(
                f,
                "invalid bytes size, should be between {} and {}, got {}",
                TRANSFER_OWNERSHIP_ANNOUNCEMENT_MIN_SIZE,
                TRANSFER_OWNERSHIP_ANNOUNCEMENT_MAX_SIZE,
                size
            ),
            Self::InvalidTokenPubkey(e) => {
                write!(f, "invalid token_pubkey: {}", e)
            }
            Self::MalformedScript(e) => {
                write!(f, "invalid script: {}", e)
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for TransferOwnershipAnnouncementParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTokenPubkey(e) => Some(e),
            Self::MalformedScript(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TokenPubkeyParseError> for TransferOwnershipAnnouncementParseError {
    fn from(err: TokenPubkeyParseError) -> Self {
        Self::InvalidTokenPubkey(err)
    }
}

impl From<encode::Error> for TransferOwnershipAnnouncementParseError {
    fn from(err: encode::Error) -> Self {
        Self::MalformedScript(err)
    }
}

impl From<TransferOwnershipAnnouncementParseError> for AnnouncementParseError {
    fn from(err: TransferOwnershipAnnouncementParseError) -> Self {
        AnnouncementParseError::InvalidAnnouncementData(err.to_string())
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use crate::alloc::string::ToString;
    use crate::announcements::transfer_ownership::{
        TRANSFER_OWNERSHIP_ANNOUNCEMENT_MAX_SIZE, TRANSFER_OWNERSHIP_ANNOUNCEMENT_MIN_SIZE,
    };
    use crate::{
        Announcement, AnyAnnouncement,
        announcements::{
            AnnouncementParseError, announcement_from_bytes, announcement_from_script,
        },
    };
    use alloc::{format, string::String, vec, vec::Vec};
    use bitcoin::Address;
    use bitcoin::ScriptBuf;
    use lrc20_receipts::TokenPubkey;

    use super::TransferOwnershipAnnouncement;

    pub const TEST_TOKEN_PUBKEY: &str =
        "bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30";

    pub const TEST_ADDRESS: &str = "bcrt1qcq5d37t5mve6uyzkjugn58magc6shkdys0xvnc";

    #[test]
    #[ignore]
    fn test_serialize_deserialize() {
        let token_pubkey =
            TokenPubkey::from_address(TEST_TOKEN_PUBKEY, None).expect("valid token_pubkey");
        let address = Address::from_str(TEST_ADDRESS)
            .expect("valid address")
            .assume_checked();
        let test_announcements = vec![TransferOwnershipAnnouncement {
            token_pubkey,
            new_owner: address.script_pubkey(),
        }];

        for test_announcement in test_announcements {
            let data = test_announcement.to_announcement_data_bytes();

            match TransferOwnershipAnnouncement::from_announcement_data_bytes(&data) {
                Ok(announcement) => {
                    assert_eq!(announcement, test_announcement);
                }
                Err(err) => {
                    panic!("Unexpected error: {}", err);
                }
            }

            let bytes = test_announcement.to_bytes();
            match TransferOwnershipAnnouncement::from_bytes(&bytes) {
                Ok(announcement) => {
                    assert_eq!(announcement, test_announcement);
                    assert_eq!(
                        Announcement::TransferOwnership(announcement).to_bytes(),
                        bytes
                    );
                }
                Err(err) => {
                    panic!("Unexpected error: {}", err);
                }
            }

            let announcement_script = test_announcement.to_script();
            match TransferOwnershipAnnouncement::from_script(&announcement_script) {
                Ok(announcement) => {
                    assert_eq!(announcement, test_announcement);
                }
                Err(err) => {
                    panic!("Unexpected error: {}", err);
                }
            }

            match announcement_from_script(&announcement_script) {
                Ok(announcement) => {
                    assert_eq!(
                        announcement,
                        Announcement::TransferOwnership(test_announcement)
                    );
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
                bytes: vec![0; TRANSFER_OWNERSHIP_ANNOUNCEMENT_MAX_SIZE],
                err: "invalid token_pubkey: Invalid public key structure: malformed public key"
                    .to_string(),
            },
            TestData {
                bytes: vec![0; TRANSFER_OWNERSHIP_ANNOUNCEMENT_MIN_SIZE - 1],
                err: format!(
                    "invalid bytes size, should be between {} and {}, got 47",
                    TRANSFER_OWNERSHIP_ANNOUNCEMENT_MIN_SIZE,
                    TRANSFER_OWNERSHIP_ANNOUNCEMENT_MAX_SIZE
                ),
            },
        ];

        for test in test_vector {
            match TransferOwnershipAnnouncement::from_announcement_data_bytes(&test.bytes) {
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
            // P2TR
            TestData {
                bytes: vec![76, 82, 67, 50, 48, 0, 3, 134, 176, 11, 134, 121, 220, 117, 255, 91, 28, 201, 237, 47, 160, 124, 88, 120, 11, 14, 139, 75, 122, 51, 78, 71, 14, 46, 163, 249, 253, 0, 95, 81, 32, 163, 124, 57, 3, 200, 208, 219, 101, 18, 226, 180, 11, 13, 255, 160, 94, 90, 58, 183, 54, 3, 206, 140, 156, 75, 119, 113, 229, 65, 35, 40, 249],
                data_bytes: vec![134, 176, 11, 134, 121, 220, 117, 255, 91, 28, 201, 237, 47, 160, 124, 88, 120, 11, 14, 139, 75, 122, 51, 78, 71, 14, 46, 163, 249, 253, 0, 95, 81, 32, 163, 124, 57, 3, 200, 208, 219, 101, 18, 226, 180, 11, 13, 255, 160, 94, 90, 58, 183, 54, 3, 206, 140, 156, 75, 119, 113, 229, 65, 35, 40, 249],
                script: ScriptBuf::from_hex("6a47797576000386b00b8679dc75ff5b1cc9ed2fa07c58780b0e8b4b7a334e470e2ea3f9fd005f5120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f9").unwrap(),
            },
            // P2WPKH
            TestData {
                bytes: vec![76, 82, 67, 50, 48, 0, 3, 134, 176, 11, 134, 121, 220, 117, 255, 91, 28, 201, 237, 47, 160, 124, 88, 120, 11, 14, 139, 75, 122, 51, 78, 71, 14, 46, 163, 249, 253, 0, 95, 0, 20, 232, 223, 1, 140, 126, 50, 108, 194, 83, 250, 172, 126, 70, 205, 197, 30, 104, 84, 44, 66],
                data_bytes: vec![134, 176, 11, 134, 121, 220, 117, 255, 91, 28, 201, 237, 47, 160, 124, 88, 120, 11, 14, 139, 75, 122, 51, 78, 71, 14, 46, 163, 249, 253, 0, 95, 0, 20, 232, 223, 1, 140, 126, 50, 108, 194, 83, 250, 172, 126, 70, 205, 197, 30, 104, 84, 44, 66],
                script: ScriptBuf::from_hex("6a3b797576000386b00b8679dc75ff5b1cc9ed2fa07c58780b0e8b4b7a334e470e2ea3f9fd005f0014e8df018c7e326cc253faac7e46cdc51e68542c42").unwrap(),
            },
            // P2SH
            TestData {
                bytes: vec![76, 82, 67, 50, 48, 0, 3, 134, 176, 11, 134, 121, 220, 117, 255, 91, 28, 201, 237, 47, 160, 124, 88, 120, 11, 14, 139, 75, 122, 51, 78, 71, 14, 46, 163, 249, 253, 0, 95, 0, 32, 205, 191, 144, 158, 147, 92, 133, 93, 62, 141, 27, 97, 174, 185, 197, 227, 192, 58, 232, 2, 27, 40, 104, 57, 177, 167, 47, 46, 72, 253, 186, 112],
                data_bytes: vec![134, 176, 11, 134, 121, 220, 117, 255, 91, 28, 201, 237, 47, 160, 124, 88, 120, 11, 14, 139, 75, 122, 51, 78, 71, 14, 46, 163, 249, 253, 0, 95, 0, 32, 205, 191, 144, 158, 147, 92, 133, 93, 62, 141, 27, 97, 174, 185, 197, 227, 192, 58, 232, 2, 27, 40, 104, 57, 177, 167, 47, 46, 72, 253, 186, 112],
                script: ScriptBuf::from_hex("6a47797576000386b00b8679dc75ff5b1cc9ed2fa07c58780b0e8b4b7a334e470e2ea3f9fd005f0020cdbf909e935c855d3e8d1b61aeb9c5e3c03ae8021b286839b1a72f2e48fdba70").unwrap(),
            },
        ];

        for announcement in valid_announcements {
            assert!(announcement_from_script(&announcement.script).is_ok());
            assert!(announcement_from_bytes(&announcement.bytes).is_ok());
            assert!(TransferOwnershipAnnouncement::from_bytes(&announcement.bytes).is_ok());
            assert!(
                TransferOwnershipAnnouncement::from_announcement_data_bytes(
                    &announcement.data_bytes
                )
                .is_ok()
            );
            assert!(TransferOwnershipAnnouncement::from_script(&announcement.script).is_ok());
        }
    }
}
