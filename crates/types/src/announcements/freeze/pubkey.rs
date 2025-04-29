use alloc::{string::ToString, vec::Vec};
use bitcoin::key::constants::PUBLIC_KEY_SIZE;
use bitcoin::secp256k1::{self, PublicKey};

use core::fmt;
use lrc20_receipts::{TOKEN_PUBKEY_SIZE, TokenPubkey, TokenPubkeyParseError};

use crate::{Announcement, AnyAnnouncement, network::Network};

use crate::announcements::{AnnouncementKind, AnnouncementParseError};

/// The two bytes that represent the [`pubkey freeze announcement`]'s kind.
///
/// [`pubkey freeze announcement`]: PubkeyFreezeAnnouncement
pub const PUBKEY_FREEZE_ANNOUNCEMENT_KIND: AnnouncementKind = [0, 5];
/// Size of public key in bytes.
const PUBKEY_SIZE: usize = PUBLIC_KEY_SIZE;
/// Size of freeze entry in bytes.
pub const PUBKEY_FREEZE_ENTRY_SIZE: usize = PUBKEY_SIZE + TOKEN_PUBKEY_SIZE;

/// Pubkey freeze announcement. It appears when issuer declares that pubkey is frozen or unfrozen.
///
/// # Structure
///
/// - `pubkey` - 33 bytes [`PublicKey`] of the frozen or unfrozen pubkey.
/// - `token_pubkey` - 32 bytes [`TokenPubkey`].
///
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PubkeyFreezeAnnouncement {
    /// The token_pubkey to freeze or unfreeze.
    pub token_pubkey: TokenPubkey,
    /// The pubkey that is frozen or unfrozen.
    pub pubkey: PublicKey,
}

impl PubkeyFreezeAnnouncement {
    /// Create a new freeze announcement.
    pub fn new(token_pubkey: TokenPubkey, pubkey: PublicKey) -> Self {
        Self {
            token_pubkey,
            pubkey,
        }
    }

    /// Return the pubkey of the freeze announcement.
    pub fn freeze_pubkey(&self) -> PublicKey {
        self.pubkey
    }
}

#[cfg_attr(feature = "serde", typetag::serde(name = "freeze_announcement"))]
impl AnyAnnouncement for PubkeyFreezeAnnouncement {
    fn kind(&self) -> AnnouncementKind {
        PUBKEY_FREEZE_ANNOUNCEMENT_KIND
    }

    fn minimal_block_height(&self, _network: Network) -> usize {
        // For the default, innitial announcements, there is no minimal block height.
        0
    }

    fn from_announcement_data_bytes(data: &[u8]) -> Result<Self, AnnouncementParseError> {
        if data.len() != PUBKEY_FREEZE_ENTRY_SIZE {
            return Err(PubkeyFreezeAnnouncementParseError::InvalidSize(data.len()))?;
        }

        let pubkey = PublicKey::from_slice(&data[..PUBLIC_KEY_SIZE])
            .map_err(PubkeyFreezeAnnouncementParseError::InvalidPublicKey)?;

        let token_pubkey = TokenPubkey::from_bytes(&data[PUBLIC_KEY_SIZE..])
            .map_err(PubkeyFreezeAnnouncementParseError::from)?;

        Ok(Self {
            token_pubkey,
            pubkey,
        })
    }

    fn to_announcement_data_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PUBKEY_FREEZE_ENTRY_SIZE);

        bytes.extend_from_slice(&self.pubkey.serialize());
        bytes.extend_from_slice(&self.token_pubkey.to_bytes());

        bytes
    }
}

impl From<PubkeyFreezeAnnouncement> for Announcement {
    fn from(freeze_announcement: PubkeyFreezeAnnouncement) -> Self {
        Self::PubkeyFreeze(freeze_announcement)
    }
}

/// Errors that can occur when parsing [pubkey freeze announcement].
///
/// [pubkey freeze announcement]: PubkeyFreezeAnnouncement
#[derive(Debug)]
pub enum PubkeyFreezeAnnouncementParseError {
    InvalidSize(usize),
    InvalidPublicKey(secp256k1::Error),
    InvalidTokenPubkey(TokenPubkeyParseError),
}

impl fmt::Display for PubkeyFreezeAnnouncementParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PubkeyFreezeAnnouncementParseError::InvalidSize(size) => write!(
                f,
                "invalid bytes size should be {}, got {}",
                PUBKEY_FREEZE_ENTRY_SIZE, size
            ),
            PubkeyFreezeAnnouncementParseError::InvalidPublicKey(e) => {
                write!(f, "invalid public key: {}", e)
            }
            PubkeyFreezeAnnouncementParseError::InvalidTokenPubkey(e) => {
                write!(f, "invalid token_pubkey: {}", e)
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for PubkeyFreezeAnnouncementParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PubkeyFreezeAnnouncementParseError::InvalidPublicKey(e) => Some(e),
            _ => None,
        }
    }
}

impl From<secp256k1::Error> for PubkeyFreezeAnnouncementParseError {
    fn from(err: secp256k1::Error) -> Self {
        Self::InvalidPublicKey(err)
    }
}

impl From<TokenPubkeyParseError> for PubkeyFreezeAnnouncementParseError {
    fn from(err: TokenPubkeyParseError) -> Self {
        Self::InvalidTokenPubkey(err)
    }
}

impl From<PubkeyFreezeAnnouncementParseError> for AnnouncementParseError {
    fn from(err: PubkeyFreezeAnnouncementParseError) -> Self {
        AnnouncementParseError::InvalidAnnouncementData(err.to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::announcements::freeze::pubkey::PUBKEY_FREEZE_ENTRY_SIZE;
    use crate::announcements::{
        AnnouncementParseError, PubkeyFreezeAnnouncement, announcement_from_bytes,
        announcement_from_script,
    };
    use crate::{Announcement, AnyAnnouncement};
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use alloc::{format, vec};
    use bitcoin::ScriptBuf;
    use bitcoin::secp256k1::PublicKey;
    use core::str::FromStr;
    use lrc20_receipts::TokenPubkey;
    use once_cell::sync::Lazy;

    static PUBKEY: Lazy<PublicKey> = Lazy::new(|| {
        PublicKey::from_str("020677b5829356bb5e0c0808478ac150a500ceab4894d09854b0f75fbe7b4162f8")
            .expect("Should be valid address")
    });
    pub const TEST_TOKEN_PUBKEY: &str =
        "bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30";

    #[test]
    fn test_serialize_deserialize() {
        let token_pubkey =
            TokenPubkey::from_address(TEST_TOKEN_PUBKEY, None).expect("valid token_pubkey");

        let announcement = PubkeyFreezeAnnouncement {
            token_pubkey,
            pubkey: *PUBKEY,
        };

        let data_bytes = announcement.to_announcement_data_bytes();
        let parsed_announcement =
            PubkeyFreezeAnnouncement::from_announcement_data_bytes(&data_bytes).unwrap();
        assert_eq!(announcement, parsed_announcement);
        assert_eq!(parsed_announcement.freeze_pubkey(), *PUBKEY);

        let announcement_script = announcement.to_script();
        let parsed_announcement =
            PubkeyFreezeAnnouncement::from_script(&announcement_script).unwrap();
        assert_eq!(announcement, parsed_announcement);
        assert_eq!(parsed_announcement.freeze_pubkey(), *PUBKEY);

        let parsed_announcement = announcement_from_script(&announcement_script).unwrap();
        assert_eq!(
            Announcement::PubkeyFreeze(announcement),
            parsed_announcement
        );
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
                    "invalid bytes size should be {}, got 1",
                    PUBKEY_FREEZE_ENTRY_SIZE
                )
                .to_string(),
            },
            TestData {
                bytes: vec![0; 37],
                err: format!(
                    "invalid bytes size should be {}, got 37",
                    PUBKEY_FREEZE_ENTRY_SIZE
                )
                .to_string(),
            },
        ];

        for test in test_vector {
            match PubkeyFreezeAnnouncement::from_announcement_data_bytes(&test.bytes) {
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
        let valid_announcement_bytes = vec![
            76, 82, 67, 50, 48, 0, 5, 2, 6, 119, 181, 130, 147, 86, 187, 94, 12, 8, 8, 71, 138,
            193, 80, 165, 0, 206, 171, 72, 148, 208, 152, 84, 176, 247, 95, 190, 123, 65, 98, 248,
            2, 171, 40, 211, 47, 226, 24, 211, 203, 83, 211, 48, 226, 221, 33, 219, 91, 50, 218,
            251, 159, 197, 41, 108, 66, 209, 125, 203, 28, 214, 59, 234, 178,
        ];

        let valid_announcement_data = vec![
            2, 6, 119, 181, 130, 147, 86, 187, 94, 12, 8, 8, 71, 138, 193, 80, 165, 0, 206, 171,
            72, 148, 208, 152, 84, 176, 247, 95, 190, 123, 65, 98, 248, 2, 171, 40, 211, 47, 226,
            24, 211, 203, 83, 211, 48, 226, 221, 33, 219, 91, 50, 218, 251, 159, 197, 41, 108, 66,
            209, 125, 203, 28, 214, 59, 234, 178,
        ];

        let valid_announcement_script = ScriptBuf::from_hex("6a477975760005020677b5829356bb5e0c0808478ac150a500ceab4894d09854b0f75fbe7b4162f802ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab2").unwrap();

        assert!(announcement_from_script(&valid_announcement_script).is_ok());
        assert!(announcement_from_bytes(&valid_announcement_bytes).is_ok());
        assert!(PubkeyFreezeAnnouncement::from_bytes(&valid_announcement_bytes).is_ok());
        assert!(
            PubkeyFreezeAnnouncement::from_announcement_data_bytes(&valid_announcement_data)
                .is_ok()
        );
        assert!(PubkeyFreezeAnnouncement::from_script(&valid_announcement_script).is_ok());
    }
}
