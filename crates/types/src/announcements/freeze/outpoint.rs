use alloc::{string::ToString, vec::Vec};
use bitcoin::key::constants::SCHNORR_PUBLIC_KEY_SIZE;

use core::fmt;
use core::mem::size_of;
use lrc20_receipts::{TOKEN_PUBKEY_SIZE, TokenPubkey, TokenPubkeyParseError};

use crate::{Announcement, AnyAnnouncement, network::Network};
use bitcoin::hashes::{FromSliceError, Hash};
use bitcoin::{OutPoint, Txid, XOnlyPublicKey};

use crate::announcements::{AnnouncementKind, AnnouncementParseError};

/// The two bytes that represent the [`tx freeze announcement`]'s kind.
///
/// [`tx freeze announcement`]: TxFreezeAnnouncement
pub const TX_FREEZE_ANNOUNCEMENT_KIND: AnnouncementKind = [0, 1];
/// Size of txid in bytes.
const TX_ID_SIZE: usize = size_of::<Txid>();
/// Size of vout in bytes.
const VOUT_SIZE: usize = size_of::<u32>();
/// Min size of freeze entry in bytes.
pub const FREEZE_ENTRY_MIN_SIZE: usize = TX_ID_SIZE + VOUT_SIZE + SCHNORR_PUBLIC_KEY_SIZE;
/// Max size of freeze entry in bytes.
pub const FREEZE_ENTRY_MAX_SIZE: usize = TX_ID_SIZE + VOUT_SIZE + TOKEN_PUBKEY_SIZE;

/// Tx freeze announcement. It appears when issuer declares that tx is frozen or unfrozen.
///
/// # Structure
///
/// - `txid` - 32 bytes [`Txid`] of the frozen or unfrozen transaction.
/// - `vout` - 4 bytes u32 number of the transaction's output that is frozen or unfrozen.
/// - `token_pubkey` - 32 bytes [`TokenPubkey`].
///
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TxFreezeAnnouncement {
    /// The token_pubkey to freeze or unfreeze.
    pub token_pubkey: TokenPubkey,
    /// The outpoint of the transaction that is frozen or unfrozen.
    pub outpoint: OutPoint,
}

impl TxFreezeAnnouncement {
    /// Create a new freeze announcement.
    pub fn new(token_pubkey: TokenPubkey, outpoint: OutPoint) -> Self {
        Self {
            token_pubkey,
            outpoint,
        }
    }

    /// Return the transaction id of the frozen or unfrozen transaction.
    pub fn freeze_txid(&self) -> Txid {
        self.outpoint.txid
    }

    /// Return the vout of the frozen or unfrozen transaction.
    pub fn freeze_vout(&self) -> u32 {
        self.outpoint.vout
    }

    /// Return the outpoint of the frozen or unfrozen transaction.
    pub fn freeze_outpoint(&self) -> OutPoint {
        self.outpoint
    }
}

#[cfg_attr(feature = "serde", typetag::serde(name = "freeze_announcement"))]
impl AnyAnnouncement for TxFreezeAnnouncement {
    fn kind(&self) -> AnnouncementKind {
        TX_FREEZE_ANNOUNCEMENT_KIND
    }

    fn minimal_block_height(&self, _network: Network) -> usize {
        // For the default, innitial announcements, there is no minimal block height.
        0
    }

    fn from_announcement_data_bytes(data: &[u8]) -> Result<Self, AnnouncementParseError> {
        if data.len() < FREEZE_ENTRY_MIN_SIZE || data.len() > FREEZE_ENTRY_MAX_SIZE {
            return Err(FreezeAnnouncementParseError::InvalidSize(data.len()))?;
        }

        let txid = Txid::from_slice(&data[..TX_ID_SIZE])
            .map_err(FreezeAnnouncementParseError::InvalidTxHash)?;
        let vout = u32::from_be_bytes(
            data[TX_ID_SIZE..TX_ID_SIZE + VOUT_SIZE]
                .try_into()
                .expect("Size is checked"),
        );

        let outpoint = OutPoint::new(txid, vout);
        let token_pubkey_bytes = &data[TX_ID_SIZE + VOUT_SIZE..];

        let token_pubkey = match token_pubkey_bytes.len() {
            TOKEN_PUBKEY_SIZE => TokenPubkey::from_bytes(token_pubkey_bytes)
                .map_err(FreezeAnnouncementParseError::from)?,
            _ => {
                let xonly = XOnlyPublicKey::from_slice(token_pubkey_bytes).map_err(|e| {
                    FreezeAnnouncementParseError::InvalidTokenPubkey(
                        TokenPubkeyParseError::InvalidPublicKey(e),
                    )
                })?;

                TokenPubkey::from(xonly)
            }
        };

        Ok(Self {
            token_pubkey,
            outpoint,
        })
    }

    fn to_announcement_data_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FREEZE_ENTRY_MAX_SIZE);

        bytes.extend_from_slice(&self.outpoint.txid[..]);
        bytes.extend_from_slice(&self.outpoint.vout.to_be_bytes());
        bytes.extend_from_slice(&self.token_pubkey.to_bytes());

        bytes
    }
}

impl From<TxFreezeAnnouncement> for Announcement {
    fn from(freeze_announcement: TxFreezeAnnouncement) -> Self {
        Self::TxFreeze(freeze_announcement)
    }
}

/// Errors that can occur when parsing [tx freeze announcement].
///
/// [tx freeze announcement]: TxFreezeAnnouncement
#[derive(Debug)]
pub enum FreezeAnnouncementParseError {
    InvalidSize(usize),
    InvalidTxHash(FromSliceError),
    InvalidTokenPubkey(TokenPubkeyParseError),
}

impl fmt::Display for FreezeAnnouncementParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FreezeAnnouncementParseError::InvalidSize(size) => write!(
                f,
                "invalid bytes size should be between {} and {}, got {}",
                FREEZE_ENTRY_MIN_SIZE, FREEZE_ENTRY_MAX_SIZE, size
            ),
            FreezeAnnouncementParseError::InvalidTxHash(e) => write!(f, "invalid tx hash: {}", e),
            FreezeAnnouncementParseError::InvalidTokenPubkey(e) => {
                write!(f, "invalid token_pubkey: {}", e)
            }
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for FreezeAnnouncementParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidTxHash(e) => Some(e),
            _ => None,
        }
    }
}

impl From<FromSliceError> for FreezeAnnouncementParseError {
    fn from(err: FromSliceError) -> Self {
        Self::InvalidTxHash(err)
    }
}

impl From<TokenPubkeyParseError> for FreezeAnnouncementParseError {
    fn from(err: TokenPubkeyParseError) -> Self {
        Self::InvalidTokenPubkey(err)
    }
}

impl From<FreezeAnnouncementParseError> for AnnouncementParseError {
    fn from(err: FreezeAnnouncementParseError) -> Self {
        AnnouncementParseError::InvalidAnnouncementData(err.to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::announcements::freeze::outpoint::{FREEZE_ENTRY_MAX_SIZE, FREEZE_ENTRY_MIN_SIZE};
    use crate::announcements::{
        AnnouncementParseError, TxFreezeAnnouncement, announcement_from_bytes,
        announcement_from_script,
    };
    use crate::{Announcement, AnyAnnouncement};
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use alloc::{format, vec};
    use bitcoin::{OutPoint, ScriptBuf, Txid};
    use core::str::FromStr;
    use lrc20_receipts::TokenPubkey;

    pub const TEST_TXID: &str = "abc0000000000000000000000000000000000000000000000000000000000abc";
    pub const TEST_TOKEN_PUBKEY: &str =
        "bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30";

    #[test]
    fn test_serialize_deserialize() {
        let outpoint = OutPoint {
            txid: Txid::from_str(TEST_TXID).unwrap(),
            vout: 34,
        };

        let token_pubkey =
            TokenPubkey::from_address(TEST_TOKEN_PUBKEY, None).expect("valid token_pubkey");

        let announcement = TxFreezeAnnouncement {
            token_pubkey,
            outpoint,
        };

        let data_bytes = announcement.to_announcement_data_bytes();
        let parsed_announcement =
            TxFreezeAnnouncement::from_announcement_data_bytes(&data_bytes).unwrap();
        assert_eq!(announcement, parsed_announcement);
        assert_eq!(parsed_announcement.freeze_outpoint(), outpoint);

        let announcement_script = announcement.to_script();
        let parsed_announcement = TxFreezeAnnouncement::from_script(&announcement_script).unwrap();
        assert_eq!(announcement, parsed_announcement);
        assert_eq!(parsed_announcement.freeze_outpoint(), outpoint);

        let parsed_announcement = announcement_from_script(&announcement_script).unwrap();
        assert_eq!(Announcement::TxFreeze(announcement), parsed_announcement);
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
                    "invalid bytes size should be between {} and {}, got 1",
                    FREEZE_ENTRY_MIN_SIZE, FREEZE_ENTRY_MAX_SIZE
                )
                .to_string(),
            },
            TestData {
                bytes: vec![0; 37],
                err: format!(
                    "invalid bytes size should be between {} and {}, got 37",
                    FREEZE_ENTRY_MIN_SIZE, FREEZE_ENTRY_MAX_SIZE
                )
                .to_string(),
            },
        ];

        for test in test_vector {
            match TxFreezeAnnouncement::from_announcement_data_bytes(&test.bytes) {
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
            76, 82, 67, 50, 48, 0, 1, 30, 105, 39, 50, 167, 221, 11, 231, 199, 76, 22, 97, 187,
            166, 121, 234, 176, 1, 231, 117, 202, 135, 70, 12, 206, 237, 42, 74, 39, 232, 113, 36,
            0, 0, 0, 1, 134, 176, 11, 134, 121, 220, 117, 255, 91, 28, 201, 237, 47, 160, 124, 88,
            120, 11, 14, 139, 75, 122, 51, 78, 71, 14, 46, 163, 249, 253, 0, 95,
        ];

        let valid_announcement_data = vec![
            30, 105, 39, 50, 167, 221, 11, 231, 199, 76, 22, 97, 187, 166, 121, 234, 176, 1, 231,
            117, 202, 135, 70, 12, 206, 237, 42, 74, 39, 232, 113, 36, 0, 0, 0, 1, 134, 176, 11,
            134, 121, 220, 117, 255, 91, 28, 201, 237, 47, 160, 124, 88, 120, 11, 14, 139, 75, 122,
            51, 78, 71, 14, 46, 163, 249, 253, 0, 95,
        ];

        let valid_announcement_script = ScriptBuf::from_hex("6a4979757600011e692732a7dd0be7c74c1661bba679eab001e775ca87460cceed2a4a27e871240000000186b00b8679dc75ff5b1cc9ed2fa07c58780b0e8b4b7a334e470e2ea3f9fd005f").unwrap();

        if let Err(e) = announcement_from_script(&valid_announcement_script) {
            panic!("Unexpected result: {:?}", e);
        }
        assert!(announcement_from_script(&valid_announcement_script).is_ok());
        assert!(announcement_from_bytes(&valid_announcement_bytes).is_ok());
        assert!(TxFreezeAnnouncement::from_bytes(&valid_announcement_bytes).is_ok());
        assert!(
            TxFreezeAnnouncement::from_announcement_data_bytes(&valid_announcement_data).is_ok()
        );
        assert!(TxFreezeAnnouncement::from_script(&valid_announcement_script).is_ok());
    }
}
