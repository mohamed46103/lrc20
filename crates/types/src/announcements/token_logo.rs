use crate::{Announcement, AnyAnnouncement, network::Network};
use alloc::string::{FromUtf8Error, String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use bitcoin::consensus::{ReadExt, encode};

use core::fmt;
use core2::io;
use core2::io::{Cursor, Read};
use lrc20_receipts::{TOKEN_PUBKEY_SIZE, TokenPubkey, TokenPubkeyParseError};

use crate::announcements::{AnnouncementKind, AnnouncementParseError};

/// Two bytes that represent the [`TokenLogoAnnouncement`]'s kind.
pub const TOKEN_LOGO_ANNOUNCEMENT_KIND: AnnouncementKind = [0, 6];
/// The maximum size of the token logo URL in [`TokenLogoAnnouncement`] in bytes.
pub const MAX_URL_SIZE: usize = 48;
/// The minimum size of the token logo URL in [`TokenLogoAnnouncement`] in bytes.
pub const MIN_URL_SIZE: usize = 15;
/// The minimum size of the [`TokenLogoAnnouncement`] in bytes.
pub const MIN_TOKEN_LOGO_ANNOUNCEMENT_SIZE: usize = TOKEN_PUBKEY_SIZE + MIN_URL_SIZE;
/// The maxim size of the [`TokenLogoAnnouncement`] in bytes.
pub const MAX_TOKEN_LOGO_ANNOUNCEMENT_SIZE: usize = TOKEN_PUBKEY_SIZE + MAX_URL_SIZE;

/// TokenLogo's announcement from the issuer. It contains the logo URL for the token.
///
/// # Structure
///
/// - `token_pubkey` - 33 bytes [`TokenPubkey`].
/// - `logo` - [15 - 48] bytes logo for the token.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenLogoAnnouncement {
    /// The token's [`TokenPubkey`].
    pub token_pubkey: TokenPubkey,
    /// The url of the logo.
    pub logo_url: String,
}

impl TokenLogoAnnouncement {
    /// Create a new [`TokenLogoAnnouncement`].
    pub fn new(
        token_pubkey: TokenPubkey,
        logo_url: String,
    ) -> Result<Self, TokenLogoAnnouncementParseError> {
        if logo_url.len() < MIN_URL_SIZE || logo_url.len() > MAX_URL_SIZE {
            return Err(TokenLogoAnnouncementParseError::InvalidUrlLength);
        }

        let result = Self {
            token_pubkey,
            logo_url,
        };

        Ok(result)
    }
}

#[cfg_attr(feature = "serde", typetag::serde(name = "token_pubkey_announcement"))]
impl AnyAnnouncement for TokenLogoAnnouncement {
    fn kind(&self) -> AnnouncementKind {
        TOKEN_LOGO_ANNOUNCEMENT_KIND
    }

    fn minimal_block_height(&self, _network: Network) -> usize {
        // For the default, innitial announcements, there is no minimal block height.
        0
    }

    fn from_announcement_data_bytes(data: &[u8]) -> Result<Self, AnnouncementParseError> {
        if data.len() < MIN_TOKEN_LOGO_ANNOUNCEMENT_SIZE {
            Err(TokenLogoAnnouncementParseError::ShortLength)?;
        }

        let mut cursor = Cursor::new(data);

        let mut token_pubkey_bytes = [0u8; TOKEN_PUBKEY_SIZE];

        cursor
            .read(&mut token_pubkey_bytes)
            .map_err(|err| wrap_io_error(err, "failed to read the token_pubkey"))?;

        let token_pubkey = TokenPubkey::from_bytes(&token_pubkey_bytes)
            .map_err(TokenLogoAnnouncementParseError::from)?;

        // Read the url
        let url_len = cursor
            .read_u8()
            .map_err(|err| wrap_io_error(err, "failed to read the url length"))?
            as usize;

        if !(MIN_URL_SIZE..=MAX_URL_SIZE).contains(&url_len) {
            Err(TokenLogoAnnouncementParseError::InvalidUrlLength)?;
        }

        let mut url_bytes = vec![0; url_len];
        cursor
            .read_exact(&mut url_bytes)
            .map_err(|err| wrap_io_error(err, "failed to read the url"))?;

        let logo_url = String::from_utf8(url_bytes)
            .map_err(TokenLogoAnnouncementParseError::InvalidUtf8String)?;

        let announcement = TokenLogoAnnouncement::new(token_pubkey, logo_url)?;

        Ok(announcement)
    }

    fn to_announcement_data_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(MAX_TOKEN_LOGO_ANNOUNCEMENT_SIZE);

        result.extend_from_slice(&self.token_pubkey.to_bytes());
        result.push(self.logo_url.len() as u8);
        result.extend_from_slice(self.logo_url.as_bytes());

        result
    }
}

impl From<TokenLogoAnnouncement> for Announcement {
    fn from(value: TokenLogoAnnouncement) -> Self {
        Self::TokenLogo(value)
    }
}

/// Error parsing the [`TokenLogoAnnouncement`].
#[derive(Debug)]
pub enum TokenLogoAnnouncementParseError {
    /// Short length of the announcement data. It should be at least
    /// [`MIN_TOKEN_LOGO_ANNOUNCEMENT_SIZE`].
    ShortLength,
    /// Announcement data is invalid or incorectly encoded.
    InvalidAnnouncementData(String),
    /// The string is not a valid UTF-8 string.
    InvalidUtf8String(FromUtf8Error),
    /// The length of the symbol is less than [`MIN_SYMBOL_SIZE`] or more than [`MAX_SYMBOL_SIZE`].
    InvalidUrlLength,
    /// Invalid token_pubkey.
    InvalidTokenPubkey(TokenPubkeyParseError),
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for TokenLogoAnnouncementParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8String(e) => Some(e),
            Self::InvalidTokenPubkey(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for TokenLogoAnnouncementParseError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortLength => write!(
                _f,
                "the announcement data is too short, it must be at least {} bytes",
                MIN_TOKEN_LOGO_ANNOUNCEMENT_SIZE
            ),
            Self::InvalidAnnouncementData(e) => write!(_f, "invalid announcement data: {}", e),
            Self::InvalidUtf8String(e) => write!(_f, "invalid utf-8 string: {}", e),
            Self::InvalidTokenPubkey(e) => write!(_f, "invalid token_pubkey: {}", e),
            Self::InvalidUrlLength => write!(
                _f,
                "the length of the url is invalid, it must be between {} and {}",
                MIN_URL_SIZE, MAX_URL_SIZE
            ),
        }
    }
}

impl From<FromUtf8Error> for TokenLogoAnnouncementParseError {
    fn from(err: FromUtf8Error) -> Self {
        Self::InvalidUtf8String(err)
    }
}

impl From<encode::Error> for TokenLogoAnnouncementParseError {
    fn from(err: encode::Error) -> Self {
        Self::InvalidAnnouncementData(err.to_string())
    }
}

impl From<io::Error> for TokenLogoAnnouncementParseError {
    fn from(err: io::Error) -> Self {
        Self::InvalidAnnouncementData(err.to_string())
    }
}

impl From<TokenPubkeyParseError> for TokenLogoAnnouncementParseError {
    fn from(err: TokenPubkeyParseError) -> Self {
        Self::InvalidTokenPubkey(err)
    }
}

impl From<TokenLogoAnnouncementParseError> for AnnouncementParseError {
    fn from(err: TokenLogoAnnouncementParseError) -> Self {
        AnnouncementParseError::InvalidAnnouncementData(err.to_string())
    }
}

/// Wrap Error with InvalidAnnouncementData and the given message.
fn wrap_io_error(err: impl fmt::Display, message: &str) -> TokenLogoAnnouncementParseError {
    TokenLogoAnnouncementParseError::InvalidAnnouncementData(format!("{}: {}", message, err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::announcements::{announcement_from_bytes, announcement_from_script};
    use alloc::string::ToString;
    use bitcoin::ScriptBuf;

    pub const TEST_TOKEN_PUBKEY: &str =
        "bcrt1p4v5dxtlzrrfuk57nxr3d6gwmtved47ulc55kcsk30h93e43ma2eqvrek30";

    #[test]
    fn test_serialize_deserialize() {
        struct TestData {
            announcement: TokenLogoAnnouncement,
            expect_error: bool,
        }

        let test_vector = vec![TestData {
            announcement: TokenLogoAnnouncement {
                token_pubkey: TokenPubkey::from_address(TEST_TOKEN_PUBKEY, None)
                    .expect("valid token_pubkey"),
                logo_url: "111111111111111111111111".into(),
            },
            expect_error: false,
        }];

        for test in test_vector {
            let data = test.announcement.to_announcement_data_bytes();
            match TokenLogoAnnouncement::from_announcement_data_bytes(&data) {
                Ok(announcement) => {
                    assert_eq!(announcement, test.announcement);
                }
                Err(err) => {
                    assert!(test.expect_error, "Unexpected error: {}", err);
                }
            }

            let bytes = test.announcement.to_bytes();
            match TokenLogoAnnouncement::from_bytes(&bytes) {
                Ok(announcement) => {
                    assert_eq!(announcement, test.announcement);
                    assert_eq!(Announcement::TokenLogo(announcement).to_bytes(), bytes);
                }
                Err(err) => {
                    assert!(test.expect_error, "Unexpected error: {}", err);
                }
            }

            let announcement_script = test.announcement.to_script();
            match TokenLogoAnnouncement::from_script(&announcement_script) {
                Ok(announcement) => {
                    assert_eq!(announcement, test.announcement);
                }
                Err(err) => {
                    assert!(test.expect_error, "Unexpected error: {}", err);
                }
            }

            match announcement_from_script(&announcement_script) {
                Ok(announcement) => {
                    assert_eq!(announcement, Announcement::TokenLogo(test.announcement));
                    assert_eq!(announcement.to_script(), announcement_script);
                }
                Err(err) => {
                    assert!(test.expect_error, "Unexpected error: {}", err);
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
                    "the announcement data is too short, it must be at least {} bytes",
                    MIN_TOKEN_LOGO_ANNOUNCEMENT_SIZE
                )
                .to_string(),
            },
            TestData {
                bytes: vec![0; 58],
                err: "invalid token_pubkey: Invalid public key structure: malformed public key"
                    .to_string(),
            },
        ];

        for test in test_vector {
            match TokenLogoAnnouncement::from_announcement_data_bytes(&test.bytes) {
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
                bytes: vec![76, 82, 67, 50, 48, 0, 6, 2, 171, 40, 211, 47, 226, 24, 211, 203, 83, 211, 48, 226, 221, 33, 219, 91, 50, 218, 251, 159, 197, 41, 108, 66, 209, 125, 203, 28, 214, 59, 234, 178, 24, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49],
                data_bytes: vec![2, 171, 40, 211, 47, 226, 24, 211, 203, 83, 211, 48, 226, 221, 33, 219, 91, 50, 218, 251, 159, 197, 41, 108, 66, 209, 125, 203, 28, 214, 59, 234, 178, 24, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49],
                script: ScriptBuf::from_hex("6a3f797576000602ab28d32fe218d3cb53d330e2dd21db5b32dafb9fc5296c42d17dcb1cd63beab218313131313131313131313131313131313131313131313131").unwrap(),
            },
        ];

        for announcement in valid_announcements {
            assert!(announcement_from_script(&announcement.script).is_ok());
            assert!(announcement_from_bytes(&announcement.bytes).is_ok());
            assert!(TokenLogoAnnouncement::from_bytes(&announcement.bytes).is_ok());
            assert!(
                TokenLogoAnnouncement::from_announcement_data_bytes(&announcement.data_bytes)
                    .is_ok()
            );
            assert!(TokenLogoAnnouncement::from_script(&announcement.script).is_ok());
        }
    }
}
