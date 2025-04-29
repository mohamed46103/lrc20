use alloc::string::{String, ToString};
use alloc::vec::Vec;
pub use announcement::{
    ANNOUNCEMENT_KIND_LENGTH, ANNOUNCEMENT_MINIMAL_LENGTH, ANNOUNCEMENT_PREFIX, Announcement,
    AnnouncementKind, AnnouncementParseError, AnyAnnouncement,
};
use bitcoin::Script;
use bitcoin::blockdata::opcodes::Opcode;
use bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_32;
use bitcoin::blockdata::script;
use bitcoin::blockdata::script::Instruction;
use core::fmt;
pub use freeze::{
    outpoint::{FreezeAnnouncementParseError, TX_FREEZE_ANNOUNCEMENT_KIND, TxFreezeAnnouncement},
    pubkey::{
        PUBKEY_FREEZE_ANNOUNCEMENT_KIND, PubkeyFreezeAnnouncement,
        PubkeyFreezeAnnouncementParseError,
    },
};
pub use token_logo::{TOKEN_LOGO_ANNOUNCEMENT_KIND, TokenLogoAnnouncement};
pub use token_pubkey::{
    MAX_NAME_SIZE, MAX_SYMBOL_SIZE, MAX_TOKEN_PUBKEY_ANNOUNCEMENT_SIZE, MIN_NAME_SIZE,
    MIN_SYMBOL_SIZE, MIN_TOKEN_PUBKEY_ANNOUNCEMENT_SIZE, TOKEN_PUBKEY_ANNOUNCEMENT_KIND,
    TokenPubkeyAnnouncement, TokenPubkeyInfo,
};

pub use issue::{ISSUE_ANNOUNCEMENT_KIND, IssueAnnouncement};

pub use transfer_ownership::{TRANSFER_OWNERSHIP_ANNOUNCEMENT_KIND, TransferOwnershipAnnouncement};

use crate::announcements::announcement::ANNOUNCEMENT_INSTRUCTION_NUMBER;

mod announcement;
mod freeze;
mod issue;
mod token_logo;
mod token_pubkey;
mod transfer_ownership;

/// Parse the bytes into an [`Announcement`] without specification of the [announcement kind].
///
/// # Returns
///
/// Returns the parsed announcement message or an error if the data is invalid or
/// [announcement kind] is unknown.
///
/// [announcement kind]: AnnouncementKind
pub fn announcement_from_bytes(bytes: &[u8]) -> Result<Announcement, AnnouncementParseError> {
    if bytes.len() < ANNOUNCEMENT_MINIMAL_LENGTH {
        return Err(AnnouncementParseError::ShortLength);
    }

    let prefix = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]];
    if prefix != ANNOUNCEMENT_PREFIX {
        return Err(AnnouncementParseError::InvalidPrefix);
    }

    let kind = [bytes[5], bytes[6]];
    let announcement_data = &bytes[ANNOUNCEMENT_MINIMAL_LENGTH..];

    match kind {
        TOKEN_PUBKEY_ANNOUNCEMENT_KIND => Ok(Announcement::TokenPubkey(
            TokenPubkeyAnnouncement::from_announcement_data_bytes(announcement_data)?,
        )),
        TX_FREEZE_ANNOUNCEMENT_KIND => Ok(Announcement::TxFreeze(
            TxFreezeAnnouncement::from_announcement_data_bytes(announcement_data)?,
        )),
        PUBKEY_FREEZE_ANNOUNCEMENT_KIND => Ok(Announcement::PubkeyFreeze(
            PubkeyFreezeAnnouncement::from_announcement_data_bytes(announcement_data)?,
        )),
        ISSUE_ANNOUNCEMENT_KIND => Ok(Announcement::Issue(
            IssueAnnouncement::from_announcement_data_bytes(announcement_data)?,
        )),
        TRANSFER_OWNERSHIP_ANNOUNCEMENT_KIND => Ok(Announcement::TransferOwnership(
            TransferOwnershipAnnouncement::from_announcement_data_bytes(announcement_data)?,
        )),
        TOKEN_LOGO_ANNOUNCEMENT_KIND => Ok(Announcement::TokenLogo(
            TokenLogoAnnouncement::from_announcement_data_bytes(announcement_data)?,
        )),
        _ => Err(AnnouncementParseError::UnknownAnnouncementKind),
    }
}

/// Parse the Bitcoin script into an [`Announcement`] without specification of the
/// [announcement kind].
///
/// # Returns
///
/// Returns the parsed announcement message or an error if the data is invalid or
/// [announcement kind] is unknown.
///
/// [announcement kind]: AnnouncementKind
pub fn announcement_from_script(script: &Script) -> Result<Announcement, ParseOpReturnError> {
    parse_op_return_script(script, announcement_from_bytes)
}

/// Pull the bytes from [`OP_RETURN`] in Bitcoin [`Script`] and parse it with the provided function.
///
/// # Returns
///
/// Returns the parsed value or an [error] if the script is not [`OP_RETURN`] or the parsing
/// function returns an error.
///
/// [error]: ParseOpReturnError
/// [`OP_RETURN`]: bitcoin::blockdata::opcodes::all::OP_RETURN
pub fn parse_op_return_script<T, ParseError, ParseFn>(
    script: &Script,
    parse_fn: ParseFn,
) -> Result<T, ParseOpReturnError>
where
    ParseError: fmt::Display,
    ParseFn: FnOnce(&[u8]) -> Result<T, ParseError>,
{
    if !script.is_op_return() {
        return Err(ParseOpReturnError::NoOpReturn);
    }

    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    // OP_PUSHBYTES_32 in instruction is not stored, for some reason
    if instructions.len() != ANNOUNCEMENT_INSTRUCTION_NUMBER - 1 {
        return Err(ParseOpReturnError::InvalidInstructionsNumber(
            instructions.len(),
        ));
    }

    match &instructions[1] {
        Instruction::PushBytes(bytes) => {
            if !is_announcement(bytes.as_bytes()) {
                return Err(ParseOpReturnError::IsNotAnnouncement);
            }
            parse_fn(bytes.as_bytes())
                .map_err(|err| ParseOpReturnError::InvaliOpReturnData(err.to_string()))
        }
        inst => Err(ParseOpReturnError::InvalidInstruction(
            instruction_into_opcode(inst),
        )),
    }
}

/// Error that can occur during the parsing [`OP_RETURN`] Bitcoin [`Script`].
///
/// [`OP_RETURN`]: bitcoin::blockdata::opcodes::all::OP_RETURN
#[derive(Debug)]
pub enum ParseOpReturnError {
    InvalidInstructionsNumber(usize),
    NoOpReturn,
    InvalidInstruction(Opcode),
    ScriptError(script::Error),
    IsNotAnnouncement,
    InvaliOpReturnData(String),
}

impl fmt::Display for ParseOpReturnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInstructionsNumber(num) => write!(
                f,
                "invalid number of instructions, should be {}, got {}",
                ANNOUNCEMENT_INSTRUCTION_NUMBER, num
            ),
            Self::NoOpReturn => write!(f, "no OP_RETURN in script"),
            Self::InvalidInstruction(opcode) => write!(f, "invalid opcode {}", opcode),
            Self::ScriptError(e) => write!(f, "script error: {}", e),
            Self::IsNotAnnouncement => write!(f, "it is not an announcement"),
            Self::InvaliOpReturnData(e) => write!(f, "invalid announcement: {}", e),
        }
    }
}

#[cfg(not(feature = "no-std"))]
impl std::error::Error for ParseOpReturnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ScriptError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<script::Error> for ParseOpReturnError {
    fn from(err: script::Error) -> Self {
        Self::ScriptError(err)
    }
}

fn instruction_into_opcode(inst: &Instruction) -> Opcode {
    match inst {
        Instruction::Op(op) => *op,
        Instruction::PushBytes(_) => OP_PUSHBYTES_32,
    }
}

fn is_announcement(src: &[u8]) -> bool {
    src.len() >= ANNOUNCEMENT_MINIMAL_LENGTH && src[0..5] == ANNOUNCEMENT_PREFIX
}
