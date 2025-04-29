#[cfg(feature = "consensus")]
use {
    alloc::vec::Vec,
    bitcoin::consensus::encode::Error,
    core2::io::{self, Read},
};

use serde_json::Value;

pub const METADATA_MAX_SIZE: u32 = 128 * 1024 * 1024; // 128 Mb

#[cfg(feature = "consensus")]
pub const METADATA_SIZE_BYTES_COUNT: usize = size_of::<u32>();

#[cfg(feature = "consensus")]
pub(crate) fn try_write_metadata<W: io::Write + ?Sized>(
    writer: &mut W,
    metadata: &Option<Value>,
) -> Result<usize, io::Error> {
    let mut len = 0;

    match metadata {
        Some(metadata) => {
            let metadata_bytes = serde_json::to_vec(metadata)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            let metadata_bytes_len: u32 = metadata_bytes.len() as u32;
            len += writer.write(&metadata_bytes_len.to_be_bytes())?;
            len += writer.write(&metadata_bytes)?;
        }
        None => {
            let metadata_bytes_len: u32 = 0u32;
            len += writer.write(&metadata_bytes_len.to_be_bytes())?;
        }
    }

    Ok(len)
}

#[cfg(feature = "consensus")]
pub(crate) fn try_read_metadata<R: io::Read + ?Sized>(
    reader: &mut R,
) -> Result<Option<Value>, Error> {
    let mut metadata_len_bytes = [0u8; METADATA_SIZE_BYTES_COUNT];
    reader.read_exact(&mut metadata_len_bytes)?;
    let metadata_len = u32::from_be_bytes(metadata_len_bytes);

    if metadata_len > 0 {
        let mut metadata_bytes = Vec::with_capacity(metadata_len as usize);
        reader
            .take(metadata_len as u64)
            .read_to_end(&mut metadata_bytes)?;

        let metadata: Value = serde_json::from_slice(&metadata_bytes)
            .map_err(|_err| Error::ParseFailed("Failed to parse metadata"))?;
        Ok(Some(metadata))
    } else {
        Ok(None)
    }
}
pub(crate) fn check_metadata_size(metadata: &Option<Value>) -> eyre::Result<bool> {
    match metadata {
        Some(metadata) => {
            let metadata_bytes = serde_json::to_vec(metadata)?;

            Ok(metadata_bytes.len() <= METADATA_MAX_SIZE as usize)
        }
        None => Ok(true),
    }
}
