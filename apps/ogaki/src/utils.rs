use crate::errors::Error;

use eyre::{Context, OptionExt};
use semver::Version;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};
use which::which;

pub const DEFAULT_SEARCH_PATHS: [&str; 2] = ["./lrc20d", "lrc20d"];

/// Get the absolute path to the lrc20d binary. Checks CWD, PATH for the binary. Returns an error if
/// the binary is not found.
pub fn get_lrc20d_path() -> Option<PathBuf> {
    let [local, global] = DEFAULT_SEARCH_PATHS;

    which(local).or_else(|_| which(global)).ok()
}

pub fn try_get_lrc20d_path() -> Result<PathBuf, Error> {
    get_lrc20d_path().ok_or(Error::Lrc20dNotFound)
}

/// Get the current semver version of the lrc20d binary. Returns an error if the version cannot be
/// parsed or if the lrc20d binary is not found.
pub fn get_current_version() -> Result<Version, Error> {
    let lrc20d = try_get_lrc20d_path()?;

    let output = Command::new(lrc20d)
        .arg("--version")
        .stdout(Stdio::piped())
        .spawn()
        .wrap_err("Failed to spawn LRC20d process")?
        .wait_with_output()
        .wrap_err("Failed to get version from LRC20d process")?;

    let output_str =
        String::from_utf8(output.stdout).wrap_err("Failed to parse LRC20d process output")?;

    let version_str = output_str
        .trim()
        .split(' ')
        .last()
        .ok_or_eyre("Invalid version")?;

    let version =
        Version::parse(version_str).wrap_err("Invalid semver version from LRC20d binary")?;

    Ok(version)
}
