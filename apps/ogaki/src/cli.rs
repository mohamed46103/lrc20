use std::{ffi::OsString, process::Command};

use clap::{self, Parser, Subcommand};

use crate::{
    actions::{self, RunArgs, UpdateArgs},
    errors::Error,
    utils::try_get_lrc20d_path,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Check for lrc20d updates and install them.
    Update(UpdateArgs),
    /// Check for lrc20d updates.
    CheckUpdates(UpdateArgs),
    /// Run lrc20d, automatically checking for updates and installing them.
    RunWithAutoUpdate(RunArgs),

    #[clap(external_subcommand)]
    External(Vec<OsString>),
}

impl Cli {
    pub(crate) async fn run(self) -> Result<(), Error> {
        match self.command {
            Commands::Update(args) => actions::update(&args).await.map(|_| ()),
            Commands::CheckUpdates(args) => actions::check_updates(&args).await,
            Commands::RunWithAutoUpdate(args) => actions::run(&args).await.map_err(Error::Other),
            Commands::External(args) => forward_to_underlying_cli(&args).map_err(Error::Other),
        }
    }
}

/// Forward a command to the underlying lrc20d CLI. Returns an error if the command fails or the lrc20d
/// binary is not found.
fn forward_to_underlying_cli(args: &[OsString]) -> eyre::Result<()> {
    let lrc20d_path = try_get_lrc20d_path()?;

    let mut command = Command::new(lrc20d_path);
    command.args(args);
    command.spawn().and_then(|mut child| child.wait())?;
    Ok(())
}
