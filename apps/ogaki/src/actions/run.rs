use crate::{
    actions::{self, UpdateArgs},
    utils::try_get_lrc20d_path,
};
use clap::Args;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    signal::unix::{self, SignalKind},
    time,
};

/// Configuration for lrc20d node runner.
#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    #[clap(flatten)]
    pub update_args: UpdateArgs,

    /// Interval in minutes to check for updates.
    #[clap(long, default_value = "30")]
    pub check_interval: u64,
    /// Grace period in seconds to wait for lrc20d to terminate before forcefully killing it.
    #[clap(long, default_value = "60")]
    pub grace_period: u64,

    #[clap(long = "config", short)]
    pub config_path: PathBuf,
}

/// Run lrc20d with auto-update checks. This function will check for updates every `check_interval`
/// minutes and restart lrc20d if an update is available. It will also gracefully terminate lrc20d if a
/// SIGINT is received and forcefully kill it after `grace_period` seconds.
#[tracing::instrument(name = "ogaki", skip(args))]
pub(crate) async fn run(args: &RunArgs) -> eyre::Result<()> {
    tracing::info!("Running lrc20d with auto-update checks");

    let mut interval = time::interval(Duration::from_secs(args.check_interval * 60));
    let mut child = start_lrc20d(args.config_path.as_path())?;
    let mut sigterm =
        unix::signal(SignalKind::terminate()).expect("Failed to create SIGTERM signal handler");
    let mut sigint =
        unix::signal(SignalKind::interrupt()).expect("Failed to create SIGINT signal handler");

    loop {
        tokio::select! {
            _ = interval.tick() => {
                check_and_restart_lrc20d(args, &mut child).await?;
            },
            _ = sigterm.recv() => {
                tracing::debug!("Received SIGTERM signal");
                handle_termination(&mut child, args).await?;
                break;
            }
            _ = sigint.recv() => {
                tracing::debug!("Received SIGINT signal");
                handle_termination(&mut child, args).await?;
                break;
            }
        }
    }

    Ok(())
}

/// Check for updates and restart lrc20d if an update is available.
async fn check_and_restart_lrc20d(args: &RunArgs, child: &mut Child) -> eyre::Result<()> {
    let updated_result = actions::update(&args.update_args).await;

    match updated_result {
        // Skipping in case there is no update
        Ok(is_updated) if !is_updated => {
            return Ok(());
        }
        Err(err) => {
            tracing::error!("Failed to check update, retrying soon: {}", err);
            return Ok(());
        }
        _ => {}
    };

    tracing::info!("Update detected, restarting lrc20d process...");
    terminate_lrc20d(child, args).await?;

    tracing::info!("Node process terminated. Starting new process...");
    *child = start_lrc20d(args.config_path.as_path())?;

    tracing::info!("Ogaki has given you the latest version, up and running now!");

    Ok(())
}

/// Terminate lrc20d process gracefully. Visual wrapper for `helper::terminate_lrc20d`.
async fn handle_termination(child: &mut Child, config: &RunArgs) -> eyre::Result<()> {
    terminate_lrc20d(child, config).await?;

    tracing::info!("Node process terminated. Exiting...");
    Ok(())
}

/// Start the lrc20d process with the given config. Returns child process handle or an error if the
/// lrc20d binary is not found.
pub fn start_lrc20d(config_path: impl AsRef<Path>) -> eyre::Result<Child> {
    let child = Command::new(try_get_lrc20d_path()?)
        .args(["run", "--config", config_path.as_ref().to_str().unwrap()])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    Ok(child)
}

/// Terminate the lrc20d process gracefully. Sends a SIGINT to the process and waits for the grace
/// period before forcefully killing the process.
async fn terminate_lrc20d(child: &mut Child, config: &RunArgs) -> eyre::Result<()> {
    tracing::info!("Gracefully terminating lrc20d process...");

    let pid = Pid::from_raw(child.id() as i32);
    signal::kill(pid, Signal::SIGINT)?;

    for _ in 0..config.grace_period {
        if child.try_wait()?.is_some() {
            break;
        }
        time::sleep(Duration::from_secs(1)).await;
    }

    child.kill()?;

    Ok(())
}
