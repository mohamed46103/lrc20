use std::env;
use std::path::PathBuf;

// Returns the default directory as "$HOME/.lrc20/storage"
pub(crate) fn get_default_storage_directory() -> PathBuf {
    let path = ".lrc20/storage";

    let home_dir = if let Some(home) = env::var_os("HOME") {
        Some(PathBuf::from(home))
    } else if cfg!(target_os = "windows") {
        env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        None
    };

    home_dir.map_or_else(|| PathBuf::from(path), |home| home.join(path))
}
