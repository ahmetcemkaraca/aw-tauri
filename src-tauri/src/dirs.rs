//! Directory management for ActivityWatch Tauri
//!
//! Supported platforms: Windows, Linux, macOS, Android

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

static BUNDLED_MODULES: OnceLock<PathBuf> = OnceLock::new();

pub fn set_resource_dir(resource_dir: PathBuf) {
    let _ = BUNDLED_MODULES.set(resource_dir.join("modules"));
}

pub fn bundled_modules_dir() -> Option<PathBuf> {
    if cfg!(debug_assertions) {
        if let Some(path) = std::env::var_os("PEAKACTIVITY_HELPERS_DIR") { return Some(path.into()); }
    }
    BUNDLED_MODULES.get().cloned()
}

pub fn trusted_helper(path: &std::path::Path, name: &str) -> bool {
    let Some(root) = bundled_modules_dir() else { return false; };
    trusted_helper_under(&root, path, name)
}

fn trusted_helper_under(root: &std::path::Path, path: &std::path::Path, name: &str) -> bool {
    if !matches!(name, "aw-watcher-window" | "aw-watcher-afk" | "aw-awatcher") { return false; }
    let Ok(root) = root.canonicalize() else { return false; };
    let expected = root.join(name).join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    match (path.canonicalize(), expected.canonicalize()) {
        (Ok(actual), Ok(expected)) => actual == expected && actual.starts_with(&root),
        _ => false,
    }
}

#[cfg(target_os = "android")]
use std::sync::Mutex;

#[cfg(target_os = "android")]
use lazy_static::lazy_static;

#[cfg(target_os = "android")]
lazy_static! {
    static ref ANDROID_DATA_DIR: Mutex<PathBuf> =
        Mutex::new(PathBuf::from("/data/user/0/net.activitywatch.app/files"));
}

#[cfg(not(target_os = "android"))]
pub fn get_config_dir() -> Result<PathBuf, ()> {
    let dir = dirs::config_dir()
        .ok_or(())?
        .join("peakactivity")
        .join("desktop");
    fs::create_dir_all(&dir).expect("Unable to create config dir");
    Ok(dir)
}

#[cfg(target_os = "android")]
pub fn get_config_dir() -> Result<PathBuf, ()> {
    panic!("not implemented on Android");
}

#[cfg(not(target_os = "android"))]
pub fn get_data_dir() -> Result<PathBuf, ()> {
    let dir = dirs::data_dir()
        .ok_or(())?
        .join("peakactivity")
        .join("desktop");
    fs::create_dir_all(&dir).expect("Unable to create data dir");
    Ok(dir)
}

#[cfg(target_os = "android")]
pub fn get_data_dir() -> Result<PathBuf, ()> {
    Ok(ANDROID_DATA_DIR
        .lock()
        .expect("Unable to create data dir")
        .to_path_buf())
}

#[cfg(all(not(target_os = "android"), target_os = "linux"))]
pub fn get_log_dir() -> Result<PathBuf, ()> {
    // Linux uses cache dir for logs
    let dir = dirs::cache_dir()
        .ok_or(())?
        .join("peakactivity")
        .join("desktop")
        .join("log");
    fs::create_dir_all(&dir).expect("Unable to create log dir");
    Ok(dir)
}

#[cfg(target_os = "windows")]
pub fn get_log_dir() -> Result<PathBuf, ()> {
    // Windows: %LOCALAPPDATA%\activitywatch\Logs\aw-tauri
    let dir = dirs::data_local_dir()
        .ok_or(())?
        .join("peakactivity")
        .join("Logs")
        .join("desktop");
    fs::create_dir_all(&dir).expect("Unable to create log dir");
    Ok(dir)
}

#[cfg(all(
    not(target_os = "android"),
    not(target_os = "linux"),
    not(target_os = "windows")
))]
pub fn get_log_dir() -> Result<PathBuf, ()> {
    // macOS: ~/Library/Logs/activitywatch/aw-tauri
    let dir = dirs::home_dir()
        .ok_or(())?
        .join("Library")
        .join("Logs")
        .join("peakactivity")
        .join("desktop");
    fs::create_dir_all(&dir).expect("Unable to create log dir");
    Ok(dir)
}

#[cfg(target_os = "android")]
pub fn get_log_dir() -> Result<PathBuf, ()> {
    panic!("not implemented on Android");
}

pub fn get_config_path() -> PathBuf {
    get_config_dir()
        .expect("Failed to get config dir")
        .join("config.toml")
}

pub fn get_log_path() -> PathBuf {
    get_log_dir()
        .expect("Failed to get log dir")
        .join("aw-tauri.log")
}

#[cfg(target_os = "linux")]
pub fn get_runtime_dir() -> PathBuf {
    // Linux: use XDG_RUNTIME_DIR or fallback to cache dir
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(runtime_dir)
            .join("peakactivity")
            .join("desktop");
        if let Ok(_) = fs::create_dir_all(&dir) {
            return dir;
        }
    }
    // Fallback to cache dir
    let dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("peakactivity")
        .join("desktop");
    let _ = fs::create_dir_all(&dir);
    dir
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn get_runtime_dir() -> PathBuf {
    // For Windows and macOS, use data directory for runtime files
    get_data_dir().unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(target_os = "android")]
pub fn get_runtime_dir() -> PathBuf {
    get_data_dir().unwrap_or_else(|_| PathBuf::from("/tmp"))
}

pub fn get_discovery_paths() -> Vec<PathBuf> {
    let mut discovery_paths = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Linux: XDG-compliant paths
        if let Ok(home_dir) = std::env::var("HOME") {
            let home_path = PathBuf::from(&home_dir);

            // User executables directories
            discovery_paths.push(home_path.join("bin")); // ~/bin (traditional)
            discovery_paths.push(home_path.join(".local").join("bin")); // ~/.local/bin (modern XDG)

            // XDG_DATA_HOME or ~/.local/share (user data)
            let data_dir = std::env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| home_path.join(".local").join("share"));
            discovery_paths.push(
                data_dir
                    .join("peakactivity")
                    .join("desktop")
                    .join("modules"),
            );

            // Legacy path for backward compatibility
            discovery_paths.push(home_path.join("aw-modules"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows: User-specific and system paths
        if let Ok(username) = std::env::var("USERNAME") {
            discovery_paths.push(PathBuf::from(format!(r"C:/Users/{}/aw-modules", username)));
            discovery_paths.push(PathBuf::from(format!(
                r"C:/Users/{}/AppData/Local/Programs/PeakActivity",
                username
            )));
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: Application bundle and user paths
        if let Ok(home_dir) = std::env::var("HOME") {
            discovery_paths.push(PathBuf::from(home_dir).join("aw-modules"));
        }
        // Detect if running inside a .app bundle dynamically via the executable path.
        // This replaces the previous hardcoded /Applications/ActivityWatch.app paths,
        // which broke for non-standard install locations (e.g. ~/Downloads, CI artifacts).
        //
        // Structure: Contents/MacOS/aw-tauri -> go up two levels -> Contents/Resources
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(contents_dir) = exe_path.parent().and_then(|p| p.parent()) {
                let resources_dir = contents_dir.join("Resources");
                if resources_dir.exists() {
                    // Running inside a macOS .app bundle.
                    // Modules bundled via tauri.conf.json `bundle.resources` land in Resources/modules/.
                    discovery_paths.push(resources_dir.join("modules"));
                    // Also include Resources/ directly for compatibility with modules placed
                    // at the root (e.g. legacy build_app_tauri.sh layout).
                    discovery_paths.push(resources_dir);
                }
            }
        }
    }

    #[cfg(target_os = "android")]
    {
        // Android: No discovery paths needed for mobile platform
    }

    discovery_paths
}

#[cfg(target_os = "android")]
pub fn set_android_data_dir(path: &str) {
    let mut android_data_dir = ANDROID_DATA_DIR
        .lock()
        .expect("Unable to acquire ANDROID_DATA_DIR lock");
    *android_data_dir = PathBuf::from(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_requires_the_exact_resource_path_and_cannot_escape_it() {
        let directory = std::env::temp_dir().join(format!("peak-helper-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let modules = directory.join("modules");
        let name = "aw-watcher-window";
        let executable = format!("{name}{}", std::env::consts::EXE_SUFFIX);
        let trusted = modules.join(name).join(&executable);
        fs::create_dir_all(trusted.parent().unwrap()).unwrap();
        fs::write(&trusted, b"synthetic helper").unwrap();
        let ambient = directory.join(&executable);
        fs::write(&ambient, b"unreviewed helper").unwrap();
        assert!(trusted_helper_under(&modules, &trusted, name));
        assert!(!trusted_helper_under(&modules, &ambient, name));
        assert!(!trusted_helper_under(&modules, &trusted, "aw-sync"));
        #[cfg(unix)]
        {
            fs::remove_file(&trusted).unwrap();
            std::os::unix::fs::symlink(&ambient, &trusted).unwrap();
            assert!(!trusted_helper_under(&modules, &trusted, name));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_get_dirs() {
        #[cfg(target_os = "android")]
        set_android_data_dir("/test");

        #[cfg(not(target_os = "android"))]
        {
            get_config_dir().expect("Failed to get config directory");
            get_log_dir().expect("Failed to get log directory");
        }

        get_data_dir().expect("Failed to get data directory");

        let _ = get_config_path();
        let _ = get_log_path();
        let _ = get_runtime_dir();
        let _ = get_discovery_paths();
    }

    #[test]
    fn test_paths_exist() {
        #[cfg(target_os = "android")]
        set_android_data_dir("/test");

        #[cfg(not(target_os = "android"))]
        {
            let config_path = get_config_path();
            let log_path = get_log_path();

            // The parent directories should exist after calling the functions
            assert!(config_path.parent().unwrap().exists());
            assert!(log_path.parent().unwrap().exists());
        }
    }
}
