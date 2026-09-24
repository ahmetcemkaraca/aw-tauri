//! Durable file transitions. The journal contains identifiers, never keys.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub id: String,
    pub had_active: bool,
    #[serde(default = "rollback_allowed")]
    pub rollback_allowed: bool,
}

fn rollback_allowed() -> bool { true }

impl Transition {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.len() != 32 || !self.id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("The recovery journal is invalid; files were preserved".into());
        }
        Ok(())
    }
    pub fn staged(&self) -> String { format!("staged-{}.db", self.id) }
    pub fn rollback(&self) -> String { format!("rollback-{}.db", self.id) }
}

pub fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    File::open(path).and_then(|file| file.sync_all()).map_err(|_| "Unable to sync the vault directory")?;
    Ok(())
}

pub fn move_file(source: &Path, destination: &Path, replace_metadata: bool) -> Result<(), String> {
    if !replace_metadata && (destination.exists() || destination.is_symlink()) {
        return Err("A recovery destination already exists; no file was overwritten".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" { fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32; }
        let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
        // MOVEFILE_WRITE_THROUGH plus optional replacement for managed metadata only.
        let flags = 8 | if replace_metadata { 1 } else { 0 };
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
            return Err("Unable to complete the vault file transition".into());
        }
    }
    #[cfg(not(windows))]
    if replace_metadata {
        fs::rename(source, destination).map_err(|_| "Unable to complete the vault file transition")?;
    } else {
        // A hard link is an atomic no-replace move on the same filesystem.
        fs::hard_link(source, destination).map_err(|_| "Unable to complete the vault file transition")?;
        fs::remove_file(source).map_err(|_| "Unable to complete the vault file transition")?;
    }
    sync_directory(destination.parent().ok_or("Invalid vault path")?)
}

pub fn write_journal(root: &Path, transition: &Transition) -> Result<(), String> {
    transition.validate()?;
    let path = root.join("transition.json");
    if path.exists() || path.is_symlink() { return Err("Recover the pending transition first".into()); }
    let temporary = root.join(format!("transition-{}.tmp", transition.id));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(&temporary).map_err(|_| "Unable to create the recovery journal")?;
    file.write_all(&serde_json::to_vec(transition).map_err(|_| "Unable to encode recovery journal")?)
        .and_then(|_| file.sync_all()).map_err(|_| "Unable to save the recovery journal")?;
    drop(file);
    move_file(&temporary, &path, false)
}

pub fn read_journal(root: &Path, name: &str) -> Result<Option<Transition>, String> {
    let path = root.join(name);
    if path.is_symlink() { return Err("Recovery journals must not be links".into()); }
    if !path.exists() { return Ok(None); }
    let metadata = fs::metadata(&path).map_err(|_| "Unable to read the recovery journal")?;
    if metadata.len() > 4096 { return Err("Invalid recovery journal size".into()); }
    let transition: Transition = serde_json::from_slice(&fs::read(path).map_err(|_| "Unable to read recovery journal")?)
        .map_err(|_| "Invalid recovery journal")?;
    transition.validate()?;
    Ok(Some(transition))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_identifiers_cannot_escape_the_vault() {
        assert!(Transition { id: "../outside".into(), had_active: true, rollback_allowed: true }.validate().is_err());
        let transition = Transition { id: "a".repeat(32), had_active: true, rollback_allowed: true };
        assert!(transition.validate().is_ok());
        assert!(!transition.rollback().contains('/'));
        let legacy: Transition = serde_json::from_str(&format!(r#"{{"id":"{}","had_active":true}}"#, "b".repeat(32))).unwrap();
        assert!(legacy.rollback_allowed);
        let security_transition = Transition { rollback_allowed: false, ..transition };
        assert!(!security_transition.rollback_allowed);
    }

    #[test]
    fn no_replace_move_preserves_an_existing_destination() {
        let root = std::env::temp_dir().join(format!("peakactivity-vault-files-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::write(&source, b"source").unwrap();
        fs::write(&destination, b"destination").unwrap();
        assert!(move_file(&source, &destination, false).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"source");
        assert_eq!(fs::read(&destination).unwrap(), b"destination");
        fs::remove_file(&destination).unwrap();
        move_file(&source, &destination, false).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"source");
        fs::remove_dir_all(root).unwrap();
    }
}
