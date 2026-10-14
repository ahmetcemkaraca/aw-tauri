//! Native vault lifecycle. Keys stay in the OS store; transitions preserve prior files.
use crate::vault_files::{self, Transition};
use aw_datastore::Datastore;
use aw_datastore::SyncSnapshotV1;
use aw_sync_e2ee::{EncryptedSyncSnapshotV1, RecoveryKitV1};
use keyring::{Entry, Error};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, TryLockError};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use zeroize::Zeroizing;

pub(crate) const SERVICE: &str = "app.peakactivity.desktop.vault";
pub(crate) const AI_CREDENTIAL_INDEX_ACCOUNT: &str = "ai-credential-index";
pub(crate) const AI_CREDENTIAL_ACCOUNT_PREFIX: &str = "ai-credential-";
pub(crate) const MAX_AI_CREDENTIAL_REFS: usize = 64;
const READY_FILE: &str = "vault-ready";
const READY_CONTENT: &str = "PeakActivity encrypted vault v1\n";
static VAULT: OnceLock<Mutex<Vault>> = OnceLock::new();
static REPORT_STORE: OnceLock<Datastore> = OnceLock::new();
static SUPPORT_PREVIEW: OnceLock<Mutex<Option<(String, String)>>> = OnceLock::new();

#[derive(Clone, Serialize)]
pub struct VaultStatus {
    pub state: &'static str,
    pub message: Option<String>,
    pub has_vault: bool,
    pub generation: u64,
}

struct Vault {
    directory: PathBuf,
    account: &'static str,
    _owner: File,
    store: Datastore,
    status: VaultStatus,
}

#[derive(Serialize)]
pub struct SupportBundlePreview {
    pub id: String,
    pub content: String,
}

#[derive(Default, Serialize)]
struct LogSummary {
    available: bool,
    recent_lines_scanned: usize,
    errors: usize,
    warnings: usize,
    helper_failures: usize,
}

fn summarize_log_text(content: &str) -> LogSummary {
    let mut summary = LogSummary {
        available: true,
        ..Default::default()
    };
    for line in content.lines().rev().take(500) {
        let line = line.to_ascii_lowercase();
        summary.recent_lines_scanned += 1;
        if line.contains("error") {
            summary.errors += 1;
        }
        if line.contains("warn") {
            summary.warnings += 1;
        }
        if line.contains("crashed") || line.contains("restart limit") {
            summary.helper_failures += 1;
        }
    }
    summary
}

pub fn random_secret() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(bytes.as_mut()).map_err(|_| "Secure randomness is unavailable")?;
    Ok(Zeroizing::new(
        bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    ))
}

fn key(entry: &Entry, exists: bool) -> Result<Zeroizing<String>, String> {
    match entry.get_password() {
        Ok(value) => {
            let value = Zeroizing::new(value);
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(
                    "The vault key is invalid; use recovery instead of replacing it".into(),
                );
            }
            Ok(value)
        }
        Err(Error::NoEntry) if !exists => {
            let value = random_secret()?;
            entry
                .set_password(value.as_str())
                .map_err(|_| "Unable to save the vault key in the OS secret store")?;
            // Confirm persistence before creating any database bytes.
            let saved = Zeroizing::new(
                entry
                    .get_password()
                    .map_err(|_| "Unable to confirm the saved vault key")?,
            );
            if *saved != *value {
                return Err("The OS secret store did not preserve the vault key".into());
            }
            Ok(value)
        }
        Err(Error::NoEntry) => {
            Err("The existing vault has no key in this OS account; recovery is required".into())
        }
        Err(_) => Err("The OS secret store is locked or unavailable; unlock it and retry".into()),
    }
}

pub fn data_dir(testing: bool) -> Result<PathBuf, String> {
    let path = crate::dirs::get_data_dir()
        .map_err(|_| "Local data directory is unavailable")?
        .join(if testing { "testing" } else { "vault" });
    fs::create_dir_all(&path).map_err(|_| "Unable to create the vault directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "Unable to restrict vault directory permissions")?;
    }
    Ok(path)
}

fn has_local_vault(directory: &Path) -> bool {
    match fs::read_dir(directory) {
        Ok(entries) => entries.filter_map(|entry| entry.ok()).any(|entry| {
            !matches!(
                entry.file_name().to_string_lossy().as_ref(),
                "owner.lock" | "device-id"
            )
        }),
        Err(_) => true,
    }
}

fn entry(account: &str) -> Result<Entry, String> {
    Entry::new(SERVICE, account).map_err(|_| "The native secret store is unavailable".into())
}

fn read_key(account: &str) -> Result<Zeroizing<String>, String> {
    key(&entry(account)?, true)
}

fn save_key(account: &str, secret: &str) -> Result<(), String> {
    let entry = entry(account)?;
    entry
        .set_password(secret)
        .map_err(|_| "The native secret store could not save the key")?;
    let readback = Zeroizing::new(
        entry
            .get_password()
            .map_err(|_| "The saved key could not be verified")?,
    );
    if readback.as_str() != secret {
        return Err("The native secret store returned a different key".into());
    }
    Ok(())
}

fn valid_transition_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn valid_ai_credential_ref(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("cred-")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ai_credential_accounts(serialized: &str) -> Result<Vec<String>, String> {
    let references: Vec<String> = serde_json::from_str(serialized).map_err(|_| {
        "The native AI credential index is invalid; vault files were preserved".to_string()
    })?;
    let mut unique = references.clone();
    unique.sort();
    unique.dedup();
    if references.len() > MAX_AI_CREDENTIAL_REFS
        || references != unique
        || references
            .iter()
            .any(|reference| !valid_ai_credential_ref(reference))
    {
        return Err("The native AI credential index is invalid; vault files were preserved".into());
    }
    Ok(references
        .into_iter()
        .map(|reference| format!("{AI_CREDENTIAL_ACCOUNT_PREFIX}{reference}"))
        .collect())
}

fn recovery_accounts(directory: &Path, primary: &str) -> Result<Vec<String>, String> {
    let mut ids = BTreeSet::new();
    let entries = fs::read_dir(directory).map_err(|_| "Unable to inspect local recovery files")?;
    for entry in entries {
        let entry = entry.map_err(|_| "Unable to inspect local recovery files")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        for (prefix, suffix) in [
            ("staged-", ".db"),
            ("rollback-", ".db"),
            ("transition-", ".tmp"),
            ("aborted-", ".json"),
        ] {
            if let Some(id) = name
                .strip_prefix(prefix)
                .and_then(|value| value.strip_suffix(suffix))
            {
                if valid_transition_id(id) {
                    ids.insert(id.to_string());
                }
            }
        }
        if matches!(name.as_str(), "transition.json" | "last-transition.json")
            || name.starts_with("aborted-")
        {
            if let Ok(Some(transition)) = vault_files::read_journal(directory, &name) {
                ids.insert(transition.id);
            }
        }
    }
    let mut accounts = Vec::with_capacity(ids.len() * 2 + 1);
    for id in ids {
        accounts.push(format!("{primary}.pending.{id}"));
        accounts.push(format!("{primary}.rollback.{id}"));
    }
    accounts.push(AI_CREDENTIAL_INDEX_ACCOUNT.to_string());
    match Entry::new(SERVICE, AI_CREDENTIAL_INDEX_ACCOUNT)
        .and_then(|credential| credential.get_password())
    {
        Ok(serialized) => {
            accounts.extend(ai_credential_accounts(&serialized)?);
        }
        Err(Error::NoEntry) => {}
        Err(_) => return Err("Unlock the OS secret store before deleting the local vault".into()),
    }
    accounts.push(primary.to_string());
    accounts.sort();
    accounts.dedup();
    Ok(accounts)
}

fn read_existing_keys(accounts: &[String]) -> Result<BTreeMap<String, Zeroizing<String>>, String> {
    let mut keys = BTreeMap::new();
    for account in accounts {
        match entry(account)?.get_password() {
            Ok(secret) => {
                keys.insert(account.clone(), Zeroizing::new(secret));
            }
            Err(Error::NoEntry) => {}
            Err(_) => {
                return Err("Unlock the OS secret store before deleting the local vault".into())
            }
        }
    }
    Ok(keys)
}

fn restore_keys(accounts: &[String], keys: &BTreeMap<String, Zeroizing<String>>) -> bool {
    accounts.iter().all(|account| {
        keys.get(account)
            .is_none_or(|secret| save_key(account, secret).is_ok())
    })
}

fn delete_os_keys(
    accounts: &[String],
    keys: &BTreeMap<String, Zeroizing<String>>,
) -> Result<(), String> {
    let mut attempted = Vec::new();
    for account in accounts {
        if !keys.contains_key(account) {
            continue;
        }
        attempted.push(account.clone());
        match Entry::new(SERVICE, account).and_then(|credential| credential.delete_credential()) {
            Ok(()) | Err(Error::NoEntry) => {}
            Err(_) => {
                let restored = restore_keys(&attempted, keys);
                return Err(if restored {
                    "The OS secret store refused deletion; the local vault files were preserved"
                        .into()
                } else {
                    "Key deletion failed and could not be fully rolled back; local vault files were preserved".into()
                });
            }
        }
    }
    Ok(())
}

fn erase_vault_files(directory: &Path) -> Result<(), String> {
    if directory.is_symlink() {
        return Err("The vault directory must not be a symbolic link".into());
    }
    let entries = fs::read_dir(directory).map_err(|_| "Unable to inspect local vault files")?;
    for entry in entries {
        let entry = entry.map_err(|_| "Unable to inspect local vault files")?;
        if entry.file_name().to_string_lossy() == "owner.lock" {
            continue;
        }
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|_| "Unable to inspect a local vault file")?;
        let result = if kind.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };
        result.map_err(|_| {
            "The local vault key was erased, but some encrypted files could not be removed"
        })?;
    }
    vault_files::sync_directory(directory)
}

pub fn initialize(testing: bool) -> Result<Datastore, String> {
    let directory = data_dir(testing)?;
    let owner_path = directory.join("owner.lock");
    if owner_path.is_symlink() {
        return Err("The vault lock must not be a symbolic link".into());
    }
    let owner = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(owner_path)
        .map_err(|_| "Unable to open the vault lock")?;
    owner
        .try_lock()
        .map_err(|_| "Another PeakActivity process owns this vault")?;
    let store = Datastore::new_locked();
    let status = VaultStatus {
        state: "locked",
        message: None,
        has_vault: has_local_vault(&directory),
        generation: 0,
    };
    VAULT
        .set(Mutex::new(Vault {
            directory,
            account: if testing { "testing" } else { "primary" },
            _owner: owner,
            store: store.clone(),
            status,
        }))
        .map_err(|_| "Vault already initialized")?;
    let _ = REPORT_STORE.set(store.clone());
    Ok(store)
}

pub(crate) fn invalidate_reports() {
    if let Some(store) = REPORT_STORE.get() {
        store.invalidate_report_runtime();
    }
}

pub fn status() -> VaultStatus {
    let Some(state) = VAULT.get() else {
        return VaultStatus {
            state: "failed",
            message: Some("Vault is not initialized".into()),
            has_vault: false,
            generation: 0,
        };
    };
    match state.try_lock() {
        Ok(vault) => vault.status.clone(),
        Err(TryLockError::WouldBlock) => VaultStatus {
            state: "opening",
            message: Some("Waiting for the current vault operation".into()),
            has_vault: true,
            generation: 0,
        },
        Err(TryLockError::Poisoned(poisoned)) => {
            invalidate_reports();
            let mut vault = poisoned.into_inner();
            clear_support_preview();
            crate::capture::stop();
            crate::local_session::revoke_all();
            let _ = vault.store.lock();
            vault.status.state = "failed";
            vault.status.message = Some(
                "A vault operation stopped unexpectedly. Retry to recover its journaled state."
                    .into(),
            );
            let status = vault.status.clone();
            state.clear_poison();
            status
        }
    }
}

pub fn data_changed() {
    if let Some(state) = VAULT.get() {
        if let Ok(mut vault) = state.lock() {
            vault.status.generation = vault.status.generation.saturating_add(1);
            clear_support_preview();
        }
    }
}

pub fn is_ready() -> bool {
    status().state == "ready"
}

pub(crate) fn with_ready_store<T>(
    operation: impl FnOnce(&Datastore) -> Result<T, String>,
) -> Result<T, String> {
    let state = VAULT.get().ok_or("Vault is not initialized")?;
    let vault = state.lock().map_err(|_| "Vault state unavailable")?;
    if vault.status.state != "ready" || vault.store.is_locked() {
        return Err("Unlock the encrypted vault before using device sync".into());
    }
    operation(&vault.store)
}

fn with_vault<T>(operation: impl FnOnce(&mut Vault) -> Result<T, String>) -> Result<T, String> {
    let mut vault = VAULT
        .get()
        .ok_or("Vault is not initialized")?
        .lock()
        .map_err(|_| "Vault state unavailable")?;
    apply_vault_operation(&mut vault, operation)
}

fn with_ready_vault<T>(
    operation: impl FnOnce(&mut Vault) -> Result<T, String>,
) -> Result<T, String> {
    let mut vault = VAULT
        .get()
        .ok_or("Vault is not initialized")?
        .lock()
        .map_err(|_| "Vault state unavailable")?;
    if vault.status.state != "ready" || vault.store.is_locked() {
        return Err("Unlock the encrypted vault before using device sync".into());
    }
    operation(&mut vault)
}

fn apply_vault_operation<T>(
    vault: &mut Vault,
    operation: impl FnOnce(&mut Vault) -> Result<T, String>,
) -> Result<T, String> {
    vault.status.state = "opening";
    vault.status.message = None;
    vault.status.generation = vault.status.generation.saturating_add(1);
    let result = operation(vault);
    if let Err(message) = &result {
        invalidate_reports();
        clear_support_preview();
        crate::sync::clear_pending_pairing();
        crate::capture::stop();
        crate::local_session::revoke_all();
        let _ = vault.store.lock();
        vault.status.state = "failed";
        vault.status.message = Some(message.clone());
    }
    vault.status.has_vault = has_local_vault(&vault.directory);
    result
}

fn stop(vault: &mut Vault) -> Result<(), String> {
    invalidate_reports();
    clear_support_preview();
    crate::sync::clear_pending_pairing();
    crate::capture::stop();
    crate::local_session::revoke_all();
    vault
        .store
        .lock()
        .map_err(|_| "The vault was closed but its final write could not be confirmed".into())
}

fn clear_support_preview() {
    if let Some(preview) = SUPPORT_PREVIEW.get() {
        if let Ok(mut preview) = preview.lock() {
            *preview = None;
        }
    }
}

fn mark_ready(vault: &Vault) -> Result<(), String> {
    let path = vault.directory.join(READY_FILE);
    if path.is_symlink() {
        return Err("The vault marker must not be a symbolic link".into());
    }
    if path.exists() {
        if fs::read_to_string(path).map_err(|_| "The vault marker cannot be verified")?
            == READY_CONTENT
        {
            return Ok(());
        }
        return Err("The vault marker is invalid; existing data was preserved".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Cannot record encrypted vault setup")?;
    file.write_all(READY_CONTENT.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| "Cannot verify encrypted vault setup")?;
    vault_files::sync_directory(&vault.directory)
}

fn finish_transition(vault: &Vault, transition: &Transition, secret: &str) -> Result<(), String> {
    save_key(vault.account, secret)?;
    aw_datastore::vault::verify(&vault.directory.join("activity.db"), secret)?;
    vault_files::move_file(
        &vault.directory.join("transition.json"),
        &vault.directory.join("last-transition.json"),
        true,
    )?;
    match entry(&format!("{}.pending.{}", vault.account, transition.id))?.delete_credential() {
        Ok(()) | Err(Error::NoEntry) => {}
        Err(_) => {
            return Err(
                "The active vault opened, but a temporary recovery key could not be removed".into(),
            )
        }
    }
    Ok(())
}

fn preserve_interrupted_backup_history(
    candidate: &Path,
    candidate_key: &str,
    original: &Path,
    original_account: &str,
    primary_account: &str,
) -> Result<bool, String> {
    let old = if original.exists() {
        [original_account, primary_account]
            .into_iter()
            .filter_map(|account| read_key(account).ok())
            .find(|key| aw_datastore::vault::verify(original, key).is_ok())
    } else {
        None
    };
    let unknown = original.exists() && old.is_none();
    let continuity = if let Some(old) = old {
        aw_datastore::vault::export_backup_continuity(original, &old)?
    } else {aw_datastore::SyncBackupContinuityV1::default()};
    let store = Datastore::open_encrypted(
        candidate.to_str().ok_or("Invalid candidate path")?.into(),
        candidate_key.into(),
    )
    .map_err(|_| "The pending vault could not preserve backup deletion history")?;
    let merged =
        merge_backup_continuity(&store, continuity).and_then(|_| check_backup_restore_pointer(&store));
    let closed = store
        .lock()
        .map_err(|_| "The pending vault history write could not be confirmed");
    merged?;
    closed?;
    aw_datastore::vault::verify(candidate, candidate_key)?;
    Ok(unknown)
}

fn recover_transition(vault: &mut Vault) -> Result<(), String> {
    let Some(transition) = vault_files::read_journal(&vault.directory, "transition.json")? else {
        return Ok(());
    };
    let active = vault.directory.join("activity.db");
    let staged = vault.directory.join(transition.staged());
    let rollback = vault.directory.join(transition.rollback());
    let pending = read_key(&format!("{}.pending.{}", vault.account, transition.id))?;
    if active.exists() && aw_datastore::vault::verify(&active, &pending).is_ok() {
        let unknown = preserve_interrupted_backup_history(
            &active,
            &pending,
            &rollback,
            &format!("{}.rollback.{}", vault.account, transition.id),
            vault.account,
        )?;
        finish_transition(vault, &transition, &pending)?;
        if unknown {
            vault.status.message=Some("The original vault was preserved, but its backup deletion history could not be verified.".into());
        }
        return Ok(());
    }
    if staged.exists() && aw_datastore::vault::verify(&staged, &pending).is_ok() {
        let original = if active.exists() { &active } else { &rollback };
        let unknown = preserve_interrupted_backup_history(
            &staged,
            &pending,
            original,
            &format!("{}.rollback.{}", vault.account, transition.id),
            vault.account,
        )?;
        if active.exists() {
            if rollback.exists() {
                return Err("Recovery files conflict; all versions were preserved".into());
            }
            vault_files::move_file(&active, &rollback, false)?;
        }
        vault_files::move_file(&staged, &active, false)?;
        finish_transition(vault, &transition, &pending)?;
        if unknown {
            vault.status.message=Some("The original vault was preserved, but its backup deletion history could not be verified.".into());
        }
        return Ok(());
    }
    if !active.exists() && rollback.exists() {
        let old = read_key(&format!("{}.rollback.{}", vault.account, transition.id))?;
        aw_datastore::vault::verify(&rollback, &old)?;
        vault_files::move_file(&rollback, &active, false)?;
        save_key(vault.account, &old)?;
        vault_files::move_file(
            &vault.directory.join("transition.json"),
            &vault
                .directory
                .join(format!("aborted-{}.json", transition.id)),
            false,
        )?;
        return Ok(());
    }
    Err("An interrupted vault change needs recovery. All files were preserved; do not create a new vault over them.".into())
}

fn open(vault: &mut Vault) -> Result<(), String> {
    if !vault.store.is_locked() {
        vault.status.state = "ready";
        return Ok(());
    }
    recover_transition(vault)?;
    let path = vault.directory.join("activity.db");
    let ready = vault.directory.join(READY_FILE);
    if ready.is_symlink() {
        return Err("The vault marker must not be a symbolic link".into());
    }
    if ready.exists() && !path.exists() {
        return Err(
            "The vault database is missing. Restore a backup; a new vault was not created.".into(),
        );
    }
    if path.is_symlink() {
        return Err("The vault must not be a symbolic link".into());
    }
    let secret = key(&entry(vault.account)?, path.exists())?;
    vault
        .store
        .unlock_encrypted(
            path.to_str().ok_or("Invalid vault path")?.into(),
            secret.to_string(),
        )
        .map_err(|_| {
            "The vault key did not open this database. The original data was preserved."
        })?;
    vault.status.state = "ready";
    if crate::capture::initialize(vault.store.clone()).is_err() {
        vault.status.message = Some("History is available, but recording is blocked by invalid privacy settings. Reset privacy controls to repair them.".into());
    }
    mark_ready(vault)?;
    Ok(())
}

pub fn unlock() -> Result<VaultStatus, String> {
    with_vault(|vault| {
        open(vault)?;
        Ok(vault.status.clone())
    })
}

pub fn lock() -> Result<VaultStatus, String> {
    invalidate_reports();
    crate::local_session::revoke_all();
    clear_support_preview();
    with_vault(|vault| {
        crate::sync::clear_pending_pairing();
        let pause_result = if vault.store.is_locked() {
            Ok(())
        } else {
            vault
                .store
                .pause_capture()
                .map(|_| ())
                .map_err(|_| "Recording was stopped, but its stopped state could not be saved")
        };
        crate::capture::stop();
        let close_result = vault
            .store
            .lock()
            .map_err(|_| "Vault data could not be fully closed")
            .map(|_| {
                vault.status.state = "locked";
            });
        pause_result?;
        close_result?;
        Ok(vault.status.clone())
    })
}

fn check_backup_restore_pointer(store: &Datastore) -> Result<(), String> {
    let Some(snapshot) = store
        .load_sync_snapshot()
        .map_err(|_| "The restored backup pointer could not be checked")?
    else {
        return Ok(());
    };
    let header = snapshot
        .envelopes
        .first()
        .ok_or("The restored backup pointer is invalid")?;
    let context = store
        .get_sync_policy_context()
        .map_err(|_| "Backup deletion history context is unavailable")?
        .context_id;
    store.ensure_sync_backup_not_deleted(context,header.vault_id.clone(),header.key_epoch,
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,snapshot.snapshot_id),snapshot.envelopes.iter().map(|object|object.object_id.clone()).collect())
        .map_err(|_| "The older vault refers to a backup already marked deleted; original files were preserved".into())
}

fn merge_backup_continuity(store:&Datastore,state:aw_datastore::SyncBackupContinuityV1)->Result<(),String>{
    let context=store.get_sync_policy_context().map_err(|_|"Backup history context is unavailable")?.context_id;
    store.merge_sync_backup_continuity(context,state,chrono::Utc::now().to_rfc3339()).map_err(|_|"Protected backup continuity could not be preserved".to_string())
}

fn replace(
    vault: &mut Vault,
    source: &Path,
    source_key: Option<&str>,
    reset_privacy: bool,
) -> Result<(), String> {
    replace_with(vault, source, source_key, reset_privacy, true, |_| Ok(()))
}

fn replace_with(
    vault: &mut Vault,
    source: &Path,
    source_key: Option<&str>,
    reset_privacy: bool,
    rollback_allowed: bool,
    transform: impl FnOnce(&Datastore) -> Result<(), String>,
) -> Result<(), String> {
    let mut continuity = if vault.store.is_locked() {
        aw_datastore::SyncBackupContinuityV1::default()
    } else {
        let context = vault
            .store
            .get_sync_policy_context()
            .map_err(|_| "Backup deletion history context is unavailable")?
            .context_id;
        vault
            .store
            .export_sync_backup_continuity(context)
            .map_err(|_| "Backup deletion history could not be verified")?
    };
    stop(vault)?;
    recover_transition(vault)?;
    let active = vault.directory.join("activity.db");
    let old_key = if active.exists() {
        read_key(vault.account)
            .ok()
            .filter(|key| aw_datastore::vault::verify(&active, key).is_ok())
    } else {
        None
    };
    let history_unknown = active.exists() && old_key.is_none();
    if let Some(key) = old_key.as_ref() {
        continuity = aw_datastore::vault::export_backup_continuity(&active, key)?;
    } else if history_unknown && !reset_privacy {
        return Err(
            "The current vault key is unavailable; restore a backup instead of rotating it".into(),
        );
    }
    let transition = Transition {
        id: random_secret()?[..32].to_string(),
        had_active: active.exists(),
        rollback_allowed,
    };
    let staged = vault.directory.join(transition.staged());
    let secret = random_secret()?;
    aw_datastore::vault::encrypted_copy(source, source_key, &staged, &secret)?;
    let candidate = Datastore::open_encrypted(
        staged.to_str().ok_or("Invalid staging path")?.into(),
        secret.to_string(),
    )
    .map_err(|_| "The staged database is not compatible; the active vault was not changed")?;
    if reset_privacy {
        candidate
            .reset_privacy()
            .map_err(|_| "Cannot initialize restored privacy controls")?;
    }
    if let Err(error) = merge_backup_continuity(&candidate, continuity)
        .and_then(|_| transform(&candidate))
        .and_then(|_| check_backup_restore_pointer(&candidate))
    {
        if candidate.lock().is_ok() {
            let _ = fs::remove_file(&staged);
        }
        return Err(error);
    }
    candidate
        .lock()
        .map_err(|_| "Cannot finish the staged database")?;
    aw_datastore::vault::verify(&staged, &secret)?;
    if let Some(old) = old_key.as_ref() {
        save_key(
            &format!("{}.rollback.{}", vault.account, transition.id),
            old,
        )?;
    }
    save_key(
        &format!("{}.pending.{}", vault.account, transition.id),
        &secret,
    )?;
    vault_files::write_journal(&vault.directory, &transition)?;
    if transition.had_active {
        vault_files::move_file(&active, &vault.directory.join(transition.rollback()), false)?;
    }
    vault_files::move_file(&staged, &active, false)?;
    finish_transition(vault, &transition, &secret)?;
    open(vault)?;
    if history_unknown {
        vault.status.message=Some("The original vault was preserved, but its backup deletion history could not be verified.".into());
    }
    Ok(())
}

pub(crate) fn rotate_sync_keys(revoke_device: Option<[u8; 16]>) -> Result<(bool, u64), String> {
    with_ready_vault(|vault| {
        let (material, data_key) = {
            let _workflow = crate::sync::idle_workflow()?;
            if let Some(device_id) = revoke_device {
                if vault
                    .store
                    .load_sync_device_identity()
                    .map_err(|_| "The encrypted vault cannot load its sync identity")?
                    .is_some_and(|identity| identity.device_id() == &device_id)
                {
                    return Err("The current device cannot revoke itself".into());
                }
                let active = vault
                    .store
                    .list_sync_trusted_devices()
                    .map_err(|_| "The encrypted vault cannot inspect device access")?
                    .iter()
                    .any(|peer| peer.device_id == device_id && peer.revoked_at.is_none());
                if !active {
                    return Err("The selected device is no longer active".into());
                }
            }
            crate::sync::rotated_sync_key_material(&vault.store)?
        };
        let epoch = material.key_epoch();
        let original = read_key(vault.account)?;
        let source = vault.directory.join("activity.db");
        apply_vault_operation(vault, |vault| {
            let capture = vault
                .store
                .capture_policy()
                .map_err(|_| "The vault recording state could not be checked")?;
            if capture.recording {
                vault
                    .store
                    .pause_capture()
                    .map_err(|_| "Recording must be paused before sync key rotation")?;
            }
            replace_with(
                vault,
                &source,
                Some(&original),
                false,
                revoke_device.is_none(),
                move |candidate| {
                    let snapshot = crate::sync::encrypt_current_snapshot(candidate, &data_key)?;
                    let rotated = candidate
                        .rotate_sync_key_material(
                            material,
                            snapshot,
                            revoke_device,
                            chrono::Utc::now().to_rfc3339(),
                        )
                        .map_err(|_| "The encrypted vault could not rotate sync keys")?;
                    if !rotated {
                        return Err("The selected device is no longer active".into());
                    }
                    Ok(())
                },
            )?;
            Ok((true, epoch))
        })
    })
}

pub(crate) fn restore_sync_recovery_kit(
    kit: RecoveryKitV1,
    phrase: &str,
    encrypted: EncryptedSyncSnapshotV1,
) -> Result<crate::sync::SyncRestorePreviewV1, String> {
    restore_sync_recovery_kit_with_context(kit, phrase, encrypted, None)
}

pub(crate) fn restore_sync_recovery_kit_with_context(
    kit: RecoveryKitV1,
    phrase: &str,
    encrypted: EncryptedSyncSnapshotV1,
    expected_context: Option<&str>,
) -> Result<crate::sync::SyncRestorePreviewV1, String> {
    with_ready_vault(|vault| {
        check_sync_restore_context(&vault.store, expected_context)?;
        // Validate while ready; a refused restore must not stop the current vault.
        let (recovered, export, preview) = {
            let _workflow = crate::sync::idle_workflow()?;
            crate::sync::validate_restore_preview(&vault.store, &kit, phrase, &encrypted)?
        };
        let material = crate::sync::material_from_keys(
            &recovered.account_root_key,
            &recovered.wrapped_vault_key,
        )?;
        let snapshot = SyncSnapshotV1::new(
            crate::sync::decode_fixed::<16>(&encrypted.snapshot_id)?,
            encrypted.envelopes,
        );
        let identity =
            aw_sync_e2ee::generate_device_identity().map_err(|error| error.to_string())?;
        let identity = aw_datastore::SyncDeviceIdentity::new(
            *identity.device_id_bytes(),
            identity.secret_for_storage(),
            identity.signing_seed_for_storage(),
        );
        let expected_buckets = export.activity.buckets.len();
        let expected_events = export
            .activity
            .buckets
            .values()
            .map(|bucket| {
                bucket
                    .events
                    .as_ref()
                    .map(|events| events.clone().take_inner().len())
                    .unwrap_or(0)
            })
            .sum::<usize>();
        let original = read_key(vault.account)?;
        let source = vault.directory.join("activity.db");
        // Exercise the same atomic restore before closing the active vault.
        let validation_path = vault.directory.join(format!(
            ".sync-recovery-validation-{}.db",
            &random_secret()?[..32]
        ));
        let validation_secret = random_secret()?;
        let validated = (|| {
            aw_datastore::vault::encrypted_copy(
                &source,
                Some(&original),
                &validation_path,
                &validation_secret,
            )
            .map_err(|_| "The local recovery target could not be copied privately")?;
            let validation = Datastore::open_encrypted(
                validation_path.to_string_lossy().into_owned(),
                validation_secret.to_string(),
            )
            .map_err(|_| "The recovery snapshot could not be validated privately")?;
            let result = (|| {
                validation.restore_sync_recovery_data_with_policy_target(
                    aw_models::BucketsExport { buckets: export.activity.buckets.clone() },
                    material.clone(), snapshot.clone(), export.sync.clone(), identity.clone(),Some(preview.target_policy_sha256.clone()),
                ).map_err(|_| "The recovery activity, local policy or continuity state changed or is invalid")
            })();
            validation.close();
            result
        })();
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", validation_path.display()));
        }
        let validated = validated?;
        if validated.events_skipped != 0
            || validated.buckets_created != expected_buckets
            || validated.buckets_merged != 0
            || validated.events_imported != expected_events
        {
            return Err("The recovery activity snapshot is incomplete".into());
        }
        let expected_policy = preview.target_policy_sha256.clone();
        check_sync_restore_context(&vault.store, expected_context)?;
        apply_vault_operation(vault, |vault| {
            replace_with(
                vault,
                &source,
                Some(&original),
                false,
                true,
                move |candidate| {
                    if !candidate
                        .get_buckets()
                        .map_err(|_| "The clean vault could not be checked")?
                        .is_empty()
                    {
                        return Err("Sync snapshot restore requires a clean activity vault".into());
                    }
                    let imported = candidate
                        .restore_sync_recovery_data_with_policy_target(
                            export.activity,
                            material,
                            snapshot,
                            export.sync,
                            identity,
                            Some(expected_policy),
                        )
                        .map_err(|_| "The encrypted activity snapshot could not be restored")?;
                    if imported.events_skipped != 0
                        || imported.buckets_created != expected_buckets
                        || imported.buckets_merged != 0
                        || imported.events_imported != expected_events
                    {
                        return Err("The restored activity snapshot was incomplete".into());
                    }
                    Ok(())
                },
            )?;
            crate::sync::mark_recovery_kit_pending()?;
            Ok(preview)
        })
    })
}

pub(crate) fn check_sync_restore_context(
    store: &Datastore,
    expected: Option<&str>,
) -> Result<(), String> {
    if let Some(expected) = expected {
        let current = store
            .get_sync_policy_context()
            .map_err(|_| "Recovery target context is unavailable")?;
        if current.context_id != expected {
            return Err("Recovery target changed; refresh the restore preview".into());
        }
    }
    Ok(())
}

#[derive(Serialize)]
pub struct BackupResult {
    pub recovery_code: String,
    pub status: VaultStatus,
}

fn backup(destination: PathBuf) -> Result<BackupResult, String> {
    if destination.exists() || destination.is_symlink() {
        return Err("The selected backup already exists; choose a new file name".into());
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf();
    if !parent.is_dir() {
        return Err("The selected backup folder is unavailable".into());
    }
    with_vault(|vault| {
        stop(vault)?;
        recover_transition(vault)?;
        let original = read_key(vault.account)?;
        let recovery = random_secret()?;
        let staged = parent.join(format!(
            ".peakactivity-backup-{}.tmp",
            &random_secret()?[..32]
        ));
        if let Err(error) = aw_datastore::vault::encrypted_copy(
            &vault.directory.join("activity.db"),
            Some(&original),
            &staged,
            &recovery,
        ) {
            let _ = fs::remove_file(&staged);
            return Err(error);
        }
        if let Err(error) = vault_files::move_file(&staged, &destination, false) {
            let _ = fs::remove_file(&staged);
            return Err(error);
        }
        if let Err(message) = open(vault) {
            invalidate_reports();
            crate::capture::stop();
            crate::local_session::revoke_all();
            let _ = vault.store.lock();
            vault.status.state = "failed";
            vault.status.message = Some(message);
        }
        Ok(BackupResult {
            recovery_code: recovery.to_string(),
            status: vault.status.clone(),
        })
    })
}

fn rotate() -> Result<VaultStatus, String> {
    with_vault(|vault| {
        stop(vault)?;
        recover_transition(vault)?;
        let original = read_key(vault.account)?;
        let source = vault.directory.join("activity.db");
        replace(vault, &source, Some(&original), false)?;
        Ok(vault.status.clone())
    })
}

fn rollback() -> Result<VaultStatus, String> {
    if let Some(state) = VAULT.get() {
        let vault = state.lock().map_err(|_| "Vault state unavailable")?;
        if let Some(transition) =
            vault_files::read_journal(&vault.directory, "last-transition.json")?
        {
            if !transition.rollback_allowed {
                return Err("A lost-device revocation cannot be rolled back; re-pair the remaining devices instead".into());
            }
        }
    }
    with_vault(|vault| {
        stop(vault)?;
        recover_transition(vault)?;
        let previous = vault_files::read_journal(&vault.directory, "last-transition.json")?
            .ok_or("No previous vault is available")?;
        if !previous.had_active {
            return Err("This change had no previous vault".into());
        }
        if !previous.rollback_allowed {
            return Err("A lost-device revocation cannot be rolled back; re-pair the remaining devices instead".into());
        }
        let secret = read_key(&format!("{}.rollback.{}", vault.account, previous.id))?;
        let source = vault.directory.join(previous.rollback());
        replace(vault, &source, Some(&secret), true)?;
        Ok(vault.status.clone())
    })
}

fn delete_local() -> Result<VaultStatus, String> {
    with_vault(|vault| {
        if vault.directory.is_symlink() {
            return Err("The vault directory must not be a symbolic link".into());
        }
        stop(vault)?;
        let accounts = recovery_accounts(&vault.directory, vault.account)?;
        let keys = read_existing_keys(&accounts)?;
        delete_os_keys(&accounts, &keys)?;
        erase_vault_files(&vault.directory)?;
        vault.status.state = "locked";
        vault.status.message = None;
        Ok(vault.status.clone())
    })
}

pub fn device_id(testing: bool) -> Result<String, String> {
    let path = data_dir(testing)?.join("device-id");
    if path.exists() {
        return fs::read_to_string(path).map_err(|_| "Unable to read device identifier".into());
    }
    let value = random_secret()?.to_string();
    fs::write(path, &value).map_err(|_| "Unable to store device identifier")?;
    Ok(value)
}

fn support_bundle_json(store: &Datastore, testing: bool) -> Result<String, String> {
    let policy = store
        .capture_policy()
        .map_err(|_| "Capture settings are unavailable")?;
    let buckets = store
        .get_buckets()
        .map_err(|_| "Local data summary is unavailable")?;
    let mut event_count = 0_u64;
    for bucket in buckets.values() {
        let count = store
            .get_event_count(&bucket.id, None, None)
            .map_err(|_| "Local data summary is unavailable")?;
        event_count += u64::try_from(count).map_err(|_| "Local data summary is invalid")?;
    }
    let raw_retention_days = store
        .get_key_value("settings.rawRetentionDays")
        .ok()
        .and_then(|value| serde_json::from_str::<u32>(&value).ok())
        .filter(|days| *days <= 3650)
        .unwrap_or(0);
    let privacy_filter_count = store
        .get_key_value("settings.privacy_filters")
        .ok()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok())
        .and_then(|value| value.as_array().map(Vec::len))
        .unwrap_or(0);
    let runtime = crate::capture::runtime();
    let expected_helpers = runtime
        .get("expected")
        .and_then(|value| value.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    let running_helpers = runtime
        .get("modules")
        .and_then(|value| value.as_object())
        .map(|modules| {
            modules
                .values()
                .filter(|value| value.as_bool() == Some(true))
                .count()
        })
        .unwrap_or(0);
    let log_summary = fs::read_to_string(crate::logging::get_log_path())
        .map(|content| summarize_log_text(&content))
        .unwrap_or_default();

    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": 1,
        "product": "PeakActivity",
        "version": option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"),
        "generated_at": chrono::Utc::now(),
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "testing_profile": testing,
        "vault_state": "unlocked",
        "data_summary": {"bucket_count": buckets.len(), "event_count": event_count},
        "capture": {
            "recording": policy.active(chrono::Utc::now()),
            "sources": {"window": policy.window, "idle": policy.idle, "browser": policy.browser},
            "fields": {"titles": policy.titles, "urls": policy.urls, "paths": policy.paths},
            "excluded_app_count": policy.excluded_apps.len(),
            "excluded_domain_count": policy.excluded_domains.len(),
            "privacy_filter_count": privacy_filter_count,
        },
        "helpers": {"expected": expected_helpers, "running": running_helpers},
        "log_summary": log_summary,
        "raw_retention_days": raw_retention_days,
        "redactions": {
            "activity_payloads_included": false,
            "bucket_names_included": false,
            "window_titles_included": false,
            "file_paths_included": false,
            "urls_included": false,
            "log_messages_included": false,
            "tokens_or_keys_included": false,
        }
    }))
    .map_err(|_| "Support preview could not be encoded".into())
}

async fn save_support_bundle(
    app: tauri::AppHandle,
    preview_id: String,
) -> Result<Option<String>, String> {
    let cache = SUPPORT_PREVIEW
        .get()
        .ok_or("Generate a new support preview before saving")?;
    let content = cache
        .lock()
        .map_err(|_| "Support preview is unavailable")?
        .as_ref()
        .filter(|(id, _)| id == &preview_id)
        .map(|(_, content)| content.clone())
        .ok_or("Generate a new support preview before saving")?;
    if content.len() > 64 * 1024 {
        return Err("Support preview is too large".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let Some(path) = app
            .dialog()
            .file()
            .set_title("Save redacted support bundle")
            .set_file_name("peakactivity-support.json")
            .blocking_save_file()
        else {
            return Ok(None);
        };
        let destination = path
            .into_path()
            .map_err(|_| "Choose a local support file path")?;
        if destination.exists() || destination.is_symlink() {
            return Err("The selected file already exists; choose a new file name".into());
        }
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.is_dir() {
            return Err("The selected folder is unavailable".into());
        }
        let staged = parent.join(format!(
            ".peakactivity-support-{}.tmp",
            &random_secret()?[..32]
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let write_result = (|| {
            let mut file = options
                .open(&staged)
                .map_err(|_| "Could not create the support preview file")?;
            file.write_all(content.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| "Could not write the support preview file")?;
            vault_files::move_file(&staged, &destination, false)?;
            Ok::<(), String>(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&staged);
            return Err(error);
        }
        if let Some(cache) = SUPPORT_PREVIEW.get() {
            if let Ok(mut cache) = cache.lock() {
                if cache.as_ref().is_some_and(|(id, _)| id == &preview_id) {
                    *cache = None;
                }
            }
        }
        Ok(destination
            .file_name()
            .map(|name| name.to_string_lossy().into_owned()))
    })
    .await
    .map_err(|_| "Support bundle save stopped")?
}

#[tauri::command]
pub async fn support_bundle_preview(
    window: tauri::WebviewWindow,
) -> Result<SupportBundlePreview, String> {
    crate::local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(|| {
        let state = VAULT.get().ok_or("Vault is not initialized")?;
        let vault = state.lock().map_err(|_| "Vault state unavailable")?;
        if vault.status.state != "ready" || vault.store.is_locked() {
            return Err("Unlock the vault before previewing a support bundle".into());
        }
        let content = support_bundle_json(&vault.store, vault.account == "testing")?;
        if content.len() > 64 * 1024 {
            return Err("Support preview is too large".into());
        }
        let id = random_secret()?.to_string();
        let preview = SupportBundlePreview {
            id: id.clone(),
            content: content.clone(),
        };
        *SUPPORT_PREVIEW
            .get_or_init(|| Mutex::new(None))
            .lock()
            .map_err(|_| "Support preview is unavailable")? = Some((id, content));
        Ok(preview)
    })
    .await
    .map_err(|_| "Support preview stopped")?
}

#[tauri::command]
pub async fn export_support_bundle(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
    preview_id: String,
) -> Result<Option<String>, String> {
    crate::local_session::verify_window(&window)?;
    save_support_bundle(app, preview_id).await
}

#[tauri::command]
pub fn vault_status(window: tauri::WebviewWindow) -> Result<VaultStatus, String> {
    crate::local_session::verify_window(&window)?;
    Ok(status())
}

#[tauri::command]
pub async fn unlock_vault(window: tauri::WebviewWindow) -> Result<VaultStatus, String> {
    crate::local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(unlock)
        .await
        .map_err(|_| "Unlock operation stopped")?
}

#[tauri::command]
pub async fn lock_vault(window: tauri::WebviewWindow) -> Result<VaultStatus, String> {
    crate::local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(lock)
        .await
        .map_err(|_| "Lock operation stopped")?
}

#[tauri::command]
pub async fn backup_vault(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
) -> Result<Option<BackupResult>, String> {
    crate::local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        let Some(path) = app
            .dialog()
            .file()
            .set_title("Save encrypted vault backup")
            .set_file_name("peakactivity-backup.db")
            .blocking_save_file()
        else {
            return Ok(None);
        };
        backup(path.into_path().map_err(|_| "Choose a local backup path")?).map(Some)
    })
    .await
    .map_err(|_| "Backup operation stopped")?
}

#[tauri::command]
pub async fn restore_vault(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
    recovery_code: String,
    plaintext: bool,
) -> Result<Option<VaultStatus>, String> {
    crate::local_session::verify_window(&window)?;
    let secret = Zeroizing::new(recovery_code);
    tauri::async_runtime::spawn_blocking(move || {
        let Some(path) = app.dialog().file().set_title(if plaintext { "Select plaintext Rust database" } else { "Select encrypted vault backup" }).blocking_pick_file() else { return Ok(None); };
        if !app.dialog().message("Replace the current vault with this database? The previous encrypted vault and original input file will be preserved. Restored recording starts off.")
            .title("Restore local data").buttons(MessageDialogButtons::OkCancel).blocking_show() { return Ok(None); }
        let path = path.into_path().map_err(|_| "Choose a local database file")?;
        with_vault(|vault| {
            replace(vault, &path, if plaintext { None } else { Some(secret.as_str()) }, true)?;
            Ok(Some(vault.status.clone()))
        })
    }).await.map_err(|_| "Restore operation stopped")?
}

#[tauri::command]
pub async fn rotate_vault_key(window: tauri::WebviewWindow) -> Result<VaultStatus, String> {
    crate::local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(rotate)
        .await
        .map_err(|_| "Key rotation stopped")?
}

#[tauri::command]
pub async fn rollback_vault(window: tauri::WebviewWindow) -> Result<VaultStatus, String> {
    crate::local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(rollback)
        .await
        .map_err(|_| "Rollback stopped")?
}

#[tauri::command]
pub async fn delete_local_vault(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
) -> Result<Option<VaultStatus>, String> {
    crate::local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        if !app.dialog().message("Delete this device's encrypted activity history, privacy settings, AI endpoint credentials, device identity and on-device recovery copies? Files saved outside the vault folder, app appearance preferences and logs are not deleted. This cannot be undone.")
            .title("Delete local vault").buttons(MessageDialogButtons::OkCancel).blocking_show() {
            return Ok(None);
        }
        delete_local().map(Some)
    }).await.map_err(|_| "Vault deletion stopped")?
}

#[tauri::command]
pub async fn repair_privacy(window: tauri::WebviewWindow) -> Result<VaultStatus, String> {
    crate::local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(|| {
        with_vault(|vault| {
            if vault.store.is_locked() {
                return Err("Unlock the vault first".into());
            }
            vault
                .store
                .reset_privacy()
                .map_err(|_| "Privacy controls could not be repaired")?;
            crate::capture::initialize(vault.store.clone())?;
            vault.status.state = "ready";
            vault.status.message = None;
            Ok(vault.status.clone())
        })
    })
    .await
    .map_err(|_| "Privacy repair stopped")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring::credential::{CredentialApi, CredentialBuilderApi};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    static REPORT_FAIL_READ: AtomicBool = AtomicBool::new(false);
    static REPORT_READS: AtomicUsize = AtomicUsize::new(0);
    static REPORT_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
    static REPORT_AT_FAILURE: AtomicUsize = AtomicUsize::new(0);
    struct MemoryBuilder(Arc<Mutex<BTreeMap<String, Vec<u8>>>>);
    struct MemoryCredential {
        values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        account: String,
    }
    impl CredentialApi for MemoryCredential {
        fn set_secret(&self, value: &[u8]) -> keyring::Result<()> {
            self.values
                .lock()
                .unwrap()
                .insert(self.account.clone(), value.to_vec());
            Ok(())
        }
        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            if self
                .account
                .ends_with("/native-report-lifecycle-test-vault")
                && REPORT_FAIL_READ.load(std::sync::atomic::Ordering::Acquire)
                && REPORT_READS.fetch_add(1, std::sync::atomic::Ordering::AcqRel) == 1
            {
                REPORT_AT_FAILURE.store(
                    REPORT_CALLBACKS.load(std::sync::atomic::Ordering::Acquire),
                    std::sync::atomic::Ordering::Release,
                );
                return Err(Error::NoEntry);
            }
            self.values
                .lock()
                .unwrap()
                .get(&self.account)
                .cloned()
                .ok_or(Error::NoEntry)
        }
        fn delete_credential(&self) -> keyring::Result<()> {
            self.values
                .lock()
                .unwrap()
                .remove(&self.account)
                .map(|_| ())
                .ok_or(Error::NoEntry)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
    impl CredentialBuilderApi for MemoryBuilder {
        fn build(
            &self,
            _: Option<&str>,
            service: &str,
            user: &str,
        ) -> keyring::Result<Box<keyring::credential::Credential>> {
            Ok(Box::new(MemoryCredential {
                values: self.0.clone(),
                account: format!("{service}/{user}"),
            }))
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
    struct RestoreKeyring;
    impl Drop for RestoreKeyring {
        fn drop(&mut self) {
            keyring::set_default_credential_builder(keyring::default::default_credential_builder());
        }
    }

    fn shared_test_store(directory: &Path, key: &str) -> Datastore {
        if let Some(state) = VAULT.get() {
            let store = state.lock().unwrap().store.clone();
            store.lock().unwrap();
            store
                .unlock_encrypted(
                    directory.join("activity.db").to_str().unwrap().into(),
                    key.into(),
                )
                .unwrap();
            store
        } else {
            Datastore::open_encrypted(
                directory.join("activity.db").to_str().unwrap().into(),
                key.into(),
            )
            .unwrap()
        }
    }
    fn install_test_vault(vault: Vault) {
        let store = vault.store.clone();
        if let Some(state) = VAULT.get() {
            *state.lock().unwrap() = vault;
        } else {
            assert!(VAULT.set(Mutex::new(vault)).is_ok());
        }
        let _ = REPORT_STORE.set(store);
    }

    #[test]
    fn report_lock_direct_handle_precedes_busy_poisoned_failed_and_backup_cleanup() {
        let _serial = crate::sync::tests::RECOVERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        keyring::set_default_credential_builder(Box::new(MemoryBuilder(Arc::new(Mutex::new(
            BTreeMap::new(),
        )))));
        let _keyring = RestoreKeyring;
        let directory = std::env::temp_dir().join(format!(
            "peak-native-report-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let key = "a".repeat(64);
        let account = "native-report-lifecycle-test-vault";
        save_key(account, &key).unwrap();
        let store = shared_test_store(&directory, &key);
        store.enable_capture_policy().unwrap();
        store.pause_capture().unwrap();
        install_test_vault(Vault {
            directory: directory.clone(),
            account,
            _owner: File::create(directory.join("owner.lock")).unwrap(),
            store: store.clone(),
            status: VaultStatus {
                state: "ready",
                message: None,
                has_vault: true,
                generation: 0,
            },
        });
        let sessions = crate::local_session::initialize(5600, false).unwrap();
        let token = sessions.mint(aw_server::sessions::Scope::Admin).unwrap();
        let phase = Arc::new(AtomicUsize::new(1));
        let observed_phase = phase.clone();
        let observed_sessions = sessions.clone();
        let (notice, observations) = std::sync::mpsc::channel();
        store.set_report_invalidator(Arc::new(move || {
            REPORT_CALLBACKS.fetch_add(1, Ordering::AcqRel);
            let _ = notice.send((
                observed_phase.load(Ordering::Acquire),
                observed_sessions.token_alive(&token),
                VAULT.get().is_some_and(|s| s.is_poisoned()),
            ));
        }));
        let guard = VAULT.get().unwrap().lock().unwrap();
        let (done, pending) = std::sync::mpsc::channel();
        let closer = std::thread::spawn(move || done.send(lock()).unwrap());
        let early = observations.recv_timeout(std::time::Duration::from_millis(500));
        assert!(pending.try_recv().is_err());
        drop(guard);
        pending
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap();
        closer.join().unwrap();
        assert!(
            early.is_ok(),
            "native lock waited for VAULT before invalidating reports"
        );
        assert!(
            early.unwrap().1,
            "native lock revoked the session before direct invalidation"
        );
        assert!(store.is_locked());
        while observations.try_recv().is_ok() {}
        phase.store(2, Ordering::Release);
        store
            .unlock_encrypted(
                directory.join("activity.db").to_str().unwrap().into(),
                key.clone(),
            )
            .unwrap();
        {
            let mut vault = VAULT.get().unwrap().lock().unwrap();
            stop(&mut vault).unwrap();
        }
        assert_eq!(
            observations
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap()
                .0,
            2
        );
        assert!(store.is_locked());
        while observations.try_recv().is_ok() {}
        phase.store(3, Ordering::Release);
        store
            .unlock_encrypted(
                directory.join("activity.db").to_str().unwrap().into(),
                key.clone(),
            )
            .unwrap();
        {
            let mut vault = VAULT.get().unwrap().lock().unwrap();
            assert!(apply_vault_operation(&mut vault, |_| Err::<(), String>(
                "synthetic failure".into()
            ))
            .is_err());
            assert_eq!(vault.status.state, "failed");
        }
        assert_eq!(
            observations
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap()
                .0,
            3
        );
        assert!(store.is_locked());
        while observations.try_recv().is_ok() {}
        phase.store(4, Ordering::Release);
        store
            .unlock_encrypted(
                directory.join("activity.db").to_str().unwrap().into(),
                key.clone(),
            )
            .unwrap();
        assert!(std::panic::catch_unwind(|| {
            let _guard = VAULT.get().unwrap().lock().unwrap();
            panic!("synthetic vault poison");
        })
        .is_err());
        assert_eq!(status().state, "failed");
        let poisoned = observations
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert_eq!(poisoned.0, 4);
        assert!(poisoned.2);
        assert!(!VAULT.get().unwrap().is_poisoned());
        assert!(store.is_locked());
        phase.store(5, Ordering::Release);
        store
            .unlock_encrypted(
                directory.join("activity.db").to_str().unwrap().into(),
                key.clone(),
            )
            .unwrap();
        {
            VAULT.get().unwrap().lock().unwrap().status.state = "ready";
        }
        REPORT_READS.store(0, Ordering::Release);
        REPORT_FAIL_READ.store(true, Ordering::Release);
        let result = backup(directory.join("backup.pav")).unwrap();
        REPORT_FAIL_READ.store(false, Ordering::Release);
        assert_eq!(result.status.state, "failed");
        assert!(store.is_locked());
        assert!(
            REPORT_CALLBACKS.load(Ordering::Acquire) > REPORT_AT_FAILURE.load(Ordering::Acquire)
        );
        aw_datastore::Datastore::open_encrypted(
            directory.join("backup.pav").to_str().unwrap().into(),
            result.recovery_code,
        )
        .unwrap()
        .lock()
        .unwrap();
        store.set_report_invalidator(Arc::new(|| {}));
        entry(account).unwrap().delete_credential().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn native_recovery_restore_finishes_and_preserves_continuity_and_rollback() {
        let _serial = crate::sync::tests::RECOVERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        keyring::set_default_credential_builder(Box::new(MemoryBuilder(Arc::new(Mutex::new(
            BTreeMap::new(),
        )))));
        let _keyring = RestoreKeyring;
        crate::sync::clear_pending_pairing();
        let fixture = crate::sync::tests::recovery_fixture();
        let encrypted =
            crate::sync::encrypt_current_snapshot(&fixture.source, &fixture.data_key).unwrap();
        let snapshot = aw_sync_e2ee::EncryptedSyncSnapshotV1 {
            schema_version: 1,
            snapshot_id: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                encrypted.snapshot_id,
            ),
            envelopes: encrypted.envelopes,
        };
        let directory = std::env::temp_dir().join(format!(
            "peak-native-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let original = "e".repeat(64);
        let account = "native-recovery-test-vault";
        save_key(account, &original).unwrap();
        let store = shared_test_store(&directory, &original);
        store.enable_capture_policy().unwrap();
        store.pause_capture().unwrap();
        store.set_key_value("settings.theme", "\"light\"").unwrap();
        store.set_key_value("settings.classes", "[]").unwrap();
        let mut controls = store.capture_policy().unwrap();
        controls.window = false;
        controls.idle = false;
        controls.excluded_apps = vec!["Local sensitive application".into()];
        store.set_capture_policy(controls.clone()).unwrap();
        let controls = store.capture_policy().unwrap();
        let local_filters="[{\"enabled\":true,\"bucket_prefix\":null,\"field\":\"title\",\"pattern\":\"LocalOnly\",\"action\":\"drop\",\"replacement\":null}]";
        store
            .set_key_value("settings.privacy_filters", local_filters)
            .unwrap();
        let target_identity = [0x17; 16];
        store
            .create_sync_device_identity(&aw_datastore::SyncDeviceIdentity::new(
                target_identity,
                Zeroizing::new([0x27; 32]),
                Zeroizing::new([0x37; 32]),
            ))
            .unwrap();
        let old_bytes = fs::read(directory.join("activity.db")).unwrap();
        install_test_vault(Vault {
            _owner: File::create(directory.join("owner.lock")).unwrap(),
            directory: directory.clone(),
            account,
            store,
            status: VaultStatus {
                state: "ready",
                message: None,
                has_vault: true,
                generation: 0,
            },
        });
        let before = with_ready_vault(|vault| {
            crate::sync::validate_restore_preview(
                &vault.store,
                &fixture.kit,
                &fixture.phrase,
                &snapshot,
            )
            .map(|(_, _, preview)| preview.policy_conflict_count)
        })
        .unwrap();
        assert_eq!(before, 4);
        assert!(crate::sync::restore_sync_recovery_kit_from_input(
            fixture.kit.clone(),
            "invalid-recovery-phrase".into(),
            snapshot.clone()
        )
        .is_err());
        let state = VAULT.get().unwrap().lock().unwrap();
        assert_eq!(state.status.state, "ready");
        assert_eq!(state.status.generation, 0);
        assert!(!state.store.is_locked());
        assert_eq!(
            *state
                .store
                .load_sync_device_identity()
                .unwrap()
                .unwrap()
                .device_id(),
            target_identity
        );
        assert!(fs::read(directory.join("activity.db")).unwrap() == old_bytes);
        drop(state);
        let mut malformed: serde_json::Value = serde_json::from_slice(
            &aw_sync_e2ee::decrypt_snapshot(&fixture.data_key, &snapshot).unwrap(),
        )
        .unwrap();
        let mappings = malformed["sync"]["bucket_mappings"].as_array_mut().unwrap();
        assert!(!mappings.is_empty());
        mappings.push(mappings[0].clone());
        let malformed = aw_sync_e2ee::encrypt_snapshot(
            &fixture.data_key,
            &serde_json::to_vec(&malformed).unwrap(),
        )
        .unwrap();
        assert!(crate::sync::restore_sync_recovery_kit_from_input(
            fixture.kit.clone(),
            fixture.phrase.clone(),
            malformed
        )
        .is_err());
        let state = VAULT.get().unwrap().lock().unwrap();
        assert_eq!(
            state.status.state, "ready",
            "invalid continuity must be rejected before stopping the original vault"
        );
        assert_eq!(state.status.generation, 0);
        assert!(!state.store.is_locked());
        assert_eq!(
            *state
                .store
                .load_sync_device_identity()
                .unwrap()
                .unwrap()
                .device_id(),
            target_identity
        );
        assert!(fs::read(directory.join("activity.db")).unwrap() == old_bytes);
        drop(state);
        entry(account).unwrap().delete_credential().unwrap();
        assert!(crate::sync::restore_sync_recovery_kit_from_input(
            fixture.kit.clone(),
            fixture.phrase.clone(),
            snapshot.clone()
        )
        .is_err());
        assert_eq!(
            status().state,
            "ready",
            "unavailable native key must preserve the ready vault"
        );
        save_key(account, &original).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = crate::sync::restore_sync_recovery_kit_from_input(
                fixture.kit,
                fixture.phrase,
                snapshot,
            );
            sender
                .send((result, fixture.source, fixture.origin, fixture.vault_id))
                .unwrap();
        });
        let (result, source, origin, vault_id) = receiver
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("native restore must complete without reacquiring the vault mutex");
        let result = result.unwrap();
        assert_eq!(result.tombstone_count, 1);
        assert_eq!(result.policy_conflict_count, before);
        assert!(result.policy_continuity_present);
        assert_ne!(fs::read(directory.join("activity.db")).unwrap(), old_bytes);
        let state = VAULT.get().unwrap().lock().unwrap();
        assert_eq!(state.status.state, "ready");
        let recovered_identity = state.store.load_sync_device_identity().unwrap().unwrap();
        assert_ne!(*recovered_identity.device_id(), origin);
        assert_ne!(*recovered_identity.device_id(), target_identity);
        assert_eq!(
            state.store.list_sync_operations(origin, 1, 0, 16).unwrap(),
            source.list_sync_operations(origin, 1, 0, 16).unwrap()
        );
        assert_eq!(
            state
                .store
                .load_sync_manifest_head(vault_id, 1, origin)
                .unwrap(),
            source.load_sync_manifest_head(vault_id, 1, origin).unwrap()
        );
        let restored = state.store.export_sync_recovery_state(1).unwrap();
        assert_eq!(
            restored.event_mappings,
            source.export_sync_recovery_state(1).unwrap().event_mappings
        );
        assert!(restored
            .trusted_devices
            .iter()
            .any(|peer| peer.device_id == origin));
        assert!(
            state
                .store
                .sync_baseline_progress()
                .unwrap()
                .unwrap()
                .complete
        );
        assert_eq!(
            state.store.get_key_value("settings.theme").unwrap(),
            "\"light\""
        );
        assert_eq!(state.store.get_key_value("settings.classes").unwrap(), "[]");
        assert_eq!(
            aw_models::SyncCapturePreferencesV1::from_policy(
                &state.store.capture_policy().unwrap()
            ),
            aw_models::SyncCapturePreferencesV1::from_policy(&controls)
        );
        assert_eq!(
            state
                .store
                .get_key_value("settings.privacy_filters")
                .unwrap(),
            local_filters
        );
        assert!(!state.store.capture_policy().unwrap().recording);
        assert!(!state.store.sync_enabled().unwrap());
        assert!(state.store.sync_egress_consent().unwrap().is_none());
        let fields = state
            .store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .into_iter()
            .map(|candidate| candidate.field)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(fields.len(), before);
        assert_eq!(
            state
                .store
                .get_events("aw-watcher-window_native-recovery", None, None, None)
                .unwrap()
                .len(),
            1
        );
        let transition = vault_files::read_journal(&directory, "last-transition.json")
            .unwrap()
            .unwrap();
        assert!(transition.rollback_allowed && transition.had_active);
        aw_datastore::vault::verify(&directory.join(transition.rollback()), &original).unwrap();
        let current = read_key(account).unwrap();
        assert!(current.as_str() != original.as_str());
        aw_datastore::vault::verify(&directory.join("activity.db"), &current).unwrap();
        drop(state);
        assert!(rotate_sync_keys(None).is_err());
        assert_eq!(status().state, "ready");
        lock().unwrap();
        assert!(crate::sync::idle_workflow().is_ok());
        unlock().unwrap();
        rollback().unwrap();
        with_ready_store(|store| {
            assert!(store.get_buckets().unwrap().is_empty());
            assert!(store.load_sync_key_material().unwrap().is_none());
            assert_eq!(
                *store
                    .load_sync_device_identity()
                    .unwrap()
                    .unwrap()
                    .device_id(),
                target_identity
            );
            Ok(())
        })
        .unwrap();
        lock().unwrap();
        source.close();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn native_backup_whole_vault_restore_and_rollback_preserve_newer_deletions() {
        let _serial = crate::sync::tests::RECOVERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        keyring::set_default_credential_builder(Box::new(MemoryBuilder(Arc::new(Mutex::new(
            BTreeMap::new(),
        )))));
        let _keyring = RestoreKeyring;
        let directory = std::env::temp_dir().join(format!(
            "peak-native-backup-history-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let secret = "e".repeat(64);
        let account = "native-backup-history-test";
        save_key(account, &secret).unwrap();
        let store = shared_test_store(&directory, &secret);
        store.enable_capture_policy().unwrap();
        store.pause_capture().unwrap();
        install_test_vault(Vault {
            directory: directory.clone(),
            account,
            _owner: File::create(directory.join("owner.lock")).unwrap(),
            store: store.clone(),
            status: VaultStatus {
                state: "ready",
                message: None,
                has_vault: true,
                generation: 0,
            },
        });
        let older = directory.join("older.pav");
        let older_secret = backup(older.clone()).unwrap().recovery_code;
        let fixture = crate::sync::tests::recovery_fixture();
        let artifact =
            aw_sync_e2ee::encrypt_snapshot(&fixture.data_key, &vec![7;1_100_000]).unwrap();
        let fact =
            aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&fixture.data_key, &artifact)
                .unwrap()
                .fact()
                .clone();
        store
            .merge_sync_backup_deletions(
                store.get_sync_policy_context().unwrap().context_id,
                vec![fact.clone()],
                "2026-10-14T12:00:00Z".into(),
            )
            .unwrap();
        let proof=aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&fixture.data_key,&artifact).unwrap();
        let sealed=proof.seal(&fixture.data_key).unwrap();
        store.record_sync_backup_provider_intent(store.get_sync_policy_context().unwrap().context_id,proof,&fixture.data_key,sealed,"2026-10-14T12:00:00Z".into()).unwrap();
        with_vault(|vault| replace(vault, &older, Some(&older_secret), true)).unwrap();
        let retained=store.egress_lease().unwrap().sync_backup_provider_intent(store.get_sync_policy_context().unwrap().context_id,fact.bundle_sha256.clone()).unwrap().expect("sealed provider intent survives older restore");
        assert_eq!(aw_sync_e2ee::SnapshotDeletionProofV1::open_record(&fixture.data_key,&retained).unwrap(),fact);
        let resumed=aw_sync_e2ee::SnapshotDeletionProofV1::resume(&fixture.data_key,&retained,&artifact.envelopes[1..]).unwrap();
        assert!(!resumed.is_complete());assert!(resumed.allows_object(&artifact.envelopes[1]));assert!(!resumed.allows_object(&artifact.envelopes[0]));
        assert_eq!(
            store
                .export_sync_backup_deletions(store.get_sync_policy_context().unwrap().context_id)
                .unwrap(),
            vec![fact.clone()]
        );
        let later =
            aw_sync_e2ee::encrypt_snapshot(&fixture.data_key, b"deletion after replacement")
                .unwrap();
        let second = aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&fixture.data_key, &later)
            .unwrap()
            .fact()
            .clone();
        store
            .merge_sync_backup_deletions(
                store.get_sync_policy_context().unwrap().context_id,
                vec![second.clone()],
                "2026-10-14T12:01:00Z".into(),
            )
            .unwrap();
        lock().unwrap();
        rollback().unwrap();
        let facts = store
            .export_sync_backup_deletions(store.get_sync_policy_context().unwrap().context_id)
            .unwrap();
        assert_eq!(facts.len(), 2);
        let retained=store.egress_lease().unwrap().sync_backup_provider_intent(store.get_sync_policy_context().unwrap().context_id,fact.bundle_sha256.clone()).unwrap().expect("sealed provider intent survives rollback");
        assert_eq!(aw_sync_e2ee::SnapshotDeletionProofV1::open_record(&fixture.data_key,&retained).unwrap(),fact);
        let resumed=aw_sync_e2ee::SnapshotDeletionProofV1::resume(&fixture.data_key,&retained,&artifact.envelopes[1..]).unwrap();
        assert!(!resumed.is_complete());assert!(resumed.allows_object(&artifact.envelopes[1]));assert!(!resumed.allows_object(&artifact.envelopes[0]));
        assert!(facts.contains(&fact) && facts.contains(&second));
        assert!(!store.capture_policy().unwrap().recording);
        assert!(!store.sync_enabled().unwrap());
        lock().unwrap();
        fixture.source.close();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn native_backup_whole_vault_cannot_reactivate_a_known_deleted_snapshot() {
        let _serial = crate::sync::tests::RECOVERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        keyring::set_default_credential_builder(Box::new(MemoryBuilder(Arc::new(Mutex::new(
            BTreeMap::new(),
        )))));
        let _keyring = RestoreKeyring;
        let fixture = crate::sync::tests::recovery_fixture();
        let snapshot =
            crate::sync::encrypt_current_snapshot(&fixture.source, &fixture.data_key).unwrap();
        let encrypted = EncryptedSyncSnapshotV1 {
            schema_version: 1,
            snapshot_id: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                snapshot.snapshot_id,
            ),
            envelopes: snapshot.envelopes.clone(),
        };
        let fact =
            aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&fixture.data_key, &encrypted)
                .unwrap()
                .fact()
                .clone();
        let directory = std::env::temp_dir().join(format!(
            "peak-native-forgotten-pointer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let old = "d".repeat(64);
        let source_key = "e".repeat(64);
        let account = "native-backup-forgotten-pointer";
        save_key(account, &old).unwrap();
        let active = directory.join("activity.db");
        let input = directory.join("older.pav");
        backup_history_test_file(&active, &old, "original", fact.clone());
        let input_store =
            Datastore::open_encrypted(input.to_string_lossy().into_owned(), source_key.clone())
                .unwrap();
        let material = fixture.source.load_sync_key_material().unwrap().unwrap();
        input_store.install_sync_key_material(&material).unwrap();
        input_store.save_sync_snapshot(material, snapshot).unwrap();
        input_store.close();
        let before = fs::read(&active).unwrap();
        let input_before = fs::read(&input).unwrap();
        let mut vault = Vault {
            directory: directory.clone(),
            account,
            _owner: File::create(directory.join("owner.lock")).unwrap(),
            store: Datastore::new_locked(),
            status: VaultStatus {
                state: "locked",
                message: None,
                has_vault: true,
                generation: 0,
            },
        };
        assert!(replace(&mut vault, &input, Some(&source_key), true).is_err());
        assert_eq!(fs::read(&active).unwrap(), before);
        assert_eq!(fs::read(&input).unwrap(), input_before);
        assert_eq!(*read_key(account).unwrap(), old);
        assert!(vault_files::read_journal(&directory, "transition.json")
            .unwrap()
            .is_none());
        let candidate =
            Datastore::open_encrypted(input.to_string_lossy().into_owned(), source_key.clone())
                .unwrap();
        candidate
            .merge_sync_backup_deletions(
                candidate.get_sync_policy_context().unwrap().context_id,
                vec![fact],
                "2026-10-14T12:00:00Z".into(),
            )
            .unwrap();
        candidate.close();
        let transition = Transition {
            id: "b".repeat(32),
            had_active: true,
            rollback_allowed: true,
        };
        aw_datastore::vault::encrypted_copy(
            &input,
            Some(&source_key),
            &directory.join(transition.staged()),
            &source_key,
        )
        .unwrap();
        save_key(&format!("{account}.pending.{}", transition.id), &source_key).unwrap();
        save_key(&format!("{account}.rollback.{}", transition.id), &old).unwrap();
        vault_files::write_journal(&directory, &transition).unwrap();
        assert!(recover_transition(&mut vault).is_err());
        assert_eq!(fs::read(&active).unwrap(), before);
        assert!(directory.join(transition.staged()).exists());
        assert!(vault_files::read_journal(&directory, "transition.json")
            .unwrap()
            .is_some());
        fixture.source.close();
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    fn backup_history_test_file(
        path: &Path,
        secret: &str,
        marker: &str,
        fact: aw_models::SnapshotDeletionFactV1,
    ) {
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), secret.into()).unwrap();
        store.set_key_value("history-fixture", marker).unwrap();
        store
            .merge_sync_backup_deletions(
                store.get_sync_policy_context().unwrap().context_id,
                vec![fact],
                "2026-10-14T12:00:00Z".into(),
            )
            .unwrap();
        store.close();
    }
    fn backup_history_fact(
        key: &aw_sync_e2ee::VaultDataKeyV1,
        marker: &[u8],
    ) -> aw_models::SnapshotDeletionFactV1 {
        aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(
            key,
            &aw_sync_e2ee::encrypt_snapshot(key, marker).unwrap(),
        )
        .unwrap()
        .fact()
        .clone()
    }
    #[test]
    fn native_backup_interrupted_transitions_preserve_readable_old_history() {
        let _serial = crate::sync::tests::RECOVERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        keyring::set_default_credential_builder(Box::new(MemoryBuilder(Arc::new(Mutex::new(
            BTreeMap::new(),
        )))));
        let _keyring = RestoreKeyring;
        let fixture = crate::sync::tests::recovery_fixture();
        let a = backup_history_fact(&fixture.data_key, b"candidate fact");
        let artifact=aw_sync_e2ee::encrypt_snapshot(&fixture.data_key,&vec![7;1_100_000]).unwrap();
        let b=aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&fixture.data_key,&artifact).unwrap().fact().clone();
        for case in 0..4 {
            let directory = std::env::temp_dir().join(format!(
                "peak-native-interrupted-history-{}-{}-{case}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            let transition = Transition {
                id: "a".repeat(32),
                had_active: true,
                rollback_allowed: true,
            };
            let old = "d".repeat(64);
            let pending = "e".repeat(64);
            let account = "native-backup-interrupted-history";
            save_key(account, &old).unwrap();
            save_key(&format!("{account}.pending.{}", transition.id), &pending).unwrap();
            save_key(&format!("{account}.rollback.{}", transition.id), &old).unwrap();
            if case == 3 {
                entry(&format!("{account}.rollback.{}", transition.id))
                    .unwrap()
                    .delete_credential()
                    .unwrap();
            }
            let active = directory.join("activity.db");
            let staged = directory.join(transition.staged());
            let rollback = directory.join(transition.rollback());
            let old_path = if case == 1 || case == 3 {
                &active
            } else {
                &rollback
            };
            backup_history_test_file(old_path, &old, "old", b.clone());
            let original=Datastore::open_encrypted(old_path.to_string_lossy().into_owned(),old.clone()).unwrap();
            let proof=aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&fixture.data_key,&artifact).unwrap();let sealed=proof.seal(&fixture.data_key).unwrap();
            original.record_sync_backup_provider_intent(original.get_sync_policy_context().unwrap().context_id,proof,&fixture.data_key,sealed,"2026-10-14T12:00:00Z".into()).unwrap();original.close();
            let original_bytes = fs::read(old_path).unwrap();
            if case != 2 {
                backup_history_test_file(
                    if case == 0 { &active } else { &staged },
                    &pending,
                    "candidate",
                    a.clone(),
                );
            }
            vault_files::write_journal(&directory, &transition).unwrap();
            let mut vault = Vault {
                directory: directory.clone(),
                account,
                _owner: File::create(directory.join("owner.lock")).unwrap(),
                store: Datastore::new_locked(),
                status: VaultStatus {
                    state: "locked",
                    message: None,
                    has_vault: true,
                    generation: 0,
                },
            };
            recover_transition(&mut vault).unwrap();
            let key = read_key(account).unwrap();
            let facts = aw_datastore::vault::export_backup_deletions(&active, &key).unwrap();
            if case == 2 {
                assert_eq!(facts, vec![b.clone()]);
                assert_eq!(*key, old);
                assert!(directory
                    .join(format!("aborted-{}.json", transition.id))
                    .exists());
                assert_eq!(fs::read(&active).unwrap(), original_bytes);
            } else {
                assert_eq!(facts.len(), 2);
                assert!(facts.contains(&a) && facts.contains(&b));
                assert_eq!(*key, pending);
                assert_eq!(fs::read(&rollback).unwrap(), original_bytes);
                assert!(
                    vault_files::read_journal(&directory, "last-transition.json")
                        .unwrap()
                        .is_some()
                );
                assert!(read_key(&format!("{account}.pending.{}", transition.id)).is_err());
            }
            let current_bytes = fs::read(&active).unwrap();
            recover_transition(&mut vault).unwrap();
            assert_eq!(fs::read(&active).unwrap(), current_bytes);
            let check =
                Datastore::open_encrypted(active.to_string_lossy().into_owned(), key.to_string())
                    .unwrap();
            assert_eq!(
                check.get_key_value("history-fixture").unwrap(),
                if case == 2 { "old" } else { "candidate" }
            );
            let context=check.get_sync_policy_context().unwrap().context_id;
            let record=check.egress_lease().unwrap().sync_backup_provider_intent(context,b.bundle_sha256.clone()).unwrap().unwrap();
            let resumed=aw_sync_e2ee::SnapshotDeletionProofV1::resume(&fixture.data_key,&record,&artifact.envelopes[1..]).unwrap();
            assert!(!resumed.is_complete());assert!(resumed.allows_object(&artifact.envelopes[1]));
            check.close();
            drop(vault);
            fs::remove_dir_all(directory).unwrap();
        }
        fixture.source.close();
    }
    #[test]
    fn native_backup_unreadable_original_is_preserved_with_unknown_history_message() {
        let _serial = crate::sync::tests::RECOVERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        keyring::set_default_credential_builder(Box::new(MemoryBuilder(Arc::new(Mutex::new(
            BTreeMap::new(),
        )))));
        let _keyring = RestoreKeyring;
        let fixture = crate::sync::tests::recovery_fixture();
        let a = backup_history_fact(&fixture.data_key, b"older known fact");
        let b = backup_history_fact(&fixture.data_key, b"unavailable newer fact");
        let directory = std::env::temp_dir().join(format!(
            "peak-native-unreadable-history-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let account = "native-backup-unreadable-history";
        let old = "d".repeat(64);
        let source_key = "e".repeat(64);
        let active = directory.join("activity.db");
        let input = directory.join("older.pav");
        backup_history_test_file(&active, &old, "unreadable-original", b.clone());
        backup_history_test_file(&input, &source_key, "input", a.clone());
        let before = fs::read(&active).unwrap();
        let input_before = fs::read(&input).unwrap();
        let mut vault = Vault {
            directory: directory.clone(),
            account,
            _owner: File::create(directory.join("owner.lock")).unwrap(),
            store: Datastore::new_locked(),
            status: VaultStatus {
                state: "locked",
                message: None,
                has_vault: true,
                generation: 0,
            },
        };
        replace(&mut vault, &input, Some(&source_key), true).unwrap();
        assert_eq!(vault.status.state, "ready");
        assert!(vault
            .status
            .message
            .as_ref()
            .unwrap()
            .contains("deletion history could not be verified"));
        assert_eq!(
            vault
                .store
                .export_sync_backup_deletions(
                    vault.store.get_sync_policy_context().unwrap().context_id
                )
                .unwrap(),
            vec![a]
        );
        let transition = vault_files::read_journal(&directory, "last-transition.json")
            .unwrap()
            .unwrap();
        assert_eq!(
            fs::read(directory.join(transition.rollback())).unwrap(),
            before
        );
        assert_eq!(fs::read(&input).unwrap(), input_before);
        assert_eq!(
            aw_datastore::vault::export_backup_deletions(
                &directory.join(transition.rollback()),
                &old
            )
            .unwrap(),
            vec![b]
        );
        vault.store.close();
        fixture.source.close();
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn native_backup_readable_conflicting_history_refuses_replacement() {
        let _serial = crate::sync::tests::RECOVERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        keyring::set_default_credential_builder(Box::new(MemoryBuilder(Arc::new(Mutex::new(
            BTreeMap::new(),
        )))));
        let _keyring = RestoreKeyring;
        let fixture = crate::sync::tests::recovery_fixture();
        let fact = backup_history_fact(&fixture.data_key, b"known deletion");
        let directory = std::env::temp_dir().join(format!(
            "peak-native-corrupt-history-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let account = "native-backup-corrupt-history";
        let old = "d".repeat(64);
        let source_key = "e".repeat(64);
        save_key(account, &old).unwrap();
        let active = directory.join("activity.db");
        let input = directory.join("input.pav");
        backup_history_test_file(&active, &old, "original", fact.clone());
        let mut conflict = fact;
        conflict.bundle_sha256 = "f".repeat(64);
        backup_history_test_file(&input, &source_key, "input", conflict);
        let before = fs::read(&active).unwrap();
        let input_before = fs::read(&input).unwrap();
        let mut vault = Vault {
            directory: directory.clone(),
            account,
            _owner: File::create(directory.join("owner.lock")).unwrap(),
            store: Datastore::new_locked(),
            status: VaultStatus {
                state: "locked",
                message: None,
                has_vault: true,
                generation: 0,
            },
        };
        assert!(replace(&mut vault, &input, Some(&source_key), true).is_err());
        assert_eq!(fs::read(&active).unwrap(), before);
        assert_eq!(fs::read(&input).unwrap(), input_before);
        assert_eq!(*read_key(account).unwrap(), old);
        assert!(vault_files::read_journal(&directory, "transition.json")
            .unwrap()
            .is_none());
        fixture.source.close();
        drop(vault);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "requires an isolated, unlocked native OS secret service"]
    fn native_keyring_roundtrip_and_missing_existing_vault_fail_closed() {
        // Unique service avoids touching the user's real vault or credential index.
        let service = format!("app.peakactivity.native-test.{}", std::process::id());
        let credential = Entry::new(&service, "synthetic-vault").unwrap();
        assert!(matches!(credential.get_password(), Err(Error::NoEntry)));
        let secret = key(&credential, false).unwrap();
        assert_eq!(secret.len(), 64);
        let reopened = Entry::new(&service, "synthetic-vault").unwrap();
        assert!(*key(&reopened, true).unwrap() == *secret);
        let directory = std::env::temp_dir().join(&service);
        fs::create_dir(&directory).unwrap();
        let database = directory.join("activity.db");
        let store =
            Datastore::open_encrypted(database.to_str().unwrap().into(), secret.to_string())
                .unwrap();
        store
            .set_key_value("native-check", "synthetic private value")
            .unwrap();
        store.close();
        let bytes = fs::read(&database).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3"));
        assert!(!bytes
            .windows(23)
            .any(|part| part == b"synthetic private value"));
        aw_datastore::vault::verify(&database, &key(&reopened, true).unwrap()).unwrap();
        assert!(aw_datastore::vault::verify(&database, &"0".repeat(64)).is_err());
        reopened.delete_credential().unwrap();
        assert!(key(&credential, true).is_err());
        assert!(matches!(credential.get_password(), Err(Error::NoEntry)));
        assert_eq!(fs::read(&database).unwrap(), bytes);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn existing_vault_never_gets_a_replacement_key() {
        let entry = Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()));
        assert!(key(&entry, true).is_err());
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        let first = key(&entry, false).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(*key(&entry, true).unwrap(), *first);
    }

    #[test]
    fn vault_deletion_account_list_includes_only_valid_ai_credential_refs() {
        assert_eq!(
            ai_credential_accounts(r#"["cred-0123456789abcdef0123456789abcdef"]"#).unwrap(),
            vec!["ai-credential-cred-0123456789abcdef0123456789abcdef",]
        );
        assert!(ai_credential_accounts(r#"["cred-../../secret"]"#).is_err());
        assert!(ai_credential_accounts(
            r#"["cred-0123456789abcdef0123456789abcdef","cred-0123456789abcdef0123456789abcdef"]"#
        )
        .is_err());
    }

    #[test]
    fn key_store_errors_never_trigger_plaintext_fallback() {
        let entry = Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()));
        let mock: &keyring::mock::MockCredential = entry.get_credential().downcast_ref().unwrap();
        mock.set_error(Error::Invalid(
            "synthetic".into(),
            "secret contents must not be logged".into(),
        ));
        let error = key(&entry, false).unwrap_err();
        assert!(error.contains("locked or unavailable"));
        assert!(!error.contains("secret contents"));
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }

    #[test]
    fn deletion_discovers_recovery_keys_and_keeps_the_process_lock() {
        let root =
            std::env::temp_dir().join(format!("peakactivity-vault-delete-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let outside = root.with_extension("backup");
        fs::write(&outside, b"user backup").unwrap();
        fs::write(root.join("owner.lock"), b"").unwrap();
        let rollback_id = "a".repeat(32);
        let transition_id = "b".repeat(32);
        fs::write(
            root.join(format!("rollback-{rollback_id}.db")),
            b"encrypted",
        )
        .unwrap();
        vault_files::write_journal(
            &root,
            &Transition {
                id: transition_id.clone(),
                had_active: true,
                rollback_allowed: true,
            },
        )
        .unwrap();

        let accounts = recovery_accounts(&root, "primary").unwrap();
        assert!(accounts.contains(&"primary".to_string()));
        assert!(accounts.contains(&format!("primary.pending.{transition_id}")));
        assert!(accounts.contains(&format!("primary.rollback.{rollback_id}")));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("linked-outside")).unwrap();
        }
        erase_vault_files(&root).unwrap();
        assert!(root.join("owner.lock").exists());
        assert!(!has_local_vault(&root));
        assert!(!root.join(format!("rollback-{rollback_id}.db")).exists());
        assert!(!root.join("transition.json").exists());
        assert_eq!(fs::read(&outside).unwrap(), b"user backup");
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn device_identity_alone_does_not_count_as_an_existing_vault() {
        let root = std::env::temp_dir().join(format!(
            "peakactivity-vault-detection-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("owner.lock"), b"").unwrap();
        fs::write(root.join("device-id"), b"device identifier").unwrap();
        assert!(!has_local_vault(&root));

        fs::write(root.join("activity.db"), b"encrypted database").unwrap();
        assert!(has_local_vault(&root));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn support_preview_contains_counts_but_no_activity_payloads_or_paths() {
        use aw_models::{Bucket, Event, TryVec};
        use chrono::{Duration, Utc};
        use serde_json::json;

        let store = Datastore::new_in_memory(false);
        let mut policy = store.enable_capture_policy().unwrap();
        policy.titles = true;
        store.set_capture_policy(policy).unwrap();
        let event = Event::new(
            Utc::now(),
            Duration::seconds(1),
            json!({
                "app":"Editor", "title":"private-window-title", "path":"/Users/alice/work"
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        store
            .create_bucket(&Bucket {
                bid: None,
                id: "aw-watcher-window_sensitive".into(),
                _type: "currentwindow".into(),
                client: "test".into(),
                hostname: "test".into(),
                created: None,
                data: Default::default(),
                metadata: Default::default(),
                events: Some(TryVec::new(vec![event])),
                last_updated: None,
            })
            .unwrap();

        let preview = support_bundle_json(&store, false).unwrap();
        assert!(preview.contains("\"event_count\": 1"));
        assert!(preview.contains("\"activity_payloads_included\": false"));
        assert!(!preview.contains("private-window-title"));
        assert!(!preview.contains("/Users/alice"));
        assert!(!preview.contains("aw-watcher-window_sensitive"));
        store.close();
    }

    #[test]
    fn support_log_summary_counts_without_copying_log_text() {
        let summary = summarize_log_text(
            "[ERROR] token=abc123 /Users/alice/private-title\n[WARN] helper crashed",
        );
        let encoded = serde_json::to_string(&summary).unwrap();
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.helper_failures, 1);
        assert!(!encoded.contains("abc123"));
        assert!(!encoded.contains("private-title"));
    }
}
