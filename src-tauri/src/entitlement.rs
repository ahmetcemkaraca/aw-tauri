use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aw_entitlements::{
    verify_entitlement, EntitlementAccessV1, EntitlementVerificationErrorV1,
};
use aw_models::{EntitlementRevocationSnapshotV1, SignedEntitlementV1};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{local_session, vault_files};

const ENTITLEMENT_FILE: &str = "entitlement-v1.json";
const MAX_ENTITLEMENT_FILE_BYTES: u64 = 4 * 1024 * 1024;
const REVOCATION_KEYRING_SERVICE: &str = "app.peakactivity.desktop.entitlements";

// Release public keys are provisioned only with a reviewed release build.
const TRUSTED_ENTITLEMENT_KEYS_V1: &[(&str, [u8; 32])] = &[];

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEntitlementV1 {
    entitlement: SignedEntitlementV1,
    revocations: Option<EntitlementRevocationSnapshotV1>,
}

#[derive(Serialize)]
pub struct EntitlementStatusV1 {
    pub plan_id: String,
    pub feature_ids: Vec<String>,
    pub expires_at: u64,
    pub grace_until: u64,
    pub access: EntitlementAccessV1,
}

fn trusted_keys() -> BTreeMap<String, [u8; 32]> {
    TRUSTED_ENTITLEMENT_KEYS_V1.iter()
        .map(|(key_id, public_key)| ((*key_id).to_owned(), *public_key))
        .collect()
}

fn status(
    entitlement: &SignedEntitlementV1,
    revocations: Option<&EntitlementRevocationSnapshotV1>,
    public_keys: &BTreeMap<String, [u8; 32]>,
    now: u64,
    minimum_revocation_sequence: u64,
) -> Result<EntitlementStatusV1, String> {
    let verified = verify_entitlement(
        entitlement,
        public_keys,
        now,
        revocations,
        minimum_revocation_sequence,
    ).map_err(entitlement_error)?;
    Ok(EntitlementStatusV1 {
        plan_id: verified.claims.plan_id,
        feature_ids: verified.claims.feature_ids,
        expires_at: verified.claims.expires_at,
        grace_until: verified.claims.grace_until,
        access: verified.access,
    })
}

fn entitlement_error(error: EntitlementVerificationErrorV1) -> String {
    match error {
        EntitlementVerificationErrorV1::UnknownKey => "No trusted entitlement signing key is configured".into(),
        _ => "The stored entitlement is invalid, expired or revoked".into(),
    }
}

fn entitlement_path() -> Result<PathBuf, String> {
    let directory = crate::dirs::get_config_dir()
        .map_err(|_| "The commercial entitlement directory is unavailable")?;
    fs::create_dir_all(&directory).map_err(|_| "The commercial entitlement directory is unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| "The commercial entitlement directory is unavailable")?;
    }
    let metadata = fs::symlink_metadata(&directory)
        .map_err(|_| "The commercial entitlement directory is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("The commercial entitlement directory is unsafe".into());
    }
    Ok(directory.join(ENTITLEMENT_FILE))
}

fn read_stored(path: &Path) -> Result<Option<StoredEntitlementV1>, String> {
    if path.is_symlink() {
        return Err("The stored entitlement file must not be a symbolic link".into());
    }
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(path).map_err(|_| "The stored entitlement file is unavailable")?;
    if metadata.len() > MAX_ENTITLEMENT_FILE_BYTES {
        return Err("The stored entitlement file is too large".into());
    }
    serde_json::from_slice(&fs::read(path).map_err(|_| "The stored entitlement file is unavailable")?)
        .map(Some)
        .map_err(|_| "The stored entitlement file is invalid".into())
}

fn write_stored(path: &Path, stored: &StoredEntitlementV1) -> Result<(), String> {
    if path.is_symlink() {
        return Err("The stored entitlement file must not be a symbolic link".into());
    }
    let parent = path.parent().ok_or("The commercial entitlement path is invalid")?;
    fs::create_dir_all(parent).map_err(|_| "The commercial entitlement directory is unavailable")?;
    if fs::symlink_metadata(parent).map_err(|_| "The commercial entitlement directory is unavailable")?
        .file_type().is_symlink()
    {
        return Err("The commercial entitlement directory is unsafe".into());
    }
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| "Secure randomness is unavailable")?;
    let temporary = parent.join(format!("entitlement-{}.tmp", URL_SAFE_NO_PAD.encode(nonce)));
    let bytes = serde_json::to_vec(stored).map_err(|_| "The entitlement could not be encoded")?;
    if bytes.len() as u64 > MAX_ENTITLEMENT_FILE_BYTES {
        return Err("The stored entitlement file is too large".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)
            .map_err(|_| "The entitlement file could not be staged")?;
        file.write_all(&bytes).and_then(|_| file.sync_all())
            .map_err(|_| "The entitlement file could not be saved")?;
        drop(file);
        vault_files::move_file(&temporary, path, true)
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_revocation_checkpoint(account_id: &str) -> Result<u64, String> {
    use keyring::{Entry, Error};
    let entry = Entry::new(REVOCATION_KEYRING_SERVICE, &format!("sequence:{account_id}"))
        .map_err(|_| "The OS secure store is unavailable")?;
    match entry.get_password() {
        Ok(value) => value.parse().map_err(|_| "The entitlement revocation checkpoint is invalid".into()),
        Err(Error::NoEntry) => Ok(0),
        Err(_) => Err("Unlock the OS secure store to check entitlement status".into()),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_revocation_checkpoint(account_id: &str, sequence: u64) -> Result<(), String> {
    use keyring::{Entry, Error};
    let entry = Entry::new(REVOCATION_KEYRING_SERVICE, &format!("sequence:{account_id}"))
        .map_err(|_| "The OS secure store is unavailable")?;
    let current = match entry.get_password() {
        Ok(value) => value.parse::<u64>().map_err(|_| "The entitlement revocation checkpoint is invalid")?,
        Err(Error::NoEntry) => 0,
        Err(_) => return Err("Unlock the OS secure store to update entitlement status".into()),
    };
    if sequence < current {
        return Err("An older entitlement revocation snapshot was rejected".into());
    }
    if sequence == current { return Ok(()); }
    let value = sequence.to_string();
    entry.set_password(&value).map_err(|_| "The OS secure store could not save entitlement status")?;
    let saved = entry.get_password()
        .map_err(|_| "The OS secure store could not verify entitlement status")?;
    if saved != value {
        return Err("The OS secure store did not preserve entitlement status".into());
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn read_revocation_checkpoint(_: &str) -> Result<u64, String> {
    Err("Commercial entitlements are unavailable on this companion build".into())
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn write_revocation_checkpoint(_: &str, _: u64) -> Result<(), String> {
    Err("Commercial entitlements are unavailable on this companion build".into())
}

fn current_time() -> Result<u64, String> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "The system clock is unavailable".into())
}

#[tauri::command]
pub fn install_signed_entitlement(
    window: tauri::WebviewWindow,
    entitlement: SignedEntitlementV1,
    revocations: Option<EntitlementRevocationSnapshotV1>,
) -> Result<EntitlementStatusV1, String> {
    local_session::verify_window(&window)?;
    let path = entitlement_path()?;
    let keys = trusted_keys();
    let account_id = &entitlement.payload.claims.account_id;
    let minimum_sequence = read_revocation_checkpoint(account_id)?;
    let status = status(&entitlement, revocations.as_ref(), &keys, current_time()?, minimum_sequence)?;
    if let Some(snapshot) = &revocations {
        write_revocation_checkpoint(account_id, snapshot.sequence)?;
    }
    write_stored(&path, &StoredEntitlementV1 { entitlement, revocations })?;
    Ok(status)
}

#[tauri::command]
pub fn load_entitlement_status(
    window: tauri::WebviewWindow,
) -> Result<Option<EntitlementStatusV1>, String> {
    local_session::verify_window(&window)?;
    let Some(stored) = read_stored(&entitlement_path()?)? else { return Ok(None); };
    let account_id = &stored.entitlement.payload.claims.account_id;
    let minimum_sequence = read_revocation_checkpoint(account_id)?;
    status(
        &stored.entitlement,
        stored.revocations.as_ref(),
        &trusted_keys(),
        current_time()?,
        minimum_sequence,
    ).map(Some)
}

#[cfg(test)]
mod tests {
    use super::{read_stored, status, write_stored, StoredEntitlementV1};
    use aw_models::SignedEntitlementV1;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use std::collections::BTreeMap;
    use std::fs;

    #[test]
    fn local_entitlement_file_keeps_only_the_signed_contract() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../aw-server-rust/test-vectors/entitlement-v1.json"
        )).unwrap();
        let token: SignedEntitlementV1 = serde_json::from_value(vector["entitlement"].clone()).unwrap();
        let public_key: [u8; 32] = URL_SAFE_NO_PAD.decode(vector["public_key"].as_str().unwrap())
            .unwrap().try_into().unwrap();
        let keys = BTreeMap::from([(token.payload.key_id.clone(), public_key)]);
        let verified = status(
            &token,
            None,
            &keys,
            vector["now"].as_u64().unwrap(),
            0,
        ).unwrap();
        assert_eq!(verified.plan_id, "plus");
        let directory = std::env::temp_dir().join(format!("peak-entitlement-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("entitlement-v1.json");
        write_stored(&path, &StoredEntitlementV1 { entitlement: token, revocations: None }).unwrap();
        let stored = read_stored(&path).unwrap().unwrap();
        let serialized = serde_json::to_string(&stored).unwrap();
        assert!(!serialized.contains("private-activity-marker"));
        assert_eq!(stored.entitlement.payload.claims.plan_id, "plus");
        fs::remove_dir_all(directory).unwrap();
    }
}
