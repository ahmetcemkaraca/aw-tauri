use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use aw_entitlements::{
    EntitlementAccessV1, EntitlementSourceV1, EntitlementVerificationErrorV1,
    RuntimeFeatureAccessErrorV1, RuntimeFeatureAccessV1, StoredEntitlementV1,
    VerifiedEntitlementV1, MAX_STORED_ENTITLEMENT_BYTES_V1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;

use crate::{local_session, vault_files};

const ENTITLEMENT_FILE: &str = "entitlement-v1.json";
const REVOCATION_KEYRING_SERVICE: &str = "app.peakactivity.desktop.entitlements";

// Release public keys are provisioned only with a reviewed release build.
const TRUSTED_ENTITLEMENT_KEYS_V1: &[(&str, [u8; 32])] = &[];
const MINIMUM_REVOCATION_SEQUENCE_V1: u64 = 0;

static RUNTIME: OnceLock<Arc<RuntimeFeatureAccessV1>> = OnceLock::new();

struct NativeEntitlementSource {
    path: Result<PathBuf, &'static str>,
}

impl EntitlementSourceV1 for NativeEntitlementSource {
    fn load(&self) -> Result<Option<StoredEntitlementV1>, &'static str> {
        read_stored(self.path.as_ref().map_err(|error| *error)?)
    }

    fn save(&self, proof: &StoredEntitlementV1) -> Result<(), &'static str> {
        write_stored(self.path.as_ref().map_err(|error| *error)?, proof)
    }

    fn revocation_floor(&self, scope: &str) -> Result<u64, &'static str> {
        let mut floor = read_revocation_checkpoint(scope)?;
        if let Some(stored) = self.load()? {
            // shortcut: migrate the current legacy account checkpoint; enumerate historical accounts if that migration becomes necessary.
            floor = floor.max(read_revocation_checkpoint(&stored.entitlement.payload.claims.account_id)?);
        }
        write_revocation_checkpoint(scope, floor)?;
        Ok(floor)
    }

    fn advance_revocation_floor(&self, scope: &str, sequence: u64) -> Result<(), &'static str> {
        write_revocation_checkpoint(scope, sequence)
    }
}

pub(crate) fn runtime() -> Arc<RuntimeFeatureAccessV1> {
    RUNTIME.get_or_init(|| Arc::new(RuntimeFeatureAccessV1::new(
        trusted_keys(),
        MINIMUM_REVOCATION_SEQUENCE_V1,
        Arc::new(NativeEntitlementSource { path: entitlement_path() }),
    ))).clone()
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

fn status(verified: VerifiedEntitlementV1) -> EntitlementStatusV1 {
    EntitlementStatusV1 {
        plan_id: verified.claims.plan_id,
        feature_ids: verified.claims.feature_ids,
        expires_at: verified.claims.expires_at,
        grace_until: verified.claims.grace_until,
        access: verified.access,
    }
}

fn entitlement_error(error: RuntimeFeatureAccessErrorV1) -> String {
    match error {
        RuntimeFeatureAccessErrorV1::Source(error) => error.into(),
        RuntimeFeatureAccessErrorV1::MissingEntitlement => "A signed entitlement is required for encrypted sync".into(),
        RuntimeFeatureAccessErrorV1::MissingFeature => "The entitlement does not include encrypted sync".into(),
        RuntimeFeatureAccessErrorV1::Verification(EntitlementVerificationErrorV1::UnknownKey) => "No trusted entitlement signing key is configured".into(),
        _ => "The stored entitlement is invalid, expired or revoked".into(),
    }
}

fn entitlement_path() -> Result<PathBuf, &'static str> {
    let directory = dirs::config_dir()
        .ok_or("The commercial entitlement directory is unavailable")?
        .join("peakactivity").join("desktop");
    fs::create_dir_all(&directory).map_err(|_| "The commercial entitlement directory is unavailable")?;
    let metadata = fs::symlink_metadata(&directory)
        .map_err(|_| "The commercial entitlement directory is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("The commercial entitlement directory is unsafe");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| "The commercial entitlement directory is unavailable")?;
    }
    Ok(directory.join(ENTITLEMENT_FILE))
}

fn read_stored(path: &Path) -> Result<Option<StoredEntitlementV1>, &'static str> {
    if path.is_symlink() {
        return Err("The stored entitlement file must not be a symbolic link");
    }
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(path).map_err(|_| "The stored entitlement file is unavailable")?;
    if metadata.len() > MAX_STORED_ENTITLEMENT_BYTES_V1 as u64 {
        return Err("The stored entitlement file is too large");
    }
    serde_json::from_slice(&fs::read(path).map_err(|_| "The stored entitlement file is unavailable")?)
        .map(Some)
        .map_err(|_| "The stored entitlement file is invalid")
}

fn write_stored(path: &Path, stored: &StoredEntitlementV1) -> Result<(), &'static str> {
    if path.is_symlink() {
        return Err("The stored entitlement file must not be a symbolic link");
    }
    let parent = path.parent().ok_or("The commercial entitlement path is invalid")?;
    fs::create_dir_all(parent).map_err(|_| "The commercial entitlement directory is unavailable")?;
    if fs::symlink_metadata(parent).map_err(|_| "The commercial entitlement directory is unavailable")?
        .file_type().is_symlink()
    {
        return Err("The commercial entitlement directory is unsafe");
    }
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| "Secure randomness is unavailable")?;
    let temporary = parent.join(format!("entitlement-{}.tmp", URL_SAFE_NO_PAD.encode(nonce)));
    let bytes = serde_json::to_vec(stored).map_err(|_| "The entitlement could not be encoded")?;
    if bytes.len() > MAX_STORED_ENTITLEMENT_BYTES_V1 {
        return Err("The stored entitlement file is too large");
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
            .map_err(|_| "The entitlement file could not be installed")
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_revocation_checkpoint(scope: &str) -> Result<u64, &'static str> {
    use keyring::{Entry, Error};
    let entry = Entry::new(REVOCATION_KEYRING_SERVICE, &format!("sequence:{scope}"))
        .map_err(|_| "The OS secure store is unavailable")?;
    match entry.get_password() {
        Ok(value) => value.parse().map_err(|_| "The entitlement revocation checkpoint is invalid"),
        Err(Error::NoEntry) => Ok(0),
        Err(_) => Err("Unlock the OS secure store to check entitlement status"),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_revocation_checkpoint(scope: &str, sequence: u64) -> Result<(), &'static str> {
    use keyring::{Entry, Error};
    let entry = Entry::new(REVOCATION_KEYRING_SERVICE, &format!("sequence:{scope}"))
        .map_err(|_| "The OS secure store is unavailable")?;
    let current = match entry.get_password() {
        Ok(value) => value.parse::<u64>().map_err(|_| "The entitlement revocation checkpoint is invalid")?,
        Err(Error::NoEntry) => 0,
        Err(_) => return Err("Unlock the OS secure store to update entitlement status"),
    };
    if sequence < current {
        return Err("An older entitlement revocation snapshot was rejected");
    }
    if sequence == current { return Ok(()); }
    let value = sequence.to_string();
    entry.set_password(&value).map_err(|_| "The OS secure store could not save entitlement status")?;
    let saved = entry.get_password()
        .map_err(|_| "The OS secure store could not verify entitlement status")?;
    if saved != value {
        return Err("The OS secure store did not preserve entitlement status");
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn read_revocation_checkpoint(_: &str) -> Result<u64, &'static str> {
    Err("Commercial entitlements are unavailable on this companion build")
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn write_revocation_checkpoint(_: &str, _: u64) -> Result<(), &'static str> {
    Err("Commercial entitlements are unavailable on this companion build")
}

fn current_time() -> Result<u64, String> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "The system clock is unavailable".into())
}

fn parse_import(
    entitlement: serde_json::Value,
    revocations: Option<serde_json::Value>,
) -> Result<StoredEntitlementV1, String> {
    serde_json::from_value(serde_json::json!({ "entitlement": entitlement, "revocations": revocations }))
        .map_err(|_| "The signed entitlement document is invalid".into())
}

#[tauri::command]
pub fn install_signed_entitlement(
    window: tauri::WebviewWindow,
    entitlement: serde_json::Value,
    revocations: Option<serde_json::Value>,
) -> Result<EntitlementStatusV1, String> {
    local_session::verify_window(&window)?;
    runtime().install(parse_import(entitlement, revocations)?, current_time()?)
        .map(status).map_err(entitlement_error)
}

#[tauri::command]
pub fn load_entitlement_status(
    window: tauri::WebviewWindow,
) -> Result<Option<EntitlementStatusV1>, String> {
    local_session::verify_window(&window)?;
    runtime().status(current_time()?)
        .map(|verified| verified.map(status)).map_err(entitlement_error)
}

#[cfg(test)]
mod tests {
    use super::{parse_import, status, NativeEntitlementSource, StoredEntitlementV1};
    use aw_entitlements::{verify_entitlement, EntitlementSourceV1, RuntimeFeatureAccessErrorV1, RuntimeFeatureAccessV1};
    use aw_models::SignedEntitlementV1;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Arc;

    #[test]
    fn signed_entitlement_import_rejects_tuple_arguments_at_every_token_object() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../aw-server-rust/test-vectors/entitlement-v1.json"
        )).unwrap();
        let canonical = vector["entitlement"].clone();
        let token: SignedEntitlementV1 = serde_json::from_value(canonical.clone()).unwrap();
        let public_key = URL_SAFE_NO_PAD.decode(vector["public_key"].as_str().unwrap())
            .unwrap().try_into().unwrap();
        let keys = BTreeMap::from([(token.payload.key_id.clone(), public_key)]);
        let valid = parse_import(canonical.clone(), None).unwrap();
        assert_eq!(valid.entitlement, token);
        assert!(valid.revocations.is_none());
        let verified = verify_entitlement(&valid.entitlement, &keys, vector["now"].as_u64().unwrap(), None, 0).unwrap();
        let cases: &[(&str, &[&str])] = &[
            ("/payload/claims", &["schema_version", "entitlement_id", "account_id", "plan_id", "feature_ids", "issued_at", "expires_at", "grace_until", "device_limit"]),
            ("/payload", &["key_id", "claims"]),
            ("", &["payload", "signature"]),
        ];
        for (path, fields) in cases {
            let mut tuple = canonical.clone();
            let values = fields.iter().map(|field| tuple.pointer(path).unwrap()[*field].clone()).collect();
            *tuple.pointer_mut(path).unwrap() = serde_json::Value::Array(values);
            let parsed = parse_import(tuple, None);
            if let Ok(parsed) = &parsed {
                assert_eq!(verify_entitlement(&parsed.entitlement, &keys, vector["now"].as_u64().unwrap(), None, 0).unwrap(), verified);
            }
            assert!(parsed.is_err(), "Tauri import accepted the signed tuple-form argument at {path}");
        }
    }

    #[test]
    fn local_entitlement_file_keeps_only_the_signed_contract() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../aw-server-rust/test-vectors/entitlement-v1.json"
        )).unwrap();
        let token: SignedEntitlementV1 = serde_json::from_value(vector["entitlement"].clone()).unwrap();
        let public_key: [u8; 32] = URL_SAFE_NO_PAD.decode(vector["public_key"].as_str().unwrap())
            .unwrap().try_into().unwrap();
        let keys = BTreeMap::from([(token.payload.key_id.clone(), public_key)]);
        let verified = status(verify_entitlement(
            &token,
            &keys,
            vector["now"].as_u64().unwrap(),
            None,
            0,
        ).unwrap());
        assert_eq!(verified.plan_id, "plus");
        let public_status = serde_json::to_value(&verified).unwrap();
        assert!(public_status.get("account_id").is_none());
        assert!(public_status.get("entitlement_id").is_none());
        let directory = std::env::temp_dir().join(format!("peak-entitlement-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("entitlement-v1.json");
        let source = NativeEntitlementSource { path: Ok(path.clone()) };
        source.save(&StoredEntitlementV1 { entitlement: token, revocations: None }).unwrap();
        let stored = source.load().unwrap().unwrap();
        let serialized = serde_json::to_string(&stored).unwrap();
        assert!(!serialized.contains("private-activity-marker"));
        assert_eq!(stored.entitlement.payload.claims.plan_id, "plus");
        let mut invalid = serde_json::to_value(&stored).unwrap();
        invalid["activity"] = serde_json::json!({"title": "private-activity-marker"});
        fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(source.load().is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unavailable_native_entitlement_source_denies_sync_without_blocking_construction() {
        let runtime = RuntimeFeatureAccessV1::new(BTreeMap::new(), 0,
            Arc::new(NativeEntitlementSource { path: Err("The commercial entitlement directory is unavailable") }));
        assert_eq!(runtime.require_sync_access(1),
            Err(RuntimeFeatureAccessErrorV1::Source("The commercial entitlement directory is unavailable")));
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn native_checkpoint_migration_keeps_the_global_floor_across_file_account_changes() {
        use aw_entitlements::ENTITLEMENT_REVOCATION_SCOPE_V1;
        use keyring::credential::{CredentialApi, CredentialBuilderApi};
        use std::sync::Mutex;

        let _serial = crate::sync::tests::RECOVERY_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        struct MemoryBuilder(Arc<Mutex<BTreeMap<String, Vec<u8>>>>);
        struct MemoryCredential { values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>, account: String }
        impl CredentialApi for MemoryCredential {
            fn set_secret(&self, value: &[u8]) -> keyring::Result<()> {
                self.values.lock().unwrap().insert(self.account.clone(), value.to_vec()); Ok(())
            }
            fn get_secret(&self) -> keyring::Result<Vec<u8>> {
                self.values.lock().unwrap().get(&self.account).cloned().ok_or(keyring::Error::NoEntry)
            }
            fn delete_credential(&self) -> keyring::Result<()> {
                self.values.lock().unwrap().remove(&self.account).map(|_| ()).ok_or(keyring::Error::NoEntry)
            }
            fn as_any(&self) -> &dyn std::any::Any { self }
        }
        impl CredentialBuilderApi for MemoryBuilder {
            fn build(&self, _: Option<&str>, service: &str, user: &str) -> keyring::Result<Box<keyring::credential::Credential>> {
                Ok(Box::new(MemoryCredential { values: self.0.clone(), account: format!("{service}/{user}") }))
            }
            fn as_any(&self) -> &dyn std::any::Any { self }
        }
        struct RestoreKeyring;
        impl Drop for RestoreKeyring {
            fn drop(&mut self) { keyring::set_default_credential_builder(keyring::default::default_credential_builder()); }
        }
        keyring::set_default_credential_builder(Box::new(MemoryBuilder(Arc::new(Mutex::new(BTreeMap::new())))));
        let _keyring = RestoreKeyring;
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../aw-server-rust/test-vectors/entitlement-v1.json"
        )).unwrap();
        let token: SignedEntitlementV1 = serde_json::from_value(vector["entitlement"].clone()).unwrap();
        let directory = std::env::temp_dir().join(format!("peak-entitlement-floor-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let source = NativeEntitlementSource { path: Ok(directory.join("entitlement-v1.json")) };
        let mut proof = StoredEntitlementV1 { entitlement: token, revocations: None };
        source.save(&proof).unwrap();
        super::write_revocation_checkpoint(&proof.entitlement.payload.claims.account_id, 9).unwrap();
        assert_eq!(source.revocation_floor(ENTITLEMENT_REVOCATION_SCOPE_V1).unwrap(), 9);
        assert_eq!(super::read_revocation_checkpoint(ENTITLEMENT_REVOCATION_SCOPE_V1).unwrap(), 9);
        // Simulate a replaced file; its account field cannot reset the secure global floor.
        proof.entitlement.payload.claims.account_id = URL_SAFE_NO_PAD.encode([0x33; 16]);
        source.save(&proof).unwrap();
        assert_eq!(source.revocation_floor(ENTITLEMENT_REVOCATION_SCOPE_V1).unwrap(), 9);
        assert!(source.advance_revocation_floor(ENTITLEMENT_REVOCATION_SCOPE_V1, 8).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
