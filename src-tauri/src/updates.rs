mod manifest;
mod trust;
mod verify;

use serde::{de, Deserialize, Deserializer, Serialize};
use std::sync::Mutex;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

static VERIFICATION: Mutex<()> = Mutex::new(());
use std::{fmt, marker::PhantomData};

struct Object<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Visitor<T> {
            type Value = T;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map))
            }
        }
        deserializer
            .deserialize_map(Visitor(PhantomData))
            .map(Object)
    }
}
fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    Object::<T>::deserialize(d).map(|value| value.0)
}
fn objects<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Vec::<Object<T>>::deserialize(d).map(|values| values.into_iter().map(|value| value.0).collect())
}
fn parse_object<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, UpdateError> {
    serde_json::from_slice::<Object<T>>(bytes)
        .map(|value| value.0)
        .map_err(|_| UpdateError::Manifest)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpdateError {
    NotConfigured,
    Unavailable,
    Manifest,
    Policy,
    Io,
    Limit,
    Signature,
    Busy,
}
impl UpdateError {
    pub(crate) fn public_message(self) -> &'static str {
        match self {
            Self::NotConfigured => "Local update verification is not configured.",
            Self::Unavailable => "Local update verification is unavailable.",
            Self::Manifest => "The release manifest is invalid.",
            Self::Policy => "The release bundle does not match this application.",
            Self::Io => "The release bundle could not be read safely.",
            Self::Limit => "The release bundle exceeds the verification limits.",
            Self::Signature => "The release bundle signature could not be verified.",
            Self::Busy => "A release bundle verification is already running.",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub platform: String,
    pub native_architecture: String,
}
impl Target {
    pub(crate) fn new(platform: &str, architecture: &str) -> Self {
        Self {
            platform: platform.into(),
            native_architecture: architecture.into(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SelectedArtifact {
    pub index: usize,
    pub artifact_architecture: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateIntegrityStatusV1 {
    schema_version: u8,
    state: &'static str,
    installed_version: &'static str,
    platform: String,
    native_architecture: String,
}

#[derive(Debug, Serialize)]
pub struct VerifiedBundleV1 {
    schema_version: u8,
    version: String,
    channel: String,
    support_status: String,
    platform: String,
    native_architecture: String,
    artifact_architecture: String,
    source_revision: String,
    manifest_fingerprint: String,
    artifact_fingerprint: String,
    local_integrity: &'static str,
    public_readback: &'static str,
    platform_signature: &'static str,
    release_freshness: &'static str,
    key_lifecycle: &'static str,
}

fn native_target() -> Result<Target, UpdateError> {
    let platform = match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        _ => return Err(UpdateError::Unavailable),
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "arm64",
        _ => return Err(UpdateError::Unavailable),
    };
    Ok(Target::new(platform, architecture))
}

#[tauri::command]
pub async fn update_integrity_status(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
) -> Result<UpdateIntegrityStatusV1, String> {
    crate::local_session::verify_window(&window)?;
    let target = native_target().map_err(|error| error.public_message().to_owned())?;
    tauri::async_runtime::spawn_blocking(move || {
        let state = match trust::compiled_trust() {
            Ok(None) => "not-configured",
            Err(_) => "unavailable",
            Ok(Some(trust)) => match app.path().resource_dir() {
                Ok(root)
                    if verify::PreparedTrust::capture(&root.join("update-verifier"), &trust)
                        .is_ok() =>
                {
                    "ready"
                }
                _ => "unavailable",
            },
        };
        Ok(UpdateIntegrityStatusV1 {
            schema_version: 1,
            state,
            installed_version: env!("CARGO_PKG_VERSION"),
            platform: target.platform,
            native_architecture: target.native_architecture,
        })
    })
    .await
    .map_err(|_| UpdateError::Unavailable.public_message().to_owned())?
}

#[tauri::command]
pub async fn verify_update_bundle(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
) -> Result<Option<VerifiedBundleV1>, String> {
    crate::local_session::verify_window(&window)?;
    let trust = trust::compiled_trust()
        .map_err(|error| error.public_message().to_owned())?
        .ok_or_else(|| UpdateError::NotConfigured.public_message().to_owned())?;
    let target = native_target().map_err(|error| error.public_message().to_owned())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = VERIFICATION
            .try_lock()
            .map_err(|_| UpdateError::Busy.public_message().to_owned())?;
        let resources = app
            .path()
            .resource_dir()
            .map_err(|_| UpdateError::Unavailable.public_message().to_owned())?
            .join("update-verifier");
        let helper = verify::PreparedTrust::capture(&resources, &trust)
            .map_err(|error| error.public_message().to_owned())?;
        let Some(selected) = app
            .dialog()
            .file()
            .set_title("Verify local release bundle")
            .blocking_pick_folder()
        else {
            return Ok(None);
        };
        let root = selected
            .into_path()
            .map_err(|_| UpdateError::Io.public_message().to_owned())?;
        verify::verify_captured_bundle(&root, &helper, &trust, &target)
            .map(Some)
            .map_err(|error| error.public_message().to_owned())
    })
    .await
    .map_err(|_| UpdateError::Unavailable.public_message().to_owned())?
}

#[cfg(test)]
mod tests {
    use super::{manifest::ManifestV1, trust::ReleaseTrustV1, Target, UpdateError};
    use serde_json::{json, Value};

    pub(super) fn manifest_value() -> Value {
        json!({
            "schema_version":1,"release_id":"1.2.3","version":"1.2.3","channel":"stable",
            "support_status":"supported","manifest_signer_fingerprint":"A".repeat(40),
            "source":{"repository":"https://source.invalid/project","revision":"b".repeat(40),
                "archive":"source.tar.gz","readback_url":format!("https://source.invalid/{}/source.tar.gz", "b".repeat(40)),"sha256":"0".repeat(64)},
            "sbom":{"file":"sbom.json","readback_url":"https://source.invalid/1.2.3/sbom.json","sha256":"0".repeat(64)},
            "notices":{"file":"notices.txt","readback_url":"https://source.invalid/1.2.3/notices.txt","sha256":"0".repeat(64)},
            "artifacts":[{"platform":"windows","architecture":"x86_64","file":"app.exe","sha256":"0".repeat(64),
                "signature_file":"app.exe.asc","signature_sha256":"0".repeat(64),"signer_fingerprint":"B".repeat(40)}]
        })
    }

    pub(super) fn trust_value() -> Value {
        json!({"schema_version":1,"manifest_signer_fingerprint":"A".repeat(40),
            "source_repository":"https://source.invalid/project","channel":"stable",
            "verifier_file":"gpgv","keyring_file":"trusted.gpg",
            "files":[{"name":"gpgv","sha256":"0".repeat(64)},{"name":"trusted.gpg","sha256":"0".repeat(64)}]})
    }

    fn parse(value: &Value) -> Result<ManifestV1, UpdateError> {
        ManifestV1::parse(&serde_json::to_vec(value).unwrap())
    }

    fn trust() -> ReleaseTrustV1 {
        ReleaseTrustV1::parse(&serde_json::to_vec(&trust_value()).unwrap()).unwrap()
    }

    #[test]
    fn valid_v1_preserves_delegated_artifact_signer() {
        let manifest = parse(&manifest_value()).unwrap();
        assert_eq!(manifest.artifacts[0].signer_fingerprint, "B".repeat(40));
        assert_eq!(
            manifest
                .validate(&trust(), &Target::new("windows", "x86_64"))
                .unwrap()
                .index,
            0
        );
    }

    #[test]
    fn duplicate_root_and_nested_keys_are_rejected() {
        let text = serde_json::to_string(&manifest_value()).unwrap();
        for changed in [
            text.replacen(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
                1,
            ),
            text.replacen(
                "\"archive\":\"source.tar.gz\"",
                "\"archive\":\"source.tar.gz\",\"archive\":\"source.tar.gz\"",
                1,
            ),
        ] {
            assert!(ManifestV1::parse(changed.as_bytes()).is_err());
        }
    }

    #[test]
    fn unknown_and_missing_fields_are_rejected() {
        for pointer in ["", "/source", "/sbom", "/notices", "/artifacts/0"] {
            let mut value = manifest_value();
            value.pointer_mut(pointer).unwrap()["unexpected"] = json!(true);
            assert!(parse(&value).is_err(), "unknown field at {pointer}");
        }
        let mut value = manifest_value();
        value.as_object_mut().unwrap().remove("channel");
        assert!(parse(&value).is_err());
    }

    #[test]
    fn records_accept_objects_only() {
        for pointer in ["", "/source", "/sbom", "/notices", "/artifacts/0"] {
            let mut value = manifest_value();
            let fields: Vec<_> = value
                .pointer(pointer)
                .unwrap()
                .as_object()
                .unwrap()
                .values()
                .cloned()
                .collect();
            *value.pointer_mut(pointer).unwrap() = json!(fields);
            assert!(parse(&value).is_err(), "tuple at {pointer}");
        }
    }

    #[test]
    fn manifest_byte_limit_is_inclusive() {
        let mut bytes = serde_json::to_vec(&manifest_value()).unwrap();
        bytes.resize(64_000, b' ');
        assert!(ManifestV1::parse(&bytes).is_ok());
        bytes.push(b' ');
        assert!(ManifestV1::parse(&bytes).is_err());
    }

    #[test]
    fn schema_and_artifact_counts_are_bounded() {
        for schema in [json!(true), json!(1.0), json!(2)] {
            let mut value = manifest_value();
            value["schema_version"] = schema;
            assert!(parse(&value).is_err());
        }
        for count in [0, 65] {
            let mut value = manifest_value();
            value["artifacts"] = json!(vec![value["artifacts"][0].clone(); count]);
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn unsafe_and_repeated_filenames_are_rejected() {
        for name in [
            "../app",
            "/app",
            "app/part",
            ".hidden",
            "é.exe",
            "app.exe\0",
            "release.json",
            "sbom.json",
        ] {
            let mut value = manifest_value();
            value["artifacts"][0]["file"] = json!(name);
            assert!(parse(&value).is_err(), "name {name:?}");
        }
        let mut value = manifest_value();
        value["sbom"]["file"] = json!("source.tar.gz");
        assert!(parse(&value).is_err());
    }

    #[test]
    fn invalid_hashes_revisions_and_fingerprints_are_rejected() {
        for (pointer, invalid) in [
            ("/source/sha256", "F".repeat(64)),
            ("/source/revision", "B".repeat(40)),
            ("/manifest_signer_fingerprint", "A".repeat(39)),
            ("/artifacts/0/signature_sha256", "0".repeat(63)),
        ] {
            let mut value = manifest_value();
            *value.pointer_mut(pointer).unwrap() = json!(invalid);
            assert!(parse(&value).is_err(), "{pointer}");
        }
    }

    #[test]
    fn urls_require_direct_immutable_https() {
        for url in [
            "http://source.invalid/1.2.3/a",
            "https://u:p@source.invalid/1.2.3/a",
            "https://source.invalid/1.2.3/a?q=1",
            "https://source.invalid/1.2.3/a#f",
            "https://source.invalid/mutable/a",
            "https:source.invalid/1.2.3/a",
            "https:///source.invalid/1.2.3/a",
        ] {
            let mut value = manifest_value();
            value["sbom"]["readback_url"] = json!(url);
            assert!(parse(&value).is_err(), "{url}");
        }
    }

    #[test]
    fn application_trust_controls_signer_repository_and_channel() {
        for (field, wrong) in [
            ("channel", "beta"),
            ("manifest_signer_fingerprint", &"C".repeat(40)),
        ] {
            let mut value = manifest_value();
            value[field] = json!(wrong);
            assert!(parse(&value)
                .unwrap()
                .validate(&trust(), &Target::new("windows", "x86_64"))
                .is_err());
        }
        let mut value = manifest_value();
        value["source"]["repository"] = json!("https://other.invalid/project");
        assert!(parse(&value)
            .unwrap()
            .validate(&trust(), &Target::new("windows", "x86_64"))
            .is_err());
    }

    #[test]
    fn duplicate_platform_pairs_and_unsupported_targets_fail() {
        let mut value = manifest_value();
        let duplicate = value["artifacts"][0].clone();
        value["artifacts"].as_array_mut().unwrap().push(duplicate);
        assert!(parse(&value).is_err());
        let manifest = parse(&manifest_value()).unwrap();
        for target in [
            Target::new("browser", "x86_64"),
            Target::new("windows", "armv7"),
            Target::new("linux", "x86_64"),
        ] {
            assert!(manifest.validate(&trust(), &target).is_err());
        }
    }

    #[test]
    fn macos_prefers_exact_architecture_then_universal() {
        let mut value = manifest_value();
        value["artifacts"][0]["platform"] = json!("macos");
        value["artifacts"][0]["architecture"] = json!("universal");
        let mut exact = value["artifacts"][0].clone();
        exact["architecture"] = json!("arm64");
        exact["file"] = json!("arm.app");
        exact["signature_file"] = json!("arm.app.asc");
        value["artifacts"].as_array_mut().unwrap().push(exact);
        let selected = parse(&value)
            .unwrap()
            .validate(&trust(), &Target::new("macos", "arm64"))
            .unwrap();
        assert_eq!(selected.index, 1);
        assert_eq!(selected.artifact_architecture, "arm64");
        value["artifacts"].as_array_mut().unwrap().pop();
        assert_eq!(
            parse(&value)
                .unwrap()
                .validate(&trust(), &Target::new("macos", "arm64"))
                .unwrap()
                .artifact_architecture,
            "universal"
        );
    }

    #[test]
    fn trust_records_are_strict_and_require_distinct_pinned_files() {
        assert!(ReleaseTrustV1::parse(&serde_json::to_vec(&trust_value()).unwrap()).is_ok());
        for kind in ["unknown", "same", "missing", "duplicate", "unsafe", "hash"] {
            let mut value = trust_value();
            match kind {
                "unknown" => value["runtime_override"] = json!(true),
                "same" => value["keyring_file"] = json!("gpgv"),
                "missing" => value["keyring_file"] = json!("absent.gpg"),
                "duplicate" => value["files"][1]["name"] = json!("gpgv"),
                "unsafe" => value["files"][0]["name"] = json!("../gpgv"),
                _ => value["files"][0]["sha256"] = json!("f"),
            }
            assert!(
                ReleaseTrustV1::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn absent_compiled_trust_stays_unconfigured() {
        assert!(super::trust::compiled_trust().unwrap().is_none());
    }

    #[test]
    fn trust_rejects_duplicate_and_nonobject_records() {
        let raw = serde_json::to_string(&trust_value()).unwrap();
        assert!(ReleaseTrustV1::parse(
            raw.replacen(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
                1
            )
            .as_bytes()
        )
        .is_err());
        let mut value = trust_value();
        value["files"][0] = json!(["gpgv", "0".repeat(64)]);
        assert!(ReleaseTrustV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn private_errors_never_contain_external_details() {
        assert!(!UpdateError::Signature.public_message().contains("/"));
        assert!(!UpdateError::Io.public_message().contains("gpg"));
    }
}
