use super::{trust::ReleaseTrustV1, SelectedArtifact, Target, UpdateError};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestV1 {
    pub schema_version: u8,
    pub release_id: String,
    pub version: String,
    pub channel: String,
    pub support_status: String,
    pub manifest_signer_fingerprint: String,
    #[serde(deserialize_with = "super::object")]
    pub source: Source,
    #[serde(deserialize_with = "super::object")]
    pub sbom: Evidence,
    #[serde(deserialize_with = "super::object")]
    pub notices: Evidence,
    #[serde(deserialize_with = "super::objects")]
    pub artifacts: Vec<Artifact>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    pub repository: String,
    pub revision: String,
    pub archive: String,
    pub readback_url: String,
    pub sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Evidence {
    pub file: String,
    pub readback_url: String,
    pub sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub platform: String,
    pub architecture: String,
    pub file: String,
    pub sha256: String,
    pub signature_file: String,
    pub signature_sha256: String,
    pub signer_fingerprint: String,
}

pub(super) fn filename(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}
pub(super) fn hex(value: &str, sizes: &[usize], uppercase: bool) -> bool {
    sizes.contains(&value.len())
        && value.bytes().all(|b| {
            b.is_ascii_digit()
                || (b'a'..=b'f').contains(&b)
                || (uppercase && (b'A'..=b'F').contains(&b))
        })
}
pub(super) fn channel(value: &str) -> bool {
    matches!(value, "stable" | "beta" | "preview")
}
fn version(value: &str) -> bool {
    let suffix = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    };
    let core = match value.split_once('+') {
        Some((prefix, extra)) if suffix(extra) => prefix,
        Some(_) => return false,
        None => value,
    };
    let core = match core.split_once('-') {
        Some((prefix, extra)) if suffix(extra) => prefix,
        Some(_) => return false,
        None => core,
    };
    let parts: Vec<_> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}
pub(super) fn url(value: &str, identifiers: &[&str]) -> bool {
    let Some(authority) = value
        .strip_prefix("https://")
        .map(|rest| rest.split(['/', '?', '#']).next().unwrap_or(""))
    else {
        return false;
    };
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains('\\')
        || value
            .chars()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
    {
        return false;
    }
    let Ok(parsed) = reqwest::Url::parse(value) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && (identifiers.is_empty() || identifiers.iter().any(|id| parsed.path().contains(id)))
}
fn platform_arch(platform: &str, arch: &str) -> bool {
    match platform {
        "windows" | "linux" => matches!(arch, "x86_64" | "arm64"),
        "macos" => matches!(arch, "x86_64" | "arm64" | "universal"),
        "android" => matches!(arch, "x86_64" | "arm64" | "armv7" | "universal"),
        "ios" => matches!(arch, "arm64" | "universal"),
        _ => false,
    }
}
impl ManifestV1 {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, UpdateError> {
        if bytes.len() > 64_000 {
            return Err(UpdateError::Limit);
        }
        let manifest: Self = super::parse_object(bytes)?;
        if manifest.schema_version != 1
            || manifest.release_id != manifest.version
            || !version(&manifest.version)
            || !channel(&manifest.channel)
            || !matches!(manifest.support_status.as_str(), "supported" | "limited")
            || !hex(&manifest.manifest_signer_fingerprint, &[40, 64], true)
            || !url(&manifest.source.repository, &[])
            || !hex(&manifest.source.revision, &[40, 64], false)
            || !url(&manifest.source.readback_url, &[&manifest.source.revision])
            || !(1..=64).contains(&manifest.artifacts.len())
        {
            return Err(UpdateError::Manifest);
        }
        let mut names = HashSet::from(["release.json".to_owned(), "release.json.asc".to_owned()]);
        let mut file = |name: &str, sha: &str| {
            filename(name) && hex(sha, &[64], false) && names.insert(name.to_owned())
        };
        if !file(&manifest.source.archive, &manifest.source.sha256) {
            return Err(UpdateError::Manifest);
        }
        for record in [&manifest.sbom, &manifest.notices] {
            if !url(
                &record.readback_url,
                &[&manifest.source.revision, &manifest.release_id],
            ) || !file(&record.file, &record.sha256)
            {
                return Err(UpdateError::Manifest);
            }
        }
        let mut targets = HashSet::new();
        for artifact in &manifest.artifacts {
            if !platform_arch(&artifact.platform, &artifact.architecture)
                || !targets.insert((&artifact.platform, &artifact.architecture))
                || !hex(&artifact.signer_fingerprint, &[40, 64], true)
                || !file(&artifact.file, &artifact.sha256)
                || !file(&artifact.signature_file, &artifact.signature_sha256)
            {
                return Err(UpdateError::Manifest);
            }
        }
        Ok(manifest)
    }
    pub(crate) fn validate(
        &self,
        trust: &ReleaseTrustV1,
        target: &Target,
    ) -> Result<SelectedArtifact, UpdateError> {
        if !matches!(target.platform.as_str(), "windows" | "macos" | "linux")
            || !matches!(target.native_architecture.as_str(), "x86_64" | "arm64")
            || !self
                .manifest_signer_fingerprint
                .eq_ignore_ascii_case(&trust.manifest_signer_fingerprint)
            || self.source.repository != trust.source_repository
            || self.channel != trust.channel
        {
            return Err(UpdateError::Policy);
        }
        let exact = self.artifacts.iter().position(|a| {
            a.platform == target.platform && a.architecture == target.native_architecture
        });
        let universal = if target.platform == "macos" {
            self.artifacts
                .iter()
                .position(|a| a.platform == "macos" && a.architecture == "universal")
        } else {
            None
        };
        let index = exact.or(universal).ok_or(UpdateError::Policy)?;
        Ok(SelectedArtifact {
            index,
            artifact_architecture: self.artifacts[index].architecture.clone(),
        })
    }
}
