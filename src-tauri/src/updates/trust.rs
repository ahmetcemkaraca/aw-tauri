use super::{
    manifest::{channel, filename, hex, url},
    UpdateError,
};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseTrustV1 {
    pub schema_version: u8,
    pub manifest_signer_fingerprint: String,
    pub source_repository: String,
    pub channel: String,
    pub verifier_file: String,
    pub keyring_file: String,
    #[serde(deserialize_with = "super::objects")]
    pub files: Vec<ResourcePin>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourcePin {
    pub name: String,
    pub sha256: String,
}
impl ReleaseTrustV1 {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, UpdateError> {
        if bytes.len() > 64_000 {
            return Err(UpdateError::Unavailable);
        }
        let trust: Self = super::parse_object(bytes).map_err(|_| UpdateError::Unavailable)?;
        let mut names = HashSet::new();
        if trust.schema_version != 1
            || !hex(&trust.manifest_signer_fingerprint, &[40, 64], true)
            || !url(&trust.source_repository, &[])
            || !channel(&trust.channel)
            || trust.verifier_file == trust.keyring_file
            || trust.files.is_empty()
            || trust.files.iter().any(|file| {
                !filename(&file.name)
                    || !hex(&file.sha256, &[64], false)
                    || !names.insert(file.name.as_str())
            })
            || !names.contains(trust.verifier_file.as_str())
            || !names.contains(trust.keyring_file.as_str())
        {
            return Err(UpdateError::Unavailable);
        }
        Ok(trust)
    }
}
include!(concat!(env!("OUT_DIR"), "/update-trust.rs"));
pub(crate) fn compiled_trust() -> Result<Option<ReleaseTrustV1>, UpdateError> {
    COMPILED_TRUST.map(ReleaseTrustV1::parse).transpose()
}
