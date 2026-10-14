use super::{manifest::ManifestV1, trust::ReleaseTrustV1, Target, UpdateError, VerifiedBundleV1};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const PAYLOAD_LIMIT: u64 = 1024 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 4 * PAYLOAD_LIMIT;
const OUTPUT_LIMIT: usize = 64_000;

fn directory(path: &Path) -> Result<(), UpdateError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| UpdateError::Io)?;
    if metadata.is_symlink() || !metadata.is_dir() {
        return Err(UpdateError::Io);
    }
    Ok(())
}
fn capture_file(input: &Path, output: &Path, limit: u64) -> Result<(String, u64), UpdateError> {
    let result = (|| {
        let metadata = fs::symlink_metadata(input).map_err(|_| UpdateError::Io)?;
        if metadata.is_symlink() || !metadata.is_file() {
            return Err(UpdateError::Io);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x00200000);
        }
        let mut source = options.open(input).map_err(|_| UpdateError::Io)?;
        let opened = source.metadata().map_err(|_| UpdateError::Io)?;
        if !opened.is_file() {
            return Err(UpdateError::Io);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if opened.file_attributes() & 0x400 != 0 {
                return Err(UpdateError::Io);
            }
        }
        if opened.len() > limit {
            return Err(UpdateError::Limit);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut destination = options.open(output).map_err(|_| UpdateError::Io)?;
        let mut hash = Sha256::new();
        let mut size = 0u64;
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let count = source.read(&mut buffer).map_err(|_| UpdateError::Io)?;
            if count == 0 {
                break;
            }
            size = size.checked_add(count as u64).ok_or(UpdateError::Limit)?;
            if size > limit {
                return Err(UpdateError::Limit);
            }
            hash.update(&buffer[..count]);
            destination
                .write_all(&buffer[..count])
                .map_err(|_| UpdateError::Io)?;
        }
        destination.flush().map_err(|_| UpdateError::Io)?;
        Ok((format!("{:x}", hash.finalize()), size))
    })();
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

pub(super) struct PreparedTrust {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    verifier: PathBuf,
    keyring: PathBuf,
}
impl PreparedTrust {
    pub(super) fn capture(resources: &Path, trust: &ReleaseTrustV1) -> Result<Self, UpdateError> {
        directory(resources).map_err(|_| UpdateError::Unavailable)?;
        let temporary = tempfile::Builder::new()
            .prefix("peakactivity-update-trust-")
            .tempdir()
            .map_err(|_| UpdateError::Unavailable)?;
        let root = temporary.path().to_path_buf();
        for pin in &trust.files {
            let limit = if pin.name == trust.keyring_file {
                1024 * 1024
            } else {
                64 * 1024 * 1024
            };
            let (hash, _) = capture_file(&resources.join(&pin.name), &root.join(&pin.name), limit)
                .map_err(|_| UpdateError::Unavailable)?;
            if hash != pin.sha256 {
                return Err(UpdateError::Unavailable);
            }
        }
        let verifier = root.join(&trust.verifier_file);
        let keyring = root.join(&trust.keyring_file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&verifier, fs::Permissions::from_mode(0o700))
                .map_err(|_| UpdateError::Unavailable)?;
        }
        let home = root.join("isolated-home");
        fs::create_dir(&home).map_err(|_| UpdateError::Unavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
                .map_err(|_| UpdateError::Unavailable)?;
        }
        Ok(Self {
            _temporary: temporary,
            root,
            home,
            verifier,
            keyring,
        })
    }
}

struct ChildTree {
    #[cfg(unix)]
    pid: u32,
    #[cfg(windows)]
    job: winapi::um::winnt::HANDLE,
}
impl ChildTree {
    fn attach(child: &Child) -> Result<Self, UpdateError> {
        #[cfg(unix)]
        {
            Ok(Self { pid: child.id() })
        }
        #[cfg(windows)]
        {
            use std::{os::windows::io::AsRawHandle, ptr::null_mut};
            use winapi::um::{
                handleapi::CloseHandle,
                jobapi2::{AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject},
                winnt::{
                    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                },
            };
            unsafe {
                let job = CreateJobObjectW(null_mut(), null_mut());
                if job.is_null() {
                    return Err(UpdateError::Signature);
                }
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &mut limits as *mut _ as *mut _,
                    std::mem::size_of_val(&limits) as u32,
                ) == 0
                    || AssignProcessToJobObject(job, child.as_raw_handle() as _) == 0
                {
                    CloseHandle(job);
                    return Err(UpdateError::Signature);
                }
                Ok(Self { job })
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Err(UpdateError::Unavailable)
        }
    }
}
impl Drop for ChildTree {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.pid as i32), libc::SIGKILL);
        }
        #[cfg(windows)]
        unsafe {
            winapi::um::handleapi::CloseHandle(self.job);
        }
    }
}
fn drain<R: Read + Send + 'static>(
    mut stream: R,
    excess: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, UpdateError>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let count = match stream.read(&mut buffer) {
                Ok(n) => n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(UpdateError::Signature),
            };
            if count == 0 {
                return Ok(bytes);
            }
            if bytes.len() + count > OUTPUT_LIMIT {
                excess.store(true, Ordering::Release);
                return Err(UpdateError::Signature);
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
    })
}
fn signature(
    helper: &PreparedTrust,
    sig: &Path,
    payload: &Path,
    expected: &str,
    timeout: Duration,
) -> Result<String, UpdateError> {
    let mut command = Command::new(&helper.verifier);
    command
        .args([
            "--homedir",
            helper.home.to_str().ok_or(UpdateError::Signature)?,
            "--status-fd",
            "1",
            "--keyring",
            helper.keyring.to_str().ok_or(UpdateError::Signature)?,
        ])
        .arg(sig)
        .arg(payload)
        .current_dir(&helper.root)
        .env_clear()
        .env("GNUPGHOME", &helper.home)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
    }
    let mut child = command.spawn().map_err(|_| UpdateError::Signature)?;
    let tree = match ChildTree::attach(&child) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let excess = Arc::new(AtomicBool::new(false));
    let stdout = drain(
        child.stdout.take().ok_or(UpdateError::Signature)?,
        excess.clone(),
    );
    let stderr = drain(
        child.stderr.take().ok_or(UpdateError::Signature)?,
        excess.clone(),
    );
    let started = Instant::now();
    let status = loop {
        if excess.load(Ordering::Acquire) || started.elapsed() >= timeout {
            break Err(UpdateError::Signature);
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(_) => break Err(UpdateError::Signature),
        }
    };
    drop(tree);
    let _ = child.kill();
    let _ = child.wait();
    let output = stdout.join().map_err(|_| UpdateError::Signature)?;
    let errors = stderr.join().map_err(|_| UpdateError::Signature)?;
    if !status?.success() || excess.load(Ordering::Acquire) {
        return Err(UpdateError::Signature);
    }
    let output = String::from_utf8(output?).map_err(|_| UpdateError::Signature)?;
    let _ = errors?;
    let mut fingerprints = Vec::new();
    for line in output.lines() {
        let Some(status) = line.strip_prefix("[GNUPG:] ") else {
            return Err(UpdateError::Signature);
        };
        let mut words = status.split_whitespace();
        match words.next() {
            Some("VALIDSIG") => {
                let fingerprint = words
                    .next()
                    .filter(|value| super::manifest::hex(value, &[40, 64], true))
                    .ok_or(UpdateError::Signature)?;
                fingerprints.push(fingerprint.to_ascii_uppercase());
            }
            Some("NEWSIG" | "KEY_CONSIDERED" | "SIG_ID" | "GOODSIG") => {}
            _ => return Err(UpdateError::Signature),
        }
    }
    if fingerprints.len() != 1 || !fingerprints[0].eq_ignore_ascii_case(expected) {
        return Err(UpdateError::Signature);
    }
    Ok(fingerprints.remove(0))
}

pub(crate) fn verify_bundle(
    root: &Path,
    resources: &Path,
    trust: &ReleaseTrustV1,
    target: &Target,
) -> Result<VerifiedBundleV1, UpdateError> {
    let helper = PreparedTrust::capture(resources, trust)?;
    verify_captured_bundle(root, &helper, trust, target)
}
pub(super) fn verify_captured_bundle(
    root: &Path,
    helper: &PreparedTrust,
    trust: &ReleaseTrustV1,
    target: &Target,
) -> Result<VerifiedBundleV1, UpdateError> {
    directory(root)?;
    let temporary = tempfile::Builder::new()
        .prefix("peakactivity-update-bundle-")
        .tempdir()
        .map_err(|_| UpdateError::Io)?;
    let snapshot = temporary.path();
    let manifest_file = snapshot.join("0");
    let manifest_signature = snapshot.join("1");
    capture_file(&root.join("release.json"), &manifest_file, 64_000)?;
    capture_file(&root.join("release.json.asc"), &manifest_signature, 64_000)?;
    let manifest = ManifestV1::parse(&fs::read(&manifest_file).map_err(|_| UpdateError::Io)?)?;
    let selected = manifest.validate(trust, target)?;
    let manifest_fingerprint = signature(
        helper,
        &manifest_signature,
        &manifest_file,
        &trust.manifest_signer_fingerprint,
        Duration::from_secs(15),
    )?;
    let mut counter = 2usize;
    let mut total = 0u64;
    let mut capture = |name: &str, hash: &str, limit: u64| -> Result<PathBuf, UpdateError> {
        let destination = snapshot.join(counter.to_string());
        counter += 1;
        let (actual, size) = capture_file(
            &root.join(name),
            &destination,
            limit.min(TOTAL_LIMIT - total),
        )?;
        total = total
            .checked_add(size)
            .filter(|size| *size <= TOTAL_LIMIT)
            .ok_or(UpdateError::Limit)?;
        if actual != hash {
            return Err(UpdateError::Signature);
        }
        Ok(destination)
    };
    capture(
        &manifest.source.archive,
        &manifest.source.sha256,
        PAYLOAD_LIMIT,
    )?;
    for record in [&manifest.sbom, &manifest.notices] {
        capture(&record.file, &record.sha256, PAYLOAD_LIMIT)?;
    }
    let mut artifact_fingerprint = String::new();
    for (index, artifact) in manifest.artifacts.iter().enumerate() {
        let payload = capture(&artifact.file, &artifact.sha256, PAYLOAD_LIMIT)?;
        let sig = capture(&artifact.signature_file, &artifact.signature_sha256, 64_000)?;
        let fingerprint = signature(
            helper,
            &sig,
            &payload,
            &artifact.signer_fingerprint,
            Duration::from_secs(15),
        )?;
        if index == selected.index {
            artifact_fingerprint = fingerprint;
        }
    }
    Ok(VerifiedBundleV1 {
        schema_version: 1,
        version: manifest.version,
        channel: manifest.channel,
        support_status: manifest.support_status,
        platform: target.platform.clone(),
        native_architecture: target.native_architecture.clone(),
        artifact_architecture: selected.artifact_architecture,
        source_revision: manifest.source.revision,
        manifest_fingerprint,
        artifact_fingerprint,
        local_integrity: "verified",
        public_readback: "not-checked",
        platform_signature: "not-checked",
        release_freshness: "not-checked",
        key_lifecycle: "not-checked",
    })
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::{
        fs,
        process::Command,
        time::{Duration, Instant},
    };

    struct Fixture {
        temp: tempfile::TempDir,
        home: std::path::PathBuf,
        bundle: std::path::PathBuf,
        resources: std::path::PathBuf,
        manifest: Value,
        trust: ReleaseTrustV1,
        manifest_key: String,
        artifact_key: String,
        unknown_key: String,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = Command::new("/usr/bin/gpgconf")
                .args([
                    "--homedir",
                    self.home.to_str().unwrap(),
                    "--kill",
                    "gpg-agent",
                ])
                .output();
        }
    }
    fn digest(path: &Path) -> String {
        format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
    }
    impl Fixture {
        fn gpg(&self, args: &[&str]) -> Vec<u8> {
            let output = Command::new("/usr/bin/gpg")
                .args([
                    "--no-options",
                    "--homedir",
                    self.home.to_str().unwrap(),
                    "--batch",
                    "--yes",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "synthetic GnuPG setup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        }
        fn new() -> Self {
            assert!(
                Path::new("/usr/bin/gpg").is_file() && Path::new("/usr/bin/gpgv").is_file(),
                "actual OpenPGP fixture tools are required"
            );
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("gnupg");
            fs::create_dir(&home).unwrap();
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
            let bundle = temp.path().join("bundle");
            let resources = temp.path().join("resources");
            fs::create_dir(&bundle).unwrap();
            fs::create_dir(&resources).unwrap();
            let trust = ReleaseTrustV1::parse(
                &serde_json::to_vec(&super::super::tests::trust_value()).unwrap(),
            )
            .unwrap();
            let mut fixture = Self {
                temp,
                home,
                bundle,
                resources,
                manifest: super::super::tests::manifest_value(),
                trust,
                manifest_key: String::new(),
                artifact_key: String::new(),
                unknown_key: String::new(),
            };
            let mut keys = Vec::new();
            for role in ["manifest", "artifact", "unknown"] {
                let identity = format!("Synthetic {role} <{role}@native-update-test.invalid>");
                fixture.gpg(&["--quick-generate-key", &identity, "ed25519", "sign", "0"]);
                let listing =
                    fixture.gpg(&["--with-colons", "--fingerprint", "--list-keys", &identity]);
                keys.push(
                    String::from_utf8(listing)
                        .unwrap()
                        .lines()
                        .find(|line| line.starts_with("fpr:"))
                        .unwrap()
                        .split(':')
                        .nth(9)
                        .unwrap()
                        .to_owned(),
                );
            }
            fixture.manifest_key = keys[0].clone();
            fixture.artifact_key = keys[1].clone();
            fixture.unknown_key = keys[2].clone();
            fs::copy("/usr/bin/gpgv", fixture.resources.join("gpgv")).unwrap();
            let keyring = fixture.gpg(&["--export", &fixture.manifest_key, &fixture.artifact_key]);
            fs::write(fixture.resources.join("trusted.gpg"), keyring).unwrap();
            for (name, data) in [
                ("app.exe", b"synthetic installer".as_slice()),
                ("source.tar.gz", b"synthetic source"),
                ("sbom.json", b"synthetic sbom"),
                ("notices.txt", b"synthetic notices"),
            ] {
                fs::write(fixture.bundle.join(name), data).unwrap();
            }
            fixture.sign("app.exe", &fixture.artifact_key);
            fixture.manifest["manifest_signer_fingerprint"] =
                serde_json::json!(fixture.manifest_key);
            fixture.manifest["artifacts"][0]["signer_fingerprint"] =
                serde_json::json!(fixture.artifact_key);
            fixture.manifest["source"]["sha256"] =
                serde_json::json!(digest(&fixture.bundle.join("source.tar.gz")));
            fixture.manifest["sbom"]["sha256"] =
                serde_json::json!(digest(&fixture.bundle.join("sbom.json")));
            fixture.manifest["notices"]["sha256"] =
                serde_json::json!(digest(&fixture.bundle.join("notices.txt")));
            fixture.refresh_artifact_hashes();
            fixture.write_manifest();
            fixture.trust.manifest_signer_fingerprint = fixture.manifest_key.clone();
            for pin in &mut fixture.trust.files {
                pin.sha256 = digest(&fixture.resources.join(&pin.name));
            }
            fixture
        }
        fn sign(&self, name: &str, key: &str) {
            self.gpg(&[
                "--local-user",
                key,
                "--armor",
                "--output",
                self.bundle.join(format!("{name}.asc")).to_str().unwrap(),
                "--detach-sign",
                self.bundle.join(name).to_str().unwrap(),
            ]);
        }
        fn write_manifest(&self) {
            fs::write(
                self.bundle.join("release.json"),
                serde_json::to_vec(&self.manifest).unwrap(),
            )
            .unwrap();
            self.sign("release.json", &self.manifest_key);
        }
        fn refresh_artifact_hashes(&mut self) {
            self.manifest["artifacts"][0]["sha256"] =
                serde_json::json!(digest(&self.bundle.join("app.exe")));
            self.manifest["artifacts"][0]["signature_sha256"] =
                serde_json::json!(digest(&self.bundle.join("app.exe.asc")));
        }
        fn verify(&self) -> Result<VerifiedBundleV1, UpdateError> {
            verify_bundle(
                &self.bundle,
                &self.resources,
                &self.trust,
                &Target::new("windows", "x86_64"),
            )
        }
        fn child_script(&mut self, text: &str) {
            let path = self.resources.join("gpgv");
            fs::write(&path, format!("#!/bin/sh\n{text}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            self.trust
                .files
                .iter_mut()
                .find(|p| p.name == "gpgv")
                .unwrap()
                .sha256 = digest(&path);
        }
    }

    #[test]
    fn real_delegated_signatures_verify_complete_bundle() {
        let fixture = Fixture::new();
        let result = fixture.verify().unwrap();
        assert_eq!(result.manifest_fingerprint, fixture.manifest_key);
        assert_eq!(result.artifact_fingerprint, fixture.artifact_key);
        assert_eq!(result.version, "1.2.3");
        assert_eq!(result.local_integrity, "verified");
        assert_eq!(result.public_readback, "not-checked");
        assert_eq!(result.key_lifecycle, "not-checked");
        assert_eq!(result.platform_signature, "not-checked");
        assert_eq!(result.release_freshness, "not-checked");
    }
    #[test]
    fn actual_signing_subkey_fingerprint_is_preserved() {
        let mut fixture = Fixture::new();
        fixture.gpg(&[
            "--quick-add-key",
            &fixture.artifact_key,
            "ed25519",
            "sign",
            "0",
        ]);
        let listing = fixture.gpg(&[
            "--with-colons",
            "--fingerprint",
            "--list-keys",
            &fixture.artifact_key,
        ]);
        let listing = String::from_utf8(listing).unwrap();
        let subkey = listing
            .lines()
            .filter(|line| line.starts_with("fpr:"))
            .nth(1)
            .unwrap()
            .split(':')
            .nth(9)
            .unwrap()
            .to_owned();
        let keyring = fixture.gpg(&["--export", &fixture.manifest_key, &fixture.artifact_key]);
        fs::write(fixture.resources.join("trusted.gpg"), keyring).unwrap();
        fixture
            .trust
            .files
            .iter_mut()
            .find(|pin| pin.name == "trusted.gpg")
            .unwrap()
            .sha256 = digest(&fixture.resources.join("trusted.gpg"));
        fixture.sign("app.exe", &format!("{subkey}!"));
        fixture.manifest["artifacts"][0]["signer_fingerprint"] = serde_json::json!(subkey);
        fixture.refresh_artifact_hashes();
        fixture.write_manifest();
        let result = fixture.verify().unwrap();
        assert_ne!(result.artifact_fingerprint, fixture.artifact_key);
        assert_eq!(result.artifact_fingerprint, subkey);
    }

    #[test]
    fn changed_manifest_and_matching_hash_but_stale_artifact_signature_fail() {
        let mut fixture = Fixture::new();
        fixture.manifest["support_status"] = serde_json::json!("limited");
        fs::write(
            fixture.bundle.join("release.json"),
            serde_json::to_vec(&fixture.manifest).unwrap(),
        )
        .unwrap();
        assert!(fixture.verify().is_err());
        fs::write(fixture.bundle.join("app.exe"), b"altered installer").unwrap();
        fixture.refresh_artifact_hashes();
        fixture.write_manifest();
        assert!(fixture.verify().is_err());
    }
    #[test]
    fn every_source_evidence_and_unrelated_artifact_hash_is_required() {
        let fixture = Fixture::new();
        for name in ["source.tar.gz", "sbom.json", "notices.txt", "app.exe.asc"] {
            let path = fixture.bundle.join(name);
            let original = fs::read(&path).unwrap();
            fs::write(&path, b"altered").unwrap();
            assert!(fixture.verify().is_err(), "{name}");
            fs::write(path, original).unwrap();
        }
    }
    #[test]
    fn unrelated_artifact_signature_is_also_verified() {
        let mut fixture = Fixture::new();
        let mut other = fixture.manifest["artifacts"][0].clone();
        fs::write(fixture.bundle.join("other.exe"), b"altered other artifact").unwrap();
        fs::copy(
            fixture.bundle.join("app.exe.asc"),
            fixture.bundle.join("other.exe.asc"),
        )
        .unwrap();
        other["architecture"] = serde_json::json!("arm64");
        other["file"] = serde_json::json!("other.exe");
        other["signature_file"] = serde_json::json!("other.exe.asc");
        other["sha256"] = serde_json::json!(digest(&fixture.bundle.join("other.exe")));
        fixture.manifest["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(other);
        fixture.write_manifest();
        assert!(fixture.verify().is_err());
    }
    #[test]
    fn artifact_wrong_and_unknown_signers_fail() {
        let mut fixture = Fixture::new();
        fixture.manifest["artifacts"][0]["signer_fingerprint"] =
            serde_json::json!(fixture.manifest_key);
        fixture.write_manifest();
        assert!(fixture.verify().is_err());
        fixture.sign("app.exe", &fixture.unknown_key);
        fixture.manifest["artifacts"][0]["signer_fingerprint"] =
            serde_json::json!(fixture.unknown_key);
        fixture.refresh_artifact_hashes();
        fixture.write_manifest();
        assert!(fixture.verify().is_err());
    }
    #[test]
    fn malformed_and_multiple_actual_signatures_fail() {
        let mut fixture = Fixture::new();
        let path = fixture.bundle.join("app.exe.asc");
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"malformed signature").unwrap();
        fixture.refresh_artifact_hashes();
        fixture.write_manifest();
        assert!(fixture.verify().is_err());
        let mut multiple = original.clone();
        multiple.extend_from_slice(&original);
        fs::write(path, multiple).unwrap();
        fixture.refresh_artifact_hashes();
        fixture.write_manifest();
        assert!(fixture.verify().is_err());
    }
    #[test]
    fn absent_changed_and_symlinked_resources_fail_closed() {
        let fixture = Fixture::new();
        let path = fixture.resources.join("trusted.gpg");
        let original = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(fixture.verify().is_err());
        fs::write(&path, b"wrong keyring").unwrap();
        assert!(fixture.verify().is_err());
        fs::remove_file(&path).unwrap();
        let outside = fixture.temp.path().join("keyring");
        fs::write(&outside, original).unwrap();
        std::os::unix::fs::symlink(outside, path).unwrap();
        assert!(fixture.verify().is_err());
    }
    #[test]
    fn missing_symlinked_and_nonregular_bundle_files_fail() {
        let fixture = Fixture::new();
        let path = fixture.bundle.join("app.exe");
        let data = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(fixture.verify().is_err());
        let outside = fixture.temp.path().join("outside");
        fs::write(&outside, data).unwrap();
        std::os::unix::fs::symlink(outside, &path).unwrap();
        assert!(fixture.verify().is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(fixture.verify().is_err());
    }
    #[test]
    fn captured_payload_and_signature_survive_original_replacement() {
        let fixture = Fixture::new();
        let payload = fixture.temp.path().join("0");
        let sig = fixture.temp.path().join("1");
        capture_file(&fixture.bundle.join("app.exe"), &payload, 1024).unwrap();
        capture_file(&fixture.bundle.join("app.exe.asc"), &sig, 64_000).unwrap();
        fs::write(fixture.bundle.join("app.exe"), b"changed after capture").unwrap();
        let helper = PreparedTrust::capture(&fixture.resources, &fixture.trust).unwrap();
        assert_eq!(
            signature(
                &helper,
                &sig,
                &payload,
                &fixture.artifact_key,
                Duration::from_secs(15)
            )
            .unwrap(),
            fixture.artifact_key
        );
    }
    #[test]
    fn captured_trusted_verifier_and_keyring_survive_original_replacement() {
        let fixture = Fixture::new();
        let helper = PreparedTrust::capture(&fixture.resources, &fixture.trust).unwrap();
        fs::write(fixture.resources.join("gpgv"), b"changed verifier").unwrap();
        fs::write(fixture.resources.join("trusted.gpg"), b"changed keyring").unwrap();
        assert!(signature(
            &helper,
            &fixture.bundle.join("app.exe.asc"),
            &fixture.bundle.join("app.exe"),
            &fixture.artifact_key,
            Duration::from_secs(15)
        )
        .is_ok());
    }
    #[test]
    fn capture_limits_do_not_truncate_or_leave_success() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        let output = temp.path().join("output");
        fs::write(&input, b"12345").unwrap();
        assert!(capture_file(&input, &output, 4).is_err());
        fs::remove_file(&output).ok();
        let (_, size) = capture_file(&input, &output, 5).unwrap();
        assert_eq!(size, 5);
        assert_eq!(fs::read(output).unwrap(), b"12345");
    }
    #[test]
    fn oversized_payload_and_signature_are_rejected_before_hashing() {
        let mut fixture = Fixture::new();
        File::options()
            .write(true)
            .open(fixture.bundle.join("app.exe"))
            .unwrap()
            .set_len(PAYLOAD_LIMIT + 1)
            .unwrap();
        assert_eq!(fixture.verify().unwrap_err(), UpdateError::Limit);
        fs::write(fixture.bundle.join("app.exe"), b"synthetic installer").unwrap();
        fs::write(fixture.bundle.join("app.exe.asc"), vec![b'x'; 64_001]).unwrap();
        fixture.refresh_artifact_hashes();
        fixture.write_manifest();
        assert_eq!(fixture.verify().unwrap_err(), UpdateError::Limit);
    }

    #[test]
    fn stuck_child_is_killed_reaped_and_private() {
        let mut fixture = Fixture::new();
        fixture.child_script("exec /bin/sleep 60");
        let helper = PreparedTrust::capture(&fixture.resources, &fixture.trust).unwrap();
        let start = Instant::now();
        assert_eq!(
            signature(
                &helper,
                &fixture.bundle.join("app.exe.asc"),
                &fixture.bundle.join("app.exe"),
                &fixture.artifact_key,
                Duration::from_millis(30)
            )
            .unwrap_err(),
            UpdateError::Signature
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn noisy_and_nonzero_children_fail_privately() {
        let mut fixture = Fixture::new();
        for body in [
            "exec /usr/bin/yes excessive-output",
            "echo secret-private-path >&2; exit 3",
        ] {
            fixture.child_script(body);
            let helper = PreparedTrust::capture(&fixture.resources, &fixture.trust).unwrap();
            assert_eq!(
                signature(
                    &helper,
                    &fixture.bundle.join("app.exe.asc"),
                    &fixture.bundle.join("app.exe"),
                    &fixture.artifact_key,
                    Duration::from_secs(2)
                )
                .unwrap_err(),
                UpdateError::Signature
            );
        }
    }
    #[test]
    fn helper_cwd_and_environment_are_isolated_from_bundle() {
        let mut fixture = Fixture::new();
        let report = fixture.temp.path().join("environment");
        fixture.child_script(&format!("printf '%s|%s|%s|%s' \"$PWD\" \"$GNUPGHOME\" \"${{LD_PRELOAD-}}\" \"${{LD_LIBRARY_PATH-}}\" > '{}'",report.display()));
        let helper = PreparedTrust::capture(&fixture.resources, &fixture.trust).unwrap();
        assert!(signature(
            &helper,
            &fixture.bundle.join("app.exe.asc"),
            &fixture.bundle.join("app.exe"),
            &fixture.artifact_key,
            Duration::from_secs(2)
        )
        .is_err());
        let report = fs::read_to_string(report).unwrap();
        let fields: Vec<_> = report.split('|').collect();
        assert_eq!(fields.len(), 4);
        assert_ne!(fields[0], fixture.bundle.to_str().unwrap());
        assert!(fields[1].starts_with(fields[0]));
        assert_eq!(fields[2], "");
        assert_eq!(fields[3], "");
    }
}
