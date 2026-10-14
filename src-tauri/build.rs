use std::{fs, io::Read, path::PathBuf, process::Command};

fn embed_update_trust() {
    println!("cargo:rerun-if-env-changed=PEAKACTIVITY_UPDATE_TRUST_FILE");
    println!("cargo:rerun-if-changed=../scripts/stage_update_trust.py");
    let out =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo output directory is required"));
    let code = match std::env::var_os("PEAKACTIVITY_UPDATE_TRUST_FILE") {
        None => "const COMPILED_TRUST: Option<&[u8]> = None;\n".to_owned(),
        Some(input) => {
            let input = PathBuf::from(input);
            println!("cargo:rerun-if-changed={}", input.display());
            let metadata =
                fs::symlink_metadata(&input).expect("Update trust build input is unavailable");
            assert!(
                metadata.is_file() && !metadata.is_symlink() && metadata.len() <= 64_000,
                "Update trust build input is invalid"
            );
            let mut data = Vec::new();
            fs::File::open(&input)
                .expect("Update trust build input is unavailable")
                .take(64_001)
                .read_to_end(&mut data)
                .expect("Update trust build input is unavailable");
            assert!(
                data.len() <= 64_000,
                "Update trust build input exceeds the limit"
            );
            let captured = out.join("update-trust-input.json");
            fs::write(&captured, &data).expect("Update trust build input could not be captured");
            let validated = Command::new("python3")
                .arg("../scripts/stage_update_trust.py")
                .arg("--validate-only")
                .arg(&captured)
                .output()
                .expect("Configured update verification builds require Python 3");
            assert!(
                validated.status.success(),
                "Update trust build input failed strict validation"
            );
            for name in String::from_utf8(validated.stdout)
                .expect("Update trust build validation failed")
                .lines()
            {
                println!(
                    "cargo:rerun-if-changed={}",
                    input
                        .parent()
                        .expect("Update trust build input needs a parent")
                        .join("update-verifier")
                        .join(name)
                        .display()
                );
            }
            let text = String::from_utf8(data).expect("Update trust build input is not UTF-8");
            format!("const COMPILED_TRUST: Option<&[u8]> = Some({text:?}.as_bytes());\n")
        }
    };
    fs::write(out.join("update-trust.rs"), code)
        .expect("Update trust build metadata could not be embedded");
}

fn main() {
    let webui_var = std::env::var("AW_WEBUI_DIR");
    if webui_var.is_err() {
        panic!("AW_WEBUI_DIR environment variable not set, Try running make");
    }
    println!("cargo:rerun-if-changed={}", webui_var.unwrap());
    println!("cargo:rerun-if-env-changed=AW_WEBUI_DIR");
    embed_update_trust();
    tauri_build::build();
}
