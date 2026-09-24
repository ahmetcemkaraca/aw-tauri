use keyring::Entry;
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::redirect::Policy;
use serde::Serialize;
use std::io::Read;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use zeroize::Zeroizing;

const MAX_CREDENTIAL_BYTES: usize = 8192;
const MAX_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_NATIVE_PREVIEW_BYTES: usize = 16 * 1024;
static AI_CREDENTIAL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn valid_bearer_secret(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_BYTES
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn session_bearer_header(token: &str) -> Result<HeaderValue, String> {
    let bearer = Zeroizing::new(format!("Bearer {token}"));
    let mut header = HeaderValue::from_bytes(bearer.as_bytes())
        .map_err(|_| "The local AI session is invalid".to_string())?;
    header.set_sensitive(true);
    Ok(header)
}

fn valid_reference(value: &str) -> bool {
    crate::vault::valid_ai_credential_ref(value)
}

fn entry(reference: &str) -> Result<Entry, String> {
    if !valid_reference(reference) { return Err("Invalid AI credential reference".into()); }
    Entry::new(crate::vault::SERVICE, &format!("{}{reference}", crate::vault::AI_CREDENTIAL_ACCOUNT_PREFIX))
        .map_err(|_| "The native secret store is unavailable".into())
}

fn credential_index() -> Result<Vec<String>, String> {
    match Entry::new(crate::vault::SERVICE, crate::vault::AI_CREDENTIAL_INDEX_ACCOUNT)
        .map_err(|_| "The native secret store is unavailable")?.get_password()
    {
        Ok(serialized) => {
            let serialized = Zeroizing::new(serialized);
            let refs: Vec<String> = serde_json::from_str(&serialized)
                .map_err(|_| "The native AI credential index is invalid")?;
            let mut unique = refs.clone();
            unique.sort();
            unique.dedup();
            if refs.len() > crate::vault::MAX_AI_CREDENTIAL_REFS || refs != unique || refs.iter().any(|value| !valid_reference(value)) {
                return Err("The native AI credential index is invalid".into());
            }
            Ok(refs)
        }
        Err(keyring::Error::NoEntry) => Ok(Vec::new()),
        Err(_) => Err("The native secret store is unavailable".into()),
    }
}

fn store_credential_index(references: &[String]) -> Result<(), String> {
    let index = Entry::new(crate::vault::SERVICE, crate::vault::AI_CREDENTIAL_INDEX_ACCOUNT)
        .map_err(|_| "The native secret store is unavailable")?;
    if references.is_empty() {
        return match index.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("The native AI credential index could not be updated".into()),
        };
    }
    let serialized = Zeroizing::new(serde_json::to_string(references)
        .map_err(|_| "The native AI credential index could not be updated")?);
    index.set_password(&serialized)
        .map_err(|_| "The native AI credential index could not be updated")?;
    let readback = Zeroizing::new(index.get_password()
        .map_err(|_| "The native AI credential index could not be verified")?);
    if readback.as_str() != serialized.as_str() {
        return Err("The native AI credential index could not be verified".into());
    }
    Ok(())
}

#[tauri::command]
pub fn save_ai_credential(window: tauri::WebviewWindow, secret: String) -> Result<String, String> {
    crate::local_session::verify_window(&window)?;
    if !crate::vault::is_ready() { return Err("Unlock the local vault before saving an AI credential".into()); }
    if !valid_bearer_secret(&secret) {
        return Err("The AI credential is empty or invalid".into());
    }
    let _guard = AI_CREDENTIAL_LOCK.get_or_init(|| Mutex::new(())).lock()
        .map_err(|_| "The native secret store is unavailable")?;
    let secret = Zeroizing::new(secret);
    let mut references = credential_index()?;
    if references.len() >= crate::vault::MAX_AI_CREDENTIAL_REFS {
        return Err("The native AI credential limit has been reached".into());
    }
    let mut random = Zeroizing::new([0_u8; 16]);
    getrandom::getrandom(random.as_mut()).map_err(|_| "Secure randomness is unavailable")?;
    let reference = format!("cred-{}", random.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    if references.contains(&reference) { return Err("A native AI credential reference collision occurred".into()); }
    let credential = entry(&reference)?;
    match credential.get_password() {
        Err(keyring::Error::NoEntry) => {},
        Ok(existing) => {
            let _existing = Zeroizing::new(existing);
            return Err("A native AI credential reference collision occurred".into());
        }
        Err(_) => return Err("The native secret store is unavailable".into()),
    }
    let previous_references = references.clone();
    references.push(reference.clone());
    references.sort();
    if let Err(error) = store_credential_index(&references) {
        let _ = store_credential_index(&previous_references);
        return Err(error);
    }
    if credential.set_password(secret.as_str()).is_err() {
        let _ = credential.delete_credential();
        let _ = store_credential_index(&previous_references);
        return Err("The native secret store could not save the AI credential".into());
    }
    let saved = match credential.get_password() {
        Ok(saved) => Zeroizing::new(saved),
        Err(_) => {
            let _ = credential.delete_credential();
            let _ = store_credential_index(&previous_references);
            return Err("The native secret store could not verify the AI credential".into());
        }
    };
    if saved.as_str() != secret.as_str() {
        let _ = credential.delete_credential();
        let _ = store_credential_index(&previous_references);
        return Err("The native secret store could not verify the AI credential".into());
    }
    Ok(reference)
}

#[tauri::command]
pub fn delete_ai_credential(window: tauri::WebviewWindow, credential_ref: String) -> Result<(), String> {
    crate::local_session::verify_window(&window)?;
    if !crate::vault::is_ready() { return Err("Unlock the local vault before deleting an AI credential".into()); }
    let _guard = AI_CREDENTIAL_LOCK.get_or_init(|| Mutex::new(())).lock()
        .map_err(|_| "The native secret store is unavailable")?;
    let credential = entry(&credential_ref)?;
    let existing = match credential.get_password() {
        Ok(secret) => Some(Zeroizing::new(secret)),
        Err(keyring::Error::NoEntry) => None,
        Err(_) => return Err("The native secret store is unavailable".into()),
    };
    if existing.is_some() {
        credential.delete_credential().map_err(|_| "The native secret store could not delete the AI credential")?;
    }
    let mut references = match credential_index() {
        Ok(references) => references,
        Err(error) => {
            if let Some(secret) = existing.as_ref() { let _ = credential.set_password(secret.as_str()); }
            return Err(error);
        }
    };
    let previous_references = references.clone();
    references.retain(|value| value != &credential_ref);
    if let Err(error) = store_credential_index(&references) {
        if let Some(secret) = existing.as_ref() {
            let _ = credential.set_password(secret.as_str());
        }
        let _ = store_credential_index(&previous_references);
        return Err(error);
    }
    Ok(())
}

#[tauri::command]
pub fn has_ai_credential(window: tauri::WebviewWindow, credential_ref: String) -> Result<bool, String> {
    crate::local_session::verify_window(&window)?;
    if !crate::vault::is_ready() { return Err("Unlock the local vault before checking AI credentials".into()); }
    let _guard = AI_CREDENTIAL_LOCK.get_or_init(|| Mutex::new(())).lock()
        .map_err(|_| "The native secret store is unavailable")?;
    match entry(&credential_ref)?.get_password() {
        Ok(secret) => {
            let _secret = Zeroizing::new(secret);
            Ok(true)
        }
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(_) => Err("The native secret store is unavailable".into()),
    }
}

#[derive(Serialize)]
struct SendRequest {
    profile_id: String,
    credential_ref: Option<String>,
    preview_id: String,
    approval_id: String,
}

#[tauri::command]
pub async fn send_ai_request(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
    profile_id: String,
    credential_ref: Option<String>,
    preview_id: String,
    approval_id: String,
) -> Result<serde_json::Value, String> {
    crate::local_session::verify_window(&window)?;
    if !crate::vault::is_ready() { return Err("Unlock the local vault before sending an AI request".into()); }
    if preview_id.len() != 64 || !preview_id.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || approval_id.len() != 64 || !approval_id.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("The AI preview or approval ID is invalid".into());
    }
    let preview_session = crate::local_session::ai_send_session()?;
    let preview_token = preview_session.access_token.clone();
    let port = crate::local_session::server_port()?;
    let native_profile_id = profile_id.clone();
    let native_preview_id = preview_id.clone();
    let request = SendRequest {
        profile_id,
        credential_ref,
        preview_id,
        approval_id,
    };
    tauri::async_runtime::spawn_blocking(move || {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| "The local AI request could not be created".to_string())?;
        let preview_session_header = session_bearer_header(preview_token.as_str())?;
        let preview_response = client.post(format!("http://127.0.0.1:{port}/api/0/ai/native-preview/{native_preview_id}"))
            .header("Authorization", preview_session_header)
            .json(&serde_json::json!({ "approval_id": &request.approval_id }))
            .send()
            .map_err(|_| "The native AI preview is unavailable".to_string())?;
        if !preview_response.status().is_success() { return Err("The native AI preview is unavailable".into()); }
        if preview_response.content_length().is_some_and(|length| length > MAX_NATIVE_PREVIEW_BYTES as u64) {
            return Err("The exact AI preview is too large for native confirmation".into());
        }
        let mut preview_body = Zeroizing::new(Vec::new());
        preview_response.take((MAX_NATIVE_PREVIEW_BYTES + 1) as u64).read_to_end(&mut preview_body)
            .map_err(|_| "The native AI preview could not be read".to_string())?;
        if preview_body.len() > MAX_NATIVE_PREVIEW_BYTES { return Err("The exact AI preview is too large for native confirmation".into()); }
        let preview: serde_json::Value = serde_json::from_slice(&preview_body)
            .map_err(|_| "The native AI preview is invalid".to_string())?;
        if preview.get("profile_id").and_then(serde_json::Value::as_str) != Some(native_profile_id.as_str())
            || preview.pointer("/decision/preview_id").and_then(serde_json::Value::as_str) != Some(native_preview_id.as_str())
            || preview.pointer("/decision/outcome").and_then(serde_json::Value::as_str) != Some("allow")
            || preview.get("purpose_id").and_then(serde_json::Value::as_str) != Some("ai.custom_endpoint")
            || !preview.get("origin").and_then(serde_json::Value::as_str).is_some_and(|origin| origin.starts_with("https://"))
            || preview.get("model_id").and_then(serde_json::Value::as_str).is_none_or(str::is_empty)
            || preview.pointer("/decision/sanitized_payload").and_then(serde_json::Value::as_object).is_none()
        {
            return Err("The native AI preview no longer matches this request".into());
        }
        drop(preview_session);
        let payload = preview.pointer("/decision/sanitized_payload")
            .ok_or_else(|| "The native AI preview has no sanitized payload".to_string())?;
        let payload_text = serde_json::to_string_pretty(payload)
            .map_err(|_| "The native AI preview could not be displayed".to_string())?;
        let removed = preview.pointer("/decision/removed_fields").and_then(serde_json::Value::as_array)
            .map(|fields| fields.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        let removed = if removed.is_empty() { "none".to_string() } else { removed };
        let confirmation = format!(
            "Origin: {}\nModel: {}\nPurpose: {}\nRetention: {}\nPolicy version: {}\nApproval scope: once\nRemoved fields: {}\n\nExact sanitized payload:\n{}\n\nCancel sends nothing.",
            preview.get("origin").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
            preview.get("model_id").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
            preview.get("purpose_id").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
            preview.get("retention_disclosure").and_then(serde_json::Value::as_str).unwrap_or("Not verified"),
            preview.pointer("/decision/policy_version").and_then(serde_json::Value::as_u64).unwrap_or(0),
            removed,
            payload_text,
        );
        if !app.dialog().message(confirmation).title("Review exact AI request")
            .buttons(MessageDialogButtons::OkCancel).blocking_show()
        {
            return Err("AI request cancelled".into());
        }
        let secret = request.credential_ref.as_deref().map(|reference| {
            entry(reference)?.get_password().map(Zeroizing::new)
                .map_err(|_| "The native AI credential is unavailable".to_string())
        }).transpose()?;
        if secret.as_ref().is_some_and(|value| !valid_bearer_secret(value.as_str())) {
            return Err("The native AI credential is invalid".into());
        }
        let send_session = crate::local_session::ai_send_session()?;
        let session_header = session_bearer_header(send_session.access_token.as_str())?;
        let mut client_request = client.post(format!("http://127.0.0.1:{port}/api/0/ai/send"))
            .header("Authorization", session_header)
            .header(CONTENT_TYPE, "application/json");
        if let Some(secret) = secret.as_ref() {
            let mut credential_header = HeaderValue::from_bytes(secret.as_bytes())
                .map_err(|_| "The native AI credential is invalid".to_string())?;
            credential_header.set_sensitive(true);
            client_request = client_request.header("X-PeakActivity-AI-Credential", credential_header);
        }
        let response = client_request.json(&request).send()
            .map_err(|_| "The local AI request could not be completed".to_string())?;
        drop(send_session);
        if !response.status().is_success() { return Err("The approved AI request was denied or unavailable".into()); }
        if response.content_length().is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
            return Err("The AI response is too large".into());
        }
        let mut body = Zeroizing::new(Vec::new());
        response.take((MAX_RESPONSE_BYTES + 1) as u64).read_to_end(&mut body)
            .map_err(|_| "The AI response could not be read".to_string())?;
        if body.len() > MAX_RESPONSE_BYTES { return Err("The AI response is too large".into()); }
        serde_json::from_slice(&body).map_err(|_| "The AI response was invalid".into())
    }).await.map_err(|_| "The local AI request could not be completed".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_refs_and_bearer_values_are_strictly_bounded() {
        assert!(valid_reference("cred-0123456789abcdef0123456789abcdef"));
        assert!(!valid_reference("cred-../../secret"));
        assert!(valid_bearer_secret("synthetic-token_01"));
        assert!(!valid_bearer_secret("token with spaces"));
        assert!(!valid_bearer_secret("token\nheader"));
        assert!(!valid_bearer_secret(&"x".repeat(MAX_CREDENTIAL_BYTES + 1)));
    }
}
