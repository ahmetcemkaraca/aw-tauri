use std::sync::OnceLock;
use aw_server::sessions::{Scope, Sessions};

static SESSIONS: OnceLock<Sessions> = OnceLock::new();
static PORT: OnceLock<u16> = OnceLock::new();

pub fn initialize(port: u16, testing: bool) -> Result<Sessions, String> {
    let sessions = Sessions::new(port, testing);
    PORT.set(port).map_err(|_| "Local sessions already initialized")?;
    SESSIONS.set(sessions.clone()).map_err(|_| "Local sessions already initialized")?;
    Ok(sessions)
}

pub struct CollectorLease {
    pub access_token: String,
    pub refresh_token: String,
    sessions: Sessions,
}

impl Drop for CollectorLease {
    fn drop(&mut self) { self.sessions.revoke_collector(&self.refresh_token); }
}

pub fn collector_token(name: &str) -> Result<CollectorLease, String> {
    let prefixes = match name {
        "aw-watcher-window" => vec!["aw-watcher-window_".into()],
        "aw-watcher-afk" => vec!["aw-watcher-afk_".into()],
        "aw-awatcher" => vec!["aw-watcher-window_".into(), "aw-watcher-afk_".into()],
        _ => return Err("This module is not an approved capture helper".into()),
    };
    let sessions = SESSIONS.get().ok_or("Local sessions unavailable")?.clone();
    let (access_token, refresh_token) = sessions.mint_collector(Scope::Ingest(prefixes)).map_err(str::to_string)?;
    Ok(CollectorLease { access_token, refresh_token, sessions })
}

pub(crate) fn verify_window(window: &tauri::WebviewWindow) -> Result<(), String> {
    let url = window.url().map_err(|_| "Cannot verify the requesting window")?;
    if window.label() != "main" || url.scheme() != "http"
        || !matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
        || url.port_or_known_default() != PORT.get().copied() {
        return Err("Only the local PeakActivity window can authorize a session".into());
    }
    Ok(())
}

#[tauri::command]
pub fn local_session(window: tauri::WebviewWindow) -> Result<String, String> {
    verify_window(&window)?;
    if !crate::vault::is_ready() { return Err("The vault is locked or unavailable".into()); }
    SESSIONS.get().ok_or("Local sessions unavailable")?
        .mint(Scope::Admin).map_err(str::to_string)
}

pub(crate) struct AiSendSessionLease {
    pub access_token: zeroize::Zeroizing<String>,
    sessions: Sessions,
}

impl Drop for AiSendSessionLease {
    fn drop(&mut self) { self.sessions.revoke_access_token(self.access_token.as_str()); }
}

pub(crate) fn ai_send_session() -> Result<AiSendSessionLease, String> {
    if !crate::vault::is_ready() { return Err("The vault is locked or unavailable".into()); }
    let sessions = SESSIONS.get().ok_or("Local sessions unavailable")?.clone();
    let access_token = sessions.mint(Scope::AiSend).map_err(str::to_string)?;
    Ok(AiSendSessionLease { access_token: zeroize::Zeroizing::new(access_token), sessions })
}

pub(crate) fn server_port() -> Result<u16, String> {
    PORT.get().copied().ok_or_else(|| "Local server is unavailable".into())
}

#[tauri::command]
pub fn pause_capture(window: tauri::WebviewWindow) -> Result<aw_server::CapturePolicy, String> {
    verify_window(&window)?;
    crate::capture::pause()
}

#[tauri::command]
pub fn pause_capture_for(window: tauri::WebviewWindow, minutes: u32) -> Result<aw_server::CapturePolicy, String> {
    verify_window(&window)?;
    if !matches!(minutes, 15 | 60) { return Err("Choose a 15-minute or 1-hour pause".into()); }
    crate::capture::pause_for(chrono::Duration::minutes(minutes.into()))
}

#[tauri::command]
pub fn pause_capture_until_tomorrow(window: tauri::WebviewWindow) -> Result<aw_server::CapturePolicy, String> {
    verify_window(&window)?;
    crate::capture::pause_until_tomorrow()
}

#[tauri::command]
pub fn enter_private_mode(window: tauri::WebviewWindow) -> Result<aw_server::CapturePolicy, String> {
    verify_window(&window)?;
    crate::capture::enter_private_mode()
}

#[tauri::command]
pub fn resume_capture(window: tauri::WebviewWindow) -> Result<aw_server::CapturePolicy, String> {
    verify_window(&window)?;
    crate::capture::resume()
}

#[tauri::command]
pub fn capture_runtime(window: tauri::WebviewWindow) -> Result<serde_json::Value, String> {
    verify_window(&window)?;
    Ok(crate::capture::runtime())
}

pub fn revoke_all() {
    if let Some(sessions) = SESSIONS.get() { sessions.revoke_all(); }
}
