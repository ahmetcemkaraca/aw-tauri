use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use aw_datastore::Datastore;
use aw_server::CapturePolicy;

static STORE: Mutex<Option<Datastore>> = Mutex::new(None);
static RUNTIME: Mutex<Option<serde_json::Value>> = Mutex::new(None);
// ponytail: Private Mode pauses every collector for this process; per-source privacy zones belong to EPIC-04.
static PRIVATE_MODE: AtomicBool = AtomicBool::new(false);

pub fn initialize(store: Datastore) -> Result<(), String> {
    store.enable_capture_policy().map_err(|_| "Capture policy could not be opened")?;
    PRIVATE_MODE.store(false, Ordering::SeqCst);
    let mut current_store = STORE.lock().map_err(|_| "Capture controls unavailable")?;
    let mut runtime = RUNTIME.lock().map_err(|_| "Capture status unavailable")?;
    *current_store = Some(store);
    *runtime = Some(serde_json::json!({"expected": [], "modules": {}, "private_mode": false}));
    Ok(())
}

pub fn policy() -> Option<CapturePolicy> {
    let store = STORE.lock().ok()?.clone()?;
    let policy = store.capture_policy().ok()?;
    if policy.recording { PRIVATE_MODE.store(false, Ordering::SeqCst); }
    Some(policy)
}

pub fn allowed(name: &str) -> bool {
    policy().is_some_and(|policy| policy.permits_helper(name, chrono::Utc::now()))
}

pub fn stop() {
    PRIVATE_MODE.store(false, Ordering::SeqCst);
    if let Ok(mut store) = STORE.lock() { *store = None; }
    if let Ok(mut runtime) = RUNTIME.lock() {
        *runtime = Some(serde_json::json!({"expected": [], "modules": {}, "private_mode": false}));
    }
}

pub fn pause() -> Result<CapturePolicy, String> {
    PRIVATE_MODE.store(false, Ordering::SeqCst);
    let store = STORE.lock().map_err(|_| "Capture controls unavailable")?.take();
    crate::local_session::revoke_all();
    let store = store.ok_or("Recording is stopped; the vault is unavailable")?;
    let policy = store.pause_capture().map_err(|_| "Recording stopped, but its setting could not be saved")?;
    *STORE.lock().map_err(|_| "Capture controls unavailable")? = Some(store);
    Ok(policy)
}

pub fn enter_private_mode() -> Result<CapturePolicy, String> {
    let policy = pause()?;
    PRIVATE_MODE.store(true, Ordering::SeqCst);
    Ok(policy)
}

pub fn resume() -> Result<CapturePolicy, String> {
    let store = STORE.lock().map_err(|_| "Capture controls unavailable")?.clone().ok_or("The vault is not open")?;
    let mut policy = store.capture_policy().map_err(|_| "Capture policy unavailable")?;
    if !(policy.window || policy.idle || policy.browser) {
        return Err("Enable at least one data source before resuming recording".into());
    }
    policy.recording = true;
    policy.paused_until = None;
    let policy = store.set_capture_policy(policy).map_err(|_| "Recording could not be resumed")?;
    PRIVATE_MODE.store(false, Ordering::SeqCst);
    crate::local_session::revoke_all();
    Ok(policy)
}

pub fn pause_for(duration: chrono::Duration) -> Result<CapturePolicy, String> {
    if duration <= chrono::Duration::zero() || duration > chrono::Duration::days(1) {
        return Err("Choose a pause from 1 second to 24 hours".into());
    }
    pause_until(chrono::Utc::now() + duration)
}

pub fn pause_until_tomorrow() -> Result<CapturePolicy, String> {
    use chrono::TimeZone;
    let Some(tomorrow) = chrono::Local::now().date_naive().succ_opt()
        .and_then(|date| date.and_hms_opt(0, 0, 0)) else {
        let _ = pause();
        return Err("The next local day is unavailable; recording was stopped instead".into());
    };
    let Some(local) = chrono::Local.from_local_datetime(&tomorrow).earliest() else {
        let _ = pause();
        return Err("The next local midnight is unavailable; recording was stopped instead".into());
    };
    pause_until(local.with_timezone(&chrono::Utc))
}

fn stop_after_schedule_error(store: &Datastore) -> String {
    PRIVATE_MODE.store(false, Ordering::SeqCst);
    crate::local_session::revoke_all();
    if store.pause_capture().is_ok() {
        "The scheduled pause could not be saved; recording was stopped instead".into()
    } else {
        "The scheduled pause and its fallback stop could not be confirmed; collector sessions were revoked".into()
    }
}

fn pause_until(until: chrono::DateTime<chrono::Utc>) -> Result<CapturePolicy, String> {
    let store = STORE.lock().map_err(|_| "Capture controls unavailable")?.clone().ok_or("The vault is not open")?;
    crate::local_session::revoke_all();
    PRIVATE_MODE.store(false, Ordering::SeqCst);
    let mut policy = match store.capture_policy() {
        Ok(policy) => policy,
        Err(_) => return Err(stop_after_schedule_error(&store)),
    };
    if !policy.recording || !(policy.window || policy.idle || policy.browser) {
        return Err("Start recording with at least one data source before scheduling a pause".into());
    }
    policy.paused_until = Some(until);
    match store.set_capture_policy(policy) {
        Ok(policy) => Ok(policy),
        Err(_) => Err(stop_after_schedule_error(&store)),
    }
}

pub fn private_mode() -> bool { PRIVATE_MODE.load(Ordering::SeqCst) }

pub fn is_active() -> bool {
    policy().is_some_and(|policy| policy.active(chrono::Utc::now()))
}

pub fn can_resume() -> bool {
    policy().is_some_and(|policy| policy.window || policy.idle || policy.browser)
}

fn capture_state_label(policy: Option<&CapturePolicy>, private_mode: bool, now: chrono::DateTime<chrono::Utc>) -> &'static str {
    if private_mode { return "Private Mode"; }
    let Some(policy) = policy else { return "Vault locked"; };
    if policy.active(now) { return "Recording"; }
    if policy.recording && policy.paused_until.is_some_and(|until| until > now) { return "Scheduled pause"; }
    "Recording off"
}

pub fn state_label() -> &'static str {
    let label = capture_state_label(policy().as_ref(), private_mode(), chrono::Utc::now());
    if label != "Recording" { return label; }
    let runtime = runtime();
    let expected = runtime.get("expected").and_then(serde_json::Value::as_array);
    let modules = runtime.get("modules").and_then(serde_json::Value::as_object);
    if expected.is_none_or(|expected| expected.is_empty())
        || expected.is_some_and(|expected| expected.iter().any(|name|
            name.as_str().and_then(|name| modules.and_then(|modules| modules.get(name)))
                .and_then(serde_json::Value::as_bool) != Some(true))) {
        return "Source unavailable";
    }
    label
}

pub fn runtime() -> serde_json::Value {
    RUNTIME.lock().ok().and_then(|state| state.clone()).unwrap_or_else(|| serde_json::json!({"expected": [], "modules": {}, "private_mode": false}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_state_labels_distinguish_recording_pause_and_private_mode() {
        let now = chrono::Utc::now();
        let active = aw_server::CapturePolicy { recording: true, effective_from: now - chrono::Duration::seconds(1), ..Default::default() };
        let scheduled = aw_server::CapturePolicy { recording: true, paused_until: Some(now + chrono::Duration::minutes(15)), ..active.clone() };
        let stopped = aw_server::CapturePolicy::default();
        assert_eq!(capture_state_label(Some(&active), false, now), "Recording");
        assert_eq!(capture_state_label(Some(&scheduled), false, now), "Scheduled pause");
        assert_eq!(capture_state_label(Some(&stopped), false, now), "Recording off");
        assert_eq!(capture_state_label(Some(&stopped), true, now), "Private Mode");
        assert_eq!(capture_state_label(None, false, now), "Vault locked");
    }

    #[test]
    fn failed_schedule_falls_back_to_a_persisted_capture_stop() {
        let store = Datastore::new_in_memory(false);
        let mut policy = store.enable_capture_policy().unwrap();
        policy.recording = true;
        store.set_capture_policy(policy).unwrap();

        let error = stop_after_schedule_error(&store);

        assert!(error.contains("recording was stopped"));
        assert!(!store.capture_policy().unwrap().recording);
        store.close();
    }
}

pub fn toggle_source(name: &str) -> Result<(), String> {
    let store = STORE.lock().map_err(|_| "Capture controls unavailable")?.clone().ok_or("The vault is not open")?;
    let mut policy = store.capture_policy().map_err(|_| "Capture policy unavailable")?;
    if !policy.recording { return Err("Review the data sources in Privacy settings before starting recording".into()); }
    match name {
        "aw-watcher-afk" => policy.idle = !policy.idle,
        "aw-watcher-window" => {
            let enabled = policy.window || policy.browser;
            policy.window = !enabled;
            if enabled { policy.browser = false; }
        }
        "aw-awatcher" => policy.recording = false,
        _ => return Err("This is not an approved capture source".into()),
    }
    store.set_capture_policy(policy).map_err(|_| "The capture change could not be saved")?;
    Ok(())
}

pub fn watch(manager: Arc<Mutex<crate::manager::ManagerState>>) {
    std::thread::spawn(move || {
        let mut previous = None;
        let mut previous_private_mode = false;
        let mut previous_sources = BTreeSet::new();
        let mut pending = BTreeSet::new();
        let mut next_retention_check = std::time::Instant::now();
        let mut last_retention_days = None;
        let mut last_retention_run: Option<std::time::Instant> = None;
        let mut retention_failed = false;
        loop {
            if std::time::Instant::now() >= next_retention_check {
                next_retention_check = std::time::Instant::now() + Duration::from_secs(60);
                if let Some(store) = STORE.lock().ok().and_then(|store| store.clone()) {
                    let days = store.get_key_value("settings.rawRetentionDays").ok()
                        .and_then(|value| serde_json::from_str::<u32>(&value).ok())
                        .filter(|days| *days <= 3650).unwrap_or(0);
                    let changed = last_retention_days != Some(days);
                    let due = last_retention_run.is_none_or(|last| last.elapsed() >= Duration::from_secs(24 * 60 * 60));
                    if days > 0 && (changed || due || retention_failed) {
                        match store.apply_raw_retention(days, chrono::Utc::now()) {
                            Ok(removed) => {
                                last_retention_run = Some(std::time::Instant::now());
                                retention_failed = false;
                                if removed > 0 { crate::vault::data_changed(); }
                            }
                            Err(_) => {
                                retention_failed = true;
                                log::warn!("Local raw-event retention could not complete; it will retry.");
                            }
                        }
                    }
                    if days == 0 {
                        last_retention_run = None;
                        retention_failed = false;
                    }
                    last_retention_days = Some(days);
                }
            }
            let policy = policy();
            let is_private_mode = private_mode();
            let desired: BTreeSet<String> = crate::get_config().autostart.modules.iter()
                .filter(|entry| policy.as_ref().is_some_and(|policy| policy.permits_helper(entry.name(), chrono::Utc::now())))
                .map(|entry| entry.name().to_string()).collect();
            let refresh_tray = policy != previous || is_private_mode != previous_private_mode;
            if let Ok(mut state) = manager.lock() {
                if previous != policy {
                    state.stop_modules();
                    state.reset_capture_retries();
                    pending = desired.clone();
                    previous = policy.clone();
                } else {
                    pending.extend(desired.difference(&previous_sources).cloned());
                }
                for name in previous_sources.difference(&desired) { state.stop_module(name); }
                pending.retain(|name| desired.contains(name));
                let states = state.modules_snapshot();
                for name in pending.clone() {
                    if states.get(&name) != Some(&Some(true)) {
                        state.start_module(&name, None);
                        pending.remove(&name);
                    }
                }
                previous_sources = desired.clone();
                if let Ok(mut runtime) = RUNTIME.lock() {
                    *runtime = Some(serde_json::json!({"expected": desired, "modules": state.modules_snapshot(), "private_mode": is_private_mode}));
                }
                previous_private_mode = is_private_mode;
            }
            if refresh_tray { crate::manager::refresh_tray_menu(&manager); }
            // Polling also enforces scheduled resume; crash retries stay with the manager.
            std::thread::sleep(Duration::from_millis(250));
        }
    });
}
