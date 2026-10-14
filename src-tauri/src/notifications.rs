use aw_datastore::{Datastore, DatastoreError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{collections::HashSet, fmt, marker::PhantomData};
use tauri_plugin_notification::NotificationExt;

const HISTORY_KEY: &str = "notifications.history.v1";
const LIMIT: usize = 200;
const MAX_BYTES: usize = 64 * 1024;
const MAX_RETRIES: usize = 32;
const HISTORY_UNAVAILABLE: &str =
    "Local notification history is unavailable. Clear it to start again.";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Code {
    Welcome,
    RecordingControlFailed,
    CaptureSourceUnavailable,
    CaptureSourceStopped,
    LocalNotice,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Delivery {
    Unknown,
    Attempted,
    Failed,
    Suppressed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ReviewSource {
    Home,
    Privacy,
    Categorization,
}

impl Code {
    pub(crate) fn title(self) -> &'static str {
        self.copy().0
    }

    pub(crate) fn body(self) -> &'static str {
        self.copy().1
    }

    fn copy(self) -> (&'static str, &'static str, ReviewSource) {
        match self {
            Self::Welcome => (
                "Welcome to PeakActivity",
                "Welcome to PeakActivity! Click on the tray icon to launch the dashboard.",
                ReviewSource::Home,
            ),
            Self::RecordingControlFailed => (
                "Recording control needs attention",
                "PeakActivity could not change recording. Review your privacy settings.",
                ReviewSource::Privacy,
            ),
            Self::CaptureSourceUnavailable => (
                "Capture source needs attention",
                "A capture source is unavailable. Review your privacy settings.",
                ReviewSource::Privacy,
            ),
            Self::CaptureSourceStopped => (
                "Capture source stopped",
                "A capture source stopped unexpectedly. Review your privacy settings.",
                ReviewSource::Privacy,
            ),
            Self::LocalNotice => (
                "Local PeakActivity notice",
                "PeakActivity has a local update. Review the dashboard for details.",
                ReviewSource::Home,
            ),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredHistory {
    schema_version: u32,
    #[serde(deserialize_with = "entries_from_maps")]
    entries: Vec<StoredEntry>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry {
    id: String,
    created_at: DateTime<Utc>,
    #[serde(deserialize_with = "string_enum")]
    code: Code,
    #[serde(deserialize_with = "string_enum")]
    delivery: Delivery,
}

// Serde's derived struct decoder also accepts tuples; stored history accepts objects only.
struct MapOnly<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for ObjectVisitor<T> {
            type Value = MapOnly<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

fn entries_from_maps<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<StoredEntry>, D::Error> {
    Vec::<MapOnly<StoredEntry>>::deserialize(deserializer)
        .map(|entries| entries.into_iter().map(|entry| entry.0).collect())
}

fn string_enum<'de, D: Deserializer<'de>, T: de::DeserializeOwned>(
    deserializer: D,
) -> Result<T, D::Error> {
    let value = String::deserialize(deserializer)?;
    serde_json::from_value(serde_json::Value::String(value)).map_err(de::Error::custom)
}

#[derive(Serialize)]
pub struct NotificationHistory {
    schema_version: u32,
    limit: usize,
    permission: &'static str,
    entries: Vec<NotificationEntry>,
}

#[derive(Serialize)]
struct NotificationEntry {
    id: String,
    created_at: DateTime<Utc>,
    code: Code,
    delivery: Delivery,
    title: &'static str,
    body: &'static str,
    review_source: ReviewSource,
}

fn view(history: StoredHistory) -> NotificationHistory {
    NotificationHistory {
        schema_version: 1,
        limit: LIMIT,
        permission: "unknown",
        entries: history
            .entries
            .into_iter()
            .map(|entry| {
                let (title, body, review_source) = entry.code.copy();
                NotificationEntry {
                    id: entry.id,
                    created_at: entry.created_at,
                    code: entry.code,
                    delivery: entry.delivery,
                    title,
                    body,
                    review_source,
                }
            })
            .collect(),
    }
}

fn empty_history() -> StoredHistory {
    StoredHistory {
        schema_version: 1,
        entries: Vec::new(),
    }
}

fn raw_history(store: &Datastore) -> Result<Option<String>, String> {
    if store.is_locked() || !store.is_encrypted() {
        return Err("Unlock the encrypted vault before viewing local notification history.".into());
    }
    match store.get_key_value(HISTORY_KEY) {
        Ok(value) => Ok(Some(value)),
        Err(DatastoreError::NoSuchKey(_)) => Ok(None),
        Err(_) => Err(HISTORY_UNAVAILABLE.into()),
    }
}

fn decode_history(raw: Option<&str>) -> Result<StoredHistory, String> {
    let Some(raw) = raw else {
        return Ok(empty_history());
    };
    if raw.len() > MAX_BYTES {
        return Err(HISTORY_UNAVAILABLE.into());
    }
    let history = serde_json::from_str::<MapOnly<StoredHistory>>(raw)
        .map_err(|_| HISTORY_UNAVAILABLE)?
        .0;
    if history.schema_version != 1 || history.entries.len() > LIMIT {
        return Err(HISTORY_UNAVAILABLE.into());
    }
    let mut ids = HashSet::new();
    for entry in &history.entries {
        let bytes = URL_SAFE_NO_PAD
            .decode(&entry.id)
            .map_err(|_| HISTORY_UNAVAILABLE)?;
        if bytes.len() != 16
            || URL_SAFE_NO_PAD.encode(&bytes) != entry.id
            || entry.created_at.timestamp_nanos_opt().is_none()
            || !ids.insert(&entry.id)
        {
            return Err(HISTORY_UNAVAILABLE.into());
        }
    }
    Ok(history)
}

fn read_from_store(store: &Datastore) -> Result<NotificationHistory, String> {
    decode_history(raw_history(store)?.as_deref()).map(view)
}

fn update_history(
    store: &Datastore,
    change: impl Fn(&mut StoredHistory) -> Result<bool, String>,
) -> Result<(), String> {
    for _ in 0..MAX_RETRIES {
        let raw = raw_history(store)?;
        let mut history = decode_history(raw.as_deref())?;
        if !change(&mut history)? {
            return Ok(());
        }
        let updated = serde_json::to_string(&history).map_err(|_| HISTORY_UNAVAILABLE)?;
        if updated.len() > MAX_BYTES {
            return Err(HISTORY_UNAVAILABLE.into());
        }
        if store
            .compare_and_set_key_value(HISTORY_KEY, raw.as_deref(), Some(&updated))
            .map_err(|_| HISTORY_UNAVAILABLE)?
        {
            return Ok(());
        }
    }
    Err("Local notification history changed. Try again.".into())
}

fn append_to_store(store: &Datastore, code: Code) -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| "Secure notification history IDs are unavailable.")?;
    let entry = StoredEntry {
        id: URL_SAFE_NO_PAD.encode(bytes),
        created_at: Utc::now(),
        code,
        delivery: Delivery::Unknown,
    };
    if entry.created_at.timestamp_nanos_opt().is_none() {
        return Err(HISTORY_UNAVAILABLE.into());
    }
    update_history(store, |history| {
        if history
            .entries
            .iter()
            .any(|existing| existing.id == entry.id)
        {
            return Err(HISTORY_UNAVAILABLE.into());
        }
        history.entries.push(entry.clone());
        if history.entries.len() > LIMIT {
            history.entries.drain(..history.entries.len() - LIMIT);
        }
        Ok(true)
    })?;
    Ok(entry.id)
}

fn set_delivery_in_store(store: &Datastore, id: &str, delivery: Delivery) -> Result<(), String> {
    update_history(store, |history| {
        let Some(entry) = history.entries.iter_mut().find(|entry| entry.id == id) else {
            return Ok(false);
        };
        entry.delivery = delivery;
        Ok(true)
    })
}

fn clear_in_store(store: &Datastore) -> Result<NotificationHistory, String> {
    for _ in 0..MAX_RETRIES {
        let raw = raw_history(store)?;
        if store
            .compare_and_set_key_value(HISTORY_KEY, raw.as_deref(), None)
            .map_err(|_| HISTORY_UNAVAILABLE)?
        {
            return Ok(view(empty_history()));
        }
    }
    Err("Local notification history changed. Try again.".into())
}

fn record_and_deliver(
    code: Code,
    suppressed: bool,
    append: impl FnOnce(Code) -> Result<String, String>,
    update: impl FnOnce(&str, Delivery) -> Result<(), String>,
    deliver: impl FnOnce(&str, &str) -> Result<(), ()>,
) -> Result<(), String> {
    let id = append(code);
    let delivery = if suppressed {
        Delivery::Suppressed
    } else {
        let (title, body, _) = code.copy();
        if deliver(title, body).is_ok() {
            Delivery::Attempted
        } else {
            Delivery::Failed
        }
    };
    update(&id?, delivery)
}

fn record(code: Code, suppressed: bool) {
    let result = record_and_deliver(
        code,
        suppressed,
        |code| crate::vault::with_ready_store(|store| append_to_store(store, code)),
        |id, delivery| {
            crate::vault::with_ready_store(|store| set_delivery_in_store(store, id, delivery))
        },
        |title, body| {
            let result = (|| {
                let app = crate::get_app_handle().lock().map_err(|_| ())?;
                app.notification()
                    .builder()
                    .title(title)
                    .body(body)
                    .show()
                    .map_err(|_| ())
            })();
            if result.is_err() {
                log::warn!("Local notification delivery failed");
            }
            result
        },
    );
    if result.is_err() {
        log::warn!("Local notification history could not be updated");
    }
}

pub(crate) fn notify(code: Code) {
    record(code, crate::is_daemon_mode());
}

pub(crate) fn record_suppressed(code: Code) {
    record(code, true);
}

#[tauri::command]
pub fn notification_history(window: tauri::WebviewWindow) -> Result<NotificationHistory, String> {
    crate::local_session::verify_window(&window)?;
    crate::vault::with_ready_store(read_from_store)
}

#[tauri::command]
pub fn clear_notification_history(
    window: tauri::WebviewWindow,
) -> Result<NotificationHistory, String> {
    crate::local_session::verify_window(&window)?;
    crate::vault::with_ready_store(clear_in_store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_datastore::Datastore;
    use serde_json::{json, Value};
    use std::sync::{Arc, Barrier};

    fn encrypted_store() -> Datastore {
        Datastore::open_encrypted(
            ":memory:".into(),
            "notification-history-test-key-".repeat(2),
        )
        .unwrap()
    }

    fn stored_row(id: &str) -> Value {
        json!({
            "id": id,
            "created_at": "2026-10-13T12:00:00Z",
            "code": "local-notice",
            "delivery": "unknown"
        })
    }

    fn history_with(row: Value) -> String {
        json!({ "schema_version": 1, "entries": [row] }).to_string()
    }

    #[test]
    fn encrypted_history_survives_reopen_without_extra_commit() {
        let path = std::env::temp_dir().join(format!(
            "peak-notification-history-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let key = "notification-history-reopen-key-".repeat(2);
        let store = Datastore::open_encrypted(path.to_str().unwrap().into(), key.clone()).unwrap();
        let id = append_to_store(&store, Code::Welcome).unwrap();
        set_delivery_in_store(&store, &id, Delivery::Attempted).unwrap();
        store.lock().unwrap();

        assert!(!std::fs::read(&path)
            .unwrap()
            .starts_with(b"SQLite format 3"));
        let reopened = Datastore::open_encrypted(path.to_str().unwrap().into(), key).unwrap();
        let view = read_from_store(&reopened).unwrap();
        assert_eq!(view.schema_version, 1);
        assert_eq!(view.limit, 200);
        assert_eq!(view.permission, "unknown");
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].id, id);
        assert_eq!(view.entries[0].delivery, Delivery::Attempted);
        assert_eq!(view.entries[0].title, "Welcome to PeakActivity");
        assert_eq!(view.entries[0].review_source, ReviewSource::Home);
        reopened.lock().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn append_retains_latest_two_hundred_entries_with_opaque_ids() {
        use base64::Engine;
        let store = encrypted_store();
        let first = append_to_store(&store, Code::Welcome).unwrap();
        for _ in 0..200 {
            append_to_store(&store, Code::LocalNotice).unwrap();
        }
        let view = read_from_store(&store).unwrap();
        assert_eq!(view.entries.len(), 200);
        assert!(view.entries.iter().all(|entry| entry.id != first));
        let ids: std::collections::HashSet<_> =
            view.entries.iter().map(|entry| &entry.id).collect();
        assert_eq!(ids.len(), 200);
        for entry in view.entries {
            assert_eq!(entry.id.len(), 22);
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(entry.id)
                    .unwrap()
                    .len(),
                16
            );
            assert!(entry.created_at.timestamp_nanos_opt().is_some());
        }
        let persisted = store.get_key_value("notifications.history.v1").unwrap();
        assert!(persisted.len() <= 64 * 1024);
        let persisted: Value = serde_json::from_str(&persisted).unwrap();
        assert_eq!(persisted.as_object().unwrap().len(), 2);
        for entry in persisted["entries"].as_array().unwrap() {
            assert_eq!(entry.as_object().unwrap().len(), 4);
            assert!(entry.get("body").is_none());
            assert!(entry.get("title").is_none());
        }
    }

    #[test]
    fn concurrent_append_does_not_lose_entries() {
        let store = encrypted_store();
        let barrier = Arc::new(Barrier::new(4));
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let store = store.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..8 {
                        append_to_store(&store, Code::LocalNotice).unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(read_from_store(&store).unwrap().entries.len(), 32);
    }

    #[test]
    fn clock_moving_back_does_not_evict_the_latest_arrival() {
        use base64::Engine;
        let store = encrypted_store();
        let rows: Vec<_> = (0_u16..200)
            .map(|index| {
                let mut bytes = [0_u8; 16];
                bytes[..2].copy_from_slice(&index.to_le_bytes());
                let mut row =
                    stored_row(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
                row["created_at"] = json!("2100-01-01T00:00:00Z");
                row
            })
            .collect();
        store
            .set_key_value(
                "notifications.history.v1",
                &json!({ "schema_version": 1, "entries": rows }).to_string(),
            )
            .unwrap();
        let newest = append_to_store(&store, Code::Welcome).unwrap();
        let view = read_from_store(&store).unwrap();
        assert_eq!(view.entries.len(), 200);
        assert_eq!(view.entries.last().unwrap().id, newest);
        assert!(view
            .entries
            .iter()
            .all(|entry| entry.id != "AAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn concurrent_clear_during_delivery_cannot_restore_a_cleared_entry() {
        let store = encrypted_store();
        let barrier = Arc::new(Barrier::new(2));
        let worker_store = store.clone();
        let worker_barrier = Arc::clone(&barrier);
        let delivery = std::thread::spawn(move || {
            record_and_deliver(
                Code::CaptureSourceStopped,
                false,
                |code| append_to_store(&worker_store, code),
                |id, outcome| set_delivery_in_store(&worker_store, id, outcome),
                |_, _| {
                    worker_barrier.wait();
                    worker_barrier.wait();
                    Ok(())
                },
            )
            .unwrap();
        });
        barrier.wait();
        assert_eq!(read_from_store(&store).unwrap().entries.len(), 1);
        assert!(clear_in_store(&store).unwrap().entries.is_empty());
        let survivor = append_to_store(&store, Code::Welcome).unwrap();
        barrier.wait();
        delivery.join().unwrap();
        let view = read_from_store(&store).unwrap();
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].id, survivor);
        assert_eq!(view.entries[0].delivery, Delivery::Unknown);
    }

    #[test]
    fn failed_os_delivery_keeps_the_record_with_fixed_safe_copy() {
        let store = encrypted_store();
        record_and_deliver(
            Code::RecordingControlFailed,
            false,
            |code| append_to_store(&store, code),
            |id, outcome| set_delivery_in_store(&store, id, outcome),
            |title, body| {
                let before_delivery = read_from_store(&store).unwrap();
                assert_eq!(before_delivery.entries.len(), 1);
                assert_eq!(before_delivery.entries[0].delivery, Delivery::Unknown);
                assert_eq!(title, "Recording control needs attention");
                assert_eq!(
                    body,
                    "PeakActivity could not change recording. Review your privacy settings."
                );
                Err(())
            },
        )
        .unwrap();
        let view = read_from_store(&store).unwrap();
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].delivery, Delivery::Failed);
        assert_eq!(view.permission, "unknown");
        assert_eq!(view.entries[0].review_source, ReviewSource::Privacy);
    }

    #[test]
    fn successful_os_call_records_attempt_without_claiming_permission() {
        let store = encrypted_store();
        record_and_deliver(
            Code::LocalNotice,
            false,
            |code| append_to_store(&store, code),
            |id, outcome| set_delivery_in_store(&store, id, outcome),
            |title, body| {
                assert_eq!(
                    read_from_store(&store).unwrap().entries[0].delivery,
                    Delivery::Unknown
                );
                assert_eq!(title, "Local PeakActivity notice");
                assert_eq!(
                    body,
                    "PeakActivity has a local update. Review the dashboard for details."
                );
                Ok(())
            },
        )
        .unwrap();
        let view = read_from_store(&store).unwrap();
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.entries[0].delivery, Delivery::Attempted);
        assert_eq!(view.permission, "unknown");
    }

    #[test]
    fn daemon_suppression_records_history_without_calling_delivery() {
        let store = encrypted_store();
        record_and_deliver(
            Code::LocalNotice,
            true,
            |code| append_to_store(&store, code),
            |id, outcome| set_delivery_in_store(&store, id, outcome),
            |_, _| panic!("Daemon must not contact the OS notification service"),
        )
        .unwrap();
        assert_eq!(
            read_from_store(&store).unwrap().entries[0].delivery,
            Delivery::Suppressed
        );
    }

    #[test]
    fn corrupt_history_is_preserved_and_errors_never_echo_private_input() {
        let store = encrypted_store();
        let corrupt = "private-activity-marker /private/path credential-secret";
        store
            .set_key_value("notifications.history.v1", corrupt)
            .unwrap();
        for error in [
            read_from_store(&store).err().unwrap(),
            append_to_store(&store, Code::LocalNotice).err().unwrap(),
            set_delivery_in_store(&store, "AAAAAAAAAAAAAAAAAAAAAA", Delivery::Failed)
                .err()
                .unwrap(),
        ] {
            assert_eq!(
                error,
                "Local notification history is unavailable. Clear it to start again."
            );
        }
        assert_eq!(
            store.get_key_value("notifications.history.v1").unwrap(),
            corrupt
        );
        assert!(clear_in_store(&store).unwrap().entries.is_empty());
        append_to_store(&store, Code::Welcome).unwrap();
        assert_eq!(read_from_store(&store).unwrap().entries.len(), 1);
    }

    #[test]
    fn strict_decoder_rejects_unknown_duplicate_tuple_and_invalid_fields() {
        let store = encrypted_store();
        let valid_id = "AAAAAAAAAAAAAAAAAAAAAA";
        let valid = stored_row(valid_id);
        let mut malformed = vec![
            json!({ "schema_version": 2, "entries": [] }).to_string(),
            json!({ "schema_version": 1, "entries": [], "private": "private-activity-marker" }).to_string(),
            json!([1, []]).to_string(),
            json!({ "schema_version": 1, "entries": [[valid_id, "2026-10-13T12:00:00Z", "local-notice", "unknown"]] }).to_string(),
            json!({ "schema_version": 1, "entries": [valid.clone(), valid.clone()] }).to_string(),
            "{\"schema_version\":1,\"schema_version\":1,\"entries\":[]}".into(),
            "{\"schema_version\":1,\"entries\":[{\"id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"id\":\"AQEBAQEBAQEBAQEBAQEBAQ\",\"created_at\":\"2026-10-13T12:00:00Z\",\"code\":\"local-notice\",\"delivery\":\"unknown\"}]}".into(),
            " ".repeat(64 * 1024 + 1),
        ];
        for (field, invalid) in [
            ("id", json!("not-an-opaque-id")),
            ("created_at", json!("not-a-date")),
            ("created_at", json!("9999-01-01T00:00:00Z")),
            ("code", json!("private-activity-marker")),
            ("code", json!({ "local-notice": null })),
            ("delivery", json!("granted")),
            ("delivery", json!({ "unknown": null })),
            ("body", json!("private-activity-marker")),
        ] {
            let mut row = valid.clone();
            row[field] = invalid;
            malformed.push(history_with(row));
        }
        use base64::Engine;
        let over_limit: Vec<_> = (0_u16..201)
            .map(|index| {
                let mut bytes = [0_u8; 16];
                bytes[..2].copy_from_slice(&index.to_le_bytes());
                stored_row(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
            })
            .collect();
        malformed.push(json!({ "schema_version": 1, "entries": over_limit }).to_string());
        for input in malformed {
            store
                .set_key_value("notifications.history.v1", &input)
                .unwrap();
            assert_eq!(
                read_from_store(&store).err().unwrap(),
                "Local notification history is unavailable. Clear it to start again."
            );
            assert!(append_to_store(&store, Code::Welcome).is_err());
            assert_eq!(
                store.get_key_value("notifications.history.v1").unwrap(),
                input
            );
        }
    }

    #[test]
    fn locked_and_plaintext_stores_reject_history_operations() {
        for store in [Datastore::new_locked(), Datastore::new_in_memory(false)] {
            assert!(read_from_store(&store).is_err());
            assert!(append_to_store(&store, Code::Welcome).is_err());
            assert!(clear_in_store(&store).is_err());
            assert!(
                set_delivery_in_store(&store, "AAAAAAAAAAAAAAAAAAAAAA", Delivery::Failed).is_err()
            );
        }
        let store = encrypted_store();
        append_to_store(&store, Code::Welcome).unwrap();
        store.lock().unwrap();
        assert!(read_from_store(&store).is_err());
        assert!(clear_in_store(&store).is_err());
    }

    #[test]
    fn failed_history_write_keeps_safe_operational_feedback_without_plaintext_fallback() {
        let store = Datastore::new_in_memory(false);
        let delivered = std::cell::Cell::new(false);
        assert!(record_and_deliver(
            Code::CaptureSourceUnavailable,
            false,
            |code| append_to_store(&store, code),
            |id, outcome| set_delivery_in_store(&store, id, outcome),
            |title, body| {
                assert_eq!(title, "Capture source needs attention");
                assert_eq!(
                    body,
                    "A capture source is unavailable. Review your privacy settings."
                );
                delivered.set(true);
                Ok(())
            },
        )
        .is_err());
        assert!(delivered.get());
        assert!(store.get_key_value("notifications.history.v1").is_err());
    }
}
