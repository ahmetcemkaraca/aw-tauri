use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use aw_datastore::{Datastore, SyncDeviceIdentity, SyncKeyMaterial, SyncSnapshotV1};
use aw_models::{BucketsExport, SyncOperationKindV1};
use aw_server::sync_control::{decrypt_recovery_snapshot, SyncRecoverySnapshotV1};
use aw_sync_e2ee::{
    accept_key_transfer, begin_pairing, complete_pairing, confirm_pairing, create_key_transfer,
    create_vault_data_key, decrypt_manifest, derive_pairing_session, generate_account_root_key,
    generate_device_identity, inspect_snapshot_chunk, pending_tombstone_ack_device_ids,
    respond_to_pairing, rotate_account_and_vault_key, unwrap_vault_data_key, AccountRootKeyV1,
    DeviceIdentityV1, DevicePublicIdentityV1, EncryptedKeyTransferV1, EncryptedSyncSnapshotV1,
    PairingConfirmationV1, PairingEphemeralKeyV1, PairingInvitationV1, PairingOfferV1,
    PairingResponseV1, PairingSessionV1, RecoveryKitV1, SyncKeyMaterialBundleV1, VaultDataKeyV1,
    WrappedVaultDataKeyV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{local_session, vault};
use aw_sync_e2ee::{create_recovery_kit as make_recovery_kit, open_recovery_kit};

static PENDING_PAIRING: OnceLock<Mutex<Option<PendingPairing>>> = OnceLock::new();
static RECOVERY_KIT_PENDING: AtomicBool = AtomicBool::new(false);

fn backup_context_from_store(store: &Datastore) -> Result<aw_models::SyncPolicyContextV1, String> {
    store
        .get_sync_policy_context()
        .map_err(|_| "Unlock the encrypted vault to browse backups".into())
}
fn backup_command_from_store(
    store: &Datastore,
    command: &str,
    request_json: String,
) -> Result<serde_json::Value, String> {
    aw_server::backup::invoke(
        store,
        command,
        serde_json::json!({"requestJson":request_json}),
    )
}

fn backup_delete_from_store(
    store: &Datastore,
    raw: String,
    user_accepted: bool,
) -> Result<serde_json::Value, String> {
    aw_server::backup::invoke(
        store,
        "delete_selected_sync_backup",
        serde_json::json!({"requestJson":raw,"userAccepted":user_accepted}),
    )
}
#[tauri::command]
pub async fn preview_sync_backup_delete(
    window: tauri::WebviewWindow,
    request_json: String,
) -> Result<serde_json::Value, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        vault::with_ready_store(|store| {
            backup_command_from_store(store, "preview_sync_backup_delete", request_json)
        })
    })
    .await
    .map_err(|_| "Backup deletion preview stopped")?
}
#[tauri::command]
pub async fn delete_selected_sync_backup(
    window: tauri::WebviewWindow,
    request_json: String,
    user_accepted: bool,
) -> Result<serde_json::Value, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        vault::with_ready_store(|store| {
            backup_delete_from_store(store, request_json, user_accepted)
        })
    })
    .await
    .map_err(|_| "Backup deletion stopped")?
}

fn selected_backup_preview_from_store(store: &Datastore, raw: String) -> Result<String, String> {
    let input = aw_server::backup::selected_restore_input(store, raw)?;
    crate::vault::check_sync_restore_context(store, Some(&input.target_context_id))?;
    let (_, _, preview) =
        validate_restore_preview(store, &input.kit, &input.phrase, &input.snapshot)?;
    serde_json::to_string(&preview)
        .map_err(|_| "Selected restore preview could not be encoded".into())
}

#[tauri::command]
pub async fn preview_selected_sync_backup_restore(
    window: tauri::WebviewWindow,
    request_json: String,
) -> Result<String, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        vault::with_ready_store(|store| selected_backup_preview_from_store(store, request_json))
    })
    .await
    .map_err(|_| "Selected restore preview stopped")?
}

#[tauri::command]
pub async fn restore_selected_sync_backup(
    window: tauri::WebviewWindow,
    request_json: String,
    user_accepted: bool,
) -> Result<String, String> {
    local_session::verify_window(&window)?;
    if !user_accepted {
        return Err("Review and accept the restore preview before restoring activity".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let input = vault::with_ready_store(|store| {
            aw_server::backup::selected_restore_input(store, request_json)
        })?;
        let preview = vault::restore_sync_recovery_kit_with_context(
            input.kit,
            &input.phrase,
            input.snapshot,
            Some(&input.target_context_id),
        )?;
        vault::data_changed();
        serde_json::to_string(&preview)
            .map_err(|_| "Selected restore result could not be encoded".into())
    })
    .await
    .map_err(|_| "Selected restore stopped")?
}

#[tauri::command]
pub async fn get_sync_backup_context(
    window: tauri::WebviewWindow,
) -> Result<aw_models::SyncPolicyContextV1, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(|| vault::with_ready_store(backup_context_from_store))
        .await
        .map_err(|_| "Backup context stopped")?
}

#[tauri::command]
pub async fn list_sync_backups(
    window: tauri::WebviewWindow,
    request_json: String,
) -> Result<serde_json::Value, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        vault::with_ready_store(|store| {
            backup_command_from_store(store, "list_sync_backups", request_json)
        })
    })
    .await
    .map_err(|_| "Backup catalogue stopped")?
}

#[tauri::command]
pub async fn export_selected_sync_backup(
    window: tauri::WebviewWindow,
    request_json: String,
) -> Result<String, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        vault::with_ready_store(|store| {
            match backup_command_from_store(store, "export_selected_sync_backup", request_json)? {
                serde_json::Value::String(raw) => Ok(raw),
                _ => Err("Selected backup export is invalid".into()),
            }
        })
    })
    .await
    .map_err(|_| "Selected backup export stopped")?
}

pub(crate) struct PendingPairing {
    identity: DeviceIdentityV1,
    invitation: PairingInvitationV1,
    recipient: bool,
    ephemeral: Option<PairingEphemeralKeyV1>,
    offer: Option<PairingOfferV1>,
    session: Option<PairingSessionV1>,
}

#[derive(Serialize)]
pub struct SyncDeviceSummaryV1 {
    pub schema_version: u32,
    pub device_id: String,
    pub x25519_public_key: String,
    pub ed25519_public_key: Option<String>,
    pub is_current_device: bool,
    pub paired_at: Option<String>,
    pub revoked_at: Option<String>,
    pub needs_repair: bool,
}

#[derive(Serialize)]
pub struct SyncDeviceAccessSummaryV1 {
    pub device_id: String,
    pub action: String,
    pub occurred_at: String,
}

#[derive(Serialize)]
pub struct SyncTombstoneStatusV1 {
    pub origin_device_id: String,
    pub local_event_id: u64,
    pub tombstone_counter: u64,
    pub active_device_ids: Vec<String>,
    pub pending_device_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct PairingDisplayV1 {
    pub offer: PairingOfferV1,
    pub verification_code: String,
}

#[derive(Serialize)]
pub struct SyncRecoveryDisplayV1 {
    pub recovery_phrase: String,
    pub kit: RecoveryKitV1,
}

#[derive(Serialize)]
pub struct SyncRecoveryPreviewV1 {
    pub vault_id: String,
    pub key_epoch: u64,
}

#[derive(Serialize)]
pub struct SyncRestorePreviewV1 {
    pub schema_version: u32,
    pub device_id: Option<String>,
    pub vault_id: String,
    pub key_epoch: u64,
    pub snapshot_id: String,
    pub object_count: usize,
    pub version_start: String,
    pub version_end: String,
    pub tombstone_count: usize,
    pub query_start: Option<String>,
    pub query_end: Option<String>,
    pub policy_conflict_count: usize,
    pub policy_continuity_present: bool,
    #[serde(skip)]
    pub target_policy_sha256: String,
}

#[derive(Serialize)]
pub struct SyncSnapshotInfoV1 {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub key_epoch: u64,
    pub object_count: usize,
}

fn pending_pairing() -> &'static Mutex<Option<PendingPairing>> {
    PENDING_PAIRING.get_or_init(|| Mutex::new(None))
}

pub(crate) fn clear_pending_pairing() {
    let mut pending = pending_pairing()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *pending = None;
    RECOVERY_KIT_PENDING.store(false, Ordering::Release);
}

pub(crate) fn idle_workflow() -> Result<MutexGuard<'static, Option<PendingPairing>>, String> {
    let pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    if RECOVERY_KIT_PENDING.load(Ordering::Acquire) {
        return Err("Save or cancel the current one-time recovery phrase first".into());
    }
    if pending.is_some() {
        return Err("Finish or cancel the current device pairing first".into());
    }
    Ok(pending)
}

pub(crate) fn mark_recovery_kit_pending() -> Result<(), String> {
    let _pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    RECOVERY_KIT_PENDING.store(true, Ordering::Release);
    Ok(())
}

fn load_or_create_device_identity(store: &Datastore) -> Result<(DeviceIdentityV1, bool), String> {
    if let Some(stored) = store
        .load_sync_device_identity()
        .map_err(|_| "The encrypted vault cannot load its sync identity")?
    {
        return Ok((
            DeviceIdentityV1::from_bytes(
                *stored.device_id(),
                Zeroizing::new(*stored.private_key()),
                Zeroizing::new(*stored.signing_seed()),
            ),
            false,
        ));
    }

    let identity = generate_device_identity().map_err(|error| error.to_string())?;
    store
        .create_sync_device_identity(&SyncDeviceIdentity::new(
            *identity.device_id_bytes(),
            identity.secret_for_storage(),
            identity.signing_seed_for_storage(),
        ))
        .map_err(|_| "The encrypted vault cannot save its sync identity")?;
    Ok((identity, true))
}

fn load_or_generate_sync_keys(
    store: &Datastore,
) -> Result<
    (
        AccountRootKeyV1,
        WrappedVaultDataKeyV1,
        Option<SyncKeyMaterial>,
    ),
    String,
> {
    if let Some(stored) = store
        .load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
    {
        let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*stored.account_root_key()));
        let wrapped = WrappedVaultDataKeyV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(stored.vault_id()),
            key_epoch: stored.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(stored.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(stored.wrapped_ciphertext()),
        };
        wrapped.validate().map_err(|error| error.to_string())?;
        unwrap_vault_data_key(&root, &wrapped).map_err(|error| error.to_string())?;
        return Ok((root, wrapped, None));
    }

    let root = generate_account_root_key().map_err(|error| error.to_string())?;
    let mut vault_id = [0u8; 16];
    getrandom::getrandom(&mut vault_id).map_err(|_| "Secure randomness is unavailable")?;
    let (data_key, wrapped) = create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode(vault_id), 1)
        .map_err(|error| error.to_string())?;
    drop(data_key);
    let material = material_from_keys(&root, &wrapped)?;
    Ok((root, wrapped, Some(material)))
}

pub(crate) fn material_from_keys(
    root: &AccountRootKeyV1,
    wrapped: &WrappedVaultDataKeyV1,
) -> Result<SyncKeyMaterial, String> {
    wrapped.validate().map_err(|error| error.to_string())?;
    Ok(SyncKeyMaterial::new(
        root.secret_for_storage(),
        decode_fixed::<16>(&wrapped.vault_id)?,
        wrapped.key_epoch,
        decode_fixed::<24>(&wrapped.nonce)?,
        decode_fixed::<48>(&wrapped.ciphertext)?,
    ))
}

pub(crate) fn rotated_sync_key_material(
    store: &Datastore,
) -> Result<(SyncKeyMaterial, VaultDataKeyV1), String> {
    let stored = store
        .load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
        .ok_or("Create sync keys before rotating them")?;
    let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*stored.account_root_key()));
    let wrapped = WrappedVaultDataKeyV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode(stored.vault_id()),
        key_epoch: stored.key_epoch(),
        nonce: URL_SAFE_NO_PAD.encode(stored.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(stored.wrapped_ciphertext()),
    };
    let (next_root, next_data_key, next_wrapped) =
        rotate_account_and_vault_key(&root, &wrapped).map_err(|error| error.to_string())?;
    Ok((
        material_from_keys(&next_root, &next_wrapped)?,
        next_data_key,
    ))
}

pub(crate) fn encrypt_current_snapshot(
    store: &Datastore,
    key: &VaultDataKeyV1,
) -> Result<SyncSnapshotV1, String> {
    aw_server::sync_control::encrypt_current_snapshot(store, key)
}

pub(crate) fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "Stored sync keys are invalid")?
        .try_into()
        .map_err(|_| "Stored sync keys are invalid".into())
}

#[tauri::command]
pub fn create_local_sync_identity(
    window: tauri::WebviewWindow,
) -> Result<DevicePublicIdentityV1, String> {
    local_session::verify_window(&window)?;
    let (public, created) = vault::with_ready_store(|store| {
        let (identity, created) = load_or_create_device_identity(store)?;
        Ok((identity.public_identity(), created))
    })?;
    if created {
        vault::data_changed();
    }
    Ok(public)
}

#[tauri::command]
pub fn list_sync_devices(window: tauri::WebviewWindow) -> Result<Vec<SyncDeviceSummaryV1>, String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|store| {
        let mut devices = Vec::new();
        let key_epoch = store
            .load_sync_key_material()
            .map_err(|_| "The encrypted vault cannot load its sync keys")?
            .map(|material| material.key_epoch())
            .unwrap_or(0);
        let current = store
            .load_sync_device_identity()
            .map_err(|_| "The encrypted vault cannot load its sync identity")?;
        let current_id = if let Some(stored) = current {
            let identity = DeviceIdentityV1::from_bytes(
                *stored.device_id(),
                Zeroizing::new(*stored.private_key()),
                Zeroizing::new(*stored.signing_seed()),
            );
            let public = identity.public_identity();
            let device_id = public.device_id;
            devices.push(SyncDeviceSummaryV1 {
                schema_version: 1,
                device_id: device_id.clone(),
                x25519_public_key: public.x25519_public_key,
                ed25519_public_key: Some(public.ed25519_public_key),
                is_current_device: true,
                paired_at: None,
                revoked_at: None,
                needs_repair: false,
            });
            Some(device_id)
        } else {
            None
        };
        for trusted in store
            .list_sync_trusted_devices()
            .map_err(|_| "The encrypted vault cannot list trusted sync devices")?
        {
            let device_id = URL_SAFE_NO_PAD.encode(trusted.device_id);
            if current_id.as_deref() == Some(device_id.as_str()) {
                continue;
            }
            devices.push(SyncDeviceSummaryV1 {
                schema_version: 1,
                device_id,
                x25519_public_key: URL_SAFE_NO_PAD.encode(trusted.x25519_public_key),
                ed25519_public_key: trusted
                    .ed25519_public_key
                    .map(|key| URL_SAFE_NO_PAD.encode(key)),
                is_current_device: false,
                paired_at: Some(trusted.paired_at),
                needs_repair: trusted.key_epoch != key_epoch
                    || trusted.ed25519_public_key.is_none(),
                revoked_at: trusted.revoked_at,
            });
        }
        Ok(devices)
    })
}

#[tauri::command]
pub fn create_sync_pairing(
    window: tauri::WebviewWindow,
    recipient: DevicePublicIdentityV1,
) -> Result<PairingInvitationV1, String> {
    local_session::verify_window(&window)?;
    let (invitation, created) =
        vault::with_ready_store(|store| create_sync_pairing_in_store(store, recipient))?;
    if created {
        vault::data_changed();
    }
    Ok(invitation)
}

fn create_sync_pairing_in_store(
    store: &Datastore,
    recipient: DevicePublicIdentityV1,
) -> Result<(PairingInvitationV1, bool), String> {
    let mut pending = idle_workflow()?;
    let (identity, created) = load_or_create_device_identity(store)?;
    let (invitation, ephemeral) =
        begin_pairing(&identity, &recipient).map_err(|error| error.to_string())?;
    *pending = Some(PendingPairing {
        identity,
        invitation: invitation.clone(),
        recipient: false,
        ephemeral: Some(ephemeral),
        offer: None,
        session: None,
    });
    Ok((invitation, created))
}

#[tauri::command]
pub fn respond_sync_pairing(
    window: tauri::WebviewWindow,
    invitation: PairingInvitationV1,
) -> Result<PairingResponseV1, String> {
    local_session::verify_window(&window)?;
    let (response, created) =
        vault::with_ready_store(|store| respond_sync_pairing_in_store(store, invitation))?;
    if created {
        vault::data_changed();
    }
    Ok(response)
}

fn respond_sync_pairing_in_store(
    store: &Datastore,
    invitation: PairingInvitationV1,
) -> Result<(PairingResponseV1, bool), String> {
    let mut pending = idle_workflow()?;
    let (identity, created) = load_or_create_device_identity(store)?;
    let (response, ephemeral) =
        respond_to_pairing(&identity, &invitation).map_err(|error| error.to_string())?;
    *pending = Some(PendingPairing {
        identity,
        invitation,
        recipient: true,
        ephemeral: Some(ephemeral),
        offer: None,
        session: None,
    });
    Ok((response, created))
}

#[tauri::command]
pub fn complete_sync_pairing(
    window: tauri::WebviewWindow,
    response: PairingResponseV1,
) -> Result<PairingDisplayV1, String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|_| complete_sync_pairing_from_response(response))
}

fn complete_sync_pairing_from_response(
    response: PairingResponseV1,
) -> Result<PairingDisplayV1, String> {
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    let state = pending
        .as_mut()
        .ok_or("Start or respond to a pairing before completing it")?;
    if state.recipient {
        return Err(
            "This device is waiting for the initiating device to complete the offer".into(),
        );
    }
    let invitation = state.invitation.clone();
    let offer = complete_pairing(invitation, response).map_err(|error| error.to_string())?;
    let ephemeral = state
        .ephemeral
        .take()
        .ok_or("The pairing invitation has expired; start again")?;
    let session = derive_pairing_session(&state.identity, ephemeral, offer.clone())
        .map_err(|error| error.to_string())?;
    let display = PairingDisplayV1 {
        offer: offer.clone(),
        verification_code: session.verification_code().to_owned(),
    };
    state.session = Some(session);
    state.offer = Some(display.offer.clone());
    Ok(display)
}

#[tauri::command]
pub fn prepare_sync_pairing(
    window: tauri::WebviewWindow,
    offer: PairingOfferV1,
) -> Result<String, String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|_| prepare_sync_pairing_from_offer(offer))
}

fn prepare_sync_pairing_from_offer(offer: PairingOfferV1) -> Result<String, String> {
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    let state = pending
        .as_mut()
        .ok_or("Respond to a pairing invitation before preparing the offer")?;
    if !state.recipient {
        return Err("The initiating device must complete the pairing offer".into());
    }
    if state.invitation.offer_id != offer.offer_id {
        return Err("The pairing offer does not match the active invitation".into());
    }
    let ephemeral = state
        .ephemeral
        .take()
        .ok_or("The pairing response has expired; start again")?;
    let session = derive_pairing_session(&state.identity, ephemeral, offer.clone())
        .map_err(|error| error.to_string())?;
    let code = session.verification_code().to_owned();
    state.session = Some(session);
    state.offer = Some(offer);
    Ok(code)
}

#[tauri::command]
pub fn confirm_sync_pairing(
    window: tauri::WebviewWindow,
    displayed_code: String,
    user_confirmed: bool,
) -> Result<PairingConfirmationV1, String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|_| confirm_sync_pairing_from_code(&displayed_code, user_confirmed))
}

fn confirm_sync_pairing_from_code(
    displayed_code: &str,
    user_confirmed: bool,
) -> Result<PairingConfirmationV1, String> {
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    let session = pending
        .as_mut()
        .and_then(|state| state.session.as_mut())
        .ok_or("Compare the pairing code before confirming")?;
    confirm_pairing(session, displayed_code, user_confirmed).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn create_sync_key_transfer(
    window: tauri::WebviewWindow,
    peer_confirmation: PairingConfirmationV1,
) -> Result<EncryptedKeyTransferV1, String> {
    local_session::verify_window(&window)?;
    let transfer = vault::with_ready_store(|store| {
        create_sync_key_transfer_in_store(store, peer_confirmation)
    })?;
    vault::data_changed();
    Ok(transfer)
}

fn create_sync_key_transfer_in_store(
    store: &Datastore,
    peer_confirmation: PairingConfirmationV1,
) -> Result<EncryptedKeyTransferV1, String> {
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    let state = pending
        .as_ref()
        .ok_or("Confirm a device pairing before transferring keys")?;
    if state.recipient {
        return Err("The responding device accepts the key transfer".into());
    }
    let session = state
        .session
        .as_ref()
        .ok_or("Compare and confirm the pairing code first")?;
    let (root, wrapped, new_material) = load_or_generate_sync_keys(store)?;
    let transfer = create_key_transfer(session, &peer_confirmation, &root, &wrapped)
        .map_err(|error| error.to_string())?;
    let peer = state
        .offer
        .as_ref()
        .ok_or("The pairing offer is unavailable")?;
    let recipient = peer.recipient.clone();
    ensure_peer_not_revoked(store, &recipient.device_id)?;
    store
        .record_sync_pairing(
            new_material,
            decode_fixed::<16>(&peer.offer_id)?,
            decode_fixed::<16>(&recipient.device_id)?,
            decode_fixed::<32>(&recipient.x25519_public_key)?,
            decode_fixed::<32>(&recipient.ed25519_public_key)?,
            chrono::Utc::now().to_rfc3339(),
        )
        .map_err(|_| "The encrypted vault cannot save sync keys and trusted-device history")?;
    *pending = None;
    Ok(transfer)
}

#[tauri::command]
pub fn accept_sync_key_transfer(
    window: tauri::WebviewWindow,
    peer_confirmation: PairingConfirmationV1,
    transfer: EncryptedKeyTransferV1,
) -> Result<DevicePublicIdentityV1, String> {
    local_session::verify_window(&window)?;
    let peer = vault::with_ready_store(|store| {
        accept_sync_key_transfer_in_store(store, peer_confirmation, transfer)
    })?;
    vault::data_changed();
    Ok(peer)
}

fn accept_sync_key_transfer_in_store(
    store: &Datastore,
    peer_confirmation: PairingConfirmationV1,
    transfer: EncryptedKeyTransferV1,
) -> Result<DevicePublicIdentityV1, String> {
    if store
        .load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot inspect sync keys")?
        .is_some()
    {
        return Err("This device already has sync keys; its existing data was preserved".into());
    }
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    let state = pending
        .as_mut()
        .ok_or("Prepare and confirm a pairing before accepting keys")?;
    if !state.recipient {
        return Err("The initiating device creates the key transfer".into());
    }
    let session = state
        .session
        .as_ref()
        .ok_or("Compare and confirm the pairing code first")?;
    let offer = state
        .offer
        .as_ref()
        .ok_or("The pairing offer is unavailable")?;
    let imported = accept_key_transfer(session, &peer_confirmation, &transfer)
        .map_err(|error| error.to_string())?;
    ensure_peer_not_revoked(store, &offer.issuer.device_id)?;
    let material = material_from_keys(&imported.account_root_key, &imported.wrapped_vault_key)?;
    store
        .record_sync_pairing(
            Some(material),
            decode_fixed::<16>(&offer.offer_id)?,
            decode_fixed::<16>(&offer.issuer.device_id)?,
            decode_fixed::<32>(&offer.issuer.x25519_public_key)?,
            decode_fixed::<32>(&offer.issuer.ed25519_public_key)?,
            chrono::Utc::now().to_rfc3339(),
        )
        .map_err(|_| "The encrypted vault cannot save transferred keys and device history")?;
    let peer = offer.issuer.clone();
    *pending = None;
    Ok(peer)
}

#[tauri::command]
pub fn cancel_sync_pairing(window: tauri::WebviewWindow) -> Result<(), String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|_| cancel_pending_pairing())
}

fn cancel_pending_pairing() -> Result<(), String> {
    *pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")? = None;
    Ok(())
}

#[tauri::command]
pub fn create_sync_recovery_kit(
    window: tauri::WebviewWindow,
) -> Result<SyncRecoveryDisplayV1, String> {
    local_session::verify_window(&window)?;
    let (display, new_material) = vault::with_ready_store(create_sync_recovery_kit_in_store)?;
    if new_material {
        vault::data_changed();
    }
    Ok(display)
}

fn create_sync_recovery_kit_in_store(
    store: &Datastore,
) -> Result<(SyncRecoveryDisplayV1, bool), String> {
    let _pending = idle_workflow()?;
    RECOVERY_KIT_PENDING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "Save or cancel the current one-time recovery phrase first")?;
    let result = (|| {
        if store
            .sync_recovery_confirmation()
            .map_err(|_| "The encrypted vault cannot inspect recovery status")?
            .is_some()
        {
            return Err(
                "A recovery phrase is already confirmed; rotate the sync root before replacing it"
                    .into(),
            );
        }
        let (root, wrapped, new_material) = load_or_generate_sync_keys(store)?;
        let (phrase, kit) =
            make_recovery_kit(&root, &wrapped).map_err(|error| error.to_string())?;
        if let Some(material) = &new_material {
            store
                .install_sync_key_material(material)
                .map_err(|_| "The encrypted vault cannot save sync recovery keys")?;
        }
        Ok((phrase, kit, new_material.is_some()))
    })();
    let (phrase, kit, new_material) = match result {
        Ok(result) => result,
        Err(error) => {
            RECOVERY_KIT_PENDING.store(false, Ordering::Release);
            return Err(error);
        }
    };
    Ok((
        SyncRecoveryDisplayV1 {
            recovery_phrase: phrase,
            kit,
        },
        new_material,
    ))
}

#[tauri::command]
pub fn verify_sync_recovery_kit(
    window: tauri::WebviewWindow,
    kit: RecoveryKitV1,
    recovery_phrase: String,
) -> Result<SyncRecoveryPreviewV1, String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|_| {
        let recovered =
            open_recovery_kit(&kit, &recovery_phrase).map_err(|error| error.to_string())?;
        Ok(recovery_preview(&recovered))
    })
}

fn ensure_clean_restore_target(store: &Datastore) -> Result<(), String> {
    if store
        .load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot inspect sync keys")?
        .is_some()
    {
        return Err("This device already has sync keys; its existing keys were preserved".into());
    }
    if store
        .load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot inspect local sync snapshots")?
        .is_some()
    {
        return Err(
            "This device already has a sync snapshot; its existing state was preserved".into(),
        );
    }
    if !store
        .get_buckets()
        .map_err(|_| "The encrypted vault cannot inspect local activity")?
        .is_empty()
    {
        return Err("Sync snapshot restore requires a clean activity vault".into());
    }
    if store
        .capture_policy()
        .map_err(|_| "The encrypted vault cannot inspect recording state")?
        .recording
    {
        return Err("Pause recording before restoring a sync snapshot".into());
    }
    Ok(())
}

pub(crate) fn validate_restore_preview(
    store: &Datastore,
    kit: &RecoveryKitV1,
    recovery_phrase: &str,
    snapshot: &EncryptedSyncSnapshotV1,
) -> Result<
    (
        SyncKeyMaterialBundleV1,
        SyncRecoverySnapshotV1,
        SyncRestorePreviewV1,
    ),
    String,
> {
    ensure_clean_restore_target(store)?;
    let recovered = open_recovery_kit(kit, recovery_phrase).map_err(|error| error.to_string())?;
    let data_key = unwrap_vault_data_key(&recovered.account_root_key, &recovered.wrapped_vault_key)
        .map_err(|error| error.to_string())?;
    let export = decrypt_recovery_snapshot(&data_key, snapshot)?;
    let lease = store
        .egress_lease()
        .map_err(|_| "The recovery target is unavailable")?;
    let context = lease
        .sync_policy_context()
        .map_err(|_| "The recovery target is unavailable")?
        .context_id;
    lease
        .ensure_sync_backup_not_deleted(
            context,
            URL_SAFE_NO_PAD.encode(data_key.vault_id()),
            data_key.key_epoch(),
            snapshot.snapshot_id.clone(),
            snapshot
                .envelopes
                .iter()
                .map(|o| o.object_id.clone())
                .collect(),
        )
        .map_err(|_| "This backup was already deleted in the target vault")?;
    drop(lease);

    let device_id = store
        .load_sync_device_identity()
        .map_err(|_| "The encrypted vault cannot inspect its device identity")?
        .map(|identity| URL_SAFE_NO_PAD.encode(identity.device_id()));
    let policies = store
        .preview_sync_recovery_policy(
            export.sync.clone(),
            decode_fixed::<16>(&recovered.wrapped_vault_key.vault_id)?,
            recovered.wrapped_vault_key.key_epoch,
            decode_fixed::<16>(&snapshot.snapshot_id)?,
            false,
        )
        .map_err(|_| "The encrypted recovery policy could not be compared to local settings")?;
    let mut preview = build_restore_preview(
        snapshot,
        &export.activity,
        device_id,
        recovered.wrapped_vault_key.vault_id.clone(),
        recovered.wrapped_vault_key.key_epoch,
        policies,
    );
    preview.tombstone_count = export
        .sync
        .event_mappings
        .iter()
        .filter(|mapping| mapping.deleted)
        .count();
    Ok((recovered, export, preview))
}

fn build_restore_preview(
    snapshot: &EncryptedSyncSnapshotV1,
    export: &BucketsExport,
    device_id: Option<String>,
    vault_id: String,
    key_epoch: u64,
    policies: aw_models::SyncRecoveryPolicySummaryV1,
) -> SyncRestorePreviewV1 {
    let mut query_start = None;
    let mut query_end = None;
    for event in export
        .buckets
        .values()
        .flat_map(|bucket| bucket.events.iter().flat_map(|events| events.iter()))
    {
        let timestamp = event.timestamp.to_rfc3339();
        if query_start
            .as_ref()
            .is_none_or(|start: &String| timestamp.as_str() < start.as_str())
        {
            query_start = Some(timestamp.clone());
        }
        if query_end
            .as_ref()
            .is_none_or(|end: &String| timestamp.as_str() > end.as_str())
        {
            query_end = Some(timestamp);
        }
    }
    let preview = SyncRestorePreviewV1 {
        schema_version: snapshot.schema_version,
        device_id,
        vault_id,
        key_epoch,
        snapshot_id: snapshot.snapshot_id.clone(),
        object_count: snapshot.envelopes.len(),
        version_start: snapshot.snapshot_id.clone(),
        version_end: snapshot.snapshot_id.clone(),
        tombstone_count: 0,
        query_start,
        query_end,
        policy_conflict_count: policies.conflict_count,
        policy_continuity_present: policies.continuity_present,
        target_policy_sha256: policies.target_binding_sha256,
    };
    preview
}

#[tauri::command]
pub async fn preview_sync_recovery_restore(
    window: tauri::WebviewWindow,
    kit: RecoveryKitV1,
    recovery_phrase: String,
    snapshot: EncryptedSyncSnapshotV1,
) -> Result<SyncRestorePreviewV1, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        vault::with_ready_store(|store| {
            let (_, _, preview) =
                validate_restore_preview(store, &kit, &recovery_phrase, &snapshot)?;
            Ok(preview)
        })
    })
    .await
    .map_err(|_| "Sync snapshot preview stopped")?
}

#[tauri::command]
pub async fn export_sync_snapshot(
    window: tauri::WebviewWindow,
) -> Result<Option<EncryptedSyncSnapshotV1>, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(|| {
        vault::with_ready_store(export_sync_snapshot_from_store)
    })
    .await
    .map_err(|_| "Snapshot export stopped")?
}

#[tauri::command]
pub async fn create_current_sync_snapshot(
    window: tauri::WebviewWindow,
) -> Result<SyncSnapshotInfoV1, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(|| {
        vault::with_ready_store(create_current_sync_snapshot_from_store)
    })
    .await
    .map_err(|_| "Snapshot creation stopped".to_string())?
}

fn create_current_sync_snapshot_from_store(
    store: &Datastore,
) -> Result<SyncSnapshotInfoV1, String> {
    if store
        .sync_recovery_confirmation()
        .map_err(|_| "The encrypted vault cannot inspect recovery status")?
        .is_none()
    {
        return Err(
            "Confirm a recovery kit for the current sync keys before creating a snapshot".into(),
        );
    }
    let keys = store
        .load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
        .ok_or("Create or receive sync keys before creating a snapshot")?;
    let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*keys.account_root_key()));
    let wrapped = WrappedVaultDataKeyV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode(keys.vault_id()),
        key_epoch: keys.key_epoch(),
        nonce: URL_SAFE_NO_PAD.encode(keys.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(keys.wrapped_ciphertext()),
    };
    let key = unwrap_vault_data_key(&root, &wrapped).map_err(|error| error.to_string())?;
    let snapshot = encrypt_current_snapshot(store, &key)?;
    let info = SyncSnapshotInfoV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode(snapshot.snapshot_id),
        key_epoch: keys.key_epoch(),
        object_count: snapshot.envelopes.len(),
    };
    if let Some(previous) = store
        .load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot read its current snapshot")?
    {
        queue_sync_snapshot_objects(store, &previous)?;
    }
    store
        .save_sync_snapshot(keys, snapshot)
        .map_err(|_| "The encrypted activity snapshot could not be stored".to_string())?;
    let current = store
        .load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot verify its current snapshot")?
        .ok_or("The encrypted snapshot was not stored")?;
    queue_sync_snapshot_objects(store, &current)?;
    Ok(info)
}

fn queue_sync_snapshot_objects(store: &Datastore, snapshot: &SyncSnapshotV1) -> Result<(), String> {
    let stored_at = chrono::Utc::now().to_rfc3339();
    for envelope in &snapshot.envelopes {
        envelope
            .validate()
            .map_err(|_| "Snapshot contains an invalid encrypted envelope")?;
        store
            .put_sync_object(envelope.clone(), stored_at.clone())
            .map_err(|_| "Encrypted snapshot object could not be queued")?;
    }
    Ok(())
}

fn export_sync_snapshot_from_store(
    store: &Datastore,
) -> Result<Option<EncryptedSyncSnapshotV1>, String> {
    if store
        .sync_recovery_confirmation()
        .map_err(|_| "The encrypted vault cannot inspect recovery status")?
        .is_none()
    {
        return Err(
            "Confirm a recovery kit for the current sync keys before exporting a snapshot".into(),
        );
    }
    let keys = store
        .load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
        .ok_or("Sync snapshot keys are missing")?;
    let Some(stored) = store
        .load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot load its sync snapshot")?
    else {
        return Ok(None);
    };
    let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*keys.account_root_key()));
    let wrapped = WrappedVaultDataKeyV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode(keys.vault_id()),
        key_epoch: keys.key_epoch(),
        nonce: URL_SAFE_NO_PAD.encode(keys.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(keys.wrapped_ciphertext()),
    };
    let key = unwrap_vault_data_key(&root, &wrapped).map_err(|error| error.to_string())?;
    let snapshot = EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode(stored.snapshot_id),
        envelopes: stored.envelopes,
    };
    decrypt_recovery_snapshot(&key, &snapshot)?;
    Ok(Some(snapshot))
}

#[tauri::command]
pub async fn restore_sync_recovery_kit(
    window: tauri::WebviewWindow,
    kit: RecoveryKitV1,
    recovery_phrase: String,
    snapshot: EncryptedSyncSnapshotV1,
    user_accepted: bool,
) -> Result<SyncRestorePreviewV1, String> {
    local_session::verify_window(&window)?;
    if !user_accepted {
        return Err("Review and accept the restore preview before restoring activity".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        restore_sync_recovery_kit_from_input(kit, recovery_phrase, snapshot)
    })
    .await
    .map_err(|_| "Sync snapshot restore stopped")?
}

pub(crate) fn restore_sync_recovery_kit_from_input(
    kit: RecoveryKitV1,
    recovery_phrase: String,
    snapshot: EncryptedSyncSnapshotV1,
) -> Result<SyncRestorePreviewV1, String> {
    let preview = vault::restore_sync_recovery_kit(kit, &recovery_phrase, snapshot)?;
    vault::data_changed();
    Ok(preview)
}

#[tauri::command]
pub fn confirm_sync_recovery_saved(
    window: tauri::WebviewWindow,
    user_confirmed: bool,
) -> Result<(), String> {
    local_session::verify_window(&window)?;
    if !user_confirmed {
        return Err("Confirm only after saving the recovery phrase".into());
    }
    vault::with_ready_store(confirm_sync_recovery_saved_in_store)?;
    vault::data_changed();
    Ok(())
}

fn confirm_sync_recovery_saved_in_store(store: &Datastore) -> Result<(), String> {
    let _pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    if !RECOVERY_KIT_PENDING.load(Ordering::Acquire) {
        return Err("Create a recovery kit before confirming it was saved".into());
    }
    store
        .confirm_sync_recovery_saved(chrono::Utc::now().to_rfc3339())
        .map_err(|_| "The encrypted vault cannot save recovery confirmation".to_string())?;
    RECOVERY_KIT_PENDING.store(false, Ordering::Release);
    Ok(())
}

#[tauri::command]
pub fn cancel_sync_recovery_kit(window: tauri::WebviewWindow) -> Result<(), String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|_| cancel_pending_recovery_kit())
}

fn cancel_pending_recovery_kit() -> Result<(), String> {
    let _pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    RECOVERY_KIT_PENDING.store(false, Ordering::Release);
    Ok(())
}

#[tauri::command]
pub fn sync_recovery_confirmed(window: tauri::WebviewWindow) -> Result<bool, String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|store| {
        store
            .sync_recovery_confirmation()
            .map(|confirmation| confirmation.is_some())
            .map_err(|_| "The encrypted vault cannot read recovery status".into())
    })
}

fn recovery_preview(bundle: &SyncKeyMaterialBundleV1) -> SyncRecoveryPreviewV1 {
    SyncRecoveryPreviewV1 {
        vault_id: bundle.wrapped_vault_key.vault_id.clone(),
        key_epoch: bundle.wrapped_vault_key.key_epoch,
    }
}

#[tauri::command]
pub fn list_sync_device_access_history(
    window: tauri::WebviewWindow,
) -> Result<Vec<SyncDeviceAccessSummaryV1>, String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|store| {
        Ok(store
            .list_sync_device_access_history(100)
            .map_err(|_| "The encrypted vault cannot read sync device history")?
            .into_iter()
            .map(|event| SyncDeviceAccessSummaryV1 {
                device_id: URL_SAFE_NO_PAD.encode(event.device_id),
                action: event.action,
                occurred_at: event.occurred_at,
            })
            .collect())
    })
}

fn list_sync_tombstone_statuses_from_store(
    store: &Datastore,
) -> Result<Vec<SyncTombstoneStatusV1>, String> {
    let Some(keys) = store
        .load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
    else {
        return Ok(Vec::new());
    };
    let root = AccountRootKeyV1::from_bytes(Zeroizing::new(*keys.account_root_key()));
    let wrapped = WrappedVaultDataKeyV1 {
        schema_version: 1,
        vault_id: URL_SAFE_NO_PAD.encode(keys.vault_id()),
        key_epoch: keys.key_epoch(),
        nonce: URL_SAFE_NO_PAD.encode(keys.wrapped_nonce()),
        ciphertext: URL_SAFE_NO_PAD.encode(keys.wrapped_ciphertext()),
    };
    let data_key = unwrap_vault_data_key(&root, &wrapped)
        .map_err(|_| "The encrypted vault cannot unlock sync manifests")?;
    let vault_id = URL_SAFE_NO_PAD.encode(keys.vault_id());
    let mut cursor = None;
    let mut tombstones = BTreeSet::new();
    loop {
        let page = store
            .list_sync_objects(vault_id.clone(), cursor.clone(), 64)
            .map_err(|_| "The encrypted vault cannot list sync manifests")?;
        for envelope in page.objects {
            if envelope.key_epoch != keys.key_epoch() {
                continue;
            }
            if inspect_snapshot_chunk(&data_key, &envelope).is_ok() {
                continue;
            }
            let manifest = decrypt_manifest(&data_key, &envelope)
                .map_err(|_| "A stored sync manifest failed authentication or validation")?;
            for operation in manifest.operations {
                if operation.kind != SyncOperationKindV1::Tombstone {
                    continue;
                }
                let origin = decode_fixed::<16>(&operation.origin_device_id)?;
                let event_id = operation
                    .local_event_id
                    .ok_or("A stored tombstone has no local event ID")?;
                tombstones.insert((origin, event_id, operation.counter));
            }
        }
        let Some(next_cursor) = page.next_cursor else {
            break;
        };
        if cursor.as_deref() == Some(next_cursor.as_str()) {
            return Err("Sync manifest listing did not advance".into());
        }
        cursor = Some(next_cursor);
    }

    tombstones
        .into_iter()
        .map(|(origin, event_id, counter)| {
            let state = store
                .sync_tombstone_ack_state(origin, event_id, counter)
                .map_err(|_| "The encrypted vault cannot inspect tombstone acknowledgements")?;
            let pending = pending_tombstone_ack_device_ids(
                &state.active_device_ids,
                &state.acknowledged_device_ids,
            );
            Ok(SyncTombstoneStatusV1 {
                origin_device_id: URL_SAFE_NO_PAD.encode(origin),
                local_event_id: event_id,
                tombstone_counter: counter,
                active_device_ids: state
                    .active_device_ids
                    .iter()
                    .map(|id| URL_SAFE_NO_PAD.encode(id))
                    .collect(),
                pending_device_ids: pending
                    .into_iter()
                    .map(|id| URL_SAFE_NO_PAD.encode(id))
                    .collect(),
            })
        })
        .collect()
}

#[tauri::command]
pub async fn list_sync_tombstone_statuses(
    window: tauri::WebviewWindow,
) -> Result<Vec<SyncTombstoneStatusV1>, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(|| {
        vault::with_ready_store(list_sync_tombstone_statuses_from_store)
    })
    .await
    .map_err(|_| "Tombstone status refresh stopped")?
}

#[tauri::command]
pub async fn rotate_sync_keys(window: tauri::WebviewWindow) -> Result<u64, String> {
    local_session::verify_window(&window)?;
    if RECOVERY_KIT_PENDING.load(Ordering::Acquire) {
        return Err("Save or cancel the current recovery kit before rotating sync keys".into());
    }
    let (rotated, epoch) =
        tauri::async_runtime::spawn_blocking(move || vault::rotate_sync_keys(None))
            .await
            .map_err(|_| "Sync key rotation stopped")??;
    if !rotated {
        return Err("Sync key rotation was not applied".into());
    }
    vault::data_changed();
    Ok(epoch)
}

#[tauri::command]
pub async fn revoke_sync_device(
    window: tauri::WebviewWindow,
    device_id: String,
) -> Result<bool, String> {
    local_session::verify_window(&window)?;
    if RECOVERY_KIT_PENDING.load(Ordering::Acquire) {
        return Err("Save or cancel the current recovery kit before revoking a device".into());
    }
    let device_id = decode_fixed::<16>(&device_id)?;
    let (revoked, _) =
        tauri::async_runtime::spawn_blocking(move || vault::rotate_sync_keys(Some(device_id)))
            .await
            .map_err(|_| "Sync key rotation stopped")??;
    if revoked {
        vault::data_changed();
    }
    Ok(revoked)
}

fn ensure_peer_not_revoked(store: &Datastore, peer_device_id: &str) -> Result<(), String> {
    let peer_id = decode_fixed::<16>(peer_device_id)?;
    if store
        .list_sync_trusted_devices()
        .map_err(|_| "The encrypted vault cannot inspect device access")?
        .iter()
        .any(|device| device.device_id == peer_id && device.revoked_at.is_some())
    {
        return Err("This device was revoked and cannot receive sync keys again".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        build_restore_preview, encrypt_current_snapshot, list_sync_tombstone_statuses_from_store,
        load_or_create_device_identity, material_from_keys, rotated_sync_key_material,
    };
    use aw_datastore::Datastore;
    use aw_models::{
        Bucket, BucketMetadata, BucketsExport, Event, SyncBucketDescriptorV1, SyncChunkHeaderV1,
        SyncEnvelopeV1, TryVec,
    };
    use aw_sync_e2ee::{
        create_event_tombstone, create_event_upsert, create_vault_data_key, decrypt_snapshot,
        encrypt_manifest, generate_account_root_key, unwrap_vault_data_key, DeviceIdentityV1,
        EncryptedSyncSnapshotV1, SyncManifestV1, WrappedVaultDataKeyV1,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    pub(crate) static RECOVERY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn native_backup_selected_preview_keeps_bundle_in_rust_and_requires_clean_target() {
        use aw_sync_e2ee::SyncObjectStoreV1;
        let fixture = recovery_fixture();
        super::create_current_sync_snapshot_from_store(&fixture.source).unwrap();
        let snapshot = fixture.source.load_sync_snapshot().unwrap().unwrap();
        let path = std::env::temp_dir().join(format!(
            "peak-native-selected-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let folder = aw_sync_e2ee::FolderSyncObjectStoreV1::open(&path).unwrap();
        for object in &snapshot.envelopes {
            folder.put_if_absent(object).unwrap();
        }
        let target = encrypted_test_store();
        target.enable_capture_policy().unwrap();
        target.pause_capture().unwrap();
        let context = super::backup_context_from_store(&target).unwrap();
        let mut request = json!({"schema_version":1,"source_id":"folder","context_id":context.context_id,"folder_path":path.to_str().unwrap(),"recovery":{"kit":fixture.kit,"phrase":fixture.phrase}});
        let catalogue =
            super::backup_command_from_store(&target, "list_sync_backups", request.to_string())
                .unwrap();
        request["selection"] = catalogue["versions"][0]["selection"].clone();
        let raw = super::selected_backup_preview_from_store(&target, request.to_string()).unwrap();
        let preview: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            preview["snapshot_id"],
            URL_SAFE_NO_PAD.encode(snapshot.snapshot_id)
        );
        assert!(target.get_buckets().unwrap().is_empty());
        assert!(target.load_sync_key_material().unwrap().is_none());
        assert!(crate::vault::check_sync_restore_context(&target, Some("wrong-context")).is_err());
        crate::vault::check_sync_restore_context(&target, Some(&context.context_id)).unwrap();
        target.close();
        fixture.source.close();
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn native_backup_adapter_preserves_selected_raw_export_and_current_pointer() {
        let fixture = recovery_fixture();
        let first = super::create_current_sync_snapshot_from_store(&fixture.source).unwrap();
        fixture
            .source
            .set_key_value("settings.theme", "\"light\"")
            .unwrap();
        super::create_current_sync_snapshot_from_store(&fixture.source).unwrap();
        let current = fixture.source.load_sync_snapshot().unwrap().unwrap();
        let context = super::backup_context_from_store(&fixture.source).unwrap();
        let mut request =
            json!({"schema_version":1,"source_id":"local","context_id":context.context_id});
        let listed = super::backup_command_from_store(
            &fixture.source,
            "list_sync_backups",
            request.to_string(),
        )
        .unwrap();
        assert_eq!(listed["versions"].as_array().unwrap().len(), 2);
        let row = listed["versions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["snapshot_id"] == first.snapshot_id)
            .unwrap();
        request["selection"] = row["selection"].clone();
        let exported = super::backup_command_from_store(
            &fixture.source,
            "export_selected_sync_backup",
            request.to_string(),
        )
        .unwrap();
        let raw = exported.as_str().unwrap();
        let snapshot: EncryptedSyncSnapshotV1 = serde_json::from_str(raw).unwrap();
        assert_eq!(snapshot.snapshot_id, first.snapshot_id);
        assert_eq!(snapshot.envelopes[0].key_epoch, 1);
        assert_eq!(
            fixture.source.load_sync_snapshot().unwrap().unwrap(),
            current
        );
        assert!(!raw.contains("private-recovery-marker"));
        assert!(!fixture.source.sync_enabled().unwrap());
        fixture.source.close();
    }

    #[test]
    fn native_backup_delete_adapter_requires_acceptance_and_preserves_current() {
        let fixture = recovery_fixture();
        let old = super::create_current_sync_snapshot_from_store(&fixture.source).unwrap();
        super::create_current_sync_snapshot_from_store(&fixture.source).unwrap();
        let current = fixture.source.load_sync_snapshot().unwrap();
        let context = super::backup_context_from_store(&fixture.source).unwrap();
        let mut raw =
            json!({"schema_version":1,"source_id":"local","context_id":context.context_id});
        let catalogue =
            super::backup_command_from_store(&fixture.source, "list_sync_backups", raw.to_string())
                .unwrap();
        raw["selection"] = catalogue["versions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["snapshot_id"] == old.snapshot_id)
            .unwrap()["selection"]
            .clone();
        super::backup_command_from_store(
            &fixture.source,
            "preview_sync_backup_delete",
            raw.to_string(),
        )
        .unwrap();
        assert!(super::backup_delete_from_store(&fixture.source, raw.to_string(), false).is_err());
        let removed =
            super::backup_delete_from_store(&fixture.source, raw.to_string(), true).unwrap();
        assert_eq!(removed["deleted"], raw["selection"]["object_count"]);
        assert_eq!(fixture.source.load_sync_snapshot().unwrap(), current);
        assert!(!fixture.source.sync_enabled().unwrap());
        fixture.source.close();
    }
    #[test]
    fn native_backup_delete_adapter_refuses_locked_plain_and_array_request() {
        let plain = Datastore::new_in_memory(false);
        assert!(super::backup_delete_from_store(&plain, "{}".into(), true).is_err());
        plain.close();
        let store = encrypted_test_store();
        assert!(super::backup_delete_from_store(&store, "[]".into(), true).is_err());
        store.close();
        assert!(super::backup_delete_from_store(&store, "{}".into(), true).is_err());
    }

    #[test]
    fn native_backup_adapter_rejects_locked_plain_and_ambiguous_requests() {
        let plain = Datastore::new_in_memory(false);
        assert!(super::backup_context_from_store(&plain).is_err());
        plain.close();
        let store = encrypted_test_store();
        let context = super::backup_context_from_store(&store).unwrap();
        let raw = format!(
            r#"{{"schema_version":1,"schema_version":1,"source_id":"local","context_id":"{}"}}"#,
            context.context_id
        );
        assert!(super::backup_command_from_store(&store, "list_sync_backups", raw).is_err());
        store.close();
        assert!(super::backup_context_from_store(&store).is_err());
    }

    #[test]
    fn native_backup_restore_context_rejects_a_different_worker_before_any_install() {
        let store = encrypted_test_store();
        let context = super::backup_context_from_store(&store).unwrap();
        crate::vault::check_sync_restore_context(&store, Some(&context.context_id)).unwrap();
        assert!(crate::vault::check_sync_restore_context(&store, Some("wrong-context")).is_err());
        assert!(store.load_sync_key_material().unwrap().is_none());
        store.close();
    }

    fn encrypted_test_store() -> Datastore {
        Datastore::open_encrypted(":memory:".into(), "tauri-sync-test-key-".repeat(2)).unwrap()
    }

    pub(crate) struct RecoveryFixture {
        pub source: Datastore,
        pub kit: aw_sync_e2ee::RecoveryKitV1,
        pub phrase: String,
        pub data_key: aw_sync_e2ee::VaultDataKeyV1,
        pub origin: [u8; 16],
        pub vault_id: [u8; 16],
    }

    pub(crate) fn recovery_fixture() -> RecoveryFixture {
        let source = encrypted_test_store();
        source.set_key_value("settings.theme", "\"dark\"").unwrap();
        let origin = [0x24; 16];
        let identity = DeviceIdentityV1::from_bytes(
            origin,
            Zeroizing::new([0x34; 32]),
            Zeroizing::new([0x44; 32]),
        );
        source
            .create_sync_device_identity(&aw_datastore::SyncDeviceIdentity::new(
                origin,
                identity.secret_for_storage(),
                identity.signing_seed_for_storage(),
            ))
            .unwrap();
        let bucket = Bucket {
            bid: None,
            id: "aw-watcher-window_native-recovery".into(),
            _type: "currentwindow".into(),
            client: "native-recovery-test".into(),
            hostname: "synthetic".into(),
            created: None,
            data: Default::default(),
            metadata: BucketMetadata::default(),
            events: None,
            last_updated: None,
        };
        source.create_bucket(&bucket).unwrap();
        source
            .insert_events(
                &bucket.id,
                &[
                    Event::new(
                        Utc::now() - Duration::minutes(2),
                        Duration::seconds(10),
                        json!({"app":"synthetic","title":"private-recovery-marker"})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    Event::new(
                        Utc::now() - Duration::minutes(1),
                        Duration::seconds(10),
                        json!({"app":"synthetic","title":"retained-recovery-marker"})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                ],
            )
            .unwrap();
        let control = aw_server::sync_control::SyncControl::new();
        let display = control
            .invoke(&source, "create_sync_recovery_kit", json!({}))
            .unwrap();
        control
            .invoke(
                &source,
                "confirm_sync_recovery_saved",
                json!({"userConfirmed":true}),
            )
            .unwrap();
        let mut progress = source.begin_sync_baseline().unwrap();
        while !progress.complete {
            progress = source.process_sync_baseline_batch(64).unwrap();
        }
        let deleted = source
            .get_events(&bucket.id, None, None, None)
            .unwrap()
            .remove(0);
        source
            .delete_events_by_id(&bucket.id, vec![deleted.id.unwrap()])
            .unwrap();
        let keys = source.load_sync_key_material().unwrap().unwrap();
        let vault_id = *keys.vault_id();
        source
            .commit_sync_manifest_head(
                vault_id,
                1,
                origin,
                aw_datastore::SyncManifestHeadV1::genesis(),
                aw_datastore::SyncManifestHeadV1::new(1, [0x54; 32]),
            )
            .unwrap();
        let (root, wrapped, _) = super::load_or_generate_sync_keys(&source).unwrap();
        let data_key = unwrap_vault_data_key(&root, &wrapped).unwrap();
        RecoveryFixture {
            source,
            kit: serde_json::from_value(display["kit"].clone()).unwrap(),
            phrase: display["recovery_phrase"].as_str().unwrap().into(),
            data_key,
            origin,
            vault_id,
        }
    }

    #[test]
    fn native_backup_known_deletion_refuses_raw_restore_preview() {
        let fixture = recovery_fixture();
        let native = super::encrypt_current_snapshot(&fixture.source, &fixture.data_key).unwrap();
        let snapshot = aw_sync_e2ee::EncryptedSyncSnapshotV1 {
            schema_version: 1,
            snapshot_id: URL_SAFE_NO_PAD.encode(native.snapshot_id),
            envelopes: native.envelopes,
        };
        let fact =
            aw_sync_e2ee::SnapshotDeletionProofV1::authenticate(&fixture.data_key, &snapshot)
                .unwrap()
                .fact()
                .clone();
        let target = encrypted_test_store();
        target.enable_capture_policy().unwrap();
        target.pause_capture().unwrap();
        target
            .merge_sync_backup_deletions(
                target.get_sync_policy_context().unwrap().context_id,
                vec![fact],
                "2026-10-14T12:00:00Z".into(),
            )
            .unwrap();
        assert!(
            super::validate_restore_preview(&target, &fixture.kit, &fixture.phrase, &snapshot)
                .is_err()
        );
        assert!(target.load_sync_key_material().unwrap().is_none());
        assert!(target.get_buckets().unwrap().is_empty());
        target.close();
        fixture.source.close();
    }

    #[test]
    fn native_recovery_format_works_with_core_in_both_directions() {
        let fixture = recovery_fixture();
        let core = aw_server::sync_control::SyncControl::new();
        core.invoke(&fixture.source, "create_current_sync_snapshot", json!({}))
            .unwrap();
        let core_snapshot = serde_json::from_value(
            core.invoke(&fixture.source, "export_sync_snapshot", json!({}))
                .unwrap(),
        )
        .unwrap();
        let target = encrypted_test_store();
        target.reset_privacy().unwrap();
        target.set_key_value("settings.theme", "\"light\"").unwrap();
        let native_preview =
            super::validate_restore_preview(&target, &fixture.kit, &fixture.phrase, &core_snapshot);
        let native_snapshot = encrypt_current_snapshot(&fixture.source, &fixture.data_key).unwrap();
        let native_snapshot = EncryptedSyncSnapshotV1 {
            schema_version: 1,
            snapshot_id: URL_SAFE_NO_PAD.encode(native_snapshot.snapshot_id),
            envelopes: native_snapshot.envelopes,
        };
        let core_preview = core.invoke(
            &target,
            "preview_sync_recovery_restore",
            json!({
                "kit":fixture.kit, "recoveryPhrase":fixture.phrase, "snapshot":native_snapshot,
            }),
        );
        assert!(
            native_preview.is_ok(),
            "native preview must accept the Core continuity snapshot"
        );
        assert!(
            core_preview.is_ok(),
            "Core preview must accept the native continuity snapshot"
        );
        let native_preview = native_preview.unwrap().2;
        assert_eq!(native_preview.tombstone_count, 1);
        assert!(native_preview.policy_continuity_present);
        assert_eq!(native_preview.policy_conflict_count, 2);
        assert_eq!(
            core_preview.unwrap()["policy_conflict_count"],
            native_preview.policy_conflict_count
        );
        let payload: serde_json::Value =
            serde_json::from_slice(&decrypt_snapshot(&fixture.data_key, &native_snapshot).unwrap())
                .unwrap();
        let mut legacy = payload.clone();
        legacy["sync"].as_object_mut().unwrap().remove("policy");
        let legacy = aw_sync_e2ee::encrypt_snapshot(
            &fixture.data_key,
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let legacy_native =
            super::validate_restore_preview(&target, &fixture.kit, &fixture.phrase, &legacy)
                .unwrap()
                .2;
        let legacy_core = core
            .invoke(
                &target,
                "preview_sync_recovery_restore",
                json!({"kit":fixture.kit,"recoveryPhrase":fixture.phrase,"snapshot":legacy}),
            )
            .unwrap();
        assert!(!legacy_native.policy_continuity_present);
        assert_eq!(legacy_core["policy_continuity_present"], false);
        assert_eq!(
            legacy_core["policy_conflict_count"],
            legacy_native.policy_conflict_count
        );
        let legacy_target = encrypted_test_store();
        legacy_target.reset_privacy().unwrap();
        legacy_target
            .set_key_value("settings.theme", "\"light\"")
            .unwrap();
        core.invoke(&legacy_target,"restore_sync_recovery_kit",json!({"kit":fixture.kit,"recoveryPhrase":fixture.phrase,"snapshot":legacy,"userAccepted":true})).unwrap();
        assert_eq!(
            legacy_target.get_key_value("settings.theme").unwrap(),
            "\"light\""
        );
        assert!(!legacy_target.capture_policy().unwrap().recording);
        assert!(!legacy_target.sync_enabled().unwrap());
        let fields = legacy_target
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .into_iter()
            .map(|candidate| candidate.field)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(fields.len(), legacy_native.policy_conflict_count);
        legacy_target.close();
        let mut wrong_schema = payload.clone();
        wrong_schema["schema_version"] = json!(2);
        let mut wrong_sync_schema = payload.clone();
        wrong_sync_schema["sync"]["schema_version"] = json!(2);
        let mut wrong_epoch = payload.clone();
        wrong_epoch["sync"]["key_epoch"] = json!(2);
        let mut unknown_field = payload.clone();
        unknown_field["unrecognized"] = json!(true);
        let mut missing_continuity = payload;
        missing_continuity.as_object_mut().unwrap().remove("sync");
        for invalid in [
            wrong_schema,
            wrong_sync_schema,
            wrong_epoch,
            unknown_field,
            missing_continuity,
        ] {
            let authenticated = aw_sync_e2ee::encrypt_snapshot(
                &fixture.data_key,
                &serde_json::to_vec(&invalid).unwrap(),
            )
            .unwrap();
            assert!(aw_server::sync_control::decrypt_recovery_snapshot(
                &fixture.data_key,
                &authenticated
            )
            .is_err());
        }
        assert!(target.load_sync_key_material().unwrap().is_none());
        target.close();
        fixture.source.close();
    }

    #[test]
    fn native_recovery_pairing_and_kit_are_mutually_exclusive() {
        let _serial = RECOVERY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        super::clear_pending_pairing();
        let store = encrypted_test_store();
        let (local, _) = load_or_create_device_identity(&store).unwrap();
        let peer = aw_sync_e2ee::generate_device_identity().unwrap();
        let peer_store = encrypted_test_store();
        peer_store
            .create_sync_device_identity(&aw_datastore::SyncDeviceIdentity::new(
                *peer.device_id_bytes(),
                peer.secret_for_storage(),
                peer.signing_seed_for_storage(),
            ))
            .unwrap();
        let issuer = aw_server::sync_control::SyncControl::new();
        let invitation = issuer
            .invoke(
                &peer_store,
                "create_sync_pairing",
                json!({"recipient":local.public_identity()}),
            )
            .unwrap();
        let invitation: aw_sync_e2ee::PairingInvitationV1 =
            serde_json::from_value(invitation).unwrap();
        let (response, _) =
            super::respond_sync_pairing_in_store(&store, invitation.clone()).unwrap();
        assert!(super::create_sync_recovery_kit_in_store(&store).is_err());
        assert!(store.load_sync_key_material().unwrap().is_none());
        let display = issuer
            .invoke(
                &peer_store,
                "complete_sync_pairing",
                json!({"response":response}),
            )
            .unwrap();
        let code = super::prepare_sync_pairing_from_offer(
            serde_json::from_value(display["offer"].clone()).unwrap(),
        )
        .unwrap();
        let confirmation = super::confirm_sync_pairing_from_code(&code, true).unwrap();
        let peer_confirmation = issuer
            .invoke(
                &peer_store,
                "confirm_sync_pairing",
                json!({"displayedCode":display["verification_code"],"userConfirmed":true}),
            )
            .unwrap();
        let transfer = issuer
            .invoke(
                &peer_store,
                "create_sync_key_transfer",
                json!({"peerConfirmation":confirmation}),
            )
            .unwrap();
        super::accept_sync_key_transfer_in_store(
            &store,
            serde_json::from_value(peer_confirmation).unwrap(),
            serde_json::from_value(transfer).unwrap(),
        )
        .unwrap();
        assert!(super::pending_pairing().lock().unwrap().is_none());
        assert_eq!(
            store.load_sync_key_material().unwrap().unwrap().vault_id(),
            peer_store
                .load_sync_key_material()
                .unwrap()
                .unwrap()
                .vault_id()
        );
        super::create_sync_recovery_kit_in_store(&store).unwrap();
        let original = store.load_sync_key_material().unwrap().unwrap();
        super::cancel_pending_pairing().unwrap();
        assert!(super::RECOVERY_KIT_PENDING.load(std::sync::atomic::Ordering::Acquire));
        assert!(super::create_sync_pairing_in_store(&store, peer.public_identity()).is_err());
        assert!(super::respond_sync_pairing_in_store(&store, invitation).is_err());
        super::cancel_pending_recovery_kit().unwrap();
        assert!(
            store
                .load_sync_key_material()
                .unwrap()
                .unwrap()
                .account_root_key()
                == original.account_root_key()
        );
        super::create_sync_pairing_in_store(&store, peer.public_identity()).unwrap();
        super::clear_pending_pairing();
        super::create_sync_recovery_kit_in_store(&store).unwrap();
        super::confirm_sync_recovery_saved_in_store(&store).unwrap();
        let third = encrypted_test_store();
        let recipient = aw_server::sync_control::SyncControl::new();
        let third_identity = recipient
            .invoke(&third, "create_local_sync_identity", json!({}))
            .unwrap();
        let (invitation, _) = super::create_sync_pairing_in_store(
            &store,
            serde_json::from_value(third_identity).unwrap(),
        )
        .unwrap();
        let response = recipient
            .invoke(
                &third,
                "respond_sync_pairing",
                json!({"invitation":invitation}),
            )
            .unwrap();
        let display =
            super::complete_sync_pairing_from_response(serde_json::from_value(response).unwrap())
                .unwrap();
        let code = recipient
            .invoke(
                &third,
                "prepare_sync_pairing",
                json!({"offer":display.offer}),
            )
            .unwrap();
        let confirmation =
            super::confirm_sync_pairing_from_code(&display.verification_code, true).unwrap();
        let peer_confirmation = recipient
            .invoke(
                &third,
                "confirm_sync_pairing",
                json!({"displayedCode":code,"userConfirmed":true}),
            )
            .unwrap();
        let transfer = super::create_sync_key_transfer_in_store(
            &store,
            serde_json::from_value(peer_confirmation).unwrap(),
        )
        .unwrap();
        assert!(super::pending_pairing().lock().unwrap().is_none());
        recipient
            .invoke(
                &third,
                "accept_sync_key_transfer",
                json!({"peerConfirmation":confirmation,"transfer":transfer}),
            )
            .unwrap();
        assert_eq!(
            third.load_sync_key_material().unwrap().unwrap().vault_id(),
            original.vault_id()
        );
        super::clear_pending_pairing();
        store.close();
        peer_store.close();
        third.close();
    }

    #[test]
    fn native_identity_creation_is_persistent_and_returns_only_public_identity() {
        let store = encrypted_test_store();
        let (first, created) = load_or_create_device_identity(&store).unwrap();
        assert!(created);
        let public = first.public_identity();
        let (second, created) = load_or_create_device_identity(&store).unwrap();
        assert!(!created);
        assert_eq!(public, second.public_identity());
        store.lock().unwrap();
    }

    #[test]
    fn recovery_preview_contains_metadata_but_no_decrypted_activity() {
        let event = Event::new(
            Utc::now(),
            Duration::seconds(1),
            json!({ "title": "private-activity-marker" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let bucket = Bucket {
            bid: None,
            id: "opaque-bucket".into(),
            _type: "synthetic".into(),
            client: "synthetic".into(),
            hostname: "synthetic-host".into(),
            created: None,
            data: Default::default(),
            metadata: BucketMetadata::default(),
            events: Some(TryVec::new(vec![event])),
            last_updated: None,
        };
        let export = BucketsExport {
            buckets: HashMap::from([("opaque-bucket".into(), bucket)]),
        };
        let snapshot_id = URL_SAFE_NO_PAD.encode([4; 16]);
        let snapshot = EncryptedSyncSnapshotV1 {
            schema_version: 1,
            snapshot_id: snapshot_id.clone(),
            envelopes: vec![SyncEnvelopeV1 {
                schema_version: 1,
                object_id: URL_SAFE_NO_PAD.encode([1; 16]),
                vault_id: URL_SAFE_NO_PAD.encode([2; 16]),
                key_epoch: 3,
                nonce: URL_SAFE_NO_PAD.encode([5; 24]),
                ciphertext: URL_SAFE_NO_PAD.encode([6; 32]),
            }],
        };

        let preview = build_restore_preview(
            &snapshot,
            &export,
            Some(URL_SAFE_NO_PAD.encode([7; 16])),
            URL_SAFE_NO_PAD.encode([2; 16]),
            3,
            aw_models::SyncRecoveryPolicySummaryV1 {
                schema_version: 1,
                continuity_present: false,
                conflict_count: 0,
                target_binding_sha256: String::new(),
            },
        );
        let serialized = serde_json::to_string(&preview).unwrap();

        assert_eq!(preview.object_count, 1);
        assert_eq!(preview.version_start, snapshot_id);
        assert!(preview.query_start.is_some());
        assert!(preview.query_end.is_some());
        assert!(!serialized.contains("private-activity-marker"));
    }

    #[test]
    fn native_recovery_tombstone_status_skips_queued_snapshot_chunks() {
        let store = encrypted_test_store();
        let root = generate_account_root_key().unwrap();
        let vault_id = URL_SAFE_NO_PAD.encode([0x62; 16]);
        let (data_key, wrapped) = create_vault_data_key(&root, &vault_id, 1).unwrap();
        let material = material_from_keys(&root, &wrapped).unwrap();
        let first_peer = [0x41; 16];
        let waiting_peer = [0x51; 16];
        let paired_at = "2026-09-23T12:00:00Z";
        store
            .record_sync_pairing(
                Some(material),
                [0x31; 16],
                first_peer,
                [0x71; 32],
                [0x72; 32],
                paired_at.into(),
            )
            .unwrap();
        store
            .record_sync_pairing(
                None,
                [0x32; 16],
                waiting_peer,
                [0x73; 32],
                [0x74; 32],
                paired_at.into(),
            )
            .unwrap();
        let event = Event {
            id: Some(88),
            timestamp: Utc::now(),
            duration: Duration::seconds(10),
            data: json!({ "title": "private-activity-marker" })
                .as_object()
                .unwrap()
                .clone(),
        };
        let bucket_id = [0x73; 16];
        let descriptor = SyncBucketDescriptorV1 {
            bucket_type: "app".into(),
            client: "PeakActivity".into(),
            data: std::collections::BTreeMap::new(),
        };
        let upsert = create_event_upsert(first_peer, 4, bucket_id, descriptor, &event).unwrap();
        let tombstone = create_event_tombstone(first_peer, 5, first_peer, 88, bucket_id).unwrap();
        let signing_identity = DeviceIdentityV1::from_bytes(
            first_peer,
            Zeroizing::new([0x51; 32]),
            Zeroizing::new([0x61; 32]),
        );
        let manifest = SyncManifestV1::new_signed(
            &signing_identity,
            [0x62; 16],
            1,
            1,
            [0; 32],
            vec![upsert, tombstone],
        )
        .unwrap();
        let envelope = encrypt_manifest(
            &data_key,
            &SyncChunkHeaderV1 {
                schema_version: 1,
                object_id: URL_SAFE_NO_PAD.encode([0x33; 16]),
                vault_id: vault_id.clone(),
                key_epoch: 1,
            },
            &manifest,
        )
        .unwrap();
        store.put_sync_object(envelope, paired_at.into()).unwrap();
        store
            .acknowledge_sync_tombstone(
                first_peer,
                88,
                5,
                first_peer,
                "2026-09-23T12:01:00Z".into(),
            )
            .unwrap();

        let snapshot = encrypt_current_snapshot(&store, &data_key).unwrap();
        super::queue_sync_snapshot_objects(&store, &snapshot).unwrap();
        let statuses = list_sync_tombstone_statuses_from_store(&store).unwrap();

        assert_eq!(statuses.len(), 1);
        assert_eq!(
            statuses[0].origin_device_id,
            URL_SAFE_NO_PAD.encode(first_peer)
        );
        assert_eq!(statuses[0].local_event_id, 88);
        assert_eq!(
            statuses[0].pending_device_ids,
            vec![URL_SAFE_NO_PAD.encode(waiting_peer)]
        );
        assert!(!serde_json::to_string(&statuses)
            .unwrap()
            .contains("private-activity-marker"));
        store.lock().unwrap();
    }

    #[test]
    fn native_recovery_rotation_changes_root_and_advances_the_device_epoch() {
        let store = encrypted_test_store();
        let root = generate_account_root_key().unwrap();
        let vault_id = URL_SAFE_NO_PAD.encode([0x71; 16]);
        let (_, wrapped) = create_vault_data_key(&root, &vault_id, 4).unwrap();
        let material = material_from_keys(&root, &wrapped).unwrap();
        store.install_sync_key_material(&material).unwrap();
        let bucket = Bucket {
            bid: None,
            id: "aw-watcher-window_sync-test".into(),
            _type: "currentwindow".into(),
            client: "sync-test".into(),
            hostname: "local".into(),
            created: None,
            data: Default::default(),
            metadata: BucketMetadata::default(),
            events: None,
            last_updated: None,
        };
        store.create_bucket(&bucket).unwrap();
        let event = Event::new(
            Utc::now(),
            Duration::seconds(1),
            json!({
                "app": "synthetic", "title": "private-activity-marker"
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        store.insert_events(&bucket.id, &[event]).unwrap();

        let (next, data_key) = rotated_sync_key_material(&store).unwrap();
        assert_eq!(next.key_epoch(), 5);
        assert_ne!(&*next.account_root_key(), &*material.account_root_key());
        let next_wrapped = WrappedVaultDataKeyV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(next.vault_id()),
            key_epoch: next.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(next.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(next.wrapped_ciphertext()),
        };
        assert!(unwrap_vault_data_key(&root, &next_wrapped).is_err());
        assert!(unwrap_vault_data_key(
            &aw_sync_e2ee::AccountRootKeyV1::from_bytes(Zeroizing::new(*next.account_root_key())),
            &next_wrapped,
        )
        .is_ok());
        let snapshot = encrypt_current_snapshot(&store, &data_key).unwrap();
        assert!(!format!("{snapshot:?}").contains("private-activity-marker"));
        let decrypted = decrypt_snapshot(
            &data_key,
            &EncryptedSyncSnapshotV1 {
                schema_version: 1,
                snapshot_id: URL_SAFE_NO_PAD.encode(snapshot.snapshot_id),
                envelopes: snapshot.envelopes.clone(),
            },
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&decrypted).contains("private-activity-marker"));
        assert!(store
            .rotate_sync_key_material(next, snapshot.clone(), None, "2026-09-23T12:10:00Z".into(),)
            .unwrap());
        assert_eq!(store.load_sync_snapshot().unwrap(), Some(snapshot));
        store
            .confirm_sync_recovery_saved("2026-09-23T12:11:00Z".into())
            .unwrap();
        let exported = super::export_sync_snapshot_from_store(&store)
            .unwrap()
            .unwrap();
        assert!(!serde_json::to_string(&exported)
            .unwrap()
            .contains("private-activity-marker"));
        store.lock().unwrap();
    }
}
