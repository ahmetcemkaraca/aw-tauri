use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

use aw_datastore::{Datastore, SyncDeviceIdentity, SyncKeyMaterial, SyncSnapshotV1};
use aw_models::{BucketsExport, SyncOperationKindV1, TryVec};
use aw_sync_e2ee::{
    accept_key_transfer, begin_pairing, complete_pairing, confirm_pairing,
    create_key_transfer, create_vault_data_key, derive_pairing_session,
    generate_account_root_key, generate_device_identity, respond_to_pairing,
    decrypt_snapshot, encrypt_snapshot, rotate_account_and_vault_key, unwrap_vault_data_key,
    AccountRootKeyV1, DeviceIdentityV1, DevicePublicIdentityV1,
    EncryptedKeyTransferV1, PairingConfirmationV1, PairingEphemeralKeyV1,
    PairingInvitationV1, PairingOfferV1, PairingResponseV1, PairingSessionV1,
    EncryptedSyncSnapshotV1, RecoveryKitV1, SyncKeyMaterialBundleV1, VaultDataKeyV1,
    WrappedVaultDataKeyV1,
    decrypt_manifest, pending_tombstone_ack_device_ids,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{local_session, vault};
use aw_sync_e2ee::{create_recovery_kit as make_recovery_kit, open_recovery_kit};

static PENDING_PAIRING: OnceLock<Mutex<Option<PendingPairing>>> = OnceLock::new();
static RECOVERY_KIT_PENDING: AtomicBool = AtomicBool::new(false);

struct PendingPairing {
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
    if let Ok(mut pending) = pending_pairing().lock() {
        *pending = None;
    }
    RECOVERY_KIT_PENDING.store(false, Ordering::Release);
}

fn load_or_create_device_identity(
    store: &Datastore,
) -> Result<(DeviceIdentityV1, bool), String> {
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
) -> Result<(AccountRootKeyV1, WrappedVaultDataKeyV1, Option<SyncKeyMaterial>), String> {
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

fn material_from_keys(
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

fn rotated_sync_key_material(store: &Datastore) -> Result<(SyncKeyMaterial, VaultDataKeyV1), String> {
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
    Ok((material_from_keys(&next_root, &next_wrapped)?, next_data_key))
}

pub(crate) fn encrypt_current_snapshot(
    store: &Datastore,
    key: &VaultDataKeyV1,
) -> Result<SyncSnapshotV1, String> {
    let mut buckets = store.get_buckets().map_err(|_| "The encrypted vault cannot read activity buckets")?;
    for (bucket_id, bucket) in &mut buckets {
        let events = store.get_events(bucket_id, None, None, None)
            .map_err(|_| "The encrypted vault cannot read activity events")?;
        bucket.events = Some(TryVec::new(events));
    }
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&BucketsExport { buckets })
            .map_err(|_| "Activity snapshot could not be encoded")?,
    );
    let encrypted = encrypt_snapshot(key, &plaintext).map_err(|error| error.to_string())?;
    let verified = decrypt_snapshot(key, &encrypted).map_err(|error| error.to_string())?;
    if verified.as_slice() != plaintext.as_slice() {
        return Err("The staged activity snapshot did not verify".into());
    }
    Ok(SyncSnapshotV1::new(
        decode_fixed::<16>(&encrypted.snapshot_id)?,
        encrypted.envelopes,
    ))
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
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
pub fn list_sync_devices(
    window: tauri::WebviewWindow,
) -> Result<Vec<SyncDeviceSummaryV1>, String> {
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
                ed25519_public_key: trusted.ed25519_public_key.map(|key| URL_SAFE_NO_PAD.encode(key)),
                is_current_device: false,
                paired_at: Some(trusted.paired_at),
                needs_repair: trusted.key_epoch != key_epoch || trusted.ed25519_public_key.is_none(),
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
    let (identity, invitation, ephemeral, created) = vault::with_ready_store(|store| {
        let (identity, created) = load_or_create_device_identity(store)?;
        let (invitation, ephemeral) =
            begin_pairing(&identity, &recipient).map_err(|error| error.to_string())?;
        Ok((identity, invitation, ephemeral, created))
    })?;
    if created {
        vault::data_changed();
    }
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    if pending.is_some() {
        return Err("Finish or cancel the current device pairing first".into());
    }
    *pending = Some(PendingPairing {
        identity,
        invitation: invitation.clone(),
        recipient: false,
        ephemeral: Some(ephemeral),
        offer: None,
        session: None,
    });
    Ok(invitation)
}

#[tauri::command]
pub fn respond_sync_pairing(
    window: tauri::WebviewWindow,
    invitation: PairingInvitationV1,
) -> Result<PairingResponseV1, String> {
    local_session::verify_window(&window)?;
    let (response, ephemeral, identity, created) = vault::with_ready_store(|store| {
        let (identity, created) = load_or_create_device_identity(store)?;
        let (response, ephemeral) =
            respond_to_pairing(&identity, &invitation).map_err(|error| error.to_string())?;
        Ok((response, ephemeral, identity, created))
    })?;
    if created {
        vault::data_changed();
    }
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    if pending.is_some() {
        return Err("Finish or cancel the current device pairing first".into());
    }
    *pending = Some(PendingPairing {
        identity,
        invitation,
        recipient: true,
        ephemeral: Some(ephemeral),
        offer: None,
        session: None,
    });
    Ok(response)
}

#[tauri::command]
pub fn complete_sync_pairing(
    window: tauri::WebviewWindow,
    response: PairingResponseV1,
) -> Result<PairingDisplayV1, String> {
    local_session::verify_window(&window)?;
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    let state = pending
        .as_mut()
        .ok_or("Start or respond to a pairing before completing it")?;
    if state.recipient {
        return Err("This device is waiting for the initiating device to complete the offer".into());
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
    let mut pending = pending_pairing()
        .lock()
        .map_err(|_| "Device pairing state is unavailable")?;
    let session = pending
        .as_mut()
        .and_then(|state| state.session.as_mut())
        .ok_or("Compare the pairing code before confirming")?;
    confirm_pairing(session, &displayed_code, user_confirmed)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn create_sync_key_transfer(
    window: tauri::WebviewWindow,
    peer_confirmation: PairingConfirmationV1,
) -> Result<EncryptedKeyTransferV1, String> {
    local_session::verify_window(&window)?;
    let transfer = vault::with_ready_store(|store| {
        let pending = pending_pairing()
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
        Ok(transfer)
    })?;
    vault::data_changed();
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
        Ok(offer.issuer.clone())
    })?;
    vault::data_changed();
    Ok(peer)
}

#[tauri::command]
pub fn cancel_sync_pairing(window: tauri::WebviewWindow) -> Result<(), String> {
    local_session::verify_window(&window)?;
    clear_pending_pairing();
    Ok(())
}

#[tauri::command]
pub fn create_sync_recovery_kit(
    window: tauri::WebviewWindow,
) -> Result<SyncRecoveryDisplayV1, String> {
    local_session::verify_window(&window)?;
    RECOVERY_KIT_PENDING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "Save or cancel the current one-time recovery phrase first")?;
    let result = vault::with_ready_store(|store| {
        if store
            .sync_recovery_confirmation()
            .map_err(|_| "The encrypted vault cannot inspect recovery status")?
            .is_some()
        {
            return Err("A recovery phrase is already confirmed; rotate the sync root before replacing it".into());
        }
        let (root, wrapped, new_material) = load_or_generate_sync_keys(store)?;
        let (phrase, kit) = make_recovery_kit(&root, &wrapped)
            .map_err(|error| error.to_string())?;
        if let Some(material) = &new_material {
            store
                .install_sync_key_material(material)
                .map_err(|_| "The encrypted vault cannot save sync recovery keys")?;
        }
        Ok((phrase, kit, new_material.is_some()))
    });
    let (phrase, kit, new_material) = match result {
        Ok(result) => result,
        Err(error) => {
            RECOVERY_KIT_PENDING.store(false, Ordering::Release);
            return Err(error);
        }
    };
    if new_material {
        vault::data_changed();
    }
    Ok(SyncRecoveryDisplayV1 { recovery_phrase: phrase, kit })
}

#[tauri::command]
pub fn verify_sync_recovery_kit(
    window: tauri::WebviewWindow,
    kit: RecoveryKitV1,
    recovery_phrase: String,
) -> Result<SyncRecoveryPreviewV1, String> {
    local_session::verify_window(&window)?;
    vault::with_ready_store(|_| {
        let recovered = open_recovery_kit(&kit, &recovery_phrase)
            .map_err(|error| error.to_string())?;
        Ok(recovery_preview(&recovered))
    })
}

fn ensure_clean_restore_target(store: &Datastore) -> Result<(), String> {
    if store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot inspect sync keys")?.is_some()
    {
        return Err("This device already has sync keys; its existing keys were preserved".into());
    }
    if store.load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot inspect local sync snapshots")?.is_some()
    {
        return Err("This device already has a sync snapshot; its existing state was preserved".into());
    }
    if !store.get_buckets().map_err(|_| "The encrypted vault cannot inspect local activity")?.is_empty() {
        return Err("Sync snapshot restore requires a clean activity vault".into());
    }
    if store.capture_policy().map_err(|_| "The encrypted vault cannot inspect recording state")?.recording {
        return Err("Pause recording before restoring a sync snapshot".into());
    }
    Ok(())
}

fn validate_restore_preview(
    store: &Datastore,
    kit: &RecoveryKitV1,
    recovery_phrase: &str,
    snapshot: &EncryptedSyncSnapshotV1,
) -> Result<(SyncKeyMaterialBundleV1, BucketsExport, SyncRestorePreviewV1), String> {
    ensure_clean_restore_target(store)?;
    let recovered = open_recovery_kit(kit, recovery_phrase)
        .map_err(|error| error.to_string())?;
    let data_key = unwrap_vault_data_key(&recovered.account_root_key, &recovered.wrapped_vault_key)
        .map_err(|error| error.to_string())?;
    let plaintext = decrypt_snapshot(&data_key, snapshot).map_err(|error| error.to_string())?;
    let export: BucketsExport = serde_json::from_slice(&plaintext)
        .map_err(|_| "The encrypted activity snapshot is invalid")?;
    let device_id = store.load_sync_device_identity()
        .map_err(|_| "The encrypted vault cannot inspect its device identity")?
        .map(|identity| URL_SAFE_NO_PAD.encode(identity.device_id()));
    let preview = build_restore_preview(
        snapshot,
        &export,
        device_id,
        recovered.wrapped_vault_key.vault_id.clone(),
        recovered.wrapped_vault_key.key_epoch,
    );
    Ok((recovered, export, preview))
}

fn build_restore_preview(
    snapshot: &EncryptedSyncSnapshotV1,
    export: &BucketsExport,
    device_id: Option<String>,
    vault_id: String,
    key_epoch: u64,
) -> SyncRestorePreviewV1 {
    let mut query_start = None;
    let mut query_end = None;
    for event in export.buckets.values().flat_map(|bucket| {
        bucket.events.iter().flat_map(|events| events.iter())
    }) {
        let timestamp = event.timestamp.to_rfc3339();
        if query_start.as_ref().is_none_or(|start: &String| timestamp.as_str() < start.as_str()) {
            query_start = Some(timestamp.clone());
        }
        if query_end.as_ref().is_none_or(|end: &String| timestamp.as_str() > end.as_str()) {
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
        // The current snapshot wire format contains activity buckets only.
        tombstone_count: 0,
        query_start,
        query_end,
        policy_conflict_count: 0,
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
            let (_, _, preview) = validate_restore_preview(store, &kit, &recovery_phrase, &snapshot)?;
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
    tauri::async_runtime::spawn_blocking(|| vault::with_ready_store(export_sync_snapshot_from_store))
        .await
        .map_err(|_| "Snapshot export stopped")?
}

#[tauri::command]
pub async fn create_current_sync_snapshot(
    window: tauri::WebviewWindow,
) -> Result<SyncSnapshotInfoV1, String> {
    local_session::verify_window(&window)?;
    tauri::async_runtime::spawn_blocking(|| vault::with_ready_store(create_current_sync_snapshot_from_store))
        .await
        .map_err(|_| "Snapshot creation stopped".to_string())?
}

fn create_current_sync_snapshot_from_store(store: &Datastore) -> Result<SyncSnapshotInfoV1, String> {
    if store.sync_recovery_confirmation()
        .map_err(|_| "The encrypted vault cannot inspect recovery status")?.is_none()
    {
        return Err("Confirm a recovery kit for the current sync keys before creating a snapshot".into());
    }
    let keys = store.load_sync_key_material()
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
    if let Some(previous) = store.load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot read its current snapshot")?
    {
        queue_sync_snapshot_objects(store, &previous)?;
    }
    store.save_sync_snapshot(keys, snapshot)
        .map_err(|_| "The encrypted activity snapshot could not be stored".to_string())?;
    let current = store.load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot verify its current snapshot")?
        .ok_or("The encrypted snapshot was not stored")?;
    queue_sync_snapshot_objects(store, &current)?;
    Ok(info)
}

fn queue_sync_snapshot_objects(store: &Datastore, snapshot: &SyncSnapshotV1) -> Result<(), String> {
    let stored_at = chrono::Utc::now().to_rfc3339();
    for envelope in &snapshot.envelopes {
        envelope.validate().map_err(|_| "Snapshot contains an invalid encrypted envelope")?;
        store.put_sync_object(envelope.clone(), stored_at.clone())
            .map_err(|_| "Encrypted snapshot object could not be queued")?;
    }
    Ok(())
}

fn export_sync_snapshot_from_store(
    store: &Datastore,
) -> Result<Option<EncryptedSyncSnapshotV1>, String> {
    if store.sync_recovery_confirmation()
        .map_err(|_| "The encrypted vault cannot inspect recovery status")?.is_none()
    {
        return Err("Confirm a recovery kit for the current sync keys before exporting a snapshot".into());
    }
    let keys = store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")?
        .ok_or("Sync snapshot keys are missing")?;
    let Some(stored) = store.load_sync_snapshot()
        .map_err(|_| "The encrypted vault cannot load its sync snapshot")? else {
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
    let plaintext = decrypt_snapshot(&key, &snapshot).map_err(|error| error.to_string())?;
    let _: BucketsExport = serde_json::from_slice(&plaintext)
        .map_err(|_| "The encrypted sync snapshot is invalid")?;
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
    let preview = tauri::async_runtime::spawn_blocking(move || {
        vault::with_ready_store(|store| {
            let (recovered, export, preview) = validate_restore_preview(
                store,
                &kit,
                &recovery_phrase,
                &snapshot,
            )?;
            let material = material_from_keys(&recovered.account_root_key, &recovered.wrapped_vault_key)?;
            let snapshot = SyncSnapshotV1::new(decode_fixed::<16>(&snapshot.snapshot_id)?, snapshot.envelopes);
            vault::restore_sync_snapshot(material, snapshot, export)?;
            Ok::<_, String>(preview)
        })
    })
    .await
    .map_err(|_| "Sync snapshot restore stopped")??;
    RECOVERY_KIT_PENDING.store(true, Ordering::Release);
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
    if !RECOVERY_KIT_PENDING.load(Ordering::Acquire) {
        return Err("Create a recovery kit before confirming it was saved".into());
    }
    vault::with_ready_store(|store| {
        store
            .confirm_sync_recovery_saved(chrono::Utc::now().to_rfc3339())
            .map_err(|_| "The encrypted vault cannot save recovery confirmation".into())
    })?;
    RECOVERY_KIT_PENDING.store(false, Ordering::Release);
    vault::data_changed();
    Ok(())
}

#[tauri::command]
pub fn cancel_sync_recovery_kit(window: tauri::WebviewWindow) -> Result<(), String> {
    local_session::verify_window(&window)?;
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
    let Some(keys) = store.load_sync_key_material()
        .map_err(|_| "The encrypted vault cannot load its sync keys")? else {
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
        let page = store.list_sync_objects(vault_id.clone(), cursor.clone(), 64)
            .map_err(|_| "The encrypted vault cannot list sync manifests")?;
        for envelope in page.objects {
            if envelope.key_epoch != keys.key_epoch() {
                continue;
            }
            let manifest = decrypt_manifest(&data_key, &envelope)
                .map_err(|_| "A stored sync manifest failed authentication or validation")?;
            for operation in manifest.operations {
                if operation.kind != SyncOperationKindV1::Tombstone {
                    continue;
                }
                let origin = decode_fixed::<16>(&operation.origin_device_id)?;
                let event_id = operation.local_event_id
                    .ok_or("A stored tombstone has no local event ID")?;
                tombstones.insert((origin, event_id, operation.counter));
            }
        }
        let Some(next_cursor) = page.next_cursor else { break; };
        if cursor.as_deref() == Some(next_cursor.as_str()) {
            return Err("Sync manifest listing did not advance".into());
        }
        cursor = Some(next_cursor);
    }

    tombstones.into_iter().map(|(origin, event_id, counter)| {
        let state = store.sync_tombstone_ack_state(origin, event_id, counter)
            .map_err(|_| "The encrypted vault cannot inspect tombstone acknowledgements")?;
        let pending = pending_tombstone_ack_device_ids(
            &state.active_device_ids,
            &state.acknowledged_device_ids,
        );
        Ok(SyncTombstoneStatusV1 {
            origin_device_id: URL_SAFE_NO_PAD.encode(origin),
            local_event_id: event_id,
            tombstone_counter: counter,
            active_device_ids: state.active_device_ids.iter()
                .map(|id| URL_SAFE_NO_PAD.encode(id))
                .collect(),
            pending_device_ids: pending.into_iter()
                .map(|id| URL_SAFE_NO_PAD.encode(id))
                .collect(),
        })
    }).collect()
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
pub async fn rotate_sync_keys(
    window: tauri::WebviewWindow,
) -> Result<u64, String> {
    local_session::verify_window(&window)?;
    if RECOVERY_KIT_PENDING.load(Ordering::Acquire) {
        return Err("Save or cancel the current recovery kit before rotating sync keys".into());
    }
    let (material, data_key) = vault::with_ready_store(rotated_sync_key_material)?;
    let epoch = material.key_epoch();
    let (rotated, _) = tauri::async_runtime::spawn_blocking(move || vault::rotate_sync_keys(material, data_key, None))
        .await
        .map_err(|_| "Sync key rotation stopped")??;
    if !rotated { return Err("Sync key rotation was not applied".into()); }
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
    let (material, data_key) = vault::with_ready_store(|store| {
        let current = store
            .load_sync_device_identity()
            .map_err(|_| "The encrypted vault cannot load its sync identity")?;
        if current.as_ref().is_some_and(|identity| identity.device_id() == &device_id) {
            return Err("The current device cannot revoke itself".into());
        }
        let trusted = store.list_sync_trusted_devices()
            .map_err(|_| "The encrypted vault cannot inspect device access")?;
        if !trusted.iter().any(|peer| peer.device_id == device_id && peer.revoked_at.is_none()) {
            return Err("The selected device is no longer active".into());
        }
        rotated_sync_key_material(store)
    })?;
    let (revoked, _) = tauri::async_runtime::spawn_blocking(move || {
        vault::rotate_sync_keys(material, data_key, Some(device_id))
    })
    .await
    .map_err(|_| "Sync key rotation stopped")??;
    if revoked { vault::data_changed(); }
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
mod tests {
    use super::{build_restore_preview, encrypt_current_snapshot, list_sync_tombstone_statuses_from_store, load_or_create_device_identity, material_from_keys, rotated_sync_key_material};
    use aw_datastore::Datastore;
    use aw_models::{Bucket, BucketMetadata, BucketsExport, Event, SyncBucketDescriptorV1, SyncChunkHeaderV1, SyncEnvelopeV1, TryVec};
    use aw_sync_e2ee::{create_event_tombstone, create_event_upsert, create_vault_data_key, decrypt_snapshot, encrypt_manifest, generate_account_root_key, unwrap_vault_data_key, DeviceIdentityV1, EncryptedSyncSnapshotV1, SyncManifestV1, WrappedVaultDataKeyV1};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    fn encrypted_test_store() -> Datastore {
        Datastore::open_encrypted(":memory:".into(), "tauri-sync-test-key-".repeat(2)).unwrap()
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
            json!({ "title": "private-activity-marker" }).as_object().unwrap().clone(),
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
        );
        let serialized = serde_json::to_string(&preview).unwrap();

        assert_eq!(preview.object_count, 1);
        assert_eq!(preview.version_start, snapshot_id);
        assert!(preview.query_start.is_some());
        assert!(preview.query_end.is_some());
        assert!(!serialized.contains("private-activity-marker"));
    }

    #[test]
    fn tombstone_status_lists_unacknowledged_devices_without_event_values() {
        let store = encrypted_test_store();
        let root = generate_account_root_key().unwrap();
        let vault_id = URL_SAFE_NO_PAD.encode([0x62; 16]);
        let (data_key, wrapped) = create_vault_data_key(&root, &vault_id, 1).unwrap();
        let material = material_from_keys(&root, &wrapped).unwrap();
        let first_peer = [0x41; 16];
        let waiting_peer = [0x51; 16];
        let paired_at = "2026-09-23T12:00:00Z";
        store.record_sync_pairing(
            Some(material), [0x31; 16], first_peer, [0x71; 32], [0x72; 32], paired_at.into(),
        ).unwrap();
        store.record_sync_pairing(
            None, [0x32; 16], waiting_peer, [0x73; 32], [0x74; 32], paired_at.into(),
        ).unwrap();
        let event = Event {
            id: Some(88),
            timestamp: Utc::now(),
            duration: Duration::seconds(10),
            data: json!({ "title": "private-activity-marker" }).as_object().unwrap().clone(),
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
        ).unwrap();
        let envelope = encrypt_manifest(
            &data_key,
            &SyncChunkHeaderV1 {
                schema_version: 1,
                object_id: URL_SAFE_NO_PAD.encode([0x33; 16]),
                vault_id: vault_id.clone(),
                key_epoch: 1,
            },
            &manifest,
        ).unwrap();
        store.put_sync_object(envelope, paired_at.into()).unwrap();
        store.acknowledge_sync_tombstone(
            first_peer, 88, 5, first_peer, "2026-09-23T12:01:00Z",
        ).unwrap();

        let statuses = list_sync_tombstone_statuses_from_store(&store).unwrap();

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].origin_device_id, URL_SAFE_NO_PAD.encode(first_peer));
        assert_eq!(statuses[0].local_event_id, 88);
        assert_eq!(statuses[0].pending_device_ids, vec![URL_SAFE_NO_PAD.encode(waiting_peer)]);
        assert!(!serde_json::to_string(&statuses).unwrap().contains("private-activity-marker"));
        store.lock().unwrap();
    }

    #[test]
    fn native_rotation_changes_root_and_advances_the_device_epoch() {
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
        let event = Event::new(Utc::now(), Duration::seconds(1), json!({
            "app": "synthetic", "title": "private-activity-marker"
        }).as_object().unwrap().clone());
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
        ).is_ok());
        let snapshot = encrypt_current_snapshot(&store, &data_key).unwrap();
        assert!(!format!("{snapshot:?}").contains("private-activity-marker"));
        let decrypted = decrypt_snapshot(&data_key, &EncryptedSyncSnapshotV1 {
            schema_version: 1,
            snapshot_id: URL_SAFE_NO_PAD.encode(snapshot.snapshot_id),
            envelopes: snapshot.envelopes.clone(),
        }).unwrap();
        assert!(String::from_utf8_lossy(&decrypted).contains("private-activity-marker"));
        assert!(store.rotate_sync_key_material(
            next, snapshot.clone(), None, "2026-09-23T12:10:00Z".into(),
        ).unwrap());
        assert_eq!(store.load_sync_snapshot().unwrap(), Some(snapshot));
        store.confirm_sync_recovery_saved("2026-09-23T12:11:00Z".into()).unwrap();
        let exported = super::export_sync_snapshot_from_store(&store).unwrap().unwrap();
        assert!(!serde_json::to_string(&exported).unwrap().contains("private-activity-marker"));
        store.lock().unwrap();
    }
}
