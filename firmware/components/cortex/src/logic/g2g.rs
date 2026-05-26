use core::ffi::{c_char, c_int, c_void};
use core::mem;
use core::ptr;
use core::slice;

use crate::platform;
use crate::platform::g2g_ble;
use crate::platform::Result;

use super::action_pill::{self, ActionPill};

pub const G2G_MESSAGE_ID_LEN: usize = 32;
pub const G2G_ACTION_PILL_MAX_LEN: usize = 768;
pub const G2G_RX_SLOTS: usize = 4;
pub const G2G_SEEN_CACHE_SIZE: usize = 32;

const WIRE_VERSION: u8 = 1;
const WIRE_TYPE_ACTION_PILL: u8 = 1;
const WIRE_HEADER_LEN: usize = 46;
const WIRE_FRAGMENT_PAYLOAD_MAX: usize = g2g_ble::G2G_BLE_FRAGMENT_MAX_LEN - WIRE_HEADER_LEN;
const WIRE_FRAGMENT_MAX_COUNT: usize = 32;
const ESP_LOG_WARN: c_int = 2;
const ESP_LOG_INFO: c_int = 3;
const TAG_G2G: &[u8] = b"cortex_g2g\0";

pub type ActionPillHandler = fn(&ActionPill) -> Result;

unsafe extern "C" {
    fn esp_log_write(level: c_int, tag: *const c_char, format: *const c_char, ...);
}

struct SeenCache {
    entries: [[u8; G2G_MESSAGE_ID_LEN]; G2G_SEEN_CACHE_SIZE],
    next: usize,
    count: usize,
}

#[derive(Copy, Clone)]
struct RxSlot {
    in_use: bool,
    message_id: [u8; G2G_MESSAGE_ID_LEN],
    total_len: usize,
    frag_count: usize,
    received_mask: u32,
    bytes: [u8; G2G_ACTION_PILL_MAX_LEN],
}

static mut ACTION_PILL_HANDLER: Option<ActionPillHandler> = None;
static mut SEEN_CACHE: SeenCache = SeenCache {
    entries: [[0u8; G2G_MESSAGE_ID_LEN]; G2G_SEEN_CACHE_SIZE],
    next: 0,
    count: 0,
};
static mut RX_SLOTS: [RxSlot; G2G_RX_SLOTS] = [RxSlot::empty(); G2G_RX_SLOTS];

impl RxSlot {
    const fn empty() -> Self {
        Self {
            in_use: false,
            message_id: [0u8; G2G_MESSAGE_ID_LEN],
            total_len: 0,
            frag_count: 0,
            received_mask: 0,
            bytes: [0u8; G2G_ACTION_PILL_MAX_LEN],
        }
    }

    fn clear(&mut self) {
        *self = Self::empty();
    }
}

pub fn start(guardian_id: u32, zone_id: u32) -> Result {
    let config = g2g_ble::G2gBleConfigRaw {
        guardian_id,
        zone_id,
        on_fragment: Some(on_fragment_received),
        ctx: g2g_ble::null_ctx(),
    };

    unsafe { g2g_ble::start(Some(&config)) }
}

pub fn stop() -> Result {
    g2g_ble::stop()
}

pub fn is_running() -> bool {
    g2g_ble::is_running()
}

pub fn stats() -> g2g_ble::G2gBleStatsRaw {
    g2g_ble::stats()
}

pub fn set_action_pill_handler(handler: Option<ActionPillHandler>) {
    unsafe {
        ACTION_PILL_HANDLER = handler;
    }
}

pub fn clear_seen_cache() {
    unsafe {
        SEEN_CACHE.entries = [[0u8; G2G_MESSAGE_ID_LEN]; G2G_SEEN_CACHE_SIZE];
        SEEN_CACHE.next = 0;
        SEEN_CACHE.count = 0;
    }
}

pub fn send_action_pill(pill: &ActionPill) -> Result {
    let message_id = action_pill::compute_inner_id(pill)?;
    let bytes = action_pill_bytes(pill);
    send_action_pill_bytes(bytes, &message_id)
}

pub fn send_action_pill_bytes(bytes: &[u8], message_id: &[u8; G2G_MESSAGE_ID_LEN]) -> Result {
    if bytes.is_empty() || bytes.len() > G2G_ACTION_PILL_MAX_LEN {
        return Err(platform::ESP_ERR_INVALID_SIZE);
    }

    let frag_count = bytes.len().div_ceil(WIRE_FRAGMENT_PAYLOAD_MAX);
    if frag_count == 0 || frag_count > WIRE_FRAGMENT_MAX_COUNT {
        return Err(platform::ESP_ERR_INVALID_SIZE);
    }

    for frag_index in 0..frag_count {
        let offset = frag_index * WIRE_FRAGMENT_PAYLOAD_MAX;
        let end = (offset + WIRE_FRAGMENT_PAYLOAD_MAX).min(bytes.len());
        let payload = &bytes[offset..end];

        let mut frame = [0u8; g2g_ble::G2G_BLE_FRAGMENT_MAX_LEN];
        frame[0] = WIRE_VERSION;
        frame[1] = WIRE_TYPE_ACTION_PILL;
        write_u16_le(&mut frame[4..6], bytes.len())?;
        write_u16_le(&mut frame[6..8], offset)?;
        write_u16_le(&mut frame[8..10], frag_index)?;
        write_u16_le(&mut frame[10..12], frag_count)?;
        write_u16_le(&mut frame[12..14], payload.len())?;
        frame[14..46].copy_from_slice(message_id);
        frame[WIRE_HEADER_LEN..WIRE_HEADER_LEN + payload.len()].copy_from_slice(payload);

        g2g_ble::send_fragment(&frame[..WIRE_HEADER_LEN + payload.len()])?;
    }

    add_seen(message_id);
    Ok(())
}

pub fn handle_received_fragment(bytes: &[u8]) -> Result {
    if bytes.len() < WIRE_HEADER_LEN {
        log_g2g_reject(
            "fragment_short",
            platform::ESP_ERR_INVALID_SIZE,
            bytes.len(),
            None,
        );
        return Err(platform::ESP_ERR_INVALID_SIZE);
    }
    if bytes[0] != WIRE_VERSION
        || bytes[1] != WIRE_TYPE_ACTION_PILL
        || bytes[2] != 0
        || bytes[3] != 0
    {
        log_g2g_reject(
            "fragment_version",
            platform::ESP_ERR_INVALID_VERSION,
            bytes.len(),
            None,
        );
        return Err(platform::ESP_ERR_INVALID_VERSION);
    }

    let total_len = read_u16_le(&bytes[4..6]) as usize;
    let frag_offset = read_u16_le(&bytes[6..8]) as usize;
    let frag_index = read_u16_le(&bytes[8..10]) as usize;
    let frag_count = read_u16_le(&bytes[10..12]) as usize;
    let payload_len = read_u16_le(&bytes[12..14]) as usize;
    let message_id = read_message_id(&bytes[14..46]);
    log_g2g_header(
        total_len,
        frag_offset,
        frag_index,
        frag_count,
        payload_len,
        &message_id,
    );

    if total_len == 0
        || total_len > G2G_ACTION_PILL_MAX_LEN
        || frag_count == 0
        || frag_count > WIRE_FRAGMENT_MAX_COUNT
        || frag_index >= frag_count
        || payload_len > WIRE_FRAGMENT_PAYLOAD_MAX
        || WIRE_HEADER_LEN + payload_len != bytes.len()
        || frag_offset + payload_len > total_len
    {
        log_g2g_reject(
            "fragment_bounds",
            platform::ESP_ERR_INVALID_SIZE,
            bytes.len(),
            Some(&message_id),
        );
        return Err(platform::ESP_ERR_INVALID_SIZE);
    }

    if seen(&message_id) {
        log_g2g_reject(
            "fragment_seen",
            platform::ESP_ERR_INVALID_STATE,
            bytes.len(),
            Some(&message_id),
        );
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    let payload = &bytes[WIRE_HEADER_LEN..];
    let slot = rx_slot_for(&message_id);
    if slot.total_len == 0 {
        slot.total_len = total_len;
        slot.frag_count = frag_count;
    }
    if slot.total_len != total_len || slot.frag_count != frag_count {
        slot.clear();
        log_g2g_reject(
            "fragment_mismatch",
            platform::ESP_ERR_INVALID_STATE,
            bytes.len(),
            Some(&message_id),
        );
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    let bit = 1u32 << frag_index;
    if slot.received_mask & bit != 0 {
        log_g2g_reject(
            "fragment_duplicate",
            platform::ESP_ERR_INVALID_STATE,
            bytes.len(),
            Some(&message_id),
        );
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    slot.bytes[frag_offset..frag_offset + payload_len].copy_from_slice(payload);
    slot.received_mask |= bit;
    log_g2g_progress(frag_index, frag_count, slot.received_mask, &message_id);

    let complete_mask = if frag_count == 32 {
        u32::MAX
    } else {
        (1u32 << frag_count) - 1
    };

    if slot.received_mask == complete_mask {
        let mut complete = [0u8; G2G_ACTION_PILL_MAX_LEN];
        complete[..slot.total_len].copy_from_slice(&slot.bytes[..slot.total_len]);
        let complete_len = slot.total_len;
        slot.clear();
        log_g2g_complete(complete_len, &message_id);
        handle_received_action_pill_bytes(&complete[..complete_len], &message_id)?;
    }

    Ok(())
}

pub fn handle_received_action_pill_bytes(
    bytes: &[u8],
    message_id: &[u8; G2G_MESSAGE_ID_LEN],
) -> Result {
    if bytes.len() != mem::size_of::<ActionPill>() {
        log_g2g_reject(
            "pill_size",
            platform::ESP_ERR_INVALID_SIZE,
            bytes.len(),
            Some(message_id),
        );
        return Err(platform::ESP_ERR_INVALID_SIZE);
    }

    let pill = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<ActionPill>()) };
    let computed_id = match action_pill::compute_inner_id(&pill) {
        Ok(id) => id,
        Err(err) => {
            log_g2g_reject("pill_digest", err, bytes.len(), Some(message_id));
            return Err(err);
        }
    };
    if computed_id != *message_id {
        log_g2g_reject(
            "pill_id_mismatch",
            platform::ESP_ERR_INVALID_CRC,
            bytes.len(),
            Some(message_id),
        );
        return Err(platform::ESP_ERR_INVALID_CRC);
    }

    if seen_or_add(message_id) {
        log_g2g_reject(
            "pill_seen",
            platform::ESP_ERR_INVALID_STATE,
            bytes.len(),
            Some(message_id),
        );
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    unsafe {
        if let Some(handler) = ACTION_PILL_HANDLER {
            match handler(&pill) {
                Ok(()) => log_g2g_handler_result(platform::ESP_OK, message_id),
                Err(err) => {
                    log_g2g_handler_result(err, message_id);
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

unsafe extern "C" fn on_fragment_received(bytes: *const u8, len: usize, _ctx: *mut c_void) {
    if bytes.is_null() {
        return;
    }

    let fragment = unsafe { slice::from_raw_parts(bytes, len) };
    log_g2g_rx(len);
    let _ = handle_received_fragment(fragment);
}

fn rx_slot_for(message_id: &[u8; G2G_MESSAGE_ID_LEN]) -> &'static mut RxSlot {
    unsafe {
        let mut free_index = 0usize;
        let mut has_free = false;

        for i in 0..G2G_RX_SLOTS {
            if RX_SLOTS[i].in_use && RX_SLOTS[i].message_id == *message_id {
                return &mut RX_SLOTS[i];
            }
            if !RX_SLOTS[i].in_use && !has_free {
                free_index = i;
                has_free = true;
            }
        }

        let index = if has_free { free_index } else { 0 };
        RX_SLOTS[index].clear();
        RX_SLOTS[index].in_use = true;
        RX_SLOTS[index].message_id = *message_id;
        &mut RX_SLOTS[index]
    }
}

fn seen_or_add(message_id: &[u8; G2G_MESSAGE_ID_LEN]) -> bool {
    if seen(message_id) {
        return true;
    }

    add_seen(message_id);
    false
}

fn seen(message_id: &[u8; G2G_MESSAGE_ID_LEN]) -> bool {
    unsafe {
        for i in 0..SEEN_CACHE.count {
            if SEEN_CACHE.entries[i] == *message_id {
                return true;
            }
        }

        false
    }
}

fn add_seen(message_id: &[u8; G2G_MESSAGE_ID_LEN]) {
    unsafe {
        SEEN_CACHE.entries[SEEN_CACHE.next] = *message_id;
        SEEN_CACHE.next = (SEEN_CACHE.next + 1) % G2G_SEEN_CACHE_SIZE;
        if SEEN_CACHE.count < G2G_SEEN_CACHE_SIZE {
            SEEN_CACHE.count += 1;
        }
    }
}

fn action_pill_bytes(pill: &ActionPill) -> &[u8] {
    unsafe {
        slice::from_raw_parts(
            (pill as *const ActionPill).cast::<u8>(),
            mem::size_of::<ActionPill>(),
        )
    }
}

fn read_message_id(bytes: &[u8]) -> [u8; G2G_MESSAGE_ID_LEN] {
    let mut out = [0u8; G2G_MESSAGE_ID_LEN];
    out.copy_from_slice(bytes);
    out
}

fn read_u16_le(bytes: &[u8]) -> u16 {
    (bytes[0] as u16) | ((bytes[1] as u16) << 8)
}

fn write_u16_le(out: &mut [u8], value: usize) -> Result {
    if value > u16::MAX as usize || out.len() < 2 {
        return Err(platform::ESP_ERR_INVALID_SIZE);
    }

    out[0] = (value & 0xFF) as u8;
    out[1] = ((value >> 8) & 0xFF) as u8;
    Ok(())
}

fn log_tag() -> *const c_char {
    TAG_G2G.as_ptr().cast()
}

fn message_id_prefix(message_id: &[u8; G2G_MESSAGE_ID_LEN]) -> u32 {
    u32::from_be_bytes([message_id[0], message_id[1], message_id[2], message_id[3]])
}

fn log_g2g_rx(len: usize) {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_tag(),
            c"fragment rx len=%u".as_ptr(),
            len as u32,
        );
    }
}

fn log_g2g_header(
    total_len: usize,
    frag_offset: usize,
    frag_index: usize,
    frag_count: usize,
    payload_len: usize,
    message_id: &[u8; G2G_MESSAGE_ID_LEN],
) {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_tag(),
            c"fragment id=%08x total=%u offset=%u index=%u/%u payload=%u".as_ptr(),
            message_id_prefix(message_id),
            total_len as u32,
            frag_offset as u32,
            frag_index as u32,
            frag_count as u32,
            payload_len as u32,
        );
    }
}

fn log_g2g_progress(
    frag_index: usize,
    frag_count: usize,
    received_mask: u32,
    message_id: &[u8; G2G_MESSAGE_ID_LEN],
) {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_tag(),
            c"fragment accepted id=%08x index=%u/%u mask=0x%08x".as_ptr(),
            message_id_prefix(message_id),
            frag_index as u32,
            frag_count as u32,
            received_mask,
        );
    }
}

fn log_g2g_complete(total_len: usize, message_id: &[u8; G2G_MESSAGE_ID_LEN]) {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_tag(),
            c"message complete id=%08x len=%u".as_ptr(),
            message_id_prefix(message_id),
            total_len as u32,
        );
    }
}

fn log_g2g_reject(
    stage: &str,
    err: platform::EspErr,
    len: usize,
    message_id: Option<&[u8; G2G_MESSAGE_ID_LEN]>,
) {
    let id = message_id.map(message_id_prefix).unwrap_or(0);
    let stage = stage.as_bytes();
    unsafe {
        esp_log_write(
            ESP_LOG_WARN,
            log_tag(),
            c"reject stage=%.*s id=%08x len=%u err=0x%08x".as_ptr(),
            stage.len() as c_int,
            stage.as_ptr().cast::<c_char>(),
            id,
            len as u32,
            err as u32,
        );
    }
}

fn log_g2g_handler_result(err: platform::EspErr, message_id: &[u8; G2G_MESSAGE_ID_LEN]) {
    let level = if err == platform::ESP_OK {
        ESP_LOG_INFO
    } else {
        ESP_LOG_WARN
    };
    unsafe {
        esp_log_write(
            level,
            log_tag(),
            c"handler result id=%08x err=0x%08x".as_ptr(),
            message_id_prefix(message_id),
            err as u32,
        );
    }
}
