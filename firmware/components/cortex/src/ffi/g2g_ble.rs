use core::ffi::c_void;

use crate::ffi::EspErr;

pub const G2G_BLE_FRAGMENT_MAX_LEN: usize = 220;
pub const G2G_BLE_MAX_PEERS: usize = 8;
pub const G2G_BLE_TX_QUEUE_LEN: usize = 16;

pub type G2gBleFragmentCb =
    Option<unsafe extern "C" fn(bytes: *const u8, len: usize, ctx: *mut c_void)>;

#[repr(C)]
pub struct G2gBleConfigRaw {
    pub guardian_id: u32,
    pub zone_id: u32,
    pub on_fragment: G2gBleFragmentCb,
    pub ctx: *mut c_void,
}

#[repr(C)]
pub struct G2gBleStatsRaw {
    pub discovered_peers: u64,
    pub queued_fragments: u64,
    pub tx_fragments: u64,
    pub tx_errors: u64,
    pub rx_fragments: u64,
    pub rx_errors: u64,
}

unsafe extern "C" {
    pub fn g2g_ble_start(config: *const G2gBleConfigRaw) -> EspErr;
    pub fn g2g_ble_stop() -> EspErr;
    pub fn g2g_ble_is_running() -> bool;
    pub fn g2g_ble_send_fragment(bytes: *const u8, len: usize) -> EspErr;
    pub fn g2g_ble_get_stats() -> G2gBleStatsRaw;
}
