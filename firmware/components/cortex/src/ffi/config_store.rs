use core::ffi::c_char;

use crate::ffi::EspErr;

pub const CONFIG_STORE_SSID_LEN: usize = 32;
pub const CONFIG_STORE_PASS_LEN: usize = 64;
pub const CONFIG_STORE_HOST_LEN: usize = 64;
pub const CONFIG_STORE_PUBLIC_KEY_MAX_LEN: usize = 512;
pub const CONFIG_STORE_KEY_ID_LEN: usize = 16;

#[repr(C)]
pub struct ZoneguardConfigRaw {
    pub magic: u32,
    pub version: u32,

    pub zone_id: u32,
    pub guardian_id: u32,

    pub issuer_public_key_pem: [c_char; CONFIG_STORE_PUBLIC_KEY_MAX_LEN],
    pub issuer_key_id: [u8; CONFIG_STORE_KEY_ID_LEN],

    pub sta_ssid: [c_char; CONFIG_STORE_SSID_LEN],
    pub sta_password: [c_char; CONFIG_STORE_PASS_LEN],
    pub ap_ssid: [c_char; CONFIG_STORE_SSID_LEN],
    pub ap_password: [c_char; CONFIG_STORE_PASS_LEN],

    pub ap_channel: u8,
    pub ap_max_connections: u8,

    pub swarm_port: u16,
    pub swarm_broadcast: [c_char; CONFIG_STORE_HOST_LEN],

    pub telemetry_host: [c_char; CONFIG_STORE_HOST_LEN],
    pub telemetry_port: u16,

    pub swarm_key: [u8; 32],
    pub swarm_key_len: u8,

    pub policy_version: u32,
}

unsafe extern "C" {
    pub fn config_store_init() -> EspErr;
    pub fn config_store_load(out_config: *mut ZoneguardConfigRaw) -> EspErr;
    pub fn config_store_save(config: *const ZoneguardConfigRaw) -> EspErr;
    pub fn config_store_erase() -> EspErr;
    pub fn config_store_set_defaults(config: *mut ZoneguardConfigRaw);
}
