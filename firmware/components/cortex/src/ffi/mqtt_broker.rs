use core::ffi::{c_char, c_void};

use crate::ffi::EspErr;

pub const MQTT_BROKER_DEFAULT_PORT: u16 = 1883;
pub const MQTT_BROKER_CLIENT_ID_LEN: usize = 32;
pub const MQTT_BROKER_TOPIC_LEN: usize = 96;
pub const MQTT_BROKER_PAYLOAD_MAX_LEN: usize = 256;

#[repr(C)]
pub struct MqttBrokerConnectRaw {
    pub client_id: *const c_char,
    pub username: *const c_char,
    pub password: *const u8,
    pub password_len: usize,
}

pub type MqttBrokerConnectCb =
    Option<unsafe extern "C" fn(event: *const MqttBrokerConnectRaw, ctx: *mut c_void) -> bool>;

#[repr(C)]
pub struct MqttBrokerMessageRaw {
    pub client_id: *const c_char,
    pub topic: *const c_char,
    pub payload: *const u8,
    pub payload_len: usize,
    pub qos: u8,
    pub retained: bool,
    pub remote_ip: u32,
}

pub type MqttBrokerMessageCb =
    Option<unsafe extern "C" fn(message: *const MqttBrokerMessageRaw, ctx: *mut c_void)>;

#[repr(C)]
pub struct MqttBrokerConfigRaw {
    pub listen_port: u16,
    pub bind_ip: u32,
    pub max_payload_len: u16,
    pub allow_anonymous: bool,
    pub zone_id: u32,
    pub connect_cb: MqttBrokerConnectCb,
    pub connect_ctx: *mut c_void,
    pub message_cb: MqttBrokerMessageCb,
    pub message_ctx: *mut c_void,
}

#[repr(C)]
pub struct MqttBrokerStatsRaw {
    pub listen_port: u32,
    pub bind_ip: u32,
    pub accepted_clients: u64,
    pub rejected_clients: u64,
    pub connected_clients: u64,
    pub rx_packets: u64,
    pub rx_publishes: u64,
    pub last_exit_code: i32,
}

unsafe extern "C" {
    pub fn mqtt_broker_config_defaults(config: *mut MqttBrokerConfigRaw);
    pub fn mqtt_broker_start(config: *const MqttBrokerConfigRaw) -> EspErr;
    pub fn mqtt_broker_stop() -> EspErr;
    pub fn mqtt_broker_is_running() -> bool;
    pub fn mqtt_broker_publish(
        topic: *const c_char,
        payload: *const c_void,
        payload_len: usize,
        qos: u8,
        retain: bool,
    ) -> EspErr;
    pub fn mqtt_broker_get_stats() -> MqttBrokerStatsRaw;
}
