use core::ffi::{c_char, c_void};

use crate::ffi::mqtt_broker;
use crate::platform::{esp_result, Result};

pub use crate::ffi::mqtt_broker::{
    MqttBrokerConfigRaw, MqttBrokerConnectCb, MqttBrokerConnectRaw, MqttBrokerMessageCb,
    MqttBrokerMessageRaw, MqttBrokerStatsRaw, MQTT_BROKER_CLIENT_ID_LEN, MQTT_BROKER_DEFAULT_PORT,
    MQTT_BROKER_PAYLOAD_MAX_LEN, MQTT_BROKER_TOPIC_LEN,
};

pub fn config_defaults(config: &mut MqttBrokerConfigRaw) {
    unsafe { mqtt_broker::mqtt_broker_config_defaults(config) };
}

pub unsafe fn start(config: Option<&MqttBrokerConfigRaw>) -> Result {
    let ptr = config.map_or(core::ptr::null(), |config| config);
    esp_result(unsafe { mqtt_broker::mqtt_broker_start(ptr) })
}

pub fn stop() -> Result {
    esp_result(unsafe { mqtt_broker::mqtt_broker_stop() })
}

pub fn is_running() -> bool {
    unsafe { mqtt_broker::mqtt_broker_is_running() }
}

pub unsafe fn publish(
    topic: *const c_char,
    payload: *const c_void,
    payload_len: usize,
    qos: u8,
    retain: bool,
) -> Result {
    esp_result(unsafe {
        mqtt_broker::mqtt_broker_publish(topic, payload, payload_len, qos, retain)
    })
}

pub fn stats() -> MqttBrokerStatsRaw {
    unsafe { mqtt_broker::mqtt_broker_get_stats() }
}
