pub use crate::ffi::{
    EspErr, ESP_ERR_INVALID_ARG, ESP_ERR_INVALID_CRC, ESP_ERR_INVALID_MAC,
    ESP_ERR_INVALID_RESPONSE, ESP_ERR_INVALID_SIZE, ESP_ERR_INVALID_STATE, ESP_ERR_INVALID_VERSION,
    ESP_ERR_NOT_FOUND, ESP_ERR_NOT_SUPPORTED, ESP_ERR_NO_MEM, ESP_ERR_TIMEOUT, ESP_FAIL, ESP_OK,
};

pub type Result<T = ()> = core::result::Result<T, EspErr>;

pub fn esp_result(err: EspErr) -> Result {
    if err == ESP_OK {
        Ok(())
    } else {
        Err(err)
    }
}

pub mod active_enzyme;
pub mod active_substance;
pub mod admin_server;
pub mod amino_acids;
pub mod capsule_pill;
pub mod config;
pub mod device_registry;
pub mod dns_filter;
pub mod event_bus;
pub mod flow_table;
pub mod mqtt_broker;
pub mod policy_engine;
pub mod quarantine_manager;
pub mod rate_limiter;
pub mod ribosome_store;
pub mod ribosome_table;
pub mod rna_membrane;
pub mod setup_ap;
pub mod stomach_cp_cache;
pub mod swarm_agent;
pub mod telemetry_agent;
pub mod wifi_manager;
pub mod zone_firewall;
pub mod zone_gateway;
