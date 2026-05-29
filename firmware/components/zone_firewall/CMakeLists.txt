idf_component_register(
    SRCS "zone_firewall.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        flow_table
        policy_engine
        rate_limiter
        quarantine_manager
        device_registry
        event_bus
        freertos
        log
)
