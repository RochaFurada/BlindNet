idf_component_register(
    SRCS "zone_firewall.c"
    INCLUDE_DIRS "."
    REQUIRES
        flow_table
        policy_engine
        rate_limiter
        quarantine_manager
        device_registry
        event_bus
)
