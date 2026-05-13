idf_component_register(
    SRCS "app_main.cpp"
    INCLUDE_DIRS "."
    REQUIRES
        event_bus
        config_store
        wifi_manager
        zone_gateway
        flow_table
        policy_engine
        rate_limiter
        quarantine_manager
        device_registry
        dns_filter
        zone_firewall
        swarm_agent
        telemetry_agent
        admin_server
)
