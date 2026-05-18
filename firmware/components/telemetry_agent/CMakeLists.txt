idf_component_register(
    SRCS "telemetry_agent.c"
    INCLUDE_DIRS "."
    REQUIRES
        wifi_manager
        zone_gateway
        flow_table
        policy_engine
        rate_limiter
        quarantine_manager
        swarm_agent
        esp_timer
)
