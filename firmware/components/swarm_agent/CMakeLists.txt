idf_component_register(
    SRCS "swarm_agent.c"
    INCLUDE_DIRS "."
    REQUIRES
        flow_table
        quarantine_manager
        esp_timer
        mbedtls
)
