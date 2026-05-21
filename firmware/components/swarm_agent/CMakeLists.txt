idf_component_register(
    SRCS "swarm_agent.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        esp_hw_support
        flow_table
        quarantine_manager
        esp_timer
        freertos
        log
        lwip
        mbedtls
)
