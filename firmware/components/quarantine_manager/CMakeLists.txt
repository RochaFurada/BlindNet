idf_component_register(
    SRCS "quarantine_manager.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        flow_table
        esp_timer
        freertos
        log
)
