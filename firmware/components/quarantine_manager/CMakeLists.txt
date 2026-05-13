idf_component_register(
    SRCS "quarantine_manager.c"
    INCLUDE_DIRS "."
    REQUIRES
        flow_table
        esp_timer
)
