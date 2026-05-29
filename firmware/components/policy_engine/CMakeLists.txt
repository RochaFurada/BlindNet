idf_component_register(
    SRCS "policy_engine.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        flow_table
        esp_timer
        freertos
        log
)
