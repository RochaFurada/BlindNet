idf_component_register(
    SRCS "rate_limiter.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        flow_table
        esp_timer
        freertos
        log
)
