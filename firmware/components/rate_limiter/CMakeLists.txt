idf_component_register(
    SRCS "rate_limiter.c"
    INCLUDE_DIRS "."
    REQUIRES
        flow_table
        esp_timer
)
