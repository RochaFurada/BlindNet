idf_component_register(
    SRCS "dns_filter.c"
    INCLUDE_DIRS "."
    REQUIRES event_bus esp_timer
)
