idf_component_register(
    SRCS "dns_filter.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        event_bus
        esp_timer
        freertos
        log
        lwip
)
