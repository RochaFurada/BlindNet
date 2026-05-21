idf_component_register(
    SRCS "device_registry.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        esp_timer
        event_bus
        freertos
        log
)
