idf_component_register(
    SRCS "config_store.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        esp_hw_support
        event_bus
        log
        mbedtls
        nvs_flash
)
