idf_component_register(
    SRCS "admin_server.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        esp_http_server
        esp_system
        freertos
        config_store
        log
        mbedtls
)
