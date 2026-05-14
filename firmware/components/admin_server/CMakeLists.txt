idf_component_register(
    SRCS "admin_server.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_http_server
        config_store
        mbedtls
)
