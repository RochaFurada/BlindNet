idf_component_register(
    SRCS "setup_ap.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_wifi
        esp_event
        esp_netif
        nvs_flash
        mbedtls
)
