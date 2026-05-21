idf_component_register(
    SRCS "wifi_manager.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        esp_wifi
        esp_event
        esp_hw_support
        esp_netif
        esp_system
        freertos
        log
        nvs_flash
        mbedtls
)
