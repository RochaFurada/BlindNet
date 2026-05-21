idf_component_register(
    SRCS "zone_gateway.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        esp_netif
        freertos
        log
        wifi_manager
)
