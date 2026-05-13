idf_component_register(
    SRCS "zone_gateway.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_netif
        wifi_manager
)
