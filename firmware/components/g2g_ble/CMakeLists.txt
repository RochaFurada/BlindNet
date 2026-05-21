idf_component_register(
    SRCS "g2g_ble.c"
    INCLUDE_DIRS "."
    REQUIRES
        bt
        esp_common
        freertos
        log
)
