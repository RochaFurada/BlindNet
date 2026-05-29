idf_component_register(
    SRCS "g2g_ble.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
    PRIV_REQUIRES
        bt
        freertos
        log
)

if(NOT CONFIG_BT_ENABLED OR NOT CONFIG_BT_NIMBLE_ENABLED)
    message(WARNING
        "g2g_ble requires NimBLE. Enable CONFIG_BT_ENABLED and "
        "CONFIG_BT_NIMBLE_ENABLED with idf.py menuconfig or sdkconfig.defaults."
    )
endif()
