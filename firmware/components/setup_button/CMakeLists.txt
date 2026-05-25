idf_component_register(
    SRCS "setup_button.c"
    INCLUDE_DIRS "."
    REQUIRES
        driver
        esp_common
        freertos
        log
)
