idf_component_register(
    SRCS "MQTT_broker.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        freertos
        log
        lwip
        mosquitto
)
