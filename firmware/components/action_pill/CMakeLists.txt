# action_pill e o componente ESP-IDF real.
# As pastas capsule_pill/ e active_substance/ sao submodulos internos:
# seus .c entram aqui como fontes deste mesmo componente.
idf_component_register(
    SRCS
        "action_pill.cpp"
        "capsule_pill/capsule_pill.c"
        "active_substance/active_substance.c"
    INCLUDE_DIRS
        "."
        "capsule_pill"
        "active_substance"
    REQUIRES
        mbedtls
)
