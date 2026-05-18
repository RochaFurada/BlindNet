idf_component_register(
    SRCS
        "stomach_cp_cache.c"
    INCLUDE_DIRS "."
    REQUIRES
        action_pill
        membrane
        mbedtls
)
