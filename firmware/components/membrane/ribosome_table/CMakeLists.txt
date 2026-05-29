idf_component_register(
    SRCS
        "ribosome_table.c"
        "ribosome_store.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_common
        mbedtls
        nvs_flash
        rna_membrane
)
