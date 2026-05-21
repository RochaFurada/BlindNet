idf_component_register(
    SRCS "rna_membrane.c"
    INCLUDE_DIRS "."
    REQUIRES
        amino_acids
        esp_common
        nvs_flash
)
