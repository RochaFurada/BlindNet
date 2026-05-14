idf_component_register(
    SRCS
        "ribosome_table.c"
        "ribosome_store.c"
    INCLUDE_DIRS
        "."
        "../rna_membrane"
        "../rna_membrane/amino_acids"
    REQUIRES nvs_flash
)
