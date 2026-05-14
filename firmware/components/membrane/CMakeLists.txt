idf_component_register(
    SRCS
        "membrane.cpp"
        "ribosome_table/ribosome_table.c"
        "ribosome_table/ribosome_store.c"
        "rna_membrane/rna_membrane.c"
        "rna_membrane/amino_acids/amino_acids.c"
    INCLUDE_DIRS
        "."
        "ribosome_table"
        "rna_membrane"
        "rna_membrane/amino_acids"
    REQUIRES nvs_flash
)
