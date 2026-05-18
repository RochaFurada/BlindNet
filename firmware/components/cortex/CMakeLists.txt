idf_component_register(
    SRCS "cortex_component.c"
    INCLUDE_DIRS "include"
    REQUIRES
        action_pill
        admin_server
        config_store
        device_registry
        dns_filter
        event_bus
        flow_table
        membrane
        MQTT_broker
        policy_engine
        quarantine_manager
        rate_limiter
        setup_ap
        stomach
        swarm_agent
        telemetry_agent
        wifi_manager
        zone_firewall
        zone_gateway
)

set(CORTEX_CRATE_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(CORTEX_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-target")

if(IDF_TARGET STREQUAL "esp32")
    set(CORTEX_RUST_TARGET "xtensa-esp32-espidf")
elseif(IDF_TARGET STREQUAL "esp32s2")
    set(CORTEX_RUST_TARGET "xtensa-esp32s2-espidf")
elseif(IDF_TARGET STREQUAL "esp32s3")
    set(CORTEX_RUST_TARGET "xtensa-esp32s3-espidf")
else()
    message(FATAL_ERROR "Unsupported Rust ESP-IDF target for cortex: ${IDF_TARGET}")
endif()

set(CORTEX_RUST_PROFILE "release")
set(CORTEX_RUST_LIB
    "${CORTEX_TARGET_DIR}/${CORTEX_RUST_TARGET}/${CORTEX_RUST_PROFILE}/libcortex.a"
)
file(GLOB_RECURSE CORTEX_RUST_SOURCES CONFIGURE_DEPENDS
    "${CORTEX_CRATE_DIR}/src/*.rs"
)

find_program(CARGO_EXECUTABLE cargo)
if(NOT CARGO_EXECUTABLE)
    message(FATAL_ERROR "cargo was not found. Install the ESP Rust toolchain with espup.")
endif()

add_custom_command(
    OUTPUT "${CORTEX_RUST_LIB}"
    COMMAND "${CMAKE_COMMAND}" -E env
        "CARGO_TARGET_DIR=${CORTEX_TARGET_DIR}"
        "${CARGO_EXECUTABLE}" build
            --manifest-path "${CORTEX_CRATE_DIR}/Cargo.toml"
            --target "${CORTEX_RUST_TARGET}"
            --release
    DEPENDS
        "${CORTEX_CRATE_DIR}/Cargo.toml"
        "${CORTEX_CRATE_DIR}/Cargo.lock"
        "${CORTEX_CRATE_DIR}/.cargo/config.toml"
        "${CORTEX_CRATE_DIR}/rust-toolchain.toml"
        ${CORTEX_RUST_SOURCES}
    WORKING_DIRECTORY "${CORTEX_CRATE_DIR}"
    COMMENT "Building Rust cortex component"
    VERBATIM
)

add_custom_target(cortex_rust_build DEPENDS "${CORTEX_RUST_LIB}")
add_dependencies(${COMPONENT_LIB} cortex_rust_build)
target_link_libraries(${COMPONENT_LIB} PUBLIC "${CORTEX_RUST_LIB}")

set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${CORTEX_TARGET_DIR}")
