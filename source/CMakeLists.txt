set(CMAKE_INCLUDE_CURRENT_DIR TRUE)

set(genroot "${CMAKE_CURRENT_BINARY_DIR}/_gen")
set(gen_cpp "${PROJECT_SOURCE_DIR}/generate.py")
set(wayland_xml "${PROJECT_SOURCE_DIR}/wayland.xml")

# Config depends on those two files
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${gen_cpp}" "${wayland_xml}")

# Get a list of source files that will be generated
execute_process(
    COMMAND "${PYTHON_EXECUTABLE}" "${gen_cpp}"
        --xml "${wayland_xml}"
        --out "${genroot}"
        --list
    OUTPUT_VARIABLE out
    RESULT_VARIABLE res
)
if(res)
    message(FATAL_ERROR "Failed to execute Python for generating the Wayland bindings. What gives?")
endif()
string(REPLACE "\n" ";" sources "${out}")
set_source_files_properties(${sources} PROPERTIES GENERATED TRUE)

add_custom_command(
    OUTPUT ${sources}
    DEPENDS "${gen_cpp}" "${wayland_xml}"
    COMMAND "${PYTHON_EXECUTABLE}" "${gen_cpp}"
        --xml "${wayland_xml}"
        --out "${genroot}"
    COMMENT "Generating C++ Wayland bindings"
    )

wlxx_add_library(wl++
    wl/wl.hpp
    ${sources}
    )

target_compile_features(wl++ PUBLIC cxx_std_14)
target_link_libraries(wl++ PUBLIC wayland::client)
add_library(wl++::wl++ ALIAS wl++)

if(WLXX_SHM_LIBRARY)
    target_link_libraries(wl++ PUBLIC ${WLXX_SHM_LIBRARY})
endif()

wlxx_install(TARGETS wl++
    EXPORT wlxx-targets
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    INCLUDES include
    <COMPONENT>
    )

wlxx_install(
    DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/wl"
    DESTINATION include
    <COMPONENT>
    FILES_MATCHING
        PATTERN *.hpp
    )

wlxx_install(
    DIRECTORY "${genroot}/wl"
    DESTINATION include
    <COMPONENT>
    FILES_MATCHING
        PATTERN *.hpp
    )