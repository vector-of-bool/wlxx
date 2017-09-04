include(FindPackageHandleStandardArgs)

if(TARGET wayland::client)
    return()
endif()

find_package(ffi)

if(ffi_FOUND)
    find_library(LIBWAYLAND_LIBRARY libwayland-client.a DOC "Wayland client library")
    find_path(LIBWAYLAND_INCLUDE_DIR wayland-client.h DOC "Path to Waylnad client include directory")

    add_library(wayland::client STATIC IMPORTED)

    if(NOT LIBWAYLAND_LIBRARY)
        message(WARNING_AUTHOR "No libwaylient-client installed. Install the wayland development packages.")
    else()
        set_target_properties(wayland::client PROPERTIES
            IMPORTED_LOCATION "${LIBWAYLAND_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${LIBWAYLAND_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES ffi::ffi
            )
    endif()
    find_package_handle_standard_args(
        wayland-client
        REQUIRED_VARS LIBWAYLAND_LIBRARY LIBWAYLAND_INCLUDE_DIR
        )
else()
    find_package_handle_standard_args(
        wayland-client
        REQUIRED_VARS LIBWAYLAND_LIBRARY LIBWAYLND_INCLUDE_DIR
        FAIL_MESSAGE "Wayland not imported. No libffi installed."
    )
endif()