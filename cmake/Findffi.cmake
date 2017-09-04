include(FindPackageHandleStandardArgs)

if(TARGET ffi::ffi)
    return()
endif()

find_library(LIBFFI_LIBRARY libffi_pic.a)
find_path(LIBFFI_INCLUDE_DIR ffi.h)

if(LIBFFI_LIBRARY AND LIBFFI_INCLUDE_DIR)
    add_library(ffi::ffi STATIC IMPORTED)

    set_target_properties(ffi::ffi PROPERTIES
        IMPORTED_LOCATION "${LIBFFI_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBFFI_INCLUDE_DIR}"
        )
    set(ffi_FOUND TRUE)
else()
    set(ffi_FOUND FALSE)
endif()

find_package_handle_standard_args(
    ffi
    DEFAULT_MESSAGE
    LIBFFI_LIBRARY LIBFFI_INCLUDE_DIR
    )