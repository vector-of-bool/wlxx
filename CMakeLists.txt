cmake_minimum_required(VERSION 3.2)
project(wl++ VERSION 0.1.0)

include(requirements.cmake)

find_package(Boost QUIET)

if(NOT WLXX_REQUIREMENTS_MET)
    message(FATAL_ERROR "wl++ platform requirements are not met. Cannot build.")
endif()

if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(is_root TRUE)
else()
    set(is_root FALSE)
endif()

set(WLXX_IS_ROOT_PROJECT "${is_root}" CACHE INTERNAL "")
if(WLXX_IS_ROOT_PROJECT)
    set(comp wlxx)
else()
    set(comp NO_INSTALL)
endif()
set(WLXX_INSTALL_COMPONENT "${comp}" CACHE STRING "wl++ install component name, or NO_INSTALL to disable installation")
set(WLXX_LIBRARY_TYPE "" CACHE STRING "Set the library type for wl++ generated libraries")
set(WLXX_PIC ${CMAKE_POSITION_INDEPENDENT_CODE} CACHE BOOL "Build wl++ with position-independent-code")

function(wlxx_install)
    if(NOT WLXX_INSTALL_COMPONENT STREQUAL "NO_INSTALL")
        string(REPLACE "<COMPONENT>" "COMPONENT;${WLXX_INSTALL_COMPONENT}" args "${ARGN}")
        install(${args})
    endif()
endfunction()

function(wlxx_add_library name)
    add_library(${name} ${WLXX_LIBRARY_TYPE} ${ARGN})
    if(WLXX_PIC)
        set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE TRUE)
    else()
        set_property(TARGET ${name} PROPERTY POSITION_INDEPENDENT_CODE FALSE)
    endif()
endfunction()

add_subdirectory(source)

wlxx_install(EXPORT wlxx-targets DESTINATION share/cmake)

if(TARGET Boost::boost)
    add_executable(wlxx-example example.cpp)
    target_link_libraries(wlxx-example PRIVATE wl++ Boost::boost)
endif()