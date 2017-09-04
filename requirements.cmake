list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

set(met TRUE)

find_package(wayland-client)
if(NOT wayland-client_FOUND)
    message(STATUS "Cannot build wl++ without libwayland-client")
    set(met FALSE)
endif()

find_program(PYTHON_EXECUTABLE NAMES python2.7 python2 python DOC "Path to Python executable")
if(NOT PYTHON_EXECUTABLE)
    message(STATUS "Cannot build wl++ without Python (for code generation)")
    set(met FALSE)
endif()

find_package(Boost)
if(NOT Boost_FOUND)
    message(STATUS "Cannot build wl++ wihtout Boost (For Boost.Interprocess)")
    set(met FALSE)
endif()

include(CMakePushCheckState)
include(CheckCXXSourceCompiles)

cmake_push_check_state(RESET)
check_cxx_source_compiles([[
    #include <sys/mman.h>

    int main() {
        return shm_open("", 0, 0);
    }
]] HAVE_SHM_WITHOUT_LINK)

set(CMAKE_REQUIRED_LIBRARIES -lrt)
check_cxx_source_compiles([[
    #include <sys/mman.h>

    int main() {
        return shm_open("", 0, 0);
    }
]] HAVE_SHM_WITH_RT_LINK)
if(HAVE_SHM_WITHOUT_LINK)
    set(WLXX_SHM_LIBRARY FALSE)
elseif(HAVE_SHM_WITH_RT_LINK)
    set(WLXX_SHM_LIBRARY -lrt)
elseif(WIN32)
    set(WLXX_SHM_LIBRARY FALSE)
else()
    message(STATUS "Unsure of how to link shared memory on this platform...")
endif()

cmake_pop_check_state()

set(WLXX_REQUIREMENTS_MET "${met}" CACHE BOOL "Are the wl++ requirements met?" FORCE)