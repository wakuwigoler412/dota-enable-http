cmake_minimum_required(VERSION 3.26)
project(dota_enable_http LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT MSVC)
  message(FATAL_ERROR "dota-enable-http targets Windows/MSVC only.")
endif()

# Version embedded in the exe. CI passes the release tag without its "v".
set(APP_VERSION "0.0.0-dev" CACHE STRING "Version embedded in the executable")
if(NOT APP_VERSION MATCHES "^([0-9]+)[.]([0-9]+)[.]([0-9]+)(-[0-9A-Za-z.-]+)?$")
  message(FATAL_ERROR "APP_VERSION must be MAJOR.MINOR.PATCH[-suffix], got '${APP_VERSION}'")
endif()
set(APP_VERSION_MAJOR ${CMAKE_MATCH_1})
set(APP_VERSION_MINOR ${CMAKE_MATCH_2})
set(APP_VERSION_PATCH ${CMAKE_MATCH_3})
configure_file(src/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc @ONLY)

# Static CRT: the exe runs without the Visual C++ Redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_options(/W4 /WX /permissive- /EHsc /utf-8)
add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)

# Gate finder: pure buffer logic, shared with the tests.
add_library(gate STATIC src/gate.cpp)
target_include_directories(gate PUBLIC src)

add_executable(dota-enable-http src/main.cpp src/process.cpp
               ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
target_compile_definitions(dota-enable-http PRIVATE APP_VERSION="${APP_VERSION}")
target_link_libraries(dota-enable-http PRIVATE gate)

enable_testing()
add_executable(tests tests/tests.cpp)
target_link_libraries(tests PRIVATE gate)
add_test(NAME tests COMMAND tests)
