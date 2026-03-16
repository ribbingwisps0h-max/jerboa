cmake_minimum_required(VERSION 3.16)

project(jtp
    VERSION     3.0.0
    DESCRIPTION "Jerboa Transport Protocol v3 — RAW + UDP + QUIC + AES-256-GCM + fragmentation"
    LANGUAGES   CXX
)

set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

# ─── Platform guard ───────────────────────────────────────────────────────
if(NOT (CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR
        CMAKE_SYSTEM_NAME STREQUAL "Linux"))
    message(FATAL_ERROR "JTP requires macOS or Linux (for now).")
endif()

# ─── Compiler flags ───────────────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow
                        -Wconversion -Wsign-conversion -Wno-unused-parameter)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O2)
    endif()
endif()

# ─── OpenSSL ──────────────────────────────────────────────────────────────
# macOS: brew install openssl@3
# Linux: sudo apt-get install libssl-dev
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR
        "OpenSSL not found.\n"
        "  macOS:  brew install openssl@3\n"
        "  Ubuntu: sudo apt-get install libssl-dev")
endif()

# ─── Target ───────────────────────────────────────────────────────────────
add_executable(jtp
    jtp.h
    jtp.cpp
    main.cpp
    README.md
)

target_include_directories(jtp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(jtp PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Threads REQUIRED)
    target_link_libraries(jtp PRIVATE Threads::Threads)
endif()

install(TARGETS jtp RUNTIME DESTINATION bin)

# ─── Summary ──────────────────────────────────────────────────────────────
message(STATUS "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
message(STATUS "  JTP v${PROJECT_VERSION}  |  ${CMAKE_SYSTEM_NAME}  |  ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
message(STATUS "  ./jtp --listen-udp --key secret")
message(STATUS "  ./jtp --send-udp <ip> \"big message\" --key secret")
message(STATUS "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

# ─── Qt Creator: RAW mode as sudo ─────────────────────────────────────────
# Projects → Run → Custom Executable
#   Executable:  /usr/bin/sudo
#   Arguments:   %{buildDir}/jtp --listen
#   Working dir: %{buildDir}
#
# Android / iOS future integration:
#   The jtp.h / jtp.cpp files are pure POSIX + OpenSSL — compile them
#   as a static library for the NDK / Xcode target and call from JNI / Swift.
#   CMake Android toolchain: cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake
#   iOS: add jtp.cpp to Xcode target, link OpenSSL via CocoaPods or xcframework.
