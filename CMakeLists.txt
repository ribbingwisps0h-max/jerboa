cmake_minimum_required(VERSION 3.16)

project(jtp
    VERSION     2.0.0
    DESCRIPTION "Jerboa Transport Protocol v2 – RAW + UDP + QUIC-like tunnels"
    LANGUAGES   CXX
)

set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
        "Build type: Debug | Release | RelWithDebInfo | MinSizeRel" FORCE)
endif()

# ─── Compiler flags ───────────────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow
                        -Wconversion -Wsign-conversion)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O2)
    endif()
endif()

# ─── Platform guard ───────────────────────────────────────────────────────
if(NOT (CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR
        CMAKE_SYSTEM_NAME STREQUAL "Linux"))
    message(FATAL_ERROR "JTP requires macOS or Linux.")
endif()

# ─── Target ───────────────────────────────────────────────────────────────
add_executable(jtp JTP.h JTP.cpp main.cpp
    README.md)
target_include_directories(jtp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Threads REQUIRED)
    target_link_libraries(jtp PRIVATE Threads::Threads)
endif()

install(TARGETS jtp RUNTIME DESTINATION bin)

# ─── Summary ──────────────────────────────────────────────────────────────
message(STATUS "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
message(STATUS "  JTP v${PROJECT_VERSION}  |  ${CMAKE_SYSTEM_NAME}  |  ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
message(STATUS "  RAW mode  (root):  sudo ./jtp --listen")
message(STATUS "                     sudo ./jtp --send <ip> \"<msg>\"")
message(STATUS "  UDP mode  (any) :       ./jtp --listen-udp")
message(STATUS "                          ./jtp --send-udp  <ip> \"<msg>\"")
message(STATUS "  QUIC mode (any) :       ./jtp --listen-quic")
message(STATUS "                          ./jtp --send-quic <ip> \"<msg>\" [sid]")
message(STATUS "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

# ─── Qt Creator: run as sudo ──────────────────────────────────────────────
# Projects → Run → Custom Executable
#   Executable : /usr/bin/sudo
#   Arguments  : %{buildDir}/jtp --listen
#   Working dir: %{buildDir}
