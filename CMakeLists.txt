cmake_minimum_required(VERSION 3.16)

# ─── Project metadata ─────────────────────────────────────────────────────
project(jtp
    VERSION     1.0.0
    DESCRIPTION "Jerboa Transport Protocol – experimental IPv4 transport"
    LANGUAGES   CXX
)

# ─── C++ standard ─────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)   # Enforce strict ISO C++17

# ─── Default build type ───────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
        "Choose: Debug | Release | RelWithDebInfo | MinSizeRel" FORCE)
endif()

# ─── Compiler-specific warnings ───────────────────────────────────────────
# Targets Clang (macOS, LLVM toolchain) and GCC (Linux).
# MSVC is intentionally unsupported (raw sockets on Windows differ).
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wno-unused-parameter    # tolerated in signal handler stubs
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O2)
    endif()
else()
    message(WARNING "Untested compiler: ${CMAKE_CXX_COMPILER_ID}. "
                    "JTP requires POSIX raw-socket APIs (macOS/Linux only).")
endif()

# ─── Platform guard ───────────────────────────────────────────────────────
if(NOT (CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR
        CMAKE_SYSTEM_NAME STREQUAL "Linux"))
    message(FATAL_ERROR
        "JTP only supports macOS (Darwin) and Linux. "
        "Detected: ${CMAKE_SYSTEM_NAME}")
endif()

# ─── Source files ─────────────────────────────────────────────────────────
set(JTP_SOURCES
    JTP.h
    JTP.cpp
    main.cpp
)

# ─── Executable target ────────────────────────────────────────────────────
add_executable(jtp ${JTP_SOURCES}
    README.md)

target_include_directories(jtp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ─── Platform-specific linker flags ───────────────────────────────────────
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # On Linux, link pthreads explicitly (std::mutex/atomic pull it in).
    find_package(Threads REQUIRED)
    target_link_libraries(jtp PRIVATE Threads::Threads)
endif()

# macOS: no extra libraries required; BSD sockets are in libSystem.

# ─── Installation (optional) ──────────────────────────────────────────────
install(TARGETS jtp
    RUNTIME DESTINATION bin
)

# ─── Summary ──────────────────────────────────────────────────────────────
message(STATUS "──────────────────────────────────────────────")
message(STATUS "  Project   : ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "  Platform  : ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Compiler  : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ std   : ${CMAKE_CXX_STANDARD}")
message(STATUS "──────────────────────────────────────────────")
message(STATUS "  *** Raw sockets require root / sudo ***")
message(STATUS "  Run with:  sudo ./jtp --listen")
message(STATUS "             sudo ./jtp --send <ip> \"<msg>\"")
message(STATUS "──────────────────────────────────────────────")

# ─── Qt Creator: 'Run with Sudo' configuration instructions ───────────────
#
# Qt Creator does not natively support running executables as root, but
# you can configure a custom run step:
#
#   1. Open: Projects → Run → Add Run Configuration → Custom Executable
#   2. Executable : /usr/bin/sudo       (or: /usr/bin/pkexec on Linux)
#   3. Arguments  : %{buildDir}/jtp --listen
#                   %{buildDir}/jtp --send 127.0.0.1 "test"
#   4. Working dir: %{buildDir}
#
# Alternatively, from a terminal inside Qt Creator (Alt+3):
#   sudo %{buildDir}/jtp --listen
#
# On macOS you can also grant the binary the net_bind capability once:
#   sudo chown root:wheel %{buildDir}/jtp && sudo chmod u+s %{buildDir}/jtp
# (setuid-root – use only on a development machine, never in production.)

