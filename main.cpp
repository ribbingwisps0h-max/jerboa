/**
 * @file main.cpp
 * @brief Jerboa Transport Protocol – command-line interface.
 *
 * Usage:
 * @code
 *   sudo ./jtp --listen
 *   sudo ./jtp --send 192.168.1.10 "Hello, Jerboa!"
 * @endcode
 *
 * The application must be executed with root / CAP_NET_RAW privileges
 * because it opens a raw IPv4 socket.
 *
 * Qt Creator integration note
 * ────────────────────────────
 * To run with elevated privileges directly from Qt Creator:
 *   Projects → Run → Run configuration → Add "sudo" wrapper, or set
 *   Executable to: /usr/bin/sudo
 *   Arguments to:  %{buildDir}/jtp --listen
 *
 * On macOS you may alternatively run:
 *   sudo %{buildDir}/jtp --listen
 * from the terminal after building.
 */

#include "JTP.h"

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <atomic>
#include <mutex>
#include <csignal>
#include <cstring>
#include <cstdlib>

// POSIX
#include <unistd.h>
#include <sys/socket.h>

// ─── Thread-safe console output ───────────────────────────────────────────

namespace console {

/// Mutex that serialises all writes to std::cout / std::cerr.
static std::mutex g_print_mutex;

/**
 * @brief Print an informational message to stdout, thread-safely.
 * @param msg  Message text (newline appended automatically).
 */
void info(std::string_view msg)
{
    std::lock_guard<std::mutex> lk(g_print_mutex);
    std::cout << "[INFO]  " << msg << '\n';
}

/**
 * @brief Print an error message to stderr, thread-safely.
 * @param msg  Message text (newline appended automatically).
 */
void error(std::string_view msg)
{
    std::lock_guard<std::mutex> lk(g_print_mutex);
    std::cerr << "[ERROR] " << msg << '\n';
}

/**
 * @brief Print a received-packet message to stdout, thread-safely.
 * @param seq      Sequence number from the JTP header.
 * @param flags    Flags byte from the JTP header.
 * @param payload  Decoded payload string.
 */
void received(uint16_t seq, uint8_t flags, std::string_view payload)
{
    std::lock_guard<std::mutex> lk(g_print_mutex);
    std::cout << "[RECV]  seq=" << seq
              << " flags=0x" << std::hex << static_cast<int>(flags) << std::dec
              << " payload=\"" << payload << "\"\n";
}

} // namespace console

// ─── Signal handling ──────────────────────────────────────────────────────

/// Set to true when SIGINT / SIGTERM is received; the receive loop polls this.
static std::atomic<bool> g_running{true};

static void signal_handler(int /*sig*/) noexcept
{
    g_running.store(false, std::memory_order_relaxed);
}

// ─── Privilege check ──────────────────────────────────────────────────────

/**
 * @brief Abort with a helpful message if the process is not running as root.
 *
 * Raw sockets require CAP_NET_RAW on Linux or root on macOS.
 */
static void require_root()
{
    if (::geteuid() != 0) {
        console::error("This program requires root privileges.");
        console::error("Please re-run with: sudo ./jtp <args>");
        std::exit(EXIT_FAILURE);
    }
}

// ─── Usage ────────────────────────────────────────────────────────────────

static void print_usage(const char* prog)
{
    std::cout
        << "\nJerboa Transport Protocol (JTP) – experimental Layer-4 datagram tool\n"
        << "IP Protocol number: " << static_cast<int>(jtp::IP_PROTO_JTP) << "\n\n"
        << "Usage:\n"
        << "  sudo " << prog << " --listen\n"
        << "  sudo " << prog << " --send <dest_ip> \"<message>\"\n\n"
        << "Flags:\n"
        << "  --listen          Capture and display incoming JTP datagrams.\n"
        << "  --send <ip> <msg> Construct and inject a JTP datagram.\n\n"
        << "Examples:\n"
        << "  sudo " << prog << " --listen\n"
        << "  sudo " << prog << " --send 127.0.0.1 \"Hello, Jerboa!\"\n\n";
}

// ─── Listen mode ──────────────────────────────────────────────────────────

/**
 * @brief Enter the packet-capture loop.
 *
 * Blocks on @ref jtp::receive_packet() until SIGINT/SIGTERM or a fatal
 * I/O error.  Each received JTP datagram is checksum-validated and its
 * payload printed via @ref console::received().
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE.
 */
static int mode_listen()
{
    console::info("Opening raw socket (proto=253)…");
    int fd = jtp::open_raw_socket();
    if (fd < 0) {
        std::string msg = "socket() failed: ";
        msg += std::strerror(errno);
        console::error(msg);
        return EXIT_FAILURE;
    }

    console::info("Listening for JTP datagrams (Ctrl-C to stop)…");

    while (g_running.load(std::memory_order_relaxed)) {
        std::vector<uint8_t> raw = jtp::receive_packet(fd);

        if (raw.empty()) {
            // Either the packet was filtered out (wrong protocol) or a
            // transient I/O error occurred — keep going.
            if (errno == EINTR) break; // Signal interrupted recvfrom.
            continue;
        }

        // Verify checksum before trusting any field.
        if (!jtp::verify_checksum(raw)) {
            console::error("Checksum mismatch – packet discarded.");
            continue;
        }

        auto hdr_opt = jtp::deserialise(raw);
        if (!hdr_opt) {
            console::error("Truncated JTP header – packet discarded.");
            continue;
        }

        const jtp::Header& hdr = *hdr_opt;

        // Sanity-check payload length against the buffer we actually received.
        std::size_t total_expected =
            static_cast<std::size_t>(jtp::HEADER_SIZE) + hdr.payload_length;
        if (raw.size() < total_expected) {
            console::error("Payload shorter than header claims – discarded.");
            continue;
        }

        // Decode payload as UTF-8 text (best-effort; JTP is payload-agnostic).
        std::string payload(
            reinterpret_cast<const char*>(raw.data() + jtp::HEADER_SIZE),
            hdr.payload_length);

        console::received(hdr.sequence_number, hdr.flags, payload);
    }

    ::close(fd);
    console::info("Listener stopped.");
    return EXIT_SUCCESS;
}

// ─── Send mode ────────────────────────────────────────────────────────────

/**
 * @brief Construct and inject a single JTP datagram.
 *
 * @param dest_ip  Dotted-decimal destination address.
 * @param message  Payload string (UTF-8).
 * @return EXIT_SUCCESS or EXIT_FAILURE.
 */
static int mode_send(const std::string& dest_ip, const std::string& message)
{
    if (message.size() > jtp::MAX_PAYLOAD) {
        std::ostringstream oss;
        oss << "Message too long (" << message.size()
            << " bytes); maximum is " << jtp::MAX_PAYLOAD << '.';
        console::error(oss.str());
        return EXIT_FAILURE;
    }

    console::info("Opening raw socket (proto=253)…");
    int fd = jtp::open_raw_socket();
    if (fd < 0) {
        std::string msg = "socket() failed: ";
        msg += std::strerror(errno);
        console::error(msg);
        return EXIT_FAILURE;
    }

    // Build header (sequence 1, MSG flag).
    jtp::Header hdr;
    hdr.sequence_number = 1;
    hdr.flags           = jtp::FLAG_MSG;
    // checksum is computed inside serialise(); payload_length set there too.

    // Convert message to byte vector.
    std::vector<uint8_t> payload(message.begin(), message.end());

    {
        std::ostringstream oss;
        oss << "Sending " << payload.size()
            << " byte(s) to " << dest_ip << " …";
        console::info(oss.str());
    }

    bool ok = jtp::send_packet(fd, dest_ip, hdr, payload);
    ::close(fd);

    if (!ok) {
        console::error("Failed to send JTP datagram.");
        return EXIT_FAILURE;
    }

    console::info("Datagram sent successfully.");
    return EXIT_SUCCESS;
}

// ─── Entry point ──────────────────────────────────────────────────────────

int main(int argc, char* argv[])
{
    // Register signal handlers so the listen loop can exit cleanly.
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Privilege gate – must be first so we fail fast with a clear message.
    require_root();

    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const std::string mode = argv[1];

    // ── --listen ──────────────────────────────────────────────────────────
    if (mode == "--listen") {
        if (argc != 2) {
            console::error("--listen takes no additional arguments.");
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        return mode_listen();
    }

    // ── --send <ip> <message> ─────────────────────────────────────────────
    if (mode == "--send") {
        if (argc != 4) {
            console::error("--send requires exactly two arguments: <dest_ip> \"<message>\".");
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        return mode_send(argv[2], argv[3]);
    }

    // ── Unknown mode ──────────────────────────────────────────────────────
    std::string msg = "Unknown mode: '";
    msg += mode;
    msg += '\'';
    console::error(msg);
    print_usage(argv[0]);
    return EXIT_FAILURE;
}
