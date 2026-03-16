/**
 * @file main.cpp
 * @brief Jerboa Transport Protocol v2 – command-line interface.
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │  Mode              │ Command                                         │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │  RAW listen        │ sudo ./jtp --listen                             │
 * │  RAW send          │ sudo ./jtp --send <ip> "<msg>"                  │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │  UDP listen        │      ./jtp --listen-udp                         │
 * │  UDP send          │      ./jtp --send-udp  <ip> "<msg>"             │
 * ├──────────────────────────────────────────────────────────────────────┤
 * │  QUIC listen       │      ./jtp --listen-quic                        │
 * │  QUIC send         │      ./jtp --send-quic <ip> "<msg>" [stream_id] │
 * └──────────────────────────────────────────────────────────────────────┘
 *
 * Qt Creator "Run as sudo" setup:
 *   Projects → Run → Custom Executable
 *   Executable : /usr/bin/sudo
 *   Arguments  : %{buildDir}/jtp --listen
 */

#include "jtp.h"

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
#include <unistd.h>
#include <sys/socket.h>

// ═══════════════════════════════════════════════════════════════════════════
// Thread-safe console
// ═══════════════════════════════════════════════════════════════════════════

namespace console {

static std::mutex g_mtx;

static void print(std::ostream& os, std::string_view tag, std::string_view msg)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    os << tag << msg << '\n';
}

void info (std::string_view m) { print(std::cout, "[INFO]  ", m); }
void error(std::string_view m) { print(std::cerr, "[ERROR] ", m); }
void warn (std::string_view m) { print(std::cout, "[WARN]  ", m); }

void received(std::string_view transport,
              const std::string& src_ip,
              uint16_t seq, uint8_t flags,
              std::string_view payload,
              const jtp::QuicFrame* qf = nullptr)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    std::cout << "[RECV/" << transport << ']'
              << " from=" << (src_ip.empty() ? "?" : src_ip)
              << " seq="  << seq
              << " flags=0x" << std::hex << static_cast<int>(flags) << std::dec;
    if (qf)
        std::cout << " stream=" << qf->stream_id
                  << " pkt#"   << qf->packet_num
                  << " rtt="   << qf->rtt_ms << "ms";
    std::cout << " payload=\"" << payload << "\"\n";
}

} // namespace console

// ═══════════════════════════════════════════════════════════════════════════
// Signal / shutdown
// ═══════════════════════════════════════════════════════════════════════════

static std::atomic<bool> g_running{true};
static void sig_handler(int) noexcept
{
    g_running.store(false, std::memory_order_relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Privilege check  (RAW only)
// ═══════════════════════════════════════════════════════════════════════════

static void require_root(std::string_view mode)
{
    if (::geteuid() != 0) {
        std::string msg = "Mode '";
        msg += mode;
        msg += "' requires root privileges. Re-run with: sudo ./jtp ";
        msg += mode;
        console::error(msg);
        std::exit(EXIT_FAILURE);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Usage
// ═══════════════════════════════════════════════════════════════════════════

static void print_usage(const char* prog)
{
    std::cout <<
        R"(
Jerboa Transport Protocol (JTP) v2
IP protocol number: 253  |  Experimental (RFC 3692)

Usage:
  RAW socket  (same LAN, root required):
    sudo )" << prog << R"( --listen
    sudo )" << prog << R"( --send       <dest_ip> "<message>"

  UDP tunnel  (works through NAT / internet, no root):
       )" << prog << R"( --listen-udp
       )" << prog << R"( --send-udp    <dest_ip> "<message>"

  QUIC-like tunnel  (streams + RTT, no root):
       )" << prog << R"( --listen-quic
       )" << prog << R"( --send-quic   <dest_ip> "<message>" [stream_id]

Transport comparison:
  --send       RAW IPv4/proto=253  — fastest, LAN only, needs root
  --send-udp   JTP inside UDP      — works through home routers / internet
  --send-quic  JTP inside UDP+QUIC — stream multiplexing, packet ordering, RTT

Ports:
  UDP  tunnel: 19253/udp
  QUIC tunnel: 19254/udp

Examples:
  sudo )" << prog << R"( --listen
  sudo )" << prog << R"( --send 192.168.1.10 "hello LAN"

       )" << prog << R"( --listen-udp
       )" << prog << R"( --send-udp  203.0.113.5 "hello internet"

       )" << prog << R"( --listen-quic
       )" << prog << R"( --send-quic 203.0.113.5 "stream message" 42

)" ;
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared receive loop (UDP + QUIC modes)
// ═══════════════════════════════════════════════════════════════════════════

/// Decode a raw JTP buffer into a Packet and print it.
static bool decode_and_print(const std::vector<uint8_t>& raw,
                             std::string_view transport,
                             const std::string& src_ip,
                             const jtp::QuicFrame* qf)
{
    if (raw.empty()) return false;

    if (!jtp::verify_checksum(raw)) {
        console::error("Checksum mismatch — packet discarded.");
        return false;
    }

    auto hdr_opt = jtp::deserialise(raw);
    if (!hdr_opt) {
        console::error("Truncated JTP header — packet discarded.");
        return false;
    }

    const jtp::Header& hdr = *hdr_opt;
    std::size_t expected = jtp::HEADER_SIZE + hdr.payload_length;
    if (raw.size() < expected) {
        console::error("Payload shorter than header claims — discarded.");
        return false;
    }

    std::string payload(
        reinterpret_cast<const char*>(raw.data() + jtp::HEADER_SIZE),
        hdr.payload_length);

    console::received(transport, src_ip,
                      hdr.sequence_number, hdr.flags, payload, qf);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Mode implementations
// ═══════════════════════════════════════════════════════════════════════════

// ── RAW listen ────────────────────────────────────────────────────────────
static int mode_listen_raw()
{
    require_root("--listen");
    console::info("RAW listener — opening proto=253 socket…");

    int fd = jtp::open_recv_socket();
    if (fd < 0) {
        console::error(std::string("open_recv_socket: ") + std::strerror(errno));
        return EXIT_FAILURE;
    }
    console::info("Listening for JTP/proto=253 datagrams (Ctrl-C to stop)…");

    while (g_running) {
        auto raw = jtp::receive_packet(fd);
        if (raw.empty()) {
            if (errno == EINTR) break;
            continue;
        }
        decode_and_print(raw, "RAW", "", nullptr);
    }

    ::close(fd);
    console::info("RAW listener stopped.");
    return EXIT_SUCCESS;
}

// ── RAW send ──────────────────────────────────────────────────────────────
static int mode_send_raw(const std::string& dest_ip,
                         const std::string& message)
{
    require_root("--send");
    if (message.size() > jtp::MAX_PAYLOAD) {
        console::error("Message too long for a single JTP datagram.");
        return EXIT_FAILURE;
    }

    int fd = jtp::open_raw_socket();
    if (fd < 0) {
        console::error(std::string("open_raw_socket: ") + std::strerror(errno));
        return EXIT_FAILURE;
    }

    jtp::Header hdr;
    hdr.sequence_number = 1;
    hdr.flags           = jtp::FLAG_MSG;
    std::vector<uint8_t> payload(message.begin(), message.end());

    console::info("RAW send → " + dest_ip + " (" +
                  std::to_string(payload.size()) + " bytes)…");

    bool ok = jtp::send_packet(fd, dest_ip, hdr, payload);
    ::close(fd);

    if (!ok) { console::error("send_packet failed."); return EXIT_FAILURE; }
    console::info("RAW datagram sent.");
    return EXIT_SUCCESS;
}

// ── UDP listen ────────────────────────────────────────────────────────────
static int mode_listen_udp()
{
    console::info("UDP tunnel listener — binding to port " +
                  std::to_string(jtp::UDP_TUNNEL_PORT) + "…");

    int fd = jtp::open_udp_socket(jtp::UDP_TUNNEL_PORT);
    if (fd < 0) {
        console::error(std::string("open_udp_socket: ") + std::strerror(errno));
        return EXIT_FAILURE;
    }
    console::info("Listening for JTP-over-UDP datagrams (Ctrl-C to stop)…");

    while (g_running) {
        std::string src_ip;
        auto raw = jtp::udp_receive(fd, &src_ip);
        if (raw.empty()) {
            if (errno == EINTR) break;
            continue;  // bad magic or transient error — retry
        }
        decode_and_print(raw, "UDP", src_ip, nullptr);
    }

    ::close(fd);
    console::info("UDP listener stopped.");
    return EXIT_SUCCESS;
}

// ── UDP send ──────────────────────────────────────────────────────────────
static int mode_send_udp(const std::string& dest_ip,
                         const std::string& message)
{
    if (message.size() > jtp::MAX_PAYLOAD) {
        console::error("Message too long for a single JTP datagram.");
        return EXIT_FAILURE;
    }

    int fd = jtp::open_udp_socket(0);   // ephemeral source port
    if (fd < 0) {
        console::error(std::string("open_udp_socket: ") + std::strerror(errno));
        return EXIT_FAILURE;
    }

    jtp::Header hdr;
    hdr.sequence_number = 1;
    hdr.flags           = jtp::FLAG_MSG;
    std::vector<uint8_t> payload(message.begin(), message.end());

    console::info("UDP send → " + dest_ip + ':' +
                  std::to_string(jtp::UDP_TUNNEL_PORT) +
                  " (" + std::to_string(payload.size()) + " bytes)…");

    bool ok = jtp::udp_send(fd, dest_ip, hdr, payload);
    ::close(fd);

    if (!ok) { console::error("udp_send failed."); return EXIT_FAILURE; }
    console::info("UDP datagram sent.");
    return EXIT_SUCCESS;
}

// ── QUIC listen ───────────────────────────────────────────────────────────
static int mode_listen_quic()
{
    console::info("QUIC tunnel listener — binding to port " +
                  std::to_string(jtp::QUIC_TUNNEL_PORT) + "…");

    int fd = jtp::open_quic_socket(jtp::QUIC_TUNNEL_PORT);
    if (fd < 0) {
        console::error(std::string("open_quic_socket: ") + std::strerror(errno));
        return EXIT_FAILURE;
    }
    console::info("Listening for JTP-over-QUIC frames (Ctrl-C to stop)…");

    while (g_running) {
        std::string src_ip;
        jtp::QuicFrame qf;
        auto raw = jtp::quic_receive(fd, &qf, &src_ip);
        if (raw.empty()) {
            if (errno == EINTR) break;
            continue;
        }
        decode_and_print(raw, "QUIC", src_ip, &qf);
    }

    ::close(fd);
    console::info("QUIC listener stopped.");
    return EXIT_SUCCESS;
}

// ── QUIC send ─────────────────────────────────────────────────────────────
static int mode_send_quic(const std::string& dest_ip,
                          const std::string& message,
                          uint16_t stream_id)
{
    if (message.size() > jtp::MAX_PAYLOAD) {
        console::error("Message too long for a single JTP datagram.");
        return EXIT_FAILURE;
    }

    int fd = jtp::open_quic_socket(0);  // ephemeral source port
    if (fd < 0) {
        console::error(std::string("open_quic_socket: ") + std::strerror(errno));
        return EXIT_FAILURE;
    }

    jtp::Header hdr;
    hdr.sequence_number = 1;
    hdr.flags           = jtp::FLAG_MSG;

    jtp::QuicFrame qf;
    qf.stream_id  = stream_id;
    qf.packet_num = 0;  // incremented inside quic_send
    qf.rtt_ms     = 0;

    std::vector<uint8_t> payload(message.begin(), message.end());

    console::info("QUIC send → " + dest_ip + ':' +
                  std::to_string(jtp::QUIC_TUNNEL_PORT) +
                  " stream=" + std::to_string(stream_id) +
                  " (" + std::to_string(payload.size()) + " bytes)…");

    bool ok = jtp::quic_send(fd, dest_ip, qf, hdr, payload);
    ::close(fd);

    if (!ok) { console::error("quic_send failed."); return EXIT_FAILURE; }
    console::info("QUIC frame sent.");
    return EXIT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[])
{
    std::signal(SIGINT,  sig_handler);
    std::signal(SIGTERM, sig_handler);

    if (argc < 2) { print_usage(argv[0]); return EXIT_FAILURE; }

    const std::string mode = argv[1];

    // ── RAW ───────────────────────────────────────────────────────────────
    if (mode == "--listen") {
        if (argc != 2) {
            console::error("--listen takes no arguments.");
            return EXIT_FAILURE;
        }
        return mode_listen_raw();
    }

    if (mode == "--send") {
        if (argc != 4) {
            console::error("Usage: --send <dest_ip> \"<message>\"");
            return EXIT_FAILURE;
        }
        return mode_send_raw(argv[2], argv[3]);
    }

    // ── UDP tunnel ────────────────────────────────────────────────────────
    if (mode == "--listen-udp") {
        if (argc != 2) {
            console::error("--listen-udp takes no arguments.");
            return EXIT_FAILURE;
        }
        return mode_listen_udp();
    }

    if (mode == "--send-udp") {
        if (argc != 4) {
            console::error("Usage: --send-udp <dest_ip> \"<message>\"");
            return EXIT_FAILURE;
        }
        return mode_send_udp(argv[2], argv[3]);
    }

    // ── QUIC tunnel ───────────────────────────────────────────────────────
    if (mode == "--listen-quic") {
        if (argc != 2) {
            console::error("--listen-quic takes no arguments.");
            return EXIT_FAILURE;
        }
        return mode_listen_quic();
    }

    if (mode == "--send-quic") {
        if (argc < 4 || argc > 5) {
            console::error("Usage: --send-quic <dest_ip> \"<message>\" [stream_id]");
            return EXIT_FAILURE;
        }
        uint16_t stream_id = 0;
        if (argc == 5) {
            int sid = std::atoi(argv[4]);
            if (sid < 0 || sid > 65535) {
                console::error("stream_id must be 0–65535.");
                return EXIT_FAILURE;
            }
            stream_id = static_cast<uint16_t>(sid);
        }
        return mode_send_quic(argv[2], argv[3], stream_id);
    }

    // ── Unknown ───────────────────────────────────────────────────────────
    console::error(std::string("Unknown mode: '") + mode + '\'');
    print_usage(argv[0]);
    return EXIT_FAILURE;
}
