/**
 * @file main.cpp
 * @brief Jerboa Transport Protocol v3 — CLI.
 *
 * ┌─────────────────┬──────────────────────────────────────────────────────┐
 * │ Mode            │ Command                                              │
 * ├─────────────────┼──────────────────────────────────────────────────────┤
 * │ RAW listen      │ sudo ./jtp --listen          [--key <passphrase>]    │
 * │ RAW send        │ sudo ./jtp --send   <ip> <msg> [--key <passphrase>]  │
 * │ UDP listen      │      ./jtp --listen-udp      [--key <passphrase>]    │
 * │ UDP send        │      ./jtp --send-udp  <ip> <msg> [--key ...]        │
 * │ QUIC listen     │      ./jtp --listen-quic     [--key <passphrase>]    │
 * │ QUIC send       │      ./jtp --send-quic <ip> <msg> [--sid N] [--key] │
 * └─────────────────┴──────────────────────────────────────────────────────┘
 *
 * Ctrl-C fix
 * ──────────
 * On both macOS and Linux recvfrom() blocks indefinitely even after a signal
 * is delivered, because the kernel restarts interrupted syscalls (SA_RESTART).
 * The fix is to set SO_RCVTIMEO = 1 s on every socket so recvfrom wakes up
 * periodically and the loop checks g_running.  SIGINT/SIGTERM use sigaction
 * with SA_RESTART *disabled* (sa_flags = 0) so the timeout fires immediately
 * on the first Ctrl-C.
 */

#include "jtp.h"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <atomic>

#include <unistd.h>
#include <sys/socket.h>

// ═══════════════════════════════════════════════════════════════════════════
// Thread-safe console
// ═══════════════════════════════════════════════════════════════════════════

namespace console {

static std::mutex g_mtx;

void info (const std::string& m) {
    std::lock_guard<std::mutex> lk(g_mtx);
    std::cout << "[INFO]  " << m << '\n' << std::flush;
}
void error(const std::string& m) {
    std::lock_guard<std::mutex> lk(g_mtx);
    std::cerr << "[ERROR] " << m << '\n' << std::flush;
}
void recv_print(const std::string& transport,
                const std::string& src,
                uint16_t seq, uint8_t flags,
                const std::string& payload,
                bool encrypted, bool fragmented,
                const jtp::QuicFrame* qf = nullptr)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    std::cout << "[RECV/" << transport << "]"
              << " from="  << (src.empty() ? "?" : src)
              << " seq="   << seq
              << " flags=0x" << std::hex << static_cast<int>(flags) << std::dec;
    if (encrypted)  std::cout << " [ENC]";
    if (fragmented) std::cout << " [FRAG]";
    if (qf)
        std::cout << " stream=" << qf->stream_id
                  << " pkt#"   << qf->packet_num;
    std::cout << "\n  payload: \"" << payload << "\"\n" << std::flush;
}

} // namespace console

// ═══════════════════════════════════════════════════════════════════════════
// Signal handling — Ctrl-C fix
// ═══════════════════════════════════════════════════════════════════════════

static std::atomic<bool> g_running{true};

static void install_signal_handlers()
{
    struct sigaction sa{};
    sa.sa_handler = [](int) noexcept {
        g_running.store(false, std::memory_order_relaxed);
    };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // ← SA_RESTART explicitly NOT set — this is the fix
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════
// Privilege check
// ═══════════════════════════════════════════════════════════════════════════

static void require_root(const std::string& mode)
{
    if (::geteuid() != 0) {
        console::error("Mode '" + mode + "' requires root. Re-run: sudo ./jtp " + mode);
        std::exit(EXIT_FAILURE);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Argument parsing helpers
// ═══════════════════════════════════════════════════════════════════════════

struct Args {
    std::string              mode;
    std::string              dest_ip;
    std::string              message;
    std::optional<jtp::Key>  key;
    uint16_t                 stream_id = 0;
};

static std::optional<jtp::Key> parse_key(int argc, char* argv[])
{
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--key") {
            return jtp::derive_key(argv[i + 1]);
        }
    }
    return std::nullopt;
}

static uint16_t parse_sid(int argc, char* argv[])
{
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--sid") {
            int v = std::atoi(argv[i + 1]);
            return (v >= 0 && v <= 65535) ? static_cast<uint16_t>(v) : 0;
        }
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared receive/reassemble logic
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Process one raw JTP packet buffer.
 *
 * Verifies checksum, decrypts if needed, feeds the reassembler if
 * fragmented, and prints the message when complete.
 *
 * @return true  if a complete message was printed.
 */
static bool process_packet(const std::vector<uint8_t>& raw,
                           const std::string&           transport,
                           const std::string&           src_ip,
                           const std::optional<jtp::Key>& key,
                           jtp::Reassembler&            reassembler,
                           const jtp::QuicFrame*        qf = nullptr)
{
    if (raw.empty()) return false;

    if (!jtp::verify_checksum(raw)) {
        console::error("CRC mismatch — discarded.");
        return false;
    }

    auto hdr_opt = jtp::deserialise_header(raw);
    if (!hdr_opt) { console::error("Truncated header — discarded."); return false; }
    const jtp::Header& hdr = *hdr_opt;

    // Determine payload offset (base header [+ frag extension])
    const bool has_frag = (hdr.flags & jtp::FLAG_FRAG) != 0;
    const std::size_t payload_offset = jtp::BASE_HEADER_SIZE +
                                       (has_frag ? jtp::FRAG_EXT_SIZE : 0);

    if (raw.size() < payload_offset + hdr.payload_length) {
        console::error("Payload truncated — discarded.");
        return false;
    }

    std::vector<uint8_t> payload(
        raw.begin() + static_cast<ptrdiff_t>(payload_offset),
        raw.begin() + static_cast<ptrdiff_t>(payload_offset + hdr.payload_length));

    // Decrypt if FLAG_CRYPT is set
    bool was_encrypted = false;
    if (hdr.flags & jtp::FLAG_CRYPT) {
        if (!key) {
            console::error("Packet is encrypted but no --key provided.");
            return false;
        }
        payload = jtp::decrypt(*key, payload);
        if (payload.empty()) {
            console::error("Decryption / auth-tag verification failed — discarded.");
            return false;
        }
        was_encrypted = true;
    }

    // Reassemble fragments if needed
    std::vector<uint8_t> message;
    bool was_fragmented = false;

    if (has_frag) {
        auto fext_opt = jtp::deserialise_frag(raw);
        if (!fext_opt) { console::error("Bad frag header — discarded."); return false; }
        was_fragmented = true;

        auto complete = reassembler.insert(src_ip, *fext_opt, payload);
        if (!complete) return false;  // waiting for more fragments
        message = std::move(*complete);
    } else {
        message = std::move(payload);
    }

    std::string text(reinterpret_cast<const char*>(message.data()), message.size());
    console::recv_print(transport, src_ip,
                        hdr.sequence_number, hdr.flags,
                        text, was_encrypted, was_fragmented, qf);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// Listen modes
// ═══════════════════════════════════════════════════════════════════════════

static int listen_raw(const std::optional<jtp::Key>& key)
{
    require_root("--listen");
    console::info("RAW listener starting (proto=253)…");
    int fd = jtp::open_recv_socket();
    if (fd < 0) { console::error("open_recv_socket failed"); return EXIT_FAILURE; }

    jtp::Reassembler reassembler;
    console::info("Listening… press Ctrl-C to stop.");

    while (g_running) {
        auto raw = jtp::recv_raw(fd);
        if (raw.empty()) continue;
        process_packet(raw, "RAW", "", key, reassembler);
    }

    ::close(fd);
    console::info("RAW listener stopped.");
    return EXIT_SUCCESS;
}

static int listen_udp(const std::optional<jtp::Key>& key)
{
    console::info("UDP tunnel listener on port " +
                  std::to_string(jtp::UDP_TUNNEL_PORT) + "…");
    int fd = jtp::open_udp_socket(jtp::UDP_TUNNEL_PORT);
    if (fd < 0) { console::error("open_udp_socket failed"); return EXIT_FAILURE; }

    jtp::Reassembler reassembler;
    console::info("Listening… press Ctrl-C to stop.");

    while (g_running) {
        std::string src;
        auto raw = jtp::recv_udp(fd, &src);
        if (raw.empty()) continue;   // timeout or bad magic — retry
        process_packet(raw, "UDP", src, key, reassembler);
    }

    ::close(fd);
    console::info("UDP listener stopped.");
    return EXIT_SUCCESS;
}

static int listen_quic(const std::optional<jtp::Key>& key)
{
    console::info("QUIC tunnel listener on port " +
                  std::to_string(jtp::QUIC_TUNNEL_PORT) + "…");
    int fd = jtp::open_quic_socket(jtp::QUIC_TUNNEL_PORT);
    if (fd < 0) { console::error("open_quic_socket failed"); return EXIT_FAILURE; }

    jtp::Reassembler reassembler;
    console::info("Listening… press Ctrl-C to stop.");

    while (g_running) {
        std::string src;
        jtp::QuicFrame qf;
        auto raw = jtp::recv_quic(fd, &qf, &src);
        if (raw.empty()) continue;
        process_packet(raw, "QUIC", src, key, reassembler, &qf);
    }

    ::close(fd);
    console::info("QUIC listener stopped.");
    return EXIT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════════
// Send modes
// ═══════════════════════════════════════════════════════════════════════════

static int do_send(const std::string& dest_ip,
                   const std::string& message,
                   jtp::Transport     transport,
                   const std::optional<jtp::Key>& key,
                   uint16_t stream_id = 0)
{
    if (transport == jtp::Transport::RAW) require_root("--send");

    const std::vector<uint8_t> payload(message.begin(), message.end());

    if (payload.size() > jtp::MAX_MSG_SIZE) {
        console::error("Message exceeds maximum size of " +
                       std::to_string(jtp::MAX_MSG_SIZE) + " bytes.");
        return EXIT_FAILURE;
    }

    std::string tag;
    int fd = -1;
    jtp::QuicFrame qf; qf.stream_id = stream_id;

    switch (transport) {
    case jtp::Transport::RAW:
        tag = "RAW";    fd = jtp::open_raw_socket();  break;
    case jtp::Transport::UDP:
        tag = "UDP";    fd = jtp::open_udp_socket(0); break;
    case jtp::Transport::QUIC:
        tag = "QUIC";   fd = jtp::open_quic_socket(0); break;
    }

    if (fd < 0) { console::error("Failed to open socket."); return EXIT_FAILURE; }

    const bool fragmented = payload.size() > jtp::MAX_FRAG_PAYLOAD;
    std::string info = tag + " send → " + dest_ip +
                       " (" + std::to_string(payload.size()) + " bytes";
    if (key)        info += ", encrypted";
    if (fragmented) info += ", fragmented";
    info += ")…";
    console::info(info);

    const jtp::Key* kp = key ? &(*key) : nullptr;
    jtp::QuicFrame* qfp = (transport == jtp::Transport::QUIC) ? &qf : nullptr;

    bool ok = jtp::send_message(fd, dest_ip, payload, transport, kp, qfp);
    ::close(fd);

    if (!ok) { console::error("Send failed."); return EXIT_FAILURE; }
    console::info("Message sent successfully.");
    return EXIT_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════════
// Usage
// ═══════════════════════════════════════════════════════════════════════════

static void print_usage(const char* prog)
{
    std::cout <<
        "\nJerboa Transport Protocol (JTP) v3\n"
        "===================================\n\n"
        "RAW  (same LAN, root required):\n"
        "  sudo " << prog << " --listen              [--key <pass>]\n"
                         "  sudo " << prog << " --send <ip> <msg>     [--key <pass>]\n\n"
                         "UDP tunnel  (NAT / internet, no root):\n"
                         "       " << prog << " --listen-udp          [--key <pass>]\n"
                         "       " << prog << " --send-udp <ip> <msg> [--key <pass>]\n\n"
                         "QUIC-like tunnel  (streams + RTT, no root):\n"
                         "       " << prog << " --listen-quic              [--key <pass>]\n"
                         "       " << prog << " --send-quic <ip> <msg>     [--sid N] [--key <pass>]\n\n"
                         "Options:\n"
                         "  --key <passphrase>   Enable AES-256-GCM encryption (both ends must match)\n"
                         "  --sid <N>            QUIC stream ID 0-65535 (default: 0)\n\n"
                         "Ports:  UDP 19253  |  QUIC 19254\n\n"
                         "Large messages are automatically fragmented and reassembled.\n"
                         "Max message size: ~91 KB (" << jtp::MAX_MSG_SIZE << " bytes)\n\n"
                                      "Examples:\n"
                                      "  ./jtp --send-udp 1.2.3.4 \"hello\"\n"
                                      "  ./jtp --send-udp 1.2.3.4 \"$(cat bigfile.txt)\" --key mysecret\n"
                                      "  ./jtp --listen-udp --key mysecret\n\n";
}

// ═══════════════════════════════════════════════════════════════════════════
// main
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[])
{
    install_signal_handlers();   // Ctrl-C fix: no SA_RESTART + SO_RCVTIMEO

    if (argc < 2) { print_usage(argv[0]); return EXIT_FAILURE; }

    const std::string mode     = argv[1];
    auto              key_opt  = parse_key(argc, argv);
    uint16_t          sid      = parse_sid(argc, argv);

    if (key_opt)
        console::info("Encryption: AES-256-GCM (key derived from passphrase)");

    // ── Listen modes ──────────────────────────────────────────────────────
    if (mode == "--listen")      return listen_raw (key_opt);
    if (mode == "--listen-udp")  return listen_udp (key_opt);
    if (mode == "--listen-quic") return listen_quic(key_opt);

    // ── Send modes ────────────────────────────────────────────────────────
    if (mode == "--send" || mode == "--send-udp" || mode == "--send-quic") {
        if (argc < 4) {
            console::error("Usage: " + mode + " <dest_ip> \"<message>\" [options]");
            return EXIT_FAILURE;
        }
        const std::string ip  = argv[2];
        const std::string msg = argv[3];

        jtp::Transport tr = jtp::Transport::UDP;
        if (mode == "--send")      tr = jtp::Transport::RAW;
        if (mode == "--send-quic") tr = jtp::Transport::QUIC;

        return do_send(ip, msg, tr, key_opt, sid);
    }

    console::error("Unknown mode: '" + mode + "'");
    print_usage(argv[0]);
    return EXIT_FAILURE;
}
