/**
 * @file jtp.h
 * @brief Jerboa Transport Protocol v3 — public API.
 *
 * Three transport modes, large-message fragmentation, and AES-256-GCM
 * envelope encryption (pure C++17 / OpenSSL, no extra frameworks).
 *
 * ┌───────────────┬──────────────┬──────────┬────────────────────────────┐
 * │ Mode          │ Transport    │ Root     │ NAT/Internet               │
 * ├───────────────┼──────────────┼──────────┼────────────────────────────┤
 * │ RAW           │ IPv4/253     │ yes      │ LAN only                   │
 * │ UDP tunnel    │ UDP/19253    │ no       │ yes                        │
 * │ QUIC-like     │ UDP/19254    │ no       │ yes + streams + RTT        │
 * └───────────────┴──────────────┴──────────┴────────────────────────────┘
 *
 * Fragmentation
 * ─────────────
 * Messages larger than MAX_FRAG_PAYLOAD are split into numbered fragments.
 * Each fragment carries a frag_id (random 32-bit tag), frag_index, and
 * frag_total in the JTP header extension.  The receiver reassembles them
 * in memory with a configurable timeout.
 *
 * Encryption (AES-256-GCM)
 * ─────────────────────────
 * When a shared 256-bit key is configured the payload of every outgoing
 * packet is encrypted:
 *
 *   [ 12-byte nonce (random) | ciphertext | 16-byte GCM auth tag ]
 *
 * The JTP CRC-16 covers the encrypted form, so tampering is detected at
 * two layers (GCM auth tag + CRC).
 *
 * Mobile / embedded portability
 * ──────────────────────────────
 * The crypto layer depends only on OpenSSL (EVP API), which is available
 * on Linux, macOS, iOS (via CocoaPods/SPM), and Android (via the NDK
 * prebuilt libssl).  The socket layer uses POSIX BSD sockets — the same
 * API available on all four platforms.
 *
 * @version 3.0.0
 */

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// ─── Platform detection ───────────────────────────────────────────────────

#if defined(__APPLE__) && defined(__MACH__)
#   define JTP_PLATFORM_MACOS 1
#elif defined(__linux__)
#   define JTP_PLATFORM_LINUX 1
#elif defined(__ANDROID__)
#   define JTP_PLATFORM_ANDROID 1
#elif defined(__IPHONE_OS_VERSION_MIN_REQUIRED) || defined(TARGET_OS_IOS)
#   define JTP_PLATFORM_IOS 1
#else
#   error "Unsupported platform."
#endif

namespace jtp {

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

constexpr uint8_t  IP_PROTO_JTP      = 253;

// JTP base header: 7 bytes
// JTP frag extension: 9 bytes  (frag_id[4] + frag_index[2] + frag_total[2] + reserved[1])
constexpr uint16_t BASE_HEADER_SIZE  = 7;
constexpr uint16_t FRAG_EXT_SIZE     = 9;
constexpr uint16_t FULL_HEADER_SIZE  = BASE_HEADER_SIZE + FRAG_EXT_SIZE; // 16 bytes

// Safe payload per fragment (UDP MTU 1472 - FULL_HEADER_SIZE - crypto overhead)
// AES-GCM overhead = 12 (nonce) + 16 (tag) = 28 bytes
constexpr uint16_t CRYPTO_OVERHEAD   = 28;
constexpr uint16_t MAX_FRAG_PAYLOAD  = 1472 - FULL_HEADER_SIZE - CRYPTO_OVERHEAD; // 1428 B

// Maximum reassembled message (64 fragments × MAX_FRAG_PAYLOAD ≈ 91 KB)
constexpr uint16_t MAX_FRAG_COUNT    = 64;
constexpr uint32_t MAX_MSG_SIZE      = static_cast<uint32_t>(MAX_FRAG_COUNT)
                                  * MAX_FRAG_PAYLOAD; // ~91 KB

// Flags
constexpr uint8_t FLAG_MSG    = 0x01;  ///< Carries user payload
constexpr uint8_t FLAG_ACK    = 0x02;  ///< Acknowledgement
constexpr uint8_t FLAG_FIN    = 0x04;  ///< Stream end
constexpr uint8_t FLAG_RST    = 0x08;  ///< Reset
constexpr uint8_t FLAG_FRAG   = 0x10;  ///< Packet is part of a fragmented message
constexpr uint8_t FLAG_CRYPT  = 0x20;  ///< Payload is AES-256-GCM encrypted

// Ports
constexpr uint16_t UDP_TUNNEL_PORT   = 19253;
constexpr uint16_t QUIC_TUNNEL_PORT  = 19254;

// Magic prefixes (4 bytes each)
constexpr uint8_t TUNNEL_MAGIC[4] = { 'J', 'T', 'P', 0x01 };
constexpr uint8_t QUIC_MAGIC[4]   = { 'J', 'T', 'Q', 0x01 };

// Crypto
constexpr std::size_t KEY_SIZE   = 32;  ///< AES-256 key bytes
constexpr std::size_t NONCE_SIZE = 12;  ///< GCM nonce bytes
constexpr std::size_t TAG_SIZE   = 16;  ///< GCM auth tag bytes

/// Symmetric key type (256-bit / 32 bytes).
using Key = std::array<uint8_t, KEY_SIZE>;

// ═══════════════════════════════════════════════════════════════════════════
// Data structures
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief JTP base header (host byte-order).
 *
 * Serialised to 7 bytes on the wire.  Never cast directly to/from memory.
 */
struct Header {
    uint16_t sequence_number = 0;
    uint8_t  flags           = 0;
    uint16_t checksum        = 0;   ///< Set by serialise(); ignored on input
    uint16_t payload_length  = 0;   ///< Set by serialise()
};

/**
 * @brief Fragmentation extension (host byte-order).
 *
 * Present on the wire only when FLAG_FRAG is set.
 * Serialised to 9 bytes immediately after the base header.
 */
struct FragExt {
    uint32_t frag_id    = 0;  ///< Random tag tying all fragments of one message
    uint16_t frag_index = 0;  ///< Zero-based fragment index
    uint16_t frag_total = 0;  ///< Total number of fragments
    uint8_t  reserved   = 0;
};

/**
 * @brief QUIC-like stream prefix (host byte-order, 6 bytes on wire).
 */
struct QuicFrame {
    uint16_t stream_id  = 0;
    uint16_t packet_num = 0;
    uint16_t rtt_ms     = 0;
};

/**
 * @brief Fully decoded inbound JTP message (already reassembled if fragmented).
 */
struct Message {
    uint16_t             sequence_number = 0;
    uint8_t              flags           = 0;
    std::string          src_ip;
    std::vector<uint8_t> payload;         ///< Decrypted, reassembled payload
    QuicFrame            quic;            ///< Populated in QUIC mode
    bool                 is_quic         = false;
    bool                 was_encrypted   = false;
    bool                 was_fragmented  = false;
};

// ═══════════════════════════════════════════════════════════════════════════
// CRC-16 / CCITT-FALSE
// ═══════════════════════════════════════════════════════════════════════════

/** @brief CRC-16/CCITT-FALSE (poly=0x1021, init=0xFFFF). */
uint16_t crc16(const uint8_t* data, std::size_t len) noexcept;

// ═══════════════════════════════════════════════════════════════════════════
// Crypto  (AES-256-GCM via OpenSSL EVP)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Encrypt @p plaintext with AES-256-GCM.
 *
 * Output layout: [ 12-byte nonce | ciphertext | 16-byte GCM tag ]
 *
 * @param key        32-byte symmetric key.
 * @param plaintext  Data to encrypt.
 * @return           Encrypted blob, or empty on error.
 */
std::vector<uint8_t> encrypt(const Key& key,
                             const std::vector<uint8_t>& plaintext);

/**
 * @brief Decrypt and authenticate an AES-256-GCM blob.
 *
 * Expects the layout produced by @ref encrypt().
 *
 * @param key        32-byte symmetric key.
 * @param ciphertext Encrypted blob (nonce + ct + tag).
 * @return           Plaintext, or empty if authentication fails.
 */
std::vector<uint8_t> decrypt(const Key& key,
                             const std::vector<uint8_t>& ciphertext);

/**
 * @brief Derive a 256-bit key from a human-readable passphrase.
 *
 * Uses PBKDF2-HMAC-SHA256 with a fixed salt and 100 000 iterations —
 * suitable for development.  Production should use a proper key exchange.
 *
 * @param passphrase  UTF-8 passphrase.
 * @return            32-byte derived key.
 */
Key derive_key(const std::string& passphrase);

// ═══════════════════════════════════════════════════════════════════════════
// Serialisation
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Encode one JTP packet (base header [+ frag ext] + payload).
 *
 * If @p fext is non-null, FLAG_FRAG is set automatically and the 9-byte
 * fragmentation extension is appended after the base header.
 * The CRC-16 covers the entire buffer.
 */
std::vector<uint8_t> serialise(Header hdr,
                               const std::vector<uint8_t>& payload,
                               const FragExt* fext = nullptr);

/** @brief Parse base header.  Returns nullopt if buffer too short. */
std::optional<Header> deserialise_header(const std::vector<uint8_t>& buf);

/** @brief Parse frag extension (must be called only when FLAG_FRAG is set). */
std::optional<FragExt> deserialise_frag(const std::vector<uint8_t>& buf);

/** @brief Verify CRC-16 of a complete packet. */
bool verify_checksum(const std::vector<uint8_t>& buf) noexcept;

// ═══════════════════════════════════════════════════════════════════════════
// Reassembly cache
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Thread-safe in-memory fragment reassembly buffer.
 *
 * Fragments are keyed by (src_ip, frag_id).  A complete message is
 * returned as soon as all frag_total pieces arrive.  Incomplete entries
 * older than @p timeout_ms are pruned on each insert.
 */
class Reassembler {
public:
    explicit Reassembler(uint32_t timeout_ms = 5000);

    /**
     * @brief Feed one fragment.
     *
     * @param src_ip  Sender's IP (used to namespace the frag_id).
     * @param fext    Parsed fragmentation extension.
     * @param data    Fragment payload bytes.
     * @return        Reassembled message when all fragments arrived,
     *                otherwise std::nullopt.
     */
    std::optional<std::vector<uint8_t>>
    insert(const std::string& src_ip,
           const FragExt& fext,
           const std::vector<uint8_t>& data);

private:
    struct Entry {
        std::vector<std::vector<uint8_t>> fragments;
        uint16_t                          total       = 0;
        uint16_t                          received    = 0;
        std::chrono::steady_clock::time_point created;
    };

    std::map<std::pair<std::string, uint32_t>, Entry> cache_;
    std::mutex                                         mtx_;
    uint32_t                                           timeout_ms_;

    void prune_locked();
};

// ═══════════════════════════════════════════════════════════════════════════
// RAW socket transport  (root required, LAN only)
// ═══════════════════════════════════════════════════════════════════════════

/** @brief Open IPPROTO_RAW send socket (IP_HDRINCL=1). */
int open_raw_socket() noexcept;

/** @brief Open SOCK_RAW/IP_PROTO_JTP receive socket. */
int open_recv_socket() noexcept;

/**
 * @brief Send one JTP datagram (possibly a fragment) via raw IPv4.
 *
 * @param key  If non-null, payload is AES-256-GCM encrypted before send.
 */
bool send_raw(int sock_fd,
              const std::string& dest_ip,
              Header hdr,
              const std::vector<uint8_t>& payload,
              const FragExt* fext   = nullptr,
              const Key*     key    = nullptr);

/** @brief Receive one raw JTP packet.  Strips IP header. */
std::vector<uint8_t> recv_raw(int sock_fd);

// ═══════════════════════════════════════════════════════════════════════════
// UDP tunnel transport  (no root, NAT-traversal)
// ═══════════════════════════════════════════════════════════════════════════

/** @brief Open UDP socket.  Pass UDP_TUNNEL_PORT to bind (listener). */
int open_udp_socket(uint16_t bind_port = 0) noexcept;

/**
 * @brief Send one JTP-over-UDP datagram.
 *
 * @param key  If non-null, payload is encrypted before send.
 */
bool send_udp(int sock_fd,
              const std::string& dest_ip,
              Header hdr,
              const std::vector<uint8_t>& payload,
              const FragExt* fext = nullptr,
              const Key*     key  = nullptr);

/**
 * @brief Receive one JTP-over-UDP datagram.
 *
 * @param src_ip_out  If non-null, filled with sender's IP.
 * @return            Raw JTP bytes (header + payload), empty on error/magic-fail.
 */
std::vector<uint8_t> recv_udp(int sock_fd,
                              std::string* src_ip_out = nullptr);

// ═══════════════════════════════════════════════════════════════════════════
// QUIC-like tunnel transport  (no root, streams, RTT)
// ═══════════════════════════════════════════════════════════════════════════

/** @brief Open QUIC socket.  Pass QUIC_TUNNEL_PORT to bind (listener). */
int open_quic_socket(uint16_t bind_port = 0) noexcept;

/**
 * @brief Send one JTP-over-QUIC frame.
 *
 * @p qf.packet_num is auto-incremented.
 * @param key  If non-null, payload is encrypted before send.
 */
bool send_quic(int sock_fd,
               const std::string& dest_ip,
               QuicFrame& qf,
               Header hdr,
               const std::vector<uint8_t>& payload,
               const FragExt* fext = nullptr,
               const Key*     key  = nullptr);

/**
 * @brief Receive one JTP-over-QUIC frame.
 *
 * @param frame_out   If non-null, filled with the QuicFrame prefix.
 * @param src_ip_out  If non-null, filled with sender's IP.
 * @return            Raw JTP bytes, empty on error/magic-fail.
 */
std::vector<uint8_t> recv_quic(int sock_fd,
                               QuicFrame*   frame_out   = nullptr,
                               std::string* src_ip_out  = nullptr);

// ═══════════════════════════════════════════════════════════════════════════
// High-level send helper  (fragmentation + encryption in one call)
// ═══════════════════════════════════════════════════════════════════════════

/** @brief Transport selector passed to send_message() / listen(). */
enum class Transport { RAW, UDP, QUIC };

/**
 * @brief Send an arbitrarily large message, fragmenting if necessary.
 *
 * Splits @p message into fragments of at most MAX_FRAG_PAYLOAD bytes,
 * encrypts each fragment if @p key is non-null, and transmits all
 * fragments via the selected @p transport.
 *
 * @param sock_fd    Open socket (matching @p transport).
 * @param dest_ip    Destination IPv4.
 * @param message    Raw message bytes (any size up to MAX_MSG_SIZE).
 * @param transport  Which tunnel to use.
 * @param key        Optional encryption key.
 * @param qf         QUIC frame state (only used when transport==QUIC).
 * @return           @c true if all fragments were sent successfully.
 */
bool send_message(int              sock_fd,
                  const std::string& dest_ip,
                  const std::vector<uint8_t>& message,
                  Transport        transport,
                  const Key*       key = nullptr,
                  QuicFrame*       qf  = nullptr);

} // namespace jtp
