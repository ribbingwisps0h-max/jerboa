/**
 * @file JTP.h
 * @brief Jerboa Transport Protocol v2 – public API.
 *
 * JTP is a minimal experimental transport-layer protocol (IPv4 proto=253).
 * Three transport modes are provided:
 *
 *  ┌──────────────┬───────────────────────────────────────────────────────┐
 *  │ Mode         │ Description                                           │
 *  ├──────────────┼───────────────────────────────────────────────────────┤
 *  │ RAW          │ Native IPv4/proto=253. Root required. LAN only.       │
 *  │ UDP Tunnel   │ JTP inside UDP/19253.  Works through NAT / internet.  │
 *  │ QUIC-like    │ JTP inside UDP/19254 + stream-ID, packet-num, RTT.   │
 *  └──────────────┴───────────────────────────────────────────────────────┘
 *
 * JTP Wire Header (7 bytes, big-endian):
 * @code
 *  Byte  0   1     2       3   4       5   6
 *       ┌───────┬───────┬───────────┬───────────┐
 *       │ seq   │ flags │ checksum  │ pay_len   │
 *       └───────┴───────┴───────────┴───────────┘
 *        uint16   uint8   uint16      uint16
 * @endcode
 *
 * QUIC-like prefix (6 bytes, big-endian) prepended before the JTP header:
 * @code
 *  Byte  0   1     2   3     4   5
 *       ┌───────┬───────┬───────┐
 *       │stream │pkt_nr │rtt_ms │
 *       └───────┴───────┴───────┘
 *        uint16   uint16  uint16
 * @endcode
 *
 * Full QUIC-like frame on the wire:
 *   [ QUIC_MAGIC(4) | QuicFrame(6) | JTP Header(7) | Payload ]
 *
 * Full UDP tunnel frame on the wire:
 *   [ TUNNEL_MAGIC(4) | JTP Header(7) | Payload ]
 *
 * @author  Senior Network Software Engineer
 * @version 2.0.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

// ─── Platform detection ────────────────────────────────────────────────────

#if defined(__APPLE__) && defined(__MACH__)
#   define JTP_PLATFORM_MACOS 1
#elif defined(__linux__)
#   define JTP_PLATFORM_LINUX 1
#else
#   error "Unsupported platform: JTP requires macOS or Linux."
#endif

namespace jtp {

// ═══════════════════════════════════════════════════════════════════════════
// Protocol constants
// ═══════════════════════════════════════════════════════════════════════════

constexpr uint8_t  IP_PROTO_JTP      = 253;           ///< IANA experimental
constexpr uint16_t HEADER_SIZE       = 7;              ///< JTP header bytes
constexpr uint16_t QUIC_PREFIX_SIZE  = 6;              ///< QuicFrame bytes
constexpr uint16_t MAGIC_SIZE        = 4;              ///< Magic prefix bytes
constexpr uint16_t MAX_PAYLOAD       = 1472 - HEADER_SIZE; ///< UDP-safe MTU

// Flag bits
constexpr uint8_t FLAG_MSG  = 0x01;  ///< Packet carries a user payload
constexpr uint8_t FLAG_ACK  = 0x02;  ///< Acknowledgement
constexpr uint8_t FLAG_FIN  = 0x04;  ///< Stream/connection termination
constexpr uint8_t FLAG_RST  = 0x08;  ///< Reset / error

// Transport ports
constexpr uint16_t UDP_TUNNEL_PORT   = 19253; ///< JTP-over-UDP listener port
constexpr uint16_t QUIC_TUNNEL_PORT  = 19254; ///< JTP-over-QUIC listener port

// Wire magic prefixes
constexpr uint8_t TUNNEL_MAGIC[4] = { 'J', 'T', 'P', 0x01 }; ///< UDP tunnel
constexpr uint8_t QUIC_MAGIC[4]   = { 'J', 'T', 'Q', 0x01 }; ///< QUIC tunnel

// ═══════════════════════════════════════════════════════════════════════════
// Data structures
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief JTP header in host byte-order.
 *
 * Never written directly to the wire — use serialise() / deserialise().
 * The @c checksum and @c payload_length fields are filled by serialise();
 * callers only need to set @c sequence_number and @c flags.
 */
struct Header {
    uint16_t sequence_number = 0;
    uint8_t  flags           = 0;
    uint16_t checksum        = 0;
    uint16_t payload_length  = 0;
};

/**
 * @brief QUIC-like stream prefix (host byte-order).
 *
 * Provides stream multiplexing, per-stream packet ordering, and a simple
 * RTT field populated by the receiver's ACK path.
 */
struct QuicFrame {
    uint16_t stream_id  = 0;  ///< Logical stream (0 = default/unidirectional)
    uint16_t packet_num = 0;  ///< Monotonically increasing per stream
    uint16_t rtt_ms     = 0;  ///< Last measured RTT in ms (0 = not yet known)
};

/**
 * @brief Fully decoded inbound JTP packet (any transport).
 */
struct Packet {
    Header               header;
    QuicFrame            quic;       ///< Populated only in QUIC mode
    std::string          src_ip;     ///< Sender's dotted-decimal IPv4 address
    std::vector<uint8_t> payload;
    bool                 is_quic = false;
};

// ═══════════════════════════════════════════════════════════════════════════
// CRC-16 checksum
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief CRC-16/CCITT-FALSE over an arbitrary byte range.
 *
 * Polynomial 0x1021, initial value 0xFFFF, no input/output reflection,
 * no final XOR.
 *
 * @param data  First byte of input.
 * @param len   Number of bytes to process.
 * @return      16-bit CRC.
 */
uint16_t crc16(const uint8_t* data, std::size_t len) noexcept;

// ═══════════════════════════════════════════════════════════════════════════
// Serialisation / deserialisation
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Encode a JTP header + payload into a network-ready byte vector.
 *
 * Overwrites @p hdr.payload_length with @c payload.size(), zeroes the
 * checksum field, computes CRC-16 over the whole buffer, and embeds the
 * result.
 *
 * @param hdr      Header to serialise (checksum field is ignored).
 * @param payload  Raw payload bytes.
 * @return         Complete JTP packet ready for transmission.
 */
std::vector<uint8_t> serialise(Header hdr,
                               const std::vector<uint8_t>& payload);

/**
 * @brief Decode a JTP header from raw bytes (no checksum verification).
 *
 * @param buf  Bytes starting at the JTP header.
 * @return     Parsed Header, or std::nullopt if the buffer is too short.
 */
std::optional<Header> deserialise(const std::vector<uint8_t>& buf);

/**
 * @brief Verify the CRC-16 embedded in a complete JTP packet.
 *
 * Zeroes the checksum bytes in a local copy, recomputes CRC-16, and
 * compares against the stored value.
 *
 * @param buf  Complete JTP packet bytes (header + payload).
 * @return     @c true if the checksum is valid.
 */
bool verify_checksum(const std::vector<uint8_t>& buf) noexcept;

// ═══════════════════════════════════════════════════════════════════════════
// RAW socket transport  (requires root, same L2 network only)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Open IPPROTO_RAW send socket with IP_HDRINCL=1.
 *
 * We use IPPROTO_RAW (not IP_PROTO_JTP) because it guarantees the kernel
 * will inject our pre-built datagram verbatim to the NIC, without dropping
 * packets whose protocol number it does not recognise.  IP_HDRINCL=1 lets
 * us supply the complete IP header ourselves.
 *
 * @return fd on success, -1 on failure (errno set).
 */
int open_raw_socket() noexcept;

/**
 * @brief Open SOCK_RAW/IP_PROTO_JTP receive-only socket.
 *
 * On Linux IPPROTO_RAW is send-only by kernel design; a separate socket
 * with IP_PROTO_JTP is needed to receive incoming proto=253 datagrams.
 *
 * @return fd on success, -1 on failure (errno set).
 */
int open_recv_socket() noexcept;

/**
 * @brief Send one JTP datagram via raw socket.
 *
 * Builds the 20-byte IPv4 header (proto=253) and full JTP packet, then
 * injects via @p sock_fd (must be from open_raw_socket()).
 *
 * @param sock_fd   Send socket from open_raw_socket().
 * @param dest_ip   Dotted-decimal destination IPv4.
 * @param hdr       JTP header (sequence_number, flags must be set).
 * @param payload   Payload bytes.
 * @return          @c true on success.
 */
bool send_packet(int sock_fd,
                 const std::string& dest_ip,
                 Header hdr,
                 const std::vector<uint8_t>& payload);

/**
 * @brief Receive one JTP datagram from a raw socket.
 *
 * Blocks until a packet arrives.  Strips the IP header.  Returns an empty
 * vector for non-JTP packets (caller should retry).
 *
 * @param sock_fd  Receive socket from open_recv_socket().
 * @return         Raw JTP bytes (header + payload), or empty on error/filter.
 */
std::vector<uint8_t> receive_packet(int sock_fd);

// ═══════════════════════════════════════════════════════════════════════════
// UDP tunnel transport  (NAT-traversal, no root required)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Open a UDP socket for the JTP-over-UDP tunnel.
 *
 * @param bind_port  Non-zero → bind to this port (use UDP_TUNNEL_PORT for
 *                   the listener).  Zero → ephemeral source port (sender).
 * @return           fd on success, -1 on failure.
 */
int open_udp_socket(uint16_t bind_port = 0) noexcept;

/**
 * @brief Send a JTP datagram tunnelled inside UDP.
 *
 * Wire layout of the UDP payload:
 *   [ TUNNEL_MAGIC(4) | JTP header(7) | payload ]
 *
 * @param sock_fd   Socket from open_udp_socket().
 * @param dest_ip   Destination IPv4 (dotted-decimal).
 * @param hdr       JTP header.
 * @param payload   Payload bytes.
 * @return          @c true on success.
 */
bool udp_send(int sock_fd,
              const std::string& dest_ip,
              Header hdr,
              const std::vector<uint8_t>& payload);

/**
 * @brief Receive one JTP-over-UDP datagram.
 *
 * Discards UDP datagrams that do not start with TUNNEL_MAGIC.
 *
 * @param sock_fd      Bound UDP socket from open_udp_socket().
 * @param src_ip_out   If non-null, filled with sender's IP.
 * @return             Raw JTP bytes (header + payload), or empty on
 *                     error / bad magic (caller should retry).
 */
std::vector<uint8_t> udp_receive(int sock_fd,
                                 std::string* src_ip_out = nullptr);

// ═══════════════════════════════════════════════════════════════════════════
// QUIC-like tunnel transport  (streams, ordering, RTT, no root required)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Open a UDP socket for the JTP-over-QUIC tunnel.
 *
 * @param bind_port  Non-zero → bind to QUIC_TUNNEL_PORT (listener).
 *                   Zero    → ephemeral source port (sender).
 * @return           fd on success, -1 on failure.
 */
int open_quic_socket(uint16_t bind_port = 0) noexcept;

/**
 * @brief Send a JTP datagram in a QUIC-like frame.
 *
 * Wire layout of the UDP payload:
 *   [ QUIC_MAGIC(4) | QuicFrame(6) | JTP header(7) | payload ]
 *
 * @p qf.packet_num is auto-incremented before transmission.
 *
 * @param sock_fd   Socket from open_quic_socket().
 * @param dest_ip   Destination IPv4 (dotted-decimal).
 * @param qf        QUIC frame state (stream_id, packet_num, rtt_ms).
 *                  packet_num is incremented in-place.
 * @param hdr       JTP header.
 * @param payload   Payload bytes.
 * @return          @c true on success.
 */
bool quic_send(int sock_fd,
               const std::string& dest_ip,
               QuicFrame& qf,
               Header hdr,
               const std::vector<uint8_t>& payload);

/**
 * @brief Receive one JTP-over-QUIC frame.
 *
 * Validates QUIC_MAGIC and deserialises the QuicFrame prefix.
 *
 * @param sock_fd       Bound QUIC socket from open_quic_socket().
 * @param frame_out     If non-null, filled with the parsed QuicFrame.
 * @param src_ip_out    If non-null, filled with sender's IP.
 * @return              Raw JTP bytes (header + payload), or empty on
 *                      error / bad magic (caller should retry).
 */
std::vector<uint8_t> quic_receive(int sock_fd,
                                  QuicFrame*   frame_out    = nullptr,
                                  std::string* src_ip_out   = nullptr);

} // namespace jtp
