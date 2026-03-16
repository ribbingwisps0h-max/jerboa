/**
 * @file JTP.h
 * @brief Jerboa Transport Protocol – header definitions and core API.
 *
 * JTP is a minimal experimental transport-layer protocol carried directly
 * over IPv4 (IP protocol number 253, reserved for experimentation per
 * RFC 3692).  It provides sequenced, checksummed datagrams without
 * connection state.
 *
 * Wire layout of the JTP header (7 bytes, network byte-order):
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Sequence Number        |     Flags     |   (checksum   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
 * |    continued)                 |       Payload Length          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 *
 * @author  Senior Network Software Engineer
 * @version 1.0.0
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

// ─── Protocol constants ────────────────────────────────────────────────────

namespace jtp {

/// IPv4 protocol number assigned to JTP (IANA experimental range).
constexpr uint8_t  IP_PROTO_JTP      = 253;

/// Size of the JTP header in bytes.
constexpr uint16_t HEADER_SIZE       = 7;

/// Maximum payload that fits in a single JTP datagram (MTU 1500 – IP – JTP).
constexpr uint16_t MAX_PAYLOAD       = 1500 - 20 - HEADER_SIZE;

// ─── Flag byte definitions ─────────────────────────────────────────────────

/// Flags field: carries a user message payload.
constexpr uint8_t FLAG_MSG = 0x01;

/// Flags field: acknowledgement of a received sequence number.
constexpr uint8_t FLAG_ACK = 0x02;

// ─── Header ───────────────────────────────────────────────────────────────

/**
 * @brief In-memory (host byte-order) representation of a JTP header.
 *
 * All multi-byte fields are stored in host byte-order here; serialisation
 * to/from network byte-order is handled by @ref serialise() and
 * @ref deserialise().
 */
struct Header {
    uint16_t sequence_number = 0; ///< Monotonically increasing datagram counter.
    uint8_t  flags           = 0; ///< Bitmask of FLAG_* values.
    uint16_t checksum        = 0; ///< CRC-16/CCITT-FALSE over header + payload.
    uint16_t payload_length  = 0; ///< Byte-length of the payload that follows.
};

// ─── Checksum ─────────────────────────────────────────────────────────────

/**
 * @brief Compute CRC-16/CCITT-FALSE over an arbitrary byte range.
 *
 * Polynomial: 0x1021, initial value: 0xFFFF, no final XOR, no reflection.
 * This variant is deterministic and well-suited for small datagrams.
 *
 * @param data  Pointer to the first byte of input data.
 * @param len   Number of bytes to process.
 * @return      16-bit CRC value.
 */
uint16_t crc16(const uint8_t* data, std::size_t len) noexcept;

// ─── Serialisation ────────────────────────────────────────────────────────

/**
 * @brief Serialise a JTP header + payload into a network-ready byte vector.
 *
 * The checksum field inside @p hdr is *ignored*; a fresh checksum is
 * computed over the serialised header (with checksum field zeroed) and the
 * supplied @p payload, then embedded at the correct offset.
 *
 * @param hdr      Header fields (host byte-order, checksum field ignored).
 * @param payload  Raw payload bytes.
 * @return         Contiguous buffer ready for transmission.
 */
std::vector<uint8_t> serialise(Header hdr,
                               const std::vector<uint8_t>& payload);

/**
 * @brief Deserialise a JTP header from a raw byte buffer.
 *
 * Validates that @p buf is large enough to hold the header.  Does *not*
 * verify the checksum — call @ref verify_checksum() separately.
 *
 * @param buf  Raw bytes beginning at the start of the JTP header.
 * @return     Parsed header on success, or std::nullopt if the buffer is
 *             too short.
 */
std::optional<Header> deserialise(const std::vector<uint8_t>& buf);

/**
 * @brief Verify the checksum embedded in a raw JTP packet.
 *
 * Recomputes the CRC over the entire buffer (with the two checksum bytes
 * temporarily zeroed) and compares against the stored value.
 *
 * @param buf  Raw bytes of the complete JTP packet (header + payload).
 * @return     @c true if the checksum matches.
 */
bool verify_checksum(const std::vector<uint8_t>& buf) noexcept;

// ─── Socket helpers ───────────────────────────────────────────────────────

/**
 * @brief Open a raw IPv4 socket bound to IP_PROTO_JTP.
 *
 * On macOS the socket is opened with @c IPPROTO_RAW and the
 * @c IP_HDRINCL option is set so that the kernel prepends the IP header
 * when sending (matching Linux behaviour for our use-case).
 *
 * On Linux the socket is opened with @c IPPROTO_RAW and @c IP_HDRINCL
 * is explicitly disabled so the kernel manages the IP header on receive,
 * matching what @ref receive_packet() expects.
 *
 * @return File descriptor on success, or -1 on failure (errno is set).
 */
int open_raw_socket() noexcept;

/**
 * @brief Send a JTP datagram to the specified destination.
 *
 * Constructs the JTP packet from @p hdr and @p payload, then injects it
 * via @p sock_fd as a raw IP datagram with protocol 253.
 *
 * @param sock_fd   Open raw socket descriptor (from @ref open_raw_socket).
 * @param dest_ip   Dotted-decimal destination IPv4 address.
 * @param hdr       JTP header (sequence_number and flags must be set).
 * @param payload   Payload bytes.
 * @return          @c true on success.
 */
bool send_packet(int sock_fd,
                 const std::string& dest_ip,
                 Header hdr,
                 const std::vector<uint8_t>& payload);

/**
 * @brief Block until one JTP packet arrives, then return its raw bytes.
 *
 * Reads from @p sock_fd and discards packets whose IP protocol field is
 * not @ref IP_PROTO_JTP.  On Linux the kernel-prepended IP header is
 * stripped before returning.  On macOS the IP header is already present
 * in the recvfrom buffer and is similarly stripped.
 *
 * @param sock_fd  Open raw socket descriptor.
 * @return         Raw JTP packet bytes (header + payload) on success, or
 *                 an empty vector on I/O error.
 */
std::vector<uint8_t> receive_packet(int sock_fd);

} // namespace jtp
