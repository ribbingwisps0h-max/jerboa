/**
 * @file JTP.cpp
 * @brief Jerboa Transport Protocol – implementation.
 *
 * See JTP.h for the full protocol description and API documentation.
 */

#include "JTP.h"

#include <cstring>
#include <stdexcept>
#include <iostream>
#include <system_error>

// BSD / POSIX socket headers
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

// Platform-specific IP header
#ifdef JTP_PLATFORM_MACOS
#   include <netinet/ip.h>
#   define JTP_IP_HDR_TYPE struct ip
#else
#   include <netinet/ip.h>
#   define JTP_IP_HDR_TYPE struct iphdr
#endif

namespace jtp {

// ─── Checksum ─────────────────────────────────────────────────────────────

uint16_t crc16(const uint8_t* data, std::size_t len) noexcept
{
    uint16_t crc = 0xFFFF;
    for (std::size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (int bit = 0; bit < 8; ++bit) {
            if (crc & 0x8000)
                crc = static_cast<uint16_t>((crc << 1) ^ 0x1021);
            else
                crc = static_cast<uint16_t>(crc << 1);
        }
    }
    return crc;
}

// ─── Serialisation ────────────────────────────────────────────────────────

std::vector<uint8_t> serialise(Header hdr,
                               const std::vector<uint8_t>& payload)
{
    hdr.payload_length = static_cast<uint16_t>(payload.size());

    // Allocate header + payload space.
    std::vector<uint8_t> buf(HEADER_SIZE + payload.size(), 0x00);

    // Write header fields in network byte-order (big-endian).
    buf[0] = static_cast<uint8_t>(hdr.sequence_number >> 8);
    buf[1] = static_cast<uint8_t>(hdr.sequence_number & 0xFF);
    buf[2] = hdr.flags;
    // bytes [3..4] = checksum (written after CRC computation, leave 0)
    buf[5] = static_cast<uint8_t>(hdr.payload_length >> 8);
    buf[6] = static_cast<uint8_t>(hdr.payload_length & 0xFF);

    // Copy payload after the header.
    if (!payload.empty())
        std::memcpy(buf.data() + HEADER_SIZE, payload.data(), payload.size());

    // Compute CRC over the entire buffer (checksum bytes still zero).
    uint16_t crc = crc16(buf.data(), buf.size());

    // Embed checksum in network byte-order.
    buf[3] = static_cast<uint8_t>(crc >> 8);
    buf[4] = static_cast<uint8_t>(crc & 0xFF);

    return buf;
}

std::optional<Header> deserialise(const std::vector<uint8_t>& buf)
{
    if (buf.size() < HEADER_SIZE)
        return std::nullopt;

    Header hdr;
    hdr.sequence_number = static_cast<uint16_t>(
        (static_cast<uint16_t>(buf[0]) << 8) | buf[1]);
    hdr.flags           = buf[2];
    hdr.checksum        = static_cast<uint16_t>(
        (static_cast<uint16_t>(buf[3]) << 8) | buf[4]);
    hdr.payload_length  = static_cast<uint16_t>(
        (static_cast<uint16_t>(buf[5]) << 8) | buf[6]);

    return hdr;
}

bool verify_checksum(const std::vector<uint8_t>& buf) noexcept
{
    if (buf.size() < HEADER_SIZE)
        return false;

    // Extract the stored checksum.
    uint16_t stored = static_cast<uint16_t>(
        (static_cast<uint16_t>(buf[3]) << 8) | buf[4]);

    // Zero the checksum bytes in a local copy, then recompute.
    std::vector<uint8_t> tmp(buf);
    tmp[3] = 0x00;
    tmp[4] = 0x00;

    uint16_t computed = crc16(tmp.data(), tmp.size());
    return computed == stored;
}

// ─── Socket helpers ───────────────────────────────────────────────────────

int open_raw_socket() noexcept
{
    // AF_INET / SOCK_RAW with our custom protocol number.
    int fd = ::socket(AF_INET, SOCK_RAW, IP_PROTO_JTP);
    if (fd < 0) {
        return -1;
    }

#ifdef JTP_PLATFORM_MACOS
    // On macOS we do NOT set IP_HDRINCL so that the kernel automatically
    // prepends a valid IP header when we send.  On receive the IP header
    // IS included in the recvfrom buffer (kernel behaviour), so we strip it.
    // Nothing extra to set here.
    (void)0;
#else
    // On Linux, SOCK_RAW with a custom protocol number already has
    // IP_HDRINCL = 0 by default (kernel fills IP header on send and
    // includes it in the receive buffer).  We make this explicit.
    int opt = 0;
    if (::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        ::close(fd);
        return -1;
    }
#endif

    return fd;
}

bool send_packet(int sock_fd,
                 const std::string& dest_ip,
                 Header hdr,
                 const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> pkt = serialise(hdr, payload);

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port   = 0; // unused for raw sockets
    if (::inet_pton(AF_INET, dest_ip.c_str(), &dest.sin_addr) != 1) {
        std::cerr << "[JTP] Invalid destination IP: " << dest_ip << '\n';
        return false;
    }

    ssize_t sent = ::sendto(sock_fd,
                            pkt.data(), pkt.size(),
                            0,
                            reinterpret_cast<struct sockaddr*>(&dest),
                            sizeof(dest));
    if (sent < 0) {
        std::cerr << "[JTP] sendto failed: " << std::strerror(errno) << '\n';
        return false;
    }
    return true;
}

std::vector<uint8_t> receive_packet(int sock_fd)
{
    // Buffer large enough for maximum IP + JTP datagram.
    constexpr std::size_t RECV_BUF = 65535;
    std::vector<uint8_t> raw(RECV_BUF);

    struct sockaddr_in src{};
    socklen_t src_len = sizeof(src);

    ssize_t n = ::recvfrom(sock_fd,
                           raw.data(), raw.size(),
                           0,
                           reinterpret_cast<struct sockaddr*>(&src),
                           &src_len);
    if (n < 0) {
        // Return empty vector to signal error; caller checks errno.
        return {};
    }

    raw.resize(static_cast<std::size_t>(n));

    // Both macOS and Linux include the IP header in the received buffer.
    // Strip it to expose the raw JTP header + payload.
    if (raw.size() < sizeof(struct ip)) {
        return {}; // Truncated — discard.
    }

    // The IP header length is encoded in the lower nibble of the first byte,
    // in units of 32-bit words (same layout on both platforms).
    uint8_t  ihl_byte  = raw[0];
    std::size_t ip_hdr_len = static_cast<std::size_t>(ihl_byte & 0x0F) * 4;

    // Validate the claimed IP protocol field (byte offset 9 in the IP header).
    if (raw.size() < 10 || raw[9] != IP_PROTO_JTP) {
        return {}; // Not a JTP packet — tell caller to retry.
    }

    if (raw.size() <= ip_hdr_len) {
        return {}; // Nothing after the IP header.
    }

    // Return only the JTP portion.
    return std::vector<uint8_t>(raw.begin() + static_cast<ptrdiff_t>(ip_hdr_len),
                                raw.end());
}

} // namespace jtp
