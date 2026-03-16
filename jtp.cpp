/**
 * @file JTP.cpp
 * @brief Jerboa Transport Protocol v2 – implementation.
 *
 * Implements three transport modes:
 *   1. RAW  – native IPv4/proto=253 with manually built IP header
 *   2. UDP  – JTP-in-UDP for NAT traversal
 *   3. QUIC – JTP-in-UDP with stream multiplexing and RTT framing
 */

#include "jtp.h"

#include <cstring>
#include <iostream>
#include <chrono>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

namespace jtp {

// ═══════════════════════════════════════════════════════════════════════════
// CRC-16 / CCITT-FALSE
// ═══════════════════════════════════════════════════════════════════════════

uint16_t crc16(const uint8_t* data, std::size_t len) noexcept
{
    uint16_t crc = 0xFFFF;
    for (std::size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (int b = 0; b < 8; ++b)
            crc = (crc & 0x8000)
                      ? static_cast<uint16_t>((crc << 1) ^ 0x1021)
                      : static_cast<uint16_t>(crc << 1);
    }
    return crc;
}

// ═══════════════════════════════════════════════════════════════════════════
// Serialisation helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Write a big-endian uint16 into buf[0..1].
static inline void put_u16(uint8_t* buf, uint16_t v) noexcept
{
    buf[0] = static_cast<uint8_t>(v >> 8);
    buf[1] = static_cast<uint8_t>(v & 0xFF);
}

/// Read a big-endian uint16 from buf[0..1].
static inline uint16_t get_u16(const uint8_t* buf) noexcept
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(buf[0]) << 8) | buf[1]);
}

// ═══════════════════════════════════════════════════════════════════════════
// JTP packet serialisation
// ═══════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> serialise(Header hdr,
                               const std::vector<uint8_t>& payload)
{
    hdr.payload_length = static_cast<uint16_t>(payload.size());

    std::vector<uint8_t> buf(HEADER_SIZE + payload.size(), 0x00);

    put_u16(buf.data() + 0, hdr.sequence_number);
    buf[2] = hdr.flags;
    // buf[3..4] = checksum — zeroed, filled after CRC
    put_u16(buf.data() + 5, hdr.payload_length);

    if (!payload.empty())
        std::memcpy(buf.data() + HEADER_SIZE, payload.data(), payload.size());

    uint16_t crc = crc16(buf.data(), buf.size());
    put_u16(buf.data() + 3, crc);

    return buf;
}

std::optional<Header> deserialise(const std::vector<uint8_t>& buf)
{
    if (buf.size() < HEADER_SIZE)
        return std::nullopt;

    Header hdr;
    hdr.sequence_number = get_u16(buf.data() + 0);
    hdr.flags           = buf[2];
    hdr.checksum        = get_u16(buf.data() + 3);
    hdr.payload_length  = get_u16(buf.data() + 5);
    return hdr;
}

bool verify_checksum(const std::vector<uint8_t>& buf) noexcept
{
    if (buf.size() < HEADER_SIZE) return false;

    uint16_t stored = get_u16(buf.data() + 3);

    std::vector<uint8_t> tmp(buf);
    tmp[3] = tmp[4] = 0x00;

    return crc16(tmp.data(), tmp.size()) == stored;
}

// ═══════════════════════════════════════════════════════════════════════════
// RAW transport – internal helpers
// ═══════════════════════════════════════════════════════════════════════════

/// One's-complement checksum for the IPv4 header.
static uint16_t ip_checksum(const void* data, std::size_t len) noexcept
{
    const auto* p = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *reinterpret_cast<const uint8_t*>(p);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

/**
 * @brief Build a minimal 20-byte IPv4 header into @p buf.
 *
 * Platform-neutral: written as a raw byte array to avoid struct ip /
 * struct iphdr field-name divergence between macOS and Linux.
 */
static void build_ip_header(uint8_t* buf,
                            uint32_t src_addr,
                            uint32_t dst_addr,
                            uint16_t total_len) noexcept
{
    std::memset(buf, 0, 20);
    buf[0]  = 0x45;                              // Version=4, IHL=5
    buf[1]  = 0x00;                              // DSCP/ECN
    put_u16(buf + 2,  total_len);                // Total length
    put_u16(buf + 4,  0x0001);                   // Identification
    buf[6]  = 0x40; buf[7] = 0x00;              // Flags=DF, frag=0
    buf[8]  = 64;                                // TTL
    buf[9]  = IP_PROTO_JTP;                      // Protocol = 253
    // buf[10..11] = header checksum (computed below)
    std::memcpy(buf + 12, &src_addr, 4);
    std::memcpy(buf + 16, &dst_addr, 4);

    uint16_t cksum = ip_checksum(buf, 20);
    put_u16(buf + 10, cksum);
}

// ═══════════════════════════════════════════════════════════════════════════
// RAW transport – public API
// ═══════════════════════════════════════════════════════════════════════════

int open_raw_socket() noexcept
{
    // IPPROTO_RAW: kernel injects our pre-built datagram verbatim.
    // IP_HDRINCL=1: we supply the full IP header.
    int fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        std::cerr << "[RAW] socket() failed: " << std::strerror(errno) << '\n';
        return -1;
    }
    int one = 1;
    if (::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "[RAW] setsockopt(IP_HDRINCL) failed: "
                  << std::strerror(errno) << '\n';
        ::close(fd);
        return -1;
    }
    return fd;
}

int open_recv_socket() noexcept
{
    // IPPROTO_RAW is send-only on Linux; IP_PROTO_JTP receives proto=253.
    int fd = ::socket(AF_INET, SOCK_RAW, IP_PROTO_JTP);
    if (fd < 0) {
        std::cerr << "[RAW] recv socket() failed: "
                  << std::strerror(errno) << '\n';
        return -1;
    }
    return fd;
}

bool send_packet(int sock_fd,
                 const std::string& dest_ip,
                 Header hdr,
                 const std::vector<uint8_t>& payload)
{
    uint32_t dst_addr = 0;
    if (::inet_pton(AF_INET, dest_ip.c_str(), &dst_addr) != 1) {
        std::cerr << "[RAW] Invalid destination IP: " << dest_ip << '\n';
        return false;
    }
    uint32_t src_addr = htonl(INADDR_ANY);

    std::vector<uint8_t> jtp_pkt = serialise(hdr, payload);

    constexpr std::size_t IP_HDR = 20;
    const auto total = static_cast<uint16_t>(IP_HDR + jtp_pkt.size());
    std::vector<uint8_t> datagram(IP_HDR + jtp_pkt.size());

    build_ip_header(datagram.data(), src_addr, dst_addr, total);
    std::memcpy(datagram.data() + IP_HDR, jtp_pkt.data(), jtp_pkt.size());

    struct sockaddr_in dest{};
    dest.sin_family      = AF_INET;
    dest.sin_port        = 0;
    dest.sin_addr.s_addr = dst_addr;

    ssize_t sent = ::sendto(sock_fd,
                            datagram.data(), datagram.size(), 0,
                            reinterpret_cast<struct sockaddr*>(&dest),
                            sizeof(dest));
    if (sent < 0) {
        std::cerr << "[RAW] sendto failed: " << std::strerror(errno) << '\n';
        return false;
    }
    std::cerr << "[RAW] sent " << sent << " bytes → " << dest_ip << '\n';
    return true;
}

std::vector<uint8_t> receive_packet(int sock_fd)
{
    constexpr std::size_t RECV_BUF = 65535;
    std::vector<uint8_t> raw(RECV_BUF);
    struct sockaddr_in src{};
    socklen_t src_len = sizeof(src);

    ssize_t n = ::recvfrom(sock_fd, raw.data(), raw.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &src_len);
    if (n < 0) return {};

    raw.resize(static_cast<std::size_t>(n));

    if (raw.size() < 10) return {};               // Too short for IP header
    if (raw[9] != IP_PROTO_JTP) return {};        // Wrong protocol — skip

    std::size_t ihl = static_cast<std::size_t>(raw[0] & 0x0F) * 4;
    if (raw.size() <= ihl) return {};

    return std::vector<uint8_t>(raw.begin() + static_cast<ptrdiff_t>(ihl),
                                raw.end());
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared UDP socket helper
// ═══════════════════════════════════════════════════════════════════════════

static int open_udp_socket_impl(uint16_t bind_port,
                                const char* tag) noexcept
{
    int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        std::cerr << '[' << tag << "] socket(UDP) failed: "
                  << std::strerror(errno) << '\n';
        return -1;
    }

    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind_port != 0) {
        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port        = htons(bind_port);

        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)) < 0) {
            std::cerr << '[' << tag << "] bind(" << bind_port << ") failed: "
                      << std::strerror(errno) << '\n';
            ::close(fd);
            return -1;
        }
        std::cerr << '[' << tag << "] Listening on UDP port "
                  << bind_port << '\n';
    }
    return fd;
}

// ═══════════════════════════════════════════════════════════════════════════
// UDP tunnel transport
// ═══════════════════════════════════════════════════════════════════════════

int open_udp_socket(uint16_t bind_port) noexcept
{
    return open_udp_socket_impl(bind_port, "UDP");
}

bool udp_send(int sock_fd,
              const std::string& dest_ip,
              Header hdr,
              const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> jtp_pkt = serialise(hdr, payload);

    // Build:  TUNNEL_MAGIC(4) | JTP packet
    std::vector<uint8_t> frame;
    frame.reserve(MAGIC_SIZE + jtp_pkt.size());
    frame.insert(frame.end(), TUNNEL_MAGIC, TUNNEL_MAGIC + MAGIC_SIZE);
    frame.insert(frame.end(), jtp_pkt.begin(), jtp_pkt.end());

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(UDP_TUNNEL_PORT);
    if (::inet_pton(AF_INET, dest_ip.c_str(), &dest.sin_addr) != 1) {
        std::cerr << "[UDP] Invalid IP: " << dest_ip << '\n';
        return false;
    }

    ssize_t sent = ::sendto(sock_fd, frame.data(), frame.size(), 0,
                            reinterpret_cast<struct sockaddr*>(&dest),
                            sizeof(dest));
    if (sent < 0) {
        std::cerr << "[UDP] sendto failed: " << std::strerror(errno) << '\n';
        return false;
    }
    std::cerr << "[UDP] sent " << sent << " bytes → "
              << dest_ip << ':' << UDP_TUNNEL_PORT << '\n';
    return true;
}

std::vector<uint8_t> udp_receive(int sock_fd, std::string* src_ip_out)
{
    constexpr std::size_t RECV_BUF = 65535;
    std::vector<uint8_t> buf(RECV_BUF);
    struct sockaddr_in src{};
    socklen_t src_len = sizeof(src);

    ssize_t n = ::recvfrom(sock_fd, buf.data(), buf.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &src_len);
    if (n < 0) return {};

    buf.resize(static_cast<std::size_t>(n));

    // Validate TUNNEL_MAGIC
    if (buf.size() < MAGIC_SIZE ||
        std::memcmp(buf.data(), TUNNEL_MAGIC, MAGIC_SIZE) != 0)
        return {};  // Not a JTP-UDP frame — discard

    if (src_ip_out) {
        char tmp[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &src.sin_addr, tmp, sizeof(tmp));
        *src_ip_out = tmp;
    }

    // Return bytes after magic = raw JTP packet
    return std::vector<uint8_t>(buf.begin() + MAGIC_SIZE, buf.end());
}

// ═══════════════════════════════════════════════════════════════════════════
// QUIC-like tunnel transport
// ═══════════════════════════════════════════════════════════════════════════

int open_quic_socket(uint16_t bind_port) noexcept
{
    return open_udp_socket_impl(bind_port, "QUIC");
}

bool quic_send(int sock_fd,
               const std::string& dest_ip,
               QuicFrame& qf,
               Header hdr,
               const std::vector<uint8_t>& payload)
{
    // Auto-increment packet number per stream
    ++qf.packet_num;

    std::vector<uint8_t> jtp_pkt = serialise(hdr, payload);

    // Build:  QUIC_MAGIC(4) | QuicFrame(6) | JTP packet
    std::vector<uint8_t> frame;
    frame.reserve(MAGIC_SIZE + QUIC_PREFIX_SIZE + jtp_pkt.size());

    frame.insert(frame.end(), QUIC_MAGIC, QUIC_MAGIC + MAGIC_SIZE);

    // Serialise QuicFrame (big-endian)
    uint8_t qf_bytes[QUIC_PREFIX_SIZE];
    put_u16(qf_bytes + 0, qf.stream_id);
    put_u16(qf_bytes + 2, qf.packet_num);
    put_u16(qf_bytes + 4, qf.rtt_ms);
    frame.insert(frame.end(), qf_bytes, qf_bytes + QUIC_PREFIX_SIZE);

    frame.insert(frame.end(), jtp_pkt.begin(), jtp_pkt.end());

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(QUIC_TUNNEL_PORT);
    if (::inet_pton(AF_INET, dest_ip.c_str(), &dest.sin_addr) != 1) {
        std::cerr << "[QUIC] Invalid IP: " << dest_ip << '\n';
        return false;
    }

    ssize_t sent = ::sendto(sock_fd, frame.data(), frame.size(), 0,
                            reinterpret_cast<struct sockaddr*>(&dest),
                            sizeof(dest));
    if (sent < 0) {
        std::cerr << "[QUIC] sendto failed: " << std::strerror(errno) << '\n';
        return false;
    }
    std::cerr << "[QUIC] sent " << sent << " bytes → "
              << dest_ip << ':' << QUIC_TUNNEL_PORT
              << "  stream=" << qf.stream_id
              << " pkt#"     << qf.packet_num
              << " rtt="     << qf.rtt_ms << "ms\n";
    return true;
}

std::vector<uint8_t> quic_receive(int sock_fd,
                                  QuicFrame* frame_out,
                                  std::string* src_ip_out)
{
    constexpr std::size_t RECV_BUF = 65535;
    constexpr std::size_t HDR_OFF  = MAGIC_SIZE + QUIC_PREFIX_SIZE;

    std::vector<uint8_t> buf(RECV_BUF);
    struct sockaddr_in src{};
    socklen_t src_len = sizeof(src);

    ssize_t n = ::recvfrom(sock_fd, buf.data(), buf.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &src_len);
    if (n < 0) return {};

    buf.resize(static_cast<std::size_t>(n));

    // Validate QUIC_MAGIC
    if (buf.size() < HDR_OFF ||
        std::memcmp(buf.data(), QUIC_MAGIC, MAGIC_SIZE) != 0)
        return {};  // Not a JTP-QUIC frame — discard

    if (frame_out) {
        const uint8_t* qb = buf.data() + MAGIC_SIZE;
        frame_out->stream_id  = get_u16(qb + 0);
        frame_out->packet_num = get_u16(qb + 2);
        frame_out->rtt_ms     = get_u16(qb + 4);
    }

    if (src_ip_out) {
        char tmp[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &src.sin_addr, tmp, sizeof(tmp));
        *src_ip_out = tmp;
    }

    // Return bytes after magic + QuicFrame = raw JTP packet
    return std::vector<uint8_t>(
        buf.begin() + static_cast<ptrdiff_t>(HDR_OFF), buf.end());
}

} // namespace jtp
