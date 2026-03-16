/**
 * @file jtp.cpp
 * @brief Jerboa Transport Protocol v3 — implementation.
 */

#include "jtp.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <random>

// POSIX sockets
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// OpenSSL (AES-256-GCM + PBKDF2)
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace jtp {

// ═══════════════════════════════════════════════════════════════════════════
// Internal wire helpers
// ═══════════════════════════════════════════════════════════════════════════

static inline void put_u16(uint8_t* p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}
static inline void put_u32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >>  8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}
static inline uint16_t get_u16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
static inline uint32_t get_u32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
           static_cast<uint32_t>(p[3]);
}

// ═══════════════════════════════════════════════════════════════════════════
// CRC-16 / CCITT-FALSE
// ═══════════════════════════════════════════════════════════════════════════

uint16_t crc16(const uint8_t* data, std::size_t len) noexcept {
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
// AES-256-GCM encryption / decryption
// ═══════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> encrypt(const Key& key,
                             const std::vector<uint8_t>& plaintext)
{
    // Generate random 12-byte nonce
    std::array<uint8_t, NONCE_SIZE> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(NONCE_SIZE)) != 1) {
        std::cerr << "[CRYPTO] RAND_bytes failed\n";
        return {};
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> ciphertext(plaintext.size());
    std::array<uint8_t, TAG_SIZE> tag{};
    int outlen = 0;

    bool ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key.data(), nonce.data()) == 1 &&
        EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(TAG_SIZE), tag.data()) == 1;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { std::cerr << "[CRYPTO] Encryption failed\n"; return {}; }

    // Output: nonce(12) | ciphertext | tag(16)
    std::vector<uint8_t> out;
    out.reserve(NONCE_SIZE + ciphertext.size() + TAG_SIZE);
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

std::vector<uint8_t> decrypt(const Key& key,
                             const std::vector<uint8_t>& blob)
{
    if (blob.size() < NONCE_SIZE + TAG_SIZE) {
        std::cerr << "[CRYPTO] Blob too short to decrypt\n";
        return {};
    }

    const uint8_t* nonce      = blob.data();
    const uint8_t* ciphertext = blob.data() + NONCE_SIZE;
    const std::size_t ct_len  = blob.size() - NONCE_SIZE - TAG_SIZE;
    const uint8_t* tag        = blob.data() + NONCE_SIZE + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> plaintext(ct_len);
    int outlen = 0;

    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key.data(), nonce) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
                          ciphertext, static_cast<int>(ct_len)) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(TAG_SIZE),
                            const_cast<uint8_t*>(tag)) == 1 &&
        EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen) == 1;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { std::cerr << "[CRYPTO] Decryption / auth-tag verification failed\n"; return {}; }
    return plaintext;
}

Key derive_key(const std::string& passphrase)
{
    // Fixed salt — for production replace with a per-session random salt
    // exchanged out-of-band.
    static const uint8_t SALT[] = "JTP_v3_SALT_2025";
    Key key{};
    PKCS5_PBKDF2_HMAC(passphrase.c_str(),
                      static_cast<int>(passphrase.size()),
                      SALT, static_cast<int>(sizeof(SALT) - 1),
                      100000,
                      EVP_sha256(),
                      static_cast<int>(KEY_SIZE),
                      key.data());
    return key;
}

// ═══════════════════════════════════════════════════════════════════════════
// Serialisation
// ═══════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> serialise(Header hdr,
                               const std::vector<uint8_t>& payload,
                               const FragExt* fext)
{
    if (fext) hdr.flags |= FLAG_FRAG;

    const std::size_t hdr_bytes = BASE_HEADER_SIZE + (fext ? FRAG_EXT_SIZE : 0);
    hdr.payload_length = static_cast<uint16_t>(payload.size());

    std::vector<uint8_t> buf(hdr_bytes + payload.size(), 0x00);

    // Base header
    put_u16(buf.data() + 0, hdr.sequence_number);
    buf[2] = hdr.flags;
    // buf[3..4] = checksum (zeroed, filled after CRC)
    put_u16(buf.data() + 5, hdr.payload_length);

    // Frag extension immediately after base header
    if (fext) {
        uint8_t* p = buf.data() + BASE_HEADER_SIZE;
        put_u32(p + 0, fext->frag_id);
        put_u16(p + 4, fext->frag_index);
        put_u16(p + 6, fext->frag_total);
        p[8] = fext->reserved;
    }

    if (!payload.empty())
        std::memcpy(buf.data() + hdr_bytes, payload.data(), payload.size());

    uint16_t crc = crc16(buf.data(), buf.size());
    put_u16(buf.data() + 3, crc);

    return buf;
}

std::optional<Header> deserialise_header(const std::vector<uint8_t>& buf)
{
    if (buf.size() < BASE_HEADER_SIZE) return std::nullopt;
    Header h;
    h.sequence_number = get_u16(buf.data() + 0);
    h.flags           = buf[2];
    h.checksum        = get_u16(buf.data() + 3);
    h.payload_length  = get_u16(buf.data() + 5);
    return h;
}

std::optional<FragExt> deserialise_frag(const std::vector<uint8_t>& buf)
{
    if (buf.size() < BASE_HEADER_SIZE + FRAG_EXT_SIZE) return std::nullopt;
    const uint8_t* p = buf.data() + BASE_HEADER_SIZE;
    FragExt f;
    f.frag_id    = get_u32(p + 0);
    f.frag_index = get_u16(p + 4);
    f.frag_total = get_u16(p + 6);
    f.reserved   = p[8];
    return f;
}

bool verify_checksum(const std::vector<uint8_t>& buf) noexcept
{
    if (buf.size() < BASE_HEADER_SIZE) return false;
    uint16_t stored = get_u16(buf.data() + 3);
    std::vector<uint8_t> tmp(buf);
    tmp[3] = tmp[4] = 0x00;
    return crc16(tmp.data(), tmp.size()) == stored;
}

// ═══════════════════════════════════════════════════════════════════════════
// Reassembler
// ═══════════════════════════════════════════════════════════════════════════

Reassembler::Reassembler(uint32_t timeout_ms)
    : timeout_ms_(timeout_ms) {}

void Reassembler::prune_locked()
{
    auto now = std::chrono::steady_clock::now();
    for (auto it = cache_.begin(); it != cache_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now - it->second.created).count();
        if (static_cast<uint32_t>(age) > timeout_ms_)
            it = cache_.erase(it);
        else
            ++it;
    }
}

std::optional<std::vector<uint8_t>>
Reassembler::insert(const std::string& src_ip,
                    const FragExt& fext,
                    const std::vector<uint8_t>& data)
{
    std::lock_guard<std::mutex> lk(mtx_);
    prune_locked();

    auto key = std::make_pair(src_ip, fext.frag_id);
    auto& entry = cache_[key];

    if (entry.total == 0) {
        // First fragment for this frag_id
        entry.total     = fext.frag_total;
        entry.received  = 0;
        entry.fragments.resize(fext.frag_total);
        entry.created   = std::chrono::steady_clock::now();
    }

    if (fext.frag_index >= entry.total) return std::nullopt; // sanity
    if (entry.fragments[fext.frag_index].empty()) {
        entry.fragments[fext.frag_index] = data;
        ++entry.received;
    }

    if (entry.received < entry.total) return std::nullopt;

    // All fragments arrived — reassemble
    std::vector<uint8_t> message;
    for (auto& frag : entry.fragments)
        message.insert(message.end(), frag.begin(), frag.end());

    cache_.erase(key);
    return message;
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal: prepare payload (encrypt if key present)
// ═══════════════════════════════════════════════════════════════════════════

static std::vector<uint8_t>
prepare_payload(const std::vector<uint8_t>& raw,
                Header& hdr,
                const Key* key)
{
    if (key) {
        auto enc = encrypt(*key, raw);
        if (enc.empty()) return {};
        hdr.flags |= FLAG_CRYPT;
        return enc;
    }
    return raw;
}

// ═══════════════════════════════════════════════════════════════════════════
// RAW socket transport
// ═══════════════════════════════════════════════════════════════════════════

static uint16_t ip_checksum(const void* data, std::size_t len) noexcept {
    const auto* p = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *reinterpret_cast<const uint8_t*>(p);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static void build_ip_header(uint8_t* buf,
                            uint32_t src, uint32_t dst,
                            uint16_t total_len) noexcept
{
    std::memset(buf, 0, 20);
    buf[0] = 0x45; buf[1] = 0x00;
    put_u16(buf + 2, total_len);
    put_u16(buf + 4, 0x0001);
    buf[6] = 0x40; buf[7] = 0x00;  // DF flag
    buf[8] = 64;
    buf[9] = IP_PROTO_JTP;
    std::memcpy(buf + 12, &src, 4);
    std::memcpy(buf + 16, &dst, 4);
    put_u16(buf + 10, ip_checksum(buf, 20));
}

int open_raw_socket() noexcept
{
    int fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) { std::cerr << "[RAW] socket: " << strerror(errno) << '\n'; return -1; }
    int one = 1;
    if (::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "[RAW] IP_HDRINCL: " << strerror(errno) << '\n';
        ::close(fd); return -1;
    }
    return fd;
}

int open_recv_socket() noexcept
{
    int fd = ::socket(AF_INET, SOCK_RAW, IP_PROTO_JTP);
    if (fd < 0) { std::cerr << "[RAW] recv socket: " << strerror(errno) << '\n'; return -1; }
    return fd;
}

bool send_raw(int sock_fd, const std::string& dest_ip,
              Header hdr, const std::vector<uint8_t>& payload,
              const FragExt* fext, const Key* key)
{
    auto actual = prepare_payload(payload, hdr, key);
    if (key && actual.empty()) return false;

    auto jtp_pkt = serialise(hdr, actual, fext);
    constexpr std::size_t IP_HDR = 20;
    auto total = static_cast<uint16_t>(IP_HDR + jtp_pkt.size());

    std::vector<uint8_t> datagram(IP_HDR + jtp_pkt.size());
    uint32_t dst = 0;
    if (::inet_pton(AF_INET, dest_ip.c_str(), &dst) != 1) {
        std::cerr << "[RAW] Bad IP: " << dest_ip << '\n'; return false;
    }
    build_ip_header(datagram.data(), htonl(INADDR_ANY), dst, total);
    std::memcpy(datagram.data() + IP_HDR, jtp_pkt.data(), jtp_pkt.size());

    struct sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = dst;
    ssize_t n = ::sendto(sock_fd, datagram.data(), datagram.size(), 0,
                         reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
    if (n < 0) { std::cerr << "[RAW] sendto: " << strerror(errno) << '\n'; return false; }
    return true;
}

std::vector<uint8_t> recv_raw(int sock_fd)
{
    std::vector<uint8_t> raw(65535);
    struct sockaddr_in src{}; socklen_t slen = sizeof(src);
    ssize_t n = ::recvfrom(sock_fd, raw.data(), raw.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &slen);
    if (n < 0) return {};
    raw.resize(static_cast<std::size_t>(n));
    if (raw.size() < 10 || raw[9] != IP_PROTO_JTP) return {};
    std::size_t ihl = static_cast<std::size_t>(raw[0] & 0x0F) * 4;
    if (raw.size() <= ihl) return {};
    return std::vector<uint8_t>(raw.begin() + static_cast<ptrdiff_t>(ihl), raw.end());
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared UDP socket factory
// ═══════════════════════════════════════════════════════════════════════════

static int make_udp_socket(uint16_t bind_port, const char* tag) noexcept
{
    int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) { std::cerr << '[' << tag << "] socket: " << strerror(errno) << '\n'; return -1; }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    // Set receive timeout so recvfrom is interruptible on all platforms
    struct timeval tv{}; tv.tv_sec = 1; tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (bind_port) {
        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port        = htons(bind_port);
        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::cerr << '[' << tag << "] bind(" << bind_port << "): "
                      << strerror(errno) << '\n';
            ::close(fd); return -1;
        }
    }
    return fd;
}

// ═══════════════════════════════════════════════════════════════════════════
// UDP tunnel
// ═══════════════════════════════════════════════════════════════════════════

int open_udp_socket(uint16_t bind_port) noexcept {
    return make_udp_socket(bind_port, "UDP");
}

bool send_udp(int sock_fd, const std::string& dest_ip,
              Header hdr, const std::vector<uint8_t>& payload,
              const FragExt* fext, const Key* key)
{
    auto actual = prepare_payload(payload, hdr, key);
    if (key && actual.empty()) return false;

    auto jtp_pkt = serialise(hdr, actual, fext);

    std::vector<uint8_t> frame;
    frame.reserve(4 + jtp_pkt.size());
    frame.insert(frame.end(), TUNNEL_MAGIC, TUNNEL_MAGIC + 4);
    frame.insert(frame.end(), jtp_pkt.begin(), jtp_pkt.end());

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET; sa.sin_port = htons(UDP_TUNNEL_PORT);
    if (::inet_pton(AF_INET, dest_ip.c_str(), &sa.sin_addr) != 1) {
        std::cerr << "[UDP] Bad IP: " << dest_ip << '\n'; return false;
    }
    ssize_t n = ::sendto(sock_fd, frame.data(), frame.size(), 0,
                         reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
    if (n < 0) { std::cerr << "[UDP] sendto: " << strerror(errno) << '\n'; return false; }
    return true;
}

std::vector<uint8_t> recv_udp(int sock_fd, std::string* src_ip_out)
{
    std::vector<uint8_t> buf(65535);
    struct sockaddr_in src{}; socklen_t slen = sizeof(src);
    ssize_t n = ::recvfrom(sock_fd, buf.data(), buf.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &slen);
    if (n < 0) return {};
    buf.resize(static_cast<std::size_t>(n));
    if (buf.size() < 4 || std::memcmp(buf.data(), TUNNEL_MAGIC, 4) != 0) return {};
    if (src_ip_out) {
        char tmp[INET_ADDRSTRLEN]{}; ::inet_ntop(AF_INET, &src.sin_addr, tmp, sizeof(tmp));
        *src_ip_out = tmp;
    }
    return std::vector<uint8_t>(buf.begin() + 4, buf.end());
}

// ═══════════════════════════════════════════════════════════════════════════
// QUIC-like tunnel
// ═══════════════════════════════════════════════════════════════════════════

int open_quic_socket(uint16_t bind_port) noexcept {
    return make_udp_socket(bind_port, "QUIC");
}

bool send_quic(int sock_fd, const std::string& dest_ip,
               QuicFrame& qf,
               Header hdr, const std::vector<uint8_t>& payload,
               const FragExt* fext, const Key* key)
{
    ++qf.packet_num;

    auto actual = prepare_payload(payload, hdr, key);
    if (key && actual.empty()) return false;

    auto jtp_pkt = serialise(hdr, actual, fext);

    // Frame: QUIC_MAGIC(4) + QuicFrame(6) + JTP packet
    std::vector<uint8_t> frame;
    frame.reserve(4 + 6 + jtp_pkt.size());
    frame.insert(frame.end(), QUIC_MAGIC, QUIC_MAGIC + 4);

    uint8_t qb[6];
    put_u16(qb + 0, qf.stream_id);
    put_u16(qb + 2, qf.packet_num);
    put_u16(qb + 4, qf.rtt_ms);
    frame.insert(frame.end(), qb, qb + 6);
    frame.insert(frame.end(), jtp_pkt.begin(), jtp_pkt.end());

    struct sockaddr_in sa{};
    sa.sin_family = AF_INET; sa.sin_port = htons(QUIC_TUNNEL_PORT);
    if (::inet_pton(AF_INET, dest_ip.c_str(), &sa.sin_addr) != 1) {
        std::cerr << "[QUIC] Bad IP: " << dest_ip << '\n'; return false;
    }
    ssize_t n = ::sendto(sock_fd, frame.data(), frame.size(), 0,
                         reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
    if (n < 0) { std::cerr << "[QUIC] sendto: " << strerror(errno) << '\n'; return false; }
    return true;
}

std::vector<uint8_t> recv_quic(int sock_fd,
                               QuicFrame* frame_out,
                               std::string* src_ip_out)
{
    std::vector<uint8_t> buf(65535);
    struct sockaddr_in src{}; socklen_t slen = sizeof(src);
    ssize_t n = ::recvfrom(sock_fd, buf.data(), buf.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&src), &slen);
    if (n < 0) return {};
    buf.resize(static_cast<std::size_t>(n));

    constexpr std::size_t HDR_OFF = 4 + 6; // magic + QuicFrame
    if (buf.size() < HDR_OFF || std::memcmp(buf.data(), QUIC_MAGIC, 4) != 0) return {};

    if (frame_out) {
        const uint8_t* qb = buf.data() + 4;
        frame_out->stream_id  = get_u16(qb + 0);
        frame_out->packet_num = get_u16(qb + 2);
        frame_out->rtt_ms     = get_u16(qb + 4);
    }
    if (src_ip_out) {
        char tmp[INET_ADDRSTRLEN]{}; ::inet_ntop(AF_INET, &src.sin_addr, tmp, sizeof(tmp));
        *src_ip_out = tmp;
    }
    return std::vector<uint8_t>(buf.begin() + static_cast<ptrdiff_t>(HDR_OFF), buf.end());
}

// ═══════════════════════════════════════════════════════════════════════════
// High-level fragmented send
// ═══════════════════════════════════════════════════════════════════════════

bool send_message(int sock_fd,
                  const std::string& dest_ip,
                  const std::vector<uint8_t>& message,
                  Transport transport,
                  const Key* key,
                  QuicFrame* qf)
{
    if (message.size() > MAX_MSG_SIZE) {
        std::cerr << "[JTP] Message too large (" << message.size()
        << " > " << MAX_MSG_SIZE << ")\n";
        return false;
    }

    // Calculate number of fragments needed
    const std::size_t frag_size = MAX_FRAG_PAYLOAD;
    const auto total_frags = static_cast<uint16_t>(
        (message.size() + frag_size - 1) / frag_size);

    // Generate random frag_id
    std::mt19937 rng(std::random_device{}());
    uint32_t frag_id = std::uniform_int_distribution<uint32_t>(1, 0xFFFFFFFF)(rng);

    static uint16_t seq = 0;

    for (uint16_t i = 0; i < total_frags; ++i) {
        std::size_t offset = static_cast<std::size_t>(i) * frag_size;
        std::size_t chunk  = std::min(frag_size, message.size() - offset);

        std::vector<uint8_t> frag_data(
            message.begin() + static_cast<ptrdiff_t>(offset),
            message.begin() + static_cast<ptrdiff_t>(offset + chunk));

        Header hdr;
        hdr.sequence_number = ++seq;
        hdr.flags           = FLAG_MSG;

        FragExt* fext_ptr = nullptr;
        FragExt  fext{};
        if (total_frags > 1) {
            fext.frag_id    = frag_id;
            fext.frag_index = i;
            fext.frag_total = total_frags;
            fext_ptr        = &fext;
        }

        bool ok = false;
        switch (transport) {
        case Transport::RAW:
            ok = send_raw(sock_fd, dest_ip, hdr, frag_data, fext_ptr, key);
            break;
        case Transport::UDP:
            ok = send_udp(sock_fd, dest_ip, hdr, frag_data, fext_ptr, key);
            break;
        case Transport::QUIC:
            if (!qf) { std::cerr << "[JTP] QuicFrame required for QUIC transport\n"; return false; }
            ok = send_quic(sock_fd, dest_ip, *qf, hdr, frag_data, fext_ptr, key);
            break;
        }
        if (!ok) {
            std::cerr << "[JTP] Fragment " << i << '/' << total_frags << " failed\n";
            return false;
        }
    }
    return true;
}

} // namespace jtp
