# Jerboa Transport Protocol (JTP) v3

Experimental transport-layer protocol with three backends, large-message
fragmentation, and AES-256-GCM envelope encryption.

---

## What's new in v3

| Feature | v2 | v3 |
|---|---|---|
| Filenames | `JTP.h / JTP.cpp` | `jtp.h / jtp.cpp` |
| Ctrl-C on macOS & Linux | broken | fixed (`sigaction` + `SO_RCVTIMEO`) |
| Max message size | 1 packet (~1 KB) | **~91 KB** (auto-fragmented) |
| Encryption | none | **AES-256-GCM** via `--key` |
| Transport modes | 3 | 3 (same) |

---

## Transport Modes

```
┌──────────────┬──────────────┬──────────┬──────────────────────────────┐
│ Mode         │ Transport    │ Root?    │ Through NAT / internet?      │
├──────────────┼──────────────┼──────────┼──────────────────────────────┤
│ RAW          │ IPv4/253     │ yes      │ no — home routers block it   │
│ UDP tunnel   │ UDP/19253    │ no       │ yes                          │
│ QUIC-like    │ UDP/19254    │ no       │ yes + streams + RTT          │
└──────────────┴──────────────┴──────────┴──────────────────────────────┘
```

---

## Wire Format

### JTP base header (7 bytes)

```
Byte  0    1    2    3    4    5    6
     ┌────────┬────┬─────────┬────────┐
     │  seq   │flg │checksum │pay_len │
     └────────┴────┴─────────┴────────┘
      uint16   u8   uint16    uint16
```

Flags: `0x01`=MSG `0x02`=ACK `0x04`=FIN `0x08`=RST `0x10`=FRAG `0x20`=CRYPT

### Fragmentation extension (9 bytes, present when FLAG_FRAG set)

```
Byte  0-3      4-5         6-7         8
     ┌──────────┬──────────┬──────────┬────┐
     │ frag_id  │frag_index│frag_total│rsv │
     └──────────┴──────────┴──────────┴────┘
      uint32     uint16     uint16     u8
```

### Encrypted payload layout

When FLAG_CRYPT is set the payload field contains:
```
[ 12-byte nonce | ciphertext | 16-byte GCM auth tag ]
```

### UDP tunnel frame
```
[ "JTP\x01"(4) | JTP header | [frag ext] | payload ]
```

### QUIC-like frame
```
[ "JTQ\x01"(4) | QuicFrame(6) | JTP header | [frag ext] | payload ]
```

---

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| C++17 compiler | GCC ≥ 9 / Clang ≥ 11 | language |
| CMake | ≥ 3.16 | build |
| OpenSSL | ≥ 1.1 | AES-256-GCM + PBKDF2 |

### Install OpenSSL

```bash
# macOS
brew install openssl@3

# Ubuntu / Debian
sudo apt-get install libssl-dev

# Android NDK  — libssl is bundled in NDK since r21
# iOS          — use OpenSSL-Universal CocoaPod or xcframework
```

---

## Build

```bash
# Linux
sudo apt-get install -y g++ cmake libssl-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# macOS
brew install cmake openssl@3
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build --parallel

# Cross-compile for Ubuntu from macOS (Docker)
docker run --rm -v "$(pwd)":/src -w /src ubuntu:24.04 \
  bash -c "apt-get update -qq && \
           apt-get install -y -qq g++ cmake libssl-dev && \
           cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
           cmake --build build --parallel && \
           cp build/jtp /src/jtp_linux"
```

---

## Usage

### Basic UDP (no encryption)

```bash
# Receiver
./build/jtp --listen-udp

# Sender
./build/jtp --send-udp 1.2.3.4 "hello"
```

### Encrypted UDP

Both sides must use the same passphrase:

```bash
./build/jtp --listen-udp --key "my_secret_pass"
./build/jtp --send-udp 1.2.3.4 "secret message" --key "my_secret_pass"
```

### Large message (auto-fragmented)

```bash
# Send a 50 KB file
./build/jtp --send-udp 1.2.3.4 "$(cat largefile.txt)" --key "pass"

# Or binary via hex (future: --file flag planned)
```

### QUIC with stream ID

```bash
./build/jtp --listen-quic --key "pass"
./build/jtp --send-quic 1.2.3.4 "stream 42 message" --sid 42 --key "pass"
```

### RAW (LAN only, root required)

```bash
sudo ./build/jtp --listen --key "pass"
sudo ./build/jtp --send 192.168.1.10 "LAN message" --key "pass"
```

---

## Firewall

Open ports on the receiver:

```bash
# Ubuntu ufw
sudo ufw allow 19253/udp   # UDP tunnel
sudo ufw allow 19254/udp   # QUIC tunnel

# iptables
sudo iptables -A INPUT -p udp --dport 19253 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 19254 -j ACCEPT
```

Home router: forward UDP 19253 and 19254 to the receiver's internal IP.

---

## Ctrl-C Fix (technical detail)

The previous version used `std::signal()` with default `SA_RESTART` semantics.
On Linux and macOS, `SA_RESTART` causes the kernel to silently restart a
blocked `recvfrom()` after a signal, so Ctrl-C appeared to do nothing.

**Fix applied in v3:**
1. `sigaction()` with `sa_flags = 0` — disables `SA_RESTART`.
2. `SO_RCVTIMEO = 1s` on every socket — `recvfrom()` returns `EAGAIN`
   every second, letting the `while (g_running)` loop check the flag.
3. On Ctrl-C: signal fires → `g_running = false` → next `recvfrom` either
   returns `EINTR` immediately or times out within 1 second.

---

## Roadmap — Messenger + Smart City (MQTT-like)

### Phase 1 — Current (v3)
- [x] RAW / UDP / QUIC-like transport
- [x] Fragmentation (up to ~91 KB)
- [x] AES-256-GCM encryption
- [x] Cross-platform: Linux + macOS

### Phase 2 — Mobile
- [ ] Android: compile `jtp.cpp` as `.so` via NDK + JNI wrapper
- [ ] iOS: compile `jtp.cpp` as `.a` / xcframework + Swift wrapper
- [ ] CMake Android/iOS toolchain files

### Phase 3 — Messenger
- [ ] Session key exchange (ECDH over QUIC stream 0)
- [ ] User identity (Ed25519 signing)
- [ ] Message persistence (SQLite)
- [ ] Push notifications (APNs / FCM bridge)

### Phase 4 — Smart City / MQTT-like broker
- [ ] JTP broker (multi-client fan-out)
- [ ] Topic-based pub/sub using QUIC stream IDs as topic handles
- [ ] QoS levels (fire-and-forget / at-least-once via ACK)
- [ ] TLS mutual auth for device identity

---

## Qt Creator — RAW mode as root

1. Projects → Run → Custom Executable
2. Executable: `/usr/bin/sudo`
3. Arguments: `%{buildDir}/jtp --listen`

UDP/QUIC need no sudo — use a normal run configuration.
