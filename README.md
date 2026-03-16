# Jerboa Transport Protocol (JTP)

> An experimental Layer-4 datagram protocol carried over IPv4 raw sockets
> (IP protocol number 253, IANA experimental range per RFC 3692).

---

## Table of Contents

1. [Protocol Specification](#protocol-specification)
2. [Project Structure](#project-structure)
3. [Prerequisites](#prerequisites)
4. [Build Instructions](#build-instructions)
5. [Usage](#usage)
6. [Qt Creator Integration](#qt-creator-integration)
7. [Design Notes](#design-notes)
8. [Security Considerations](#security-considerations)

---

## Protocol Specification

### Wire Header (7 bytes, network byte-order / big-endian)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Sequence Number        |     Flags     |   Checksum Hi |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Checksum Lo  |        Payload Length         |  Payload ...  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field            | Offset | Size   | Description                                   |
|------------------|--------|--------|-----------------------------------------------|
| `sequence_number`| 0      | 2 bytes| Monotonically increasing datagram counter      |
| `flags`          | 2      | 1 byte | `0x01` = MSG (payload present), `0x02` = ACK  |
| `checksum`       | 3      | 2 bytes| CRC-16/CCITT-FALSE over zeroed header+payload  |
| `payload_length` | 5      | 2 bytes| Byte-length of the following payload           |

### Checksum Algorithm

CRC-16/CCITT-FALSE:
- Polynomial : `0x1021`
- Initial    : `0xFFFF`
- Reflection : none
- Final XOR  : none

The checksum is computed over the full packet with the two checksum bytes set
to `0x00`, then written back into bytes [3..4] in big-endian order.

---

## Project Structure

```
jtp/
├── CMakeLists.txt   # Cross-platform build (macOS/Linux, Clang/GCC)
├── JTP.h            # Protocol constants, Header struct, public API
├── JTP.cpp          # CRC, serialisation, raw-socket helpers
├── main.cpp         # CLI: --listen / --send, thread-safe console
└── README.md        # This document
```

---

## Prerequisites

| Requirement | macOS | Linux |
|-------------|-------|-------|
| C++ compiler | Xcode CLT (`clang++`) ≥ 13 | GCC ≥ 9 or Clang ≥ 11 |
| CMake | ≥ 3.16 | ≥ 3.16 |
| Root access | `sudo` | `sudo` or `CAP_NET_RAW` |

---

## Build Instructions

### Terminal

```bash
# 1. Clone / extract the source tree
cd jtp/

# 2. Configure
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# 3. Build
cmake --build build --parallel

# The binary is at: build/jtp
```

### Qt Creator

1. **Open project**: *File → Open File or Project* → select `CMakeLists.txt`
2. Choose a kit that matches your platform (Desktop Qt / CMake kit)
3. Click **Configure Project**
4. Build with **Ctrl+B** (or ⌘+B on macOS)

---

## Usage

> **Root privileges are required** – raw sockets are a privileged operation.

### Listener

```bash
sudo ./build/jtp --listen
```

Output example:
```
[INFO]  Opening raw socket (proto=253)…
[INFO]  Listening for JTP datagrams (Ctrl-C to stop)…
[RECV]  seq=1 flags=0x1 payload="Hello, Jerboa!"
```

### Sender

```bash
sudo ./build/jtp --send 127.0.0.1 "Hello, Jerboa!"
```

Output example:
```
[INFO]  Opening raw socket (proto=253)…
[INFO]  Sending 14 byte(s) to 127.0.0.1 …
[INFO]  Datagram sent successfully.
```

### Loopback testing (two terminals on the same machine)

```bash
# Terminal 1
sudo ./build/jtp --listen

# Terminal 2
sudo ./build/jtp --send 127.0.0.1 "ping"
sudo ./build/jtp --send 127.0.0.1 "hello from JTP"
```

---

## Qt Creator Integration

Qt Creator cannot directly elevate a process, but there are two clean
approaches:

### Option A – Custom Executable run configuration

1. *Projects → Run* tab → **Add** → *Custom Executable*
2. **Executable**: `/usr/bin/sudo`
3. **Arguments**: `%{buildDir}/jtp --listen`
4. **Working directory**: `%{buildDir}`

### Option B – Integrated terminal

Press **Alt+3** (Application Output) or open *Tools → Terminal*, then:

```bash
sudo %{buildDir}/jtp --listen
```

### Option C – setuid-root (development only, macOS/Linux)

```bash
sudo chown root:wheel ./build/jtp
sudo chmod u+s ./build/jtp
# Now Qt Creator can run it without a wrapper
./build/jtp --listen
```

⚠️ Never deploy a setuid-root binary in production.

---

## Design Notes

### Platform differences

| Concern | macOS | Linux |
|---------|-------|-------|
| `IP_HDRINCL` on send | Kernel adds IP header automatically when not set | Same; explicit `setsockopt(IP_HDRINCL, 0)` for clarity |
| Received buffer | Includes IP header (must be stripped) | Includes IP header (must be stripped) |
| IP header struct | `struct ip` (`netinet/ip.h`) | `struct iphdr` (`netinet/ip.h`) |
| IHL field access | `ip_hl` | `ihl` |

We unify both by reading the raw first byte directly (`byte[0] & 0x0F`),
avoiding struct-field differences entirely.

### Thread-safe output

All console writes are serialised through a single `std::mutex`
(`console::g_print_mutex`).  This makes the listener safe to extend with
a background receiver thread without interleaved output.

### Checksum scope

The CRC-16 covers both the header and the payload, so any bit-flip in
either is detected with high probability (Hamming distance ≥ 4 for
messages up to 32,767 bytes).

---

## Security Considerations

- JTP is an **experimental protocol** and provides **no encryption**,
  **no authentication**, and **no replay protection**.
- Raw sockets bypass the normal TCP/IP firewall rules on some
  configurations — use only on trusted networks or loopback.
- The application validates the checksum before processing any received
  packet, preventing trivially malformed packets from causing issues.
