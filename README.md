# Jerboa Transport Protocol (JTP) v2

Experimental Layer-4 datagram protocol over IPv4 (proto=253) with three
interchangeable transport backends.

---

## Transport Modes

```
┌──────────────┬────────────────┬───────────────┬───────────────────────────┐
│ Mode         │ Underlying     │ Root needed?  │ Works through NAT?        │
├──────────────┼────────────────┼───────────────┼───────────────────────────┤
│ RAW          │ IPv4/proto=253 │ Yes (sudo)    │ No — home routers drop it │
│ UDP tunnel   │ UDP/19253      │ No            │ Yes — any router/internet │
│ QUIC-like    │ UDP/19254      │ No            │ Yes + stream-ID + RTT     │
└──────────────┴────────────────┴───────────────┴───────────────────────────┘
```

### Why NAT blocks RAW

Home routers only track TCP/UDP/ICMP state. IPv4 packets with protocol 253
have no port numbers, so the router has no way to know which internal host
should receive the reply — it silently drops them.

The UDP and QUIC tunnel modes solve this by wrapping JTP inside standard
UDP datagrams, which any router can forward and track.

---

## Wire Formats

### JTP Header (7 bytes, big-endian)

```
Byte  0    1    2    3    4    5    6
     ┌────────┬────┬─────────┬────────┐
     │  seq   │flg │checksum │pay_len │
     └────────┴────┴─────────┴────────┘
      uint16   u8   uint16    uint16
```

| Field            | Size | Description                               |
|------------------|------|-------------------------------------------|
| sequence_number  | 2 B  | Monotonic datagram counter                |
| flags            | 1 B  | 0x01=MSG 0x02=ACK 0x04=FIN 0x08=RST      |
| checksum         | 2 B  | CRC-16/CCITT-FALSE (poly=0x1021)          |
| payload_length   | 2 B  | Bytes of payload following the header     |

### UDP tunnel frame

```
[ "JTP\x01"(4) | JTP header(7) | payload ]
```

### QUIC-like frame

```
[ "JTQ\x01"(4) | QuicFrame(6) | JTP header(7) | payload ]
```

QuicFrame (6 bytes, big-endian):

| Field      | Size | Description                          |
|------------|------|--------------------------------------|
| stream_id  | 2 B  | Logical stream (0 = default)         |
| packet_num | 2 B  | Per-stream monotonic counter         |
| rtt_ms     | 2 B  | Last measured RTT in milliseconds    |

---

## Project Structure

```
jtp/
├── CMakeLists.txt   # Cross-platform build (macOS Clang / Linux GCC)
├── JTP.h            # Protocol constants, structs, full public API
├── JTP.cpp          # CRC, serialisation, RAW + UDP + QUIC implementations
├── main.cpp         # CLI: six modes, thread-safe console, signal handling
└── README.md        # This document
```

---

## Build

### Linux (Ubuntu / Debian)

```bash
sudo apt-get install -y g++ cmake
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### macOS

```bash
xcode-select --install
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### Cross-compile for Ubuntu from macOS (Docker)

```bash
docker run --rm -v "$(pwd)":/src -w /src ubuntu:24.04 \
  bash -c "apt-get update -qq && apt-get install -y -qq g++ cmake && \
           cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
           cmake --build build --parallel && cp build/jtp /src/jtp_linux"
```

---

## Usage

### RAW mode — same LAN only, root required

```bash
sudo ./build/jtp --listen
sudo ./build/jtp --send 192.168.1.10 "hello LAN"
```

### UDP tunnel — through NAT / internet, no root

```bash
./build/jtp --listen-udp
./build/jtp --send-udp 203.0.113.5 "hello internet"
```

### QUIC-like tunnel — streams + RTT, no root

```bash
./build/jtp --listen-quic
./build/jtp --send-quic 203.0.113.5 "hello"
./build/jtp --send-quic 203.0.113.5 "stream message" 42
```

### Loopback test (single machine)

```bash
# Terminal 1
./build/jtp --listen-udp

# Terminal 2
./build/jtp --send-udp 127.0.0.1 "udp test"
```

---

## Firewall — open tunnel ports on receiver

### ufw
```bash
sudo ufw allow 19253/udp
sudo ufw allow 19254/udp
```

### iptables
```bash
sudo iptables -A INPUT -p udp --dport 19253 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 19254 -j ACCEPT
```

### Home router port-forward
Forward UDP 19253 and UDP 19254 to the Ubuntu machine's internal IP.

---

## Verify with tcpdump

```bash
sudo tcpdump -i eth0 -n 'ip proto 253' -v    # RAW
sudo tcpdump -i eth0 -n 'udp port 19253' -v  # UDP tunnel
sudo tcpdump -i eth0 -n 'udp port 19254' -v  # QUIC tunnel
```

---

## Qt Creator — run RAW mode as root

1. Projects → Run → Add → Custom Executable
2. Executable: /usr/bin/sudo
3. Arguments:  %{buildDir}/jtp --listen
4. Working dir: %{buildDir}

UDP/QUIC modes need no sudo — use a normal run configuration.
