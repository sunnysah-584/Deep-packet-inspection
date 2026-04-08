# DPI Engine — Java Port

A fully-featured **Deep Packet Inspection** system ported from C++ to Java.
Supports both single-threaded and multi-threaded processing of PCAP capture files.

---

## Project Structure

```
dpi-engine/
├── pom.xml                                      ← Maven build file
├── generate_test_pcap.py                        ← Creates test PCAP data (no deps needed)
│
└── src/main/java/com/dpi/
    │
    ├── Main.java                                ← Entry point + CLI argument parsing
    │
    ├── model/
    │   ├── AppType.java      ← Application type enum (YouTube, TikTok, etc.)
    │   ├── FiveTuple.java    ← Connection identifier (src/dst IP+port + protocol)
    │   ├── Flow.java         ← Per-connection state (SNI, app type, blocked flag)
    │   ├── RawPacket.java    ← Raw bytes from PCAP + metadata
    │   └── ParsedPacket.java ← Parsed Ethernet/IP/TCP/UDP fields + payload pointer
    │
    ├── pcap/
    │   ├── PcapReader.java   ← Reads .pcap files (global header + packet records)
    │   └── PcapWriter.java   ← Writes .pcap files (forwarded packets only)
    │
    ├── parser/
    │   └── PacketParser.java ← Parses Ethernet → IPv4 → TCP/UDP headers
    │
    ├── sni/
    │   ├── SniExtractor.java      ← Extracts hostname from TLS Client Hello
    │   └── HttpHostExtractor.java ← Extracts Host header from HTTP requests
    │
    ├── rules/
    │   └── RuleManager.java  ← IP / AppType / domain blocking rules
    │
    ├── tracker/
    │   └── ConnectionTracker.java ← Per-thread flow table + SNI classification
    │
    ├── engine/
    │   ├── SimpleDpiEngine.java        ← Single-threaded engine (like main_working.cpp)
    │   ├── MultiThreadedDpiEngine.java ← Multi-threaded engine (like dpi_mt.cpp)
    │   ├── LoadBalancerThread.java     ← Distributes packets to FastPath threads
    │   ├── FastPathThread.java         ← DPI worker thread
    │   └── OutputWriterThread.java     ← Serialises forwarded packets to PCAP
    │
    ├── report/
    │   └── ReportGenerator.java  ← Prints final statistics report
    │
    └── util/
        ├── ThreadSafeQueue.java  ← Bounded blocking queue (producer-consumer)
        └── DpiStats.java         ← Atomic counters (packets, bytes, dropped, etc.)
```

---

## Build

Requires **Java 11+** and **Maven 3.6+**.

```bash
# Compile and package (creates target/dpi-engine.jar)
mvn clean package -q

# Run unit tests
mvn test
```

---

## Generate Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with YouTube, Facebook, TikTok, GitHub traffic
```

---

## Run

**Basic (multi-threaded, no blocking):**
```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap
```

**Single-threaded mode:**
```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap --simple
```

**Block YouTube and TikTok, block a specific IP:**
```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap \
    --block-app YOUTUBE \
    --block-app TIKTOK \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure thread counts:**
```bash
java -jar target/dpi-engine.jar input.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB threads × 4 FP threads = 16 processing threads
```

---

## CLI Reference

| Argument | Description | Default |
|----------|-------------|---------|
| `--simple` | Single-threaded engine | off (multi-threaded) |
| `--lbs N` | Number of Load Balancer threads | 2 |
| `--fps N` | Number of FastPath threads per LB | 2 |
| `--block-app NAME` | Block by app (YOUTUBE, TIKTOK, FACEBOOK…) | none |
| `--block-ip IP` | Block all traffic from a source IP | none |
| `--block-domain STR` | Block any SNI containing this substring | none |

Valid app names: `UNKNOWN, HTTP, HTTPS, DNS, GOOGLE, YOUTUBE, FACEBOOK, TWITTER,
INSTAGRAM, TIKTOK, NETFLIX, AMAZON, GITHUB, REDDIT, WHATSAPP, TELEGRAM, SPOTIFY, TWITCH, MICROSOFT, APPLE`

---

## Architecture

### Single-Threaded (--simple)

```
PCAP File → PcapReader → PacketParser → ConnectionTracker → PcapWriter
                                              ↓
                                         RuleManager (block/forward)
```

### Multi-Threaded

```
PcapReader (main thread)
    │
    │  hash(5-tuple) % numLbs
    ▼
LoadBalancerThread × numLbs
    │
    │  hash(5-tuple) % numFps
    ▼
FastPathThread × (numLbs × numFps)
    │  each has its own ConnectionTracker (no locking on flow state)
    │
    ▼
OutputWriterThread → PcapWriter
```

### Why Consistent Hashing?

All packets belonging to the same TCP connection (same 5-tuple) must land on
the **same FastPath thread**. This is critical because:

- The TLS Client Hello (which contains the SNI) may arrive on packet #4 of a connection
- Packets #1–3 (SYN, SYN-ACK, ACK) have no SNI yet
- The FastPath thread needs to see ALL packets of a flow to correctly classify and block it
- Without consistent routing, the SYN might go to FP-0 and the Client Hello to FP-2 — the SNI would never be associated with the flow

Consistent hashing solves this: `hash(5-tuple)` always maps to the same FP thread.

---

## How SNI Extraction Works

Even though HTTPS traffic is encrypted, the **first packet** of every connection
contains the target domain name in plaintext inside the **TLS Client Hello**:

```
TLS Record (ContentType=0x16 Handshake)
└── Handshake (Type=0x01 Client Hello)
    └── Extensions
        └── Extension Type 0x0000 (SNI)
            └── Hostname: "www.youtube.com"  ← extracted here
```

The `SniExtractor` navigates this binary structure byte-by-byte to find the hostname.

---

## Blocking Flow

```
Packet arrives
      │
      ▼
Is source IP in blocked list?   ──Yes──► DROP (mark flow blocked)
      │ No
      ▼
Is app type in blocked list?    ──Yes──► DROP
      │ No
      ▼
Does SNI match blocked domain?  ──Yes──► DROP
      │ No
      ▼
FORWARD to output PCAP
```

Once a flow is marked blocked, **all subsequent packets** of that connection are
dropped immediately without re-inspection.

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                    ║
║  Load Balancers:  2    FPs per LB:  2    Total FPs:  4           ║
╚══════════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YOUTUBE
[Rules] Blocked IP: 192.168.1.50

╔══════════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                           ║
╠══════════════════════════════════════════════════════════════════╣
║ Total Packets:               77                                  ║
║ Total Bytes:               5738                                  ║
║ TCP Packets:                 73                                  ║
║ UDP Packets:                  4                                  ║
╠══════════════════════════════════════════════════════════════════╣
║ Forwarded:                   69                                  ║
║ Dropped:                      8                                  ║
╠══════════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                          ║
╠══════════════════════════════════════════════════════════════════╣
║ HTTPS          39  50.6%  ##########                             ║
║ YOUTUBE         4   5.2%  # (BLOCKED)                            ║
║ DNS             4   5.2%  #                                      ║
║ FACEBOOK        3   3.9%                                         ║
╠══════════════════════════════════════════════════════════════════╣
║                   DETECTED DOMAINS / SNIs                        ║
╠══════════════════════════════════════════════════════════════════╣
║   www.youtube.com                       -> YOUTUBE               ║
║   www.facebook.com                      -> FACEBOOK              ║
║   github.com                            -> GITHUB                ║
╚══════════════════════════════════════════════════════════════════╝
```
