# DPI Engine - Deep Packet Inspection System in Python

This document explains the full project from basic networking ideas to the
Python code architecture. After reading it, you should understand how a packet
moves through the system and how the engine decides whether to forward or drop
traffic.

---

## Table of Contents

1. What is DPI?
2. Networking Background
3. Project Overview
4. File Structure
5. The Journey of a Packet
6. Deep Dive: Each Component
7. How SNI and HTTP Host Extraction Work
8. How Blocking Works
9. Installing and Running
10. Understanding the Output
11. Testing
12. Resume Summary

---

## 1. What is DPI?

Deep Packet Inspection, or DPI, is a technique used to inspect network packets
more deeply than a normal firewall. A basic firewall may only check source IP,
destination IP, ports, and protocol. A DPI engine also looks into the packet
payload to identify the application or website being accessed.

### Real-World Uses

- Internet service providers can classify traffic by application.
- Companies can block or monitor social media and streaming apps.
- Security tools can detect suspicious traffic patterns.
- Parental control systems can block specific websites or apps.
- Firewalls can enforce app-based policies instead of only IP-based policies.

### What This DPI Engine Does

```text
User Traffic / PCAP File
        |
        v
Python DPI Engine
        |
        +-- Parse packets
        +-- Track flows
        +-- Extract SNI or HTTP Host
        +-- Classify applications
        +-- Apply rules
        +-- Write filtered PCAP
        +-- Generate report
```

The current engine supports offline PCAP filtering and live packet inspection.
Offline mode can actually remove dropped packets from the output PCAP. Live mode
detects and reports decisions, but real live blocking needs OS-level tools such
as `iptables`, `nftables`, NFQUEUE, DNS filtering, or a proxy.

---

## 2. Networking Background

### Network Layers

When data travels across a network, it is wrapped in layers:

```text
+------------------------------------------------------+
| Layer 7: Application | HTTP, TLS, DNS                |
+------------------------------------------------------+
| Layer 4: Transport   | TCP, UDP                      |
+------------------------------------------------------+
| Layer 3: Network     | IPv4 addresses and routing    |
+------------------------------------------------------+
| Layer 2: Data Link   | Ethernet frames and MACs      |
+------------------------------------------------------+
```

This project focuses mainly on IPv4, TCP/UDP, and application payload metadata.

### Packet Structure

A packet is built like nested containers:

```text
+------------------------------------------------------+
| Ethernet Header                                      |
|   +------------------------------------------------+ |
|   | IP Header                                      | |
|   |   +------------------------------------------+ | |
|   |   | TCP/UDP Header                           | | |
|   |   |   +------------------------------------+ | | |
|   |   |   | Payload                            | | | |
|   |   |   | TLS Client Hello / HTTP Request    | | | |
|   |   |   +------------------------------------+ | | |
|   |   +------------------------------------------+ | |
|   +------------------------------------------------+ |
+------------------------------------------------------+
```

The project can also parse raw IPv4 PCAPs that do not have an Ethernet header.

### Five-Tuple

A network flow is identified using five values:

| Field | Example | Meaning |
| --- | --- | --- |
| Source IP | `192.168.1.10` | Sender |
| Destination IP | `157.240.221.35` | Receiver |
| Source Port | `12345` | Client-side port |
| Destination Port | `443` | Service port |
| Protocol | `TCP` | Transport protocol |

All packets with the same five-tuple belong to the same flow. This matters
because if the first packet in a flow is classified as blocked, later packets in
that flow should also be dropped.

### What is SNI?

SNI means Server Name Indication. It appears in the TLS Client Hello message
when a browser starts an HTTPS connection. The payload is encrypted later, but
the requested hostname can often be visible at the beginning of the TLS
handshake.

Example:

```text
TLS Client Hello
  Extensions
    SNI: www.youtube.com
```

The engine tries to extract this hostname and classify it as YouTube, Facebook,
GitHub, or another app.

---

## 3. Project Overview

### What This Project Does

```text
+----------------+      +----------------+      +----------------+
| Input PCAP     | ---> | DPI Engine     | ---> | Filtered PCAP  |
| pcaps/test.pcap|      | Python         |      | output file    |
+----------------+      +----------------+      +----------------+
                         | Parse packets |
                         | Track flows   |
                         | Classify apps |
                         | Apply rules   |
                         | Report stats  |
                         +---------------+
```

### Supported Modes

| Mode | Command | Purpose |
| --- | --- | --- |
| Offline PCAP | `--pcap pcaps/test.pcap` | Reads a capture and writes filtered output |
| Live sniffing | `--iface <interface>` | Inspects live packets and prints decisions |

### Current Capabilities

- Reads PCAP files using `dpkt`
- Parses raw IPv4 and Ethernet IPv4 packets
- Extracts TCP/UDP ports and payloads
- Tracks flows with a five-tuple
- Extracts TLS SNI
- Extracts HTTP `Host` headers
- Classifies app traffic
- Loads rules from YAML
- Blocks by app, domain, or IP
- Writes forwarded packets to a new PCAP
- Tracks forwarded and dropped packet counts
- Includes unit tests for core logic

---

## 4. File Structure

```text
dpi-engine/
├── config/
│   ├── rules.yaml              # App/domain/IP filtering rules
│   └── signatures.yaml         # Reserved for signature expansion
│
├── pcaps/
│   └── test.pcap               # Sample generated capture
│
├── src/
│   ├── main.py                 # CLI entry point
│   │
│   ├── core/
│   │   ├── dpi_engine.py       # Main pipeline controller
│   │   ├── pcap_reader.py      # Reads packets from PCAP
│   │   ├── pcap_writer.py      # Writes filtered packets to PCAP
│   │   ├── packet_parser.py    # Parses IPv4/TCP/UDP packet data
│   │   ├── flow_tracker.py     # Tracks five-tuple flows
│   │   ├── sni_extractor.py    # Extracts TLS SNI hostnames
│   │   ├── http_extractor.py   # Extracts HTTP Host headers
│   │   ├── classifier.py       # Maps domains/payloads to app types
│   │   ├── rule_manager.py     # Loads and applies blocking policy
│   │   ├── rule_engine.py      # Compatibility wrapper
│   │   └── statistics.py       # Builds final report
│   │
│   └── models/
│       ├── packet.py           # RawPacket and ParsedPacket models
│       ├── flow.py             # Flow and FlowKey models
│       ├── rule.py             # Rule model
│       └── enums.py            # Protocol, AppType, Action, FlowState
│
├── tests/
│   ├── test_classifier.py
│   ├── test_dpi_engine.py
│   ├── test_http_extractor.py
│   └── test_rule_manager.py
│
├── generate_pcap.py            # Creates sample PCAP traffic
├── requirements.txt
└── README.md
```

---

## 5. The Journey of a Packet

This section traces one packet through the Python engine.

### Step 1: Read a PCAP File

```python
reader = PcapReader("pcaps/test.pcap")
```

What happens:

1. The PCAP file is opened in binary mode.
2. `dpkt.pcap.Reader` reads the capture metadata.
3. Each packet is yielded as a `RawPacket`.

```text
RawPacket
  timestamp = 1.0
  length    = packet size
  data      = raw packet bytes
```

### Step 2: Parse Packet Headers

```python
packet = self.parser.parse(raw_packet)
```

The parser extracts:

```text
src_ip
dst_ip
src_port
dst_port
protocol
payload
packet_size
```

The parser supports:

- Raw IPv4 packets
- Ethernet packets carrying IPv4
- TCP payloads
- UDP payloads

Packets without application payloads are ignored because this DPI engine needs
payload data for classification.

### Step 3: Track the Flow

```python
flow = self.flow_tracker.add_packet(packet)
```

The flow tracker creates or updates a flow using:

```text
src_ip + dst_ip + src_port + dst_port + protocol
```

Each flow stores:

```text
packet_count
byte_count
app_type
sni
blocked
state
```

### Step 4: Inspect Payload

The engine first tries TLS SNI:

```python
domain = self.sni_extractor.extract(packet.payload)
```

If SNI is not found, it tries plaintext HTTP:

```python
domain = self.http_extractor.extract_host(packet.payload)
```

If no domain is found, the engine falls back to simple payload text matching.
This makes the sample PCAP easy to test and explain.

### Step 5: Classify the Application

```python
app_type = self.classifier.classify(classification_text)
```

Examples:

| Input text | AppType |
| --- | --- |
| `www.youtube.com` | `YOUTUBE` |
| `www.facebook.com` | `FACEBOOK` |
| `github.com` | `GITHUB` |
| `unknown.example` | `UNKNOWN` |

### Step 6: Check Rules

```python
action = self.rule_manager.evaluate(
    app_type=app_type,
    domain=domain,
    src_ip=packet.src_ip,
    dst_ip=packet.dst_ip,
)
```

The rule manager checks:

1. Is the source or destination IP blocked?
2. Is the domain blocked?
3. Is the app configured as `DROP`?
4. If no rule matches, default to `FORWARD`.

### Step 7: Forward or Drop

```python
if action == Action.DROP:
    continue

writer.write_packet(raw_packet)
```

In offline mode:

- `FORWARD` packets are written to the output PCAP.
- `DROP` packets are skipped.

So if Facebook is blocked, Facebook packets are removed from
`output/filtered.pcap`.

---

## 6. Deep Dive: Each Component

### `DpiEngine`

`src/core/dpi_engine.py` is the main controller. It connects all components:

```text
PacketParser
FlowTracker
SNIExtractor
HTTPExtractor
Classifier
RuleManager
Statistics
PcapWriter
```

This class keeps `main.py` small and makes the core DPI logic easier to test.

### `PcapReader`

`src/core/pcap_reader.py` streams packets from a PCAP file and returns
`RawPacket` objects.

It also exposes the PCAP link type so the writer can preserve the same format in
the output file.

### `PcapWriter`

`src/core/pcap_writer.py` writes packets that are allowed by policy.

It preserves:

- packet bytes
- timestamps
- link-layer type

### `PacketParser`

`src/core/packet_parser.py` uses `dpkt` to decode packet bytes into structured
data.

The parser currently supports:

- IPv4
- TCP
- UDP
- Raw IPv4 captures
- Ethernet IPv4 captures

### `FlowTracker`

`src/core/flow_tracker.py` stores conversations between machines. It ensures
that multiple packets from the same connection are grouped together.

The engine uses this to apply flow-level blocking.

### `SNIExtractor`

`src/core/sni_extractor.py` inspects TLS Client Hello payloads and looks for the
SNI extension.

This is useful for HTTPS traffic where the packet payload is encrypted after the
handshake, but the requested hostname may be visible in the first TLS packet.

### `HTTPExtractor`

`src/core/http_extractor.py` checks plaintext HTTP requests and extracts the
`Host` header.

Example:

```http
GET / HTTP/1.1
Host: www.facebook.com
```

The extractor returns:

```text
www.facebook.com
```

### `Classifier`

`src/core/classifier.py` maps domain names or payload signatures to application
types.

Supported app labels include:

- YouTube
- Facebook
- GitHub
- Instagram
- Netflix
- Telegram
- TikTok
- Unknown

### `RuleManager`

`src/core/rule_manager.py` loads filtering policy from YAML and makes the final
allow/drop decision.

It supports:

- app rules
- blocked domains
- blocked IP addresses
- default allow behavior

### `Statistics`

`src/core/statistics.py` counts:

- raw packets
- parsed packets
- flows
- total bytes
- forwarded packets
- dropped packets
- application breakdown
- dropped application breakdown
- dropped domains

---

## 7. How SNI and HTTP Host Extraction Work

### TLS SNI Path

For HTTPS traffic, the engine tries:

```text
TCP payload
    |
    v
TLS Record
    |
    v
TLS Handshake
    |
    v
Client Hello
    |
    v
Extensions
    |
    v
SNI hostname
```

If the hostname is found, the classifier uses it directly.

### HTTP Host Path

For plaintext HTTP traffic, the engine looks for:

```text
Host: example.com
```

This is useful for simple test PCAP files and non-HTTPS traffic.

### Fallback Payload Matching

If neither SNI nor HTTP Host is available, the engine decodes the payload as
text and checks whether known words such as `facebook`, `youtube`, or `github`
appear.

This is not as strong as true DPI signatures, but it is useful for learning and
for small sample captures.

---

## 8. How Blocking Works

Rules are loaded from `config/rules.yaml`.

```yaml
rules:
  - app: YOUTUBE
    action: FORWARD
    enabled: true

  - app: FACEBOOK
    action: DROP
    enabled: true

  - app: GITHUB
    action: FORWARD
    enabled: true

blocked_domains:
  - facebook.com
  - fbcdn.net

blocked_ips:
  - 157.240.221.35
```

### Rule Decision Order

```text
Packet
  |
  +-- Check blocked IPs
  |
  +-- Check blocked domains
  |
  +-- Check app rules
  |
  +-- Default: FORWARD
```

### Flow-Level Blocking

If a flow is blocked once:

```text
flow.blocked = True
```

Then later packets in that same flow are dropped automatically, even if those
later packets do not contain the original SNI or HTTP Host value.

This is important because many later packets in a connection may be encrypted or
may not contain enough payload information to classify again.

---

## 9. Installing and Running

### Install Dependencies

```bash
python3 -m pip install -r requirements.txt
```

### Generate Sample PCAP

```bash
python3 generate_pcap.py
```

This creates:

```text
pcaps/test.pcap
```

### Run Offline Filtering

```bash
python3 -m src.main --pcap pcaps/test.pcap --output output/filtered.pcap
```

With custom rules:

```bash
python3 -m src.main \
  --pcap pcaps/test.pcap \
  --output output/filtered.pcap \
  --rules config/rules.yaml
```

### Run Live Inspection

```bash
python3 -m src.main --iface <network-interface>
```

Example:

```bash
python3 -m src.main --iface wlp0s20f3
```

Live mode may require elevated permissions depending on your operating system.
It detects and reports decisions, but does not enforce real-time blocking by
itself.

---

## 10. Understanding the Output

Sample output:

```text
[DETECTED] www.youtube.com -> YOUTUBE -> FORWARD
[DETECTED] github.com -> GITHUB -> FORWARD
[DETECTED] www.facebook.com -> FACEBOOK -> DROP

[*] Filtered PCAP written to: output/filtered.pcap

===== DPI REPORT =====
Raw Packets   : 4
Parsed Packets: 4
Total Flows   : 3
Total Bytes   : 407
Forwarded     : 3
Dropped       : 1

Application Breakdown:
YOUTUBE: 1
GITHUB: 1
FACEBOOK: 1

Dropped Applications:
FACEBOOK: 1

Dropped Domains:
www.facebook.com: 1
======================
```

Meaning:

- `Raw Packets`: packets read from the PCAP.
- `Parsed Packets`: packets with usable IPv4/TCP/UDP payload.
- `Total Flows`: unique five-tuple flows.
- `Forwarded`: packets written to the filtered PCAP.
- `Dropped`: packets skipped because of policy.
- `Application Breakdown`: detected app categories.
- `Dropped Domains`: domains removed from the output.

To verify packet counts:

```bash
python3 -c "import dpkt; f=open('output/filtered.pcap','rb'); p=dpkt.pcap.Reader(f); print(sum(1 for _ in p)); f.close()"
```

---

## 11. Testing

Run all tests:

```bash
python3 -m pytest
```

Current tests cover:

- app classification
- HTTP Host extraction
- YAML rule loading
- app/domain/IP blocking
- flow-level blocking
- DPI engine packet decisions

---

## 12. Resume Summary

Built a Python-based Deep Packet Inspection engine that parses PCAP traffic,
tracks network flows, extracts TLS SNI and HTTP Host metadata, classifies
application traffic, applies configurable app/domain/IP filtering rules, writes
filtered PCAP outputs, and generates traffic statistics with unit-tested core
components.

Short version:

```text
Python DPI and PCAP filtering engine with flow tracking, SNI/HTTP Host
extraction, configurable rule-based blocking, filtered PCAP output, and tests.
```
