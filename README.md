# Python DPI Engine

A Python-based Deep Packet Inspection and PCAP filtering engine. It reads packet
captures, parses network traffic, identifies application traffic, applies
policy rules, and writes a filtered output PCAP.

This project is inspired by packet analyzer / firewall pipelines: read traffic,
inspect payload metadata, classify the application, decide allow/drop, and
report what happened.

## Features

- Reads packets from PCAP files
- Supports live packet sniffing mode
- Parses IPv4 TCP/UDP packets
- Tracks flows using the 5-tuple
- Extracts TLS SNI from HTTPS Client Hello packets
- Extracts HTTP `Host` headers from plaintext HTTP traffic
- Classifies traffic as YouTube, Facebook, GitHub, Instagram, Netflix,
  Telegram, TikTok, or Unknown
- Loads filtering rules from `config/rules.yaml`
- Blocks by app, domain, or IP address
- Applies flow-level blocking after a flow is marked as dropped
- Writes forwarded packets to a filtered output PCAP
- Generates packet, flow, app, forwarded, and dropped statistics
- Includes unit tests for core components

## Architecture

```text
Input PCAP / Live Packet
        |
        v
PcapReader / Scapy
        |
        v
PacketParser
        |
        v
FlowTracker
        |
        v
SNIExtractor / HTTPExtractor
        |
        v
Classifier
        |
        v
RuleManager
        |
        v
PcapWriter + Statistics
```

Main modules:

- `src/core/dpi_engine.py`: runs the full DPI pipeline
- `src/core/rule_manager.py`: loads and applies allow/drop rules
- `src/core/packet_parser.py`: parses raw packets into structured packets
- `src/core/flow_tracker.py`: tracks 5-tuple network flows
- `src/core/sni_extractor.py`: extracts TLS SNI
- `src/core/http_extractor.py`: extracts HTTP Host headers
- `src/core/classifier.py`: maps domains/payload signatures to apps
- `src/core/pcap_reader.py`: reads PCAP files
- `src/core/pcap_writer.py`: writes filtered PCAP files
- `src/core/statistics.py`: builds the final report

## Install

```bash
python3 -m pip install -r requirements.txt
```

## Run Offline PCAP Filtering

```bash
python3 -m src.main --pcap pcaps/test.pcap --output output/filtered.pcap
```

Expected sample behavior:

```text
[DETECTED] YOUTUBE -> YOUTUBE -> FORWARD
[DETECTED] GITHUB -> GITHUB -> FORWARD
[DETECTED] FACEBOOK -> FACEBOOK -> DROP

===== DPI REPORT =====
Raw Packets   : 4
Parsed Packets: 4
Forwarded     : 3
Dropped       : 1
```

The output file contains only forwarded packets:

```text
output/filtered.pcap
```

## Run Live Sniffing

```bash
python3 -m src.main --iface <network-interface>
```

Example:

```bash
python3 -m src.main --iface wlp0s20f3
```

Live mode currently detects and reports policy decisions. True live blocking
would require OS-level enforcement such as `iptables`, `nftables`, NFQUEUE, DNS
blocking, or a proxy.

## Configure Rules

Rules live in `config/rules.yaml`.

```yaml
rules:
  - app: FACEBOOK
    action: DROP
    enabled: true

blocked_domains:
  - facebook.com

blocked_ips:
  - 157.240.221.35
```

Run with a custom rules file:

```bash
python3 -m src.main --pcap pcaps/test.pcap --rules config/rules.yaml
```

## Run Tests

```bash
python3 -m pytest
```

## Resume Description

Built a Python-based Deep Packet Inspection engine that parses PCAP traffic,
tracks network flows, classifies application traffic using SNI, HTTP Host, and
payload signatures, applies configurable rule-based filtering, and writes
filtered PCAP outputs with traffic statistics.
