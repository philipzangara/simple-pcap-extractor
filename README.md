# Simple PCAP Extractor

A command-line tool for extracting network metadata and file artifacts from PCAP files. Built for SOC analysts who need quick visibility into capture files without opening Wireshark.

## Features

- Protocol breakdown by packet count
- Top talkers by source IP
- Bidirectional connection tracking with packet count, byte count, and duration
- Top 10 connections ranked by bytes transferred
- HTTP file extraction with MD5, SHA256, MIME type detection, and file size
- Terminal and JSON output modes

## Requirements

- Python 3.10+
- Windows: `python-magic-bin`, `scapy`
- Linux/Mac: `python-magic` + libmagic (`apt install libmagic1` or `brew install libmagic`), `scapy`

## Installation

```bash
git clone https://github.com/philipzangara/simple-pcap-extractor

cd simple-pcap-extractor
python -m venv .venv

# Windows
.venv\Scripts\Activate.ps1

# Linux/Mac
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

```bash
# Terminal output
python simple_pcap_extractor.py capture.pcap

# JSON output
python simple_pcap_extractor.py capture.pcap --output json
```

Supports `.pcap` and `.cap` files.

## Output

**Terminal mode** prints six sections: protocol counts, top talkers, all connections, top 10 connections by bytes, and extracted files with hashes.

**JSON mode** outputs a single object with the same data. Useful for piping into other tools or ingesting into a SIEM.

## File Structure

```
simple-pcap-extractor/
├── simple_pcap_extractor.py  # CLI entry point
├── extractor.py              # Packet parsing and HTTP file extraction
├── analysis_result.py        # Data container and JSON serialization
├── display.py                # Terminal output formatting
├── helpers.py                # Hashing, file type detection, connection key normalization
├── requirements.txt
└── README.md
```

## Design Notes

Packets are processed one at a time using Scapy's `PcapReader`. This keeps memory usage flat regardless of file size.

Connections are tracked as bidirectional. A packet from `A:1234 → B:80` and a reply from `B:80 → A:1234` map to the same connection entry.

HTTP file extraction pulls response bodies from packets with an `HTTPResponse` layer. Files are identified by MIME type using magic bytes, not file extension. MD5 and SHA256 are computed for each extracted body.

## Part of the Simple Tools Series

- [Simple Phishing Analyzer](https://github.com/philipzangara/simple-phishing-analyzer)
- [Simple IOC Lookup](https://github.com/philipzangara/simple-ioc-lookup)
- [Simple Log Parser](https://github.com/philipzangara/simple-log-parser)
- Simple PCAP Extractor