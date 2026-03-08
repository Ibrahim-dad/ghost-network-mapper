# Ghost Network Mapper

## Overview
A cybersecurity tool that scans local networks using Nmap to discover active devices, identify open ports, detect operating systems, and visualize network topology.

## Project Structure
```
ghost-network-mapper/
├── scanner/
│   ├── network_scan.py    # Host discovery using Nmap ping scan
│   └── port_scan.py       # Port scanning and OS detection
├── visualizer/
│   └── graph.py           # Network topology graph with NetworkX/Matplotlib
├── reports/               # Generated JSON reports and topology images
├── utils/
│   └── logger.py          # Centralized logging configuration
├── main.py                # CLI entry point with argparse
└── requirements.txt       # Python dependencies
```

## Tech Stack
- **Language**: Python 3.11
- **Network Scanning**: python-nmap (wrapper for Nmap)
- **Graph Visualization**: NetworkX + Matplotlib
- **System Dependency**: nmap (installed via Nix)

## Usage
```bash
python main.py --network 192.168.1.0/24                    # Host discovery only
python main.py --network 192.168.1.0/24 --ports            # With port scanning
python main.py --network 192.168.1.0/24 --ports --os       # With OS detection
python main.py --network 192.168.1.0/24 --ports --visualize  # With topology graph
```

## Key Features
- Network host discovery (ping scan)
- Port scanning with automatic SYN-to-TCP-connect fallback (no root required)
- OS fingerprinting (requires root/sudo)
- MAC address and vendor detection
- JSON report generation (timestamped)
- Network topology graph visualization (PNG)
- Clean CLI with argparse

## Notes
- Port scanning falls back from SYN scan to TCP connect scan when root privileges are unavailable
- OS detection requires root privileges; gracefully handles permission errors
- Reports saved to `reports/` directory with timestamps
- Topology graphs saved as `reports/network_topology.png`
