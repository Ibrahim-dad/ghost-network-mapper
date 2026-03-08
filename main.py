"""
Ghost Network Mapper
====================
A cybersecurity tool that scans a local network using Nmap to discover
active devices, identify open ports, detect operating systems, and
visualize the network topology.

Usage:
    python main.py --network 192.168.1.0/24
    python main.py --network 192.168.1.0/24 --ports
    python main.py --network 192.168.1.0/24 --ports --os
    python main.py --network 192.168.1.0/24 --ports --os --visualize
"""

import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime

from scanner.network_scan import discover_hosts
from scanner.port_scan import scan_ports, detect_os
from visualizer.graph import visualize_network
from utils.logger import setup_logger

logger = setup_logger()


def save_report(results, output_dir="reports"):
    """Save scan results to a timestamped JSON report file.

    Args:
        results: Dict containing all scan results.
        output_dir: Directory to save the report.

    Returns:
        Path to the saved report file.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(results, f, indent=4)

    logger.info(f"Report saved to {filepath}")
    return filepath


def parse_arguments():
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="Ghost Network Mapper",
        description="Scan a local network to discover devices, open ports, and OS information.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --network 192.168.1.0/24
  python main.py --network 192.168.1.0/24 --ports
  python main.py --network 192.168.1.0/24 --ports --os
  python main.py --network 192.168.1.0/24 --ports --os --visualize
        """
    )
    parser.add_argument(
        "--network", "-n",
        required=True,
        help="Target network range in CIDR notation (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "--ports", "-p",
        action="store_true",
        help="Enable port scanning on discovered hosts"
    )
    parser.add_argument(
        "--os",
        action="store_true",
        dest="detect_os",
        help="Enable OS detection on discovered hosts (may require root)"
    )
    parser.add_argument(
        "--visualize", "-v",
        action="store_true",
        help="Generate a network topology graph"
    )
    parser.add_argument(
        "--port-range",
        default="1-1024",
        help="Port range to scan (default: 1-1024)"
    )
    return parser.parse_args()


def print_banner():
    """Display the application banner."""
    banner = """\033[32m
    ░██████╗░██╗░░██╗░█████╗░░██████╗████████╗
    ██╔════╝░██║░░██║██╔══██╗██╔════╝╚══██╔══╝
    ██║░░██╗░███████║██║░░██║╚█████╗░░░░██║░░░
    ██║░░╚██╗██╔══██║██║░░██║░╚═══██╗░░░██║░░░
    ╚██████╔╝██║░░██║╚█████╔╝██████╔╝░░░██║░░░
    ░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═════╝░░░░╚═╝░░░

    👻  N E T W O R K   M A P P E R  👻
    \033[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    \033[35m⟐  Stealth Recon  ⟐  Port Hunter  ⟐  OS Ghost
    \033[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    \033[36m   [ v1.0 | by ibrahim | coded in the shadows ]
    \033[0m"""
    print(banner)


def print_host_summary(host):
    """Print a formatted summary of a single host."""
    G = "\033[32m"
    C = "\033[36m"
    M = "\033[35m"
    Y = "\033[33m"
    D = "\033[90m"
    R = "\033[0m"

    state = host.get("state", "Unknown")
    state_icon = "🟢" if state == "up" else "🔴"

    print(f"\n  {D}┌──────────────────────────────────────────────┐{R}")
    print(f"  {D}│{R} 👻 {G}{host['ip']:<20}{R} {state_icon} {C}{state}{R}")
    print(f"  {D}├──────────────────────────────────────────────┤{R}")
    print(f"  {D}│{R}  {D}├─{R} {M}hostname{R}  → {host.get('hostname', 'Unknown')}")
    if host.get("mac"):
        print(f"  {D}│{R}  {D}├─{R} {M}mac{R}       → {host['mac']}")
    if host.get("vendor"):
        print(f"  {D}│{R}  {D}├─{R} {M}vendor{R}    → {host['vendor']}")

    os_info = host.get("os", {})
    if os_info.get("os_name") and os_info["os_name"] != "Unknown":
        print(f"  {D}│{R}  {D}├─{R} {M}os{R}        → {os_info['os_name']} {D}({os_info.get('os_accuracy', 0)}%){R}")

    ports = host.get("ports", [])
    if ports:
        print(f"  {D}│{R}  {D}└─{R} {Y}⚡ open ports [{len(ports)}]{R}")
        for p in ports:
            svc = p.get("service", "unknown")
            print(f"  {D}│{R}       {G}»{R} {p['port']:>5}{D}/{R}{C}{svc:<15}{R} {D}[{p['state']}]{R}")

    print(f"  {D}└──────────────────────────────────────────────┘{R}")


def main():
    """Main entry point for Ghost Network Mapper."""
    print_banner()
    args = parse_arguments()

    # Validate the network range input
    try:
        ipaddress.ip_network(args.network, strict=False)
    except ValueError as e:
        logger.error(f"Invalid network range '{args.network}': {e}")
        sys.exit(1)

    logger.info(f"Target network: {args.network}")
    scan_start = datetime.now()

    # Phase 1: Host Discovery
    logger.info("Phase 1: Host Discovery")
    try:
        hosts = discover_hosts(args.network)
    except Exception as e:
        logger.error(f"Host discovery failed: {e}")
        sys.exit(1)

    if not hosts:
        logger.warning("No active hosts found on the network.")
        sys.exit(0)

    # Phase 2: Port Scanning (optional)
    if args.ports:
        logger.info("Phase 2: Port Scanning")
        for host in hosts:
            try:
                host["ports"] = scan_ports(host["ip"], args.port_range)
            except Exception as e:
                logger.warning(f"Port scan failed for {host['ip']}: {e}")
                host["ports"] = []

    # Phase 3: OS Detection (optional)
    if args.detect_os:
        logger.info("Phase 3: OS Detection")
        for host in hosts:
            try:
                host["os"] = detect_os(host["ip"])
            except Exception as e:
                logger.warning(f"OS detection failed for {host['ip']}: {e}")
                host["os"] = {"os_name": "Unknown", "os_accuracy": 0, "os_family": "Unknown"}

    scan_end = datetime.now()
    duration = (scan_end - scan_start).total_seconds()

    G = "\033[32m"
    C = "\033[36m"
    M = "\033[35m"
    D = "\033[90m"
    R = "\033[0m"
    B = "\033[1m"

    print(f"\n  {G}{'▓' * 50}{R}")
    print(f"  {G}▓{R}  👻  {B}{G}S C A N   C O M P L E T E{R}  👻              {G}▓{R}")
    print(f"  {G}{'▓' * 50}{R}")
    print(f"  {D}┌──────────────────────────────────────────────┐{R}")
    print(f"  {D}│{R}  {M}⟐{R} target    → {C}{args.network}{R}")
    print(f"  {D}│{R}  {M}⟐{R} ghosts    → {G}{len(hosts)} host(s) found{R}")
    print(f"  {D}│{R}  {M}⟐{R} elapsed   → {C}{duration:.2f}s{R}")
    print(f"  {D}└──────────────────────────────────────────────┘{R}")

    for host in hosts:
        print_host_summary(host)

    print(f"\n  {G}{'▓' * 50}{R}")

    # Build report data
    report = {
        "scan_info": {
            "network": args.network,
            "timestamp": scan_start.isoformat(),
            "duration_seconds": duration,
            "port_scan_enabled": args.ports,
            "os_detection_enabled": args.detect_os,
            "port_range": args.port_range if args.ports else None
        },
        "hosts": hosts
    }

    # Save JSON report
    report_path = save_report(report)
    logger.info(f"Scan complete. Report: {report_path}")

    # Phase 4: Visualization (optional)
    if args.visualize:
        logger.info("Phase 4: Generating Network Topology Graph")
        try:
            graph_path = visualize_network(hosts)
            logger.info(f"Topology graph: {graph_path}")
        except Exception as e:
            logger.error(f"Visualization failed: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
