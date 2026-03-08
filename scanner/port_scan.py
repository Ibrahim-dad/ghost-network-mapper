import nmap
from utils.logger import setup_logger

logger = setup_logger()


def scan_ports(host_ip, port_range="1-1024"):
    """Perform a port scan on a specific host.

    Scans the given host for open TCP ports using Nmap's SYN scan.

    Args:
        host_ip: Target IP address to scan.
        port_range: Port range to scan (default: '1-1024').

    Returns:
        List of dicts for each open port:
            - port: Port number
            - state: Port state (open/closed/filtered)
            - service: Service name detected on the port
    """
    scanner = nmap.PortScanner()
    logger.info(f"Scanning ports {port_range} on {host_ip}...")

    try:
        # -sS: TCP SYN scan, -T4: aggressive timing
        scanner.scan(host_ip, port_range, arguments="-sS -T4")
    except nmap.PortScannerError:
        # SYN scan requires root; fall back to TCP connect scan
        logger.warning(f"SYN scan requires root on {host_ip}, falling back to TCP connect scan.")
        try:
            scanner.scan(host_ip, port_range, arguments="-sT -T4")
        except nmap.PortScannerError as e:
            logger.error(f"Port scan error on {host_ip}: {e}")
            raise
    except Exception as e:
        logger.error(f"Unexpected error during port scan on {host_ip}: {e}")
        raise

    open_ports = []
    if host_ip in scanner.all_hosts():
        for proto in scanner[host_ip].all_protocols():
            ports = sorted(scanner[host_ip][proto].keys())
            for port in ports:
                port_info = scanner[host_ip][proto][port]
                open_ports.append({
                    "port": port,
                    "state": port_info["state"],
                    "service": port_info["name"]
                })

    logger.info(f"Found {len(open_ports)} open port(s) on {host_ip}.")
    return open_ports


def detect_os(host_ip):
    """Attempt OS detection on a specific host.

    Uses Nmap's OS fingerprinting to identify the operating system
    running on the target host. Requires root/sudo privileges.

    Args:
        host_ip: Target IP address.

    Returns:
        Dict with OS detection results:
            - os_name: Best guess OS name
            - os_accuracy: Confidence percentage
            - os_family: OS family (if available)
    """
    scanner = nmap.PortScanner()
    logger.info(f"Detecting OS on {host_ip}...")

    os_info = {
        "os_name": "Unknown",
        "os_accuracy": 0,
        "os_family": "Unknown"
    }

    try:
        # -O: Enable OS detection
        scanner.scan(host_ip, arguments="-O -T4")
    except nmap.PortScannerError as e:
        logger.warning(f"OS detection error on {host_ip}: {e}")
        logger.warning("OS detection requires root/sudo privileges.")
        return os_info
    except Exception as e:
        logger.error(f"Unexpected error during OS detection on {host_ip}: {e}")
        return os_info

    if host_ip in scanner.all_hosts():
        host_data = scanner[host_ip]
        if "osmatch" in host_data and host_data["osmatch"]:
            # Take the best (first) OS match
            best_match = host_data["osmatch"][0]
            os_info["os_name"] = best_match.get("name", "Unknown")
            os_info["os_accuracy"] = int(best_match.get("accuracy", 0))

            # Extract OS family from osclass if available
            if "osclass" in best_match and best_match["osclass"]:
                os_info["os_family"] = best_match["osclass"][0].get("osfamily", "Unknown")

    logger.info(f"OS detected on {host_ip}: {os_info['os_name']} ({os_info['os_accuracy']}% confidence)")
    return os_info
