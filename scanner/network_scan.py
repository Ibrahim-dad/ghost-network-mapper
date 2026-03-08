import nmap
from utils.logger import setup_logger

logger = setup_logger()


def discover_hosts(network_range):
    """Scan a network range to discover all active hosts.

    Uses an Nmap ping scan (-sn) to find live devices on the network
    without performing a full port scan.

    Args:
        network_range: CIDR notation network range (e.g., '192.168.1.0/24').

    Returns:
        List of dicts containing host information:
            - ip: Host IP address
            - hostname: Resolved hostname (if available)
            - state: Host state (up/down)
            - mac: MAC address (if available)
            - vendor: Hardware vendor (if available)
    """
    scanner = nmap.PortScanner()
    logger.info(f"Starting host discovery on {network_range}...")

    try:
        # -sn: Ping scan (no port scan), -T4: aggressive timing
        scanner.scan(hosts=network_range, arguments="-sn -T4")
    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during host discovery: {e}")
        raise

    hosts = []
    for host in scanner.all_hosts():
        host_info = {
            "ip": host,
            "hostname": scanner[host].hostname() or "Unknown",
            "state": scanner[host].state(),
            "mac": "",
            "vendor": ""
        }

        # Extract MAC address and vendor from the addresses section
        if "mac" in scanner[host]["addresses"]:
            host_info["mac"] = scanner[host]["addresses"]["mac"]

        if "vendor" in scanner[host] and scanner[host]["vendor"]:
            # vendor dict maps MAC -> vendor name
            mac = host_info["mac"]
            if mac and mac in scanner[host]["vendor"]:
                host_info["vendor"] = scanner[host]["vendor"][mac]

        hosts.append(host_info)

    logger.info(f"Discovered {len(hosts)} active host(s).")
    return hosts
