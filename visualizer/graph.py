import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import networkx as nx
import os
from utils.logger import setup_logger

logger = setup_logger()


def visualize_network(scan_results, output_dir="reports"):
    """Generate a network topology graph from scan results.

    Creates a star-topology visualization with a central gateway node
    connected to all discovered hosts. Nodes are color-coded and labeled
    with IP, hostname, and OS information.

    Args:
        scan_results: List of host dicts from the scanning phase.
        output_dir: Directory to save the graph image.

    Returns:
        Path to the saved graph image file.
    """
    os.makedirs(output_dir, exist_ok=True)

    G = nx.Graph()

    G.add_node("Gateway", label="[GHOST]\nGATEWAY", node_type="gateway")

    for host in scan_results:
        ip = host["ip"]
        hostname = host.get("hostname", "Unknown")
        os_name = host.get("os", {}).get("os_name", "")
        port_count = len(host.get("ports", []))

        label_parts = [ip]
        if hostname and hostname != "Unknown":
            label_parts.append(hostname)
        if os_name and os_name != "Unknown":
            label_parts.append(os_name[:20])
        if port_count > 0:
            label_parts.append(f"[{port_count} ports]")

        label = "\n".join(label_parts)
        G.add_node(ip, label=label, node_type="host")
        G.add_edge("Gateway", ip)

    color_map = []
    for node in G.nodes():
        if G.nodes[node].get("node_type") == "gateway":
            color_map.append("#00ff41")
        else:
            color_map.append("#0abdc6")

    size_map = []
    for node in G.nodes():
        if G.nodes[node].get("node_type") == "gateway":
            size_map.append(4000)
        else:
            size_map.append(2500)

    fig, ax = plt.subplots(figsize=(14, 10))
    fig.patch.set_facecolor("#0a0a0a")
    ax.set_facecolor("#0a0a0a")

    pos = nx.spring_layout(G, k=2.5, iterations=50, seed=42)

    nx.draw_networkx_nodes(
        G, pos, node_color=color_map, node_size=size_map,
        edgecolors="#00ff41", linewidths=2, alpha=0.9, ax=ax
    )

    nx.draw_networkx_edges(
        G, pos, edge_color="#00ff41", width=1.5,
        style="solid", alpha=0.4, ax=ax
    )

    labels = nx.get_node_attributes(G, "label")
    nx.draw_networkx_labels(
        G, pos, labels=labels, font_size=8,
        font_color="#00ff41", font_weight="bold",
        font_family="monospace", ax=ax
    )

    ax.set_title(
        "< GHOST NETWORK MAPPER >\n── Network Topology ──",
        fontsize=16, fontweight="bold", color="#00ff41",
        pad=20, fontfamily="monospace"
    )
    ax.axis("off")

    output_path = os.path.join(output_dir, "network_topology.png")
    plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="#0a0a0a")
    plt.close(fig)

    logger.info(f"Network topology graph saved to {output_path}")
    return output_path
