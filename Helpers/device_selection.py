import json
import ipaddress
import os
from typing import Optional


def _ensure_topology_dict(network_topology):
    if network_topology is None:
        return {}

    if isinstance(network_topology, dict):
        return network_topology

    if isinstance(network_topology, str):
        s = network_topology.strip()

        if not s:
            return {}

        # If user passed a file path instead of JSON text
        if os.path.isfile(s):
            with open(s, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return {}
                return json.loads(content)

        # If it looks like JSON text
        if s.startswith("{") or s.startswith("["):
            return json.loads(s)

        # otherwise it is not valid JSON text
        raise ValueError(f"network_topology is a string but not JSON text or valid file path: {s[:120]!r}")

    raise TypeError(f"Unsupported network_topology type: {type(network_topology)}")


def norm_device(x):
    if x is None:
        return None

    s = str(x).strip().lower()

    aliases = {
        "router1": "r1",
        "router2": "r2",
        "router3": "r3",
        "r1_2": "r1",
        "r2_2": "r2",
        "r3_2": "r3",
    }

    return aliases.get(s, s)

def wildcard_to_prefix(wc: str) -> int:
    wc_int = int(ipaddress.IPv4Address(wc))
    mask_int = (~wc_int) & 0xFFFFFFFF
    mask = ipaddress.IPv4Address(mask_int)
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def ip_wildcard_to_network(ip: str, wc: str) -> ipaddress.IPv4Network:
    if ip is None:
        return None

    s = str(ip).strip().lower()
    if s in {"any", "internet"}:
        return ipaddress.ip_network("0.0.0.0/0")

    if wc is None:
        return ipaddress.ip_network(s, strict=False) if "/" in s else ipaddress.ip_network(f"{s}/32", strict=False)

    wc = str(wc).strip()
    if wc == "255.255.255.255":
        return ipaddress.ip_network("0.0.0.0/0")

    prefix = wildcard_to_prefix(wc)
    return ipaddress.ip_network(f"{s}/{prefix}", strict=False)


def infer_wan_edge_router_from_topology(network_topology: dict) -> Optional[str]:
    network_topology = _ensure_topology_dict(network_topology)

    interfaces = network_topology.get("interfaces", {})

    for router_name, ifaces in interfaces.items():
        for _, meta in ifaces.items():
            role = str(meta.get("role", "")).strip().upper()
            if role == "WAN":
                return norm_device(router_name)

    return None


def build_router_networks_from_topology(network_topology: dict):
    network_topology = _ensure_topology_dict(network_topology)

    router_networks = {}
    interfaces = network_topology.get("interfaces", {})

    for router_name, ifaces in interfaces.items():
        r = norm_device(router_name)
        nets = []

        for _, meta in ifaces.items():
            ip_cidr = meta.get("ip")
            if not ip_cidr:
                continue
            try:
                iface = ipaddress.ip_interface(ip_cidr)
                nets.append(iface.network)
            except Exception:
                continue

        seen = set()
        unique_nets = []
        for n in nets:
            key = str(n)
            if key not in seen:
                seen.add(key)
                unique_nets.append(n)

        router_networks[r] = unique_nets

    return router_networks


def _to_ip_obj(x):
    if x is None:
        return None
    s = str(x).strip().lower()
    if s in {"any", "internet"}:
        return None
    if "/" in s:
        s = s.split("/")[0]
    try:
        return ipaddress.ip_address(s)
    except Exception:
        return None


def _to_net_obj(x):
    if x is None:
        return None
    s = str(x).strip().lower()
    if s in {"any", "internet"}:
        return ipaddress.ip_network("0.0.0.0/0")
    try:
        return ipaddress.ip_network(s, strict=False)
    except Exception:
        return None


def find_router_for_ip(ip_value, router_networks) -> Optional[str]:
    ip_obj = _to_ip_obj(ip_value)
    if ip_obj is None:
        return None

    matches = []
    for router, nets in router_networks.items():
        for net in nets:
            if ip_obj in net:
                matches.append((router, net.prefixlen))

    if not matches:
        return None

    matches.sort(key=lambda x: x[1], reverse=True)
    return matches[0][0]


def find_router_for_subnet(subnet_value, router_networks) -> Optional[str]:
    net_obj = _to_net_obj(subnet_value)
    if net_obj is None:
        return None

    if str(net_obj) == "0.0.0.0/0":
        return None

    exact = []
    overlap = []

    for router, nets in router_networks.items():
        for rnet in nets:
            if net_obj == rnet:
                exact.append((router, rnet.prefixlen))
            elif net_obj.subnet_of(rnet) or rnet.subnet_of(net_obj) or net_obj.overlaps(rnet):
                overlap.append((router, rnet.prefixlen))

    if exact:
        exact.sort(key=lambda x: x[1], reverse=True)
        return exact[0][0]

    if overlap:
        overlap.sort(key=lambda x: x[1], reverse=True)
        return overlap[0][0]

    return None

def choose_device_only_deterministic(
    source_ip,
    src_subnet,
    dst_ip,
    dst_subnet,
    network_topology
) -> Optional[str]:
    network_topology = _ensure_topology_dict(network_topology)

    router_networks = build_router_networks_from_topology(network_topology)
    wan_edge_router = infer_wan_edge_router_from_topology(network_topology)

    src_net = _to_net_obj(src_subnet)
    src_is_any = (src_net is not None and str(src_net) == "0.0.0.0/0")
    print("=== DEVICE DEBUG ===")
    print("source_ip:", source_ip)
    print("src_subnet:", src_subnet)
    print("dst_ip:", dst_ip)
    print("dst_subnet:", dst_subnet)
    print("wan_edge_router:", wan_edge_router)
    print("router_networks:", {k: [str(n) for n in v] for k, v in router_networks.items()})
    
    # Case 1: traffic comes from Internet/any
    # Prefer WAN edge router; if unavailable, fall back to destination side.
    if src_is_any:
        print("Source identified as Internet/any")
        if wan_edge_router is not None:
            print("Using WAN edge router:", wan_edge_router)
            return wan_edge_router
    
        dst_router = find_router_for_ip(dst_ip, router_networks)
        print("Destination router from dst_ip:", dst_router)
        if dst_router is not None:
            return dst_router
    
        dst_router = find_router_for_subnet(dst_subnet, router_networks)
        print("Destination router from dst_subnet:", dst_router)
        if dst_router is not None:
            return dst_router
    
        print("No router found for Internet-origin traffic")
        return None

    # Case 2: normal internal source
    src_router = find_router_for_ip(source_ip, router_networks)
    if src_router is not None:
        return src_router

    src_router = find_router_for_subnet(src_subnet, router_networks)
    if src_router is not None:
        return src_router

    # Case 3: fallback to destination side if source matching fails
    dst_router = find_router_for_ip(dst_ip, router_networks)
    if dst_router is not None:
        return dst_router

    dst_router = find_router_for_subnet(dst_subnet, router_networks)
    if dst_router is not None:
        return dst_router

    return None
