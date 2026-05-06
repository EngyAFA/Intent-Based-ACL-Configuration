import re
import os
import json
import ipaddress
from typing import Any, Dict, List, Optional, Tuple, Union
from Helpers.RuleConflict import normalize_interface_name


RFC1918_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

######### Helping function : 1- retrieve the IP and Port of a device by its name. #########
#########                    2- retrieve the PC name of a device by its IP.       #########
#########                    3- find all PCs that are in the same network.        #########
#########                    3- subnet mask → CIDR.                               #########
#########                    3- extract router facts from json.                   #########
###########################################################################################

def get_device_info(hostname, devices):
    for device in devices:
        if device.get("D_Name") == hostname:
            IP = device.get("D_IP")
            Port = device.get("D_Port")
            return IP, Port

    return None, None
    
def get_pc_name_by_ip(ip_address, Sub_Net):
    # Reverse lookup for IP address in the dictionary
    for item in Sub_Net:
        if item.get("D_IP") == ip_address:
            return item.get("D_Name")
    return "PC name not found"

def find_pcs_in_same_network(Sub_Net, ip_address): #Finds all PCs in the same network as the PC with the given target IP.

    # Find the network of the target IP
    target_network = None
    for item in Sub_Net:
        if item.get("D_IP") == ip_address:
            target_network = item.get("D_Net")
            break

    if target_network is None:
        return []

    # Find all PCs in the same network
    same_network_pcs = [pc for pc in Sub_Net if pc.get("D_Net") == target_network]

    return same_network_pcs

def mask_to_prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen

def is_rfc1918(ip: str) -> bool:
    addr = ipaddress.IPv4Address(ip)
    return any(addr in net for net in RFC1918_NETS)

def extract_router_facts_from_json(router_json: dict):
    """
    Extract interface facts for Batfish placement logic.

    Uses a small static role map for this lab first, then falls back safely.
    Role meanings:
      - LAN: directly attached user/protected subnet
      - TRANSIT: router-to-router link
      - INTERNET: external/cloud/upstream-facing interface
    """
    interfaces = []
    inside_prefixes = []
    default_route_iface = None

    hostname = str(router_json.get("hostname", "") or "").strip().lower()

    # Normalize hostname like R3_2 -> r3
    if hostname.endswith("_2"):
        hostname = hostname[:-2]

    RAW_STATIC_ROLE_MAP = {
        "r1": {
            "f0/0": "TRANSIT",
            "f0/1": "LAN",       # LAN10
            "s0/0": "TRANSIT",
            "s0/1": "TRANSIT",
            "f1/0": "TRANSIT",
        },
        "r2": {
            "f0/0": "TRANSIT",
            "f0/1": "TRANSIT",
            "f1/0": "LAN",       # LAN30
            "s0/0": "TRANSIT",
            "s0/1": "TRANSIT",
            "s0/2": "TRANSIT",
        },
        "r3": {
            "f0/0": "INTERNET",  # external/upstream-facing in your lab
            "f0/1": "LAN",       # LAN50
            "s0/0": "TRANSIT",   # toward R2
            "s0/1": "TRANSIT",
            "s0/2": "TRANSIT",
            "f1/0": "TRANSIT",
        },
    }

    STATIC_ROLE_MAP = {
        r: {normalize_interface_name(k): v for k, v in iface_map.items()}
        for r, iface_map in RAW_STATIC_ROLE_MAP.items()
    }

    role_map = STATIC_ROLE_MAP.get(hostname, {})

    for iface in router_json.get("interfaces", []):
        if iface.get("shutdown"):
            continue

        name = normalize_interface_name(iface.get("name"))
        if not name:
            continue

        ip_addr = iface.get("ip_address")
        mask = iface.get("subnet_mask")
        dhcp = iface.get("dhcp", False)

        if dhcp:
            ip = "dhcp"
            prefix = "dhcp"
        elif ip_addr and mask:
            prefix_len = mask_to_prefix(mask)
            network = ipaddress.IPv4Network(f"{ip_addr}/{prefix_len}", strict=False)
            ip = ip_addr
            prefix = str(network)
        else:
            continue

        # Static role map wins.
        role = role_map.get(name)

        # Safe fallback if interface not in map.
        if role is None:
            lname = name.lower()

            if dhcp:
                role = "INTERNET"
            elif lname.startswith("serial"):
                role = "TRANSIT"
            else:
                # Do NOT use RFC1918 => LAN here.
                # Private IPs are used on transit/external links in your lab.
                role = "LAN"

        if role == "INTERNET" and default_route_iface is None:
            default_route_iface = name

        if role == "LAN" and prefix != "dhcp":
            inside_prefixes.append(prefix)

        interfaces.append({
            "name": name,
            "ip": ip,
            "prefix": prefix,
            "role": role,
        })

    return {
        "router_interfaces": interfaces,
        "default_route_iface": default_route_iface,
        "inside_prefixes": inside_prefixes,
    }
    

# def extract_router_facts_from_json(router_json: dict):
#     interfaces = []
#     inside_prefixes = []
#     default_route_iface = None

#     for iface in router_json.get("interfaces", []):
#         if iface.get("shutdown"):
#             continue

#         name = normalize_interface_name(iface["name"])
#         ip_addr = iface.get("ip_address")
#         mask = iface.get("subnet_mask")
#         dhcp = iface.get("dhcp", False)

#         # ---- IP / Prefix ----
#         if dhcp:
#             ip = "dhcp"
#             prefix = "dhcp"
#         elif ip_addr and mask:
#             prefix_len = mask_to_prefix(mask)
#             network = ipaddress.IPv4Network(f"{ip_addr}/{prefix_len}", strict=False)
#             ip = ip_addr
#             prefix = str(network)
#         else:
#             continue  # unusable interface

#         # ---- Role inference ----
#         lname = name.lower()
#         if dhcp:
#             role = "INTERNET"
#             default_route_iface = name
#         elif lname.startswith("serial"):
#             role = "TRANSIT"
#         elif ip != "dhcp" and is_rfc1918(ip):
#             role = "LAN"
#             inside_prefixes.append(prefix)
#         else:
#             role = "TRANSIT"

#         interfaces.append({
#             "name": name,
#             "ip": ip,
#             "prefix": prefix,
#             "role": role,
#         })

#     return {
#         "router_interfaces": interfaces,
#         "default_route_iface": default_route_iface,
#         "inside_prefixes": inside_prefixes,
#     }

def _ip_in_prefix(ip, prefix):
    return ipaddress.ip_address(ip) in ipaddress.ip_network(prefix, strict=False)



def _parse_prefix(pfx):
    """Return ipaddress.ip_network or None."""
    if not pfx:
        return None
    pfx = str(pfx).strip()
    if pfx.lower() == "dhcp":
        return None
    try:
        # If given as 'a.b.c.d' without /mask, treat as /32 (host) for safe comparisons
        if "/" not in pfx:
            return ipaddress.ip_network(pfx + "/32", strict=False)
        return ipaddress.ip_network(pfx, strict=False)
    except Exception:
        return None
        
def _ip_in_prefix(ip, pfx):
    try:
        ip_obj = ipaddress.ip_address(str(ip))
        net = _parse_prefix(pfx)
        return net is not None and ip_obj in net
    except Exception:
        return False

def _prefix_is_inside(prefix,inside_set):
    """
    True if prefix matches (or is contained by) one of inside_prefixes.
    Handles CIDR and also 'network-only' strings by matching the network address.
    """
    net = _parse_prefix(prefix)
    if net is None:
        return False

    for p in inside_set:
        pnet = _parse_prefix(p)
        if pnet is None:
            continue
        # If prefix is a host (/32), check membership; else check overlap/containment
        if net.prefixlen == 32:
            if net.network_address in pnet:
                return True
        else:
            # consider inside if it overlaps/contained
            if net.subnet_of(pnet) or pnet.subnet_of(net) or net.overlaps(pnet):
                return True
    return False

def _find_iface_for_exact_prefix(prefix,router_interfaces ):
    """Match exact interface prefix string if present."""
    if not prefix:
        return None
    for i in (router_interfaces or []):
        if (i.get("prefix") or "").strip() == str(prefix).strip():
            return i
    return None


def load_topology(topology_input):
    # topology_input can be: dict, json string, or file path
    if isinstance(topology_input, dict):
        topo = topology_input
    elif isinstance(topology_input, str):
        s = topology_input.strip()
        if os.path.isfile(s):
            with open(s, "r", encoding="utf-8") as f:
                topo = json.load(f)
        else:
            topo = json.loads(s)
    else:
        raise TypeError(f"Unsupported topology type: {type(topology_input)}")

    # unwrap "root" if present
    if isinstance(topo, dict) and "root" in topo and isinstance(topo["root"], dict):
        topo = topo["root"]

    return topo

def get_objects_map(topology_input):
    topo = load_topology(topology_input)
    objs = topo.get("objects",{})
    intf = topo.get("interfaces", {})

    if not isinstance(objs, dict):
        raise ValueError("Topology objects not found at topology['objects'] (after root unwrap).")
    if not isinstance(intf, dict):
        raise ValueError("Topology interfaces not found at topology['interfaces'] (after root unwrap).")
    return objs,intf


def is_any_token(x):
    if x is None:
        return False
    s = str(x).strip().lower()
    return s in {"any", "internet", "0.0.0.0", "0.0.0.0/0"}

def extract_device_override(intent: str):
    m = re.search(r"\bR\d+\b", intent, re.IGNORECASE)
    return m.group(0).upper() if m else None
    
# Return router connected to Cloud / WAN / Internet.
def find_edge_router(interface_map):
    """
    Heuristics (first match wins):
    1) role/connected_to contains cloud/wan/internet/isp
    2) connected_to looks like external/NAT/cloud/unknown
    3) router has an interface not connected to another router (R#:ifname)
       and not connected to a switch (SW*), i.e., likely upstream/edge
    """

    # helper patterns
    router_link_pat = re.compile(r"^r\d+:\S+$", re.IGNORECASE)   # e.g. R2:s0/0/0
    switch_pat = re.compile(r"^sw\d+$", re.IGNORECASE)          # e.g. SW1

    for router, ifaces in interface_map.items():
        for _, data in ifaces.items():
            role = (data.get("role") or "").lower()
            connected = (data.get("connected_to") or "").lower()

            # 1) explicit tags
            if any(x in role for x in ["cloud", "wan", "internet", "isp"]):
                return router
            if any(x in connected for x in ["cloud", "wan", "internet", "isp", "nat"]):
                return router

    # 2) heuristic: interface connected_to is empty/unknown OR not router-link and not switch
    for router, ifaces in interface_map.items():
        for _, data in ifaces.items():
            connected = (data.get("connected_to") or "").strip()
            if connected == "" or connected.lower() in {"none", "unknown"}:
                return router

            if router_link_pat.match(connected):
                continue  # router-to-router, not edge
            if switch_pat.match(connected):
                continue  # LAN side, not edge

            # Anything else (e.g., "Cloud1", "NAT1", "ISP", "Internet") → edge
            return router

    return None
    

# Convert intent endpoint (object name or IP/CIDR) → ip_network or ip_address.
def resolve(endpoint: Any, objects: Dict[str, Any]) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv4Address]]:
    if endpoint is None:
        return None

    # normalize endpoint to string for lookup / parsing
    ep = str(endpoint).strip()

    # object-name lookup (LAN, DMZ, WEB1, Internet, etc.)
    value = objects.get(ep, ep)

    # if objects map contains weird types (dict/list), fall back to endpoint string
    if not isinstance(value, str):
        value = ep

    v = value.strip()

    if v.lower() == "any":
        return ipaddress.ip_network("0.0.0.0/0", strict=False)

    # CIDR
    if "/" in v:
        return ipaddress.ip_network(v, strict=False)

    # single IP
    return ipaddress.ip_address(v)


# Return the router whose interface subnet contains the given IP/network.
def find_router_attached_to(target, interfaces):
    """Returns router name only (kept for compatibility)."""
    ri = find_router_interface_attached_to(target, interfaces)
    return ri[0] if ri else None


def find_router_interface_attached_to(target, interfaces):
    """
    Returns (router, interface) whose interface subnet contains target (host) or overlaps target (subnet).
    """
    if target is None:
        return None

    for router, ifaces in interfaces.items():
        for if_name, data in ifaces.items():
            ip = data.get("ip")
            if not ip or ip == "dhcp":
                continue

            iface_net = ipaddress.ip_network(ip, strict=False)

            if isinstance(target, ipaddress.IPv4Address):
                if target in iface_net:
                    return (router, if_name)

            if isinstance(target, ipaddress.IPv4Network):
                if target.overlaps(iface_net):
                    return (router, if_name)

    return None

# Detect if source is Internet / any.
def is_internet(target):
    return isinstance(target, ipaddress.IPv4Network) and str(target) == "0.0.0.0/0"
    