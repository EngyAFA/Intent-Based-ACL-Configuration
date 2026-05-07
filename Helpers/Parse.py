########### Helping function: translate config file (.cfg) into JSON file (.json) ###########
#############################################################################################
import re
import os
import json
import ipaddress
from pathlib import Path
from Helpers.RuleConflict import parse_acl_rule_line, normalize_interface_name

APP_DEFAULTS = {
    "HTTP":  ("TCP", "80"),
    "HTTPS": ("TCP", "443"),
    "SSH":   ("TCP", "22"),
    "TELNET":("TCP", "23"),
    "DNS":   ("UDP", "53"),
    "ICMP":  ("ICMP", None),
}
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    
def _canon(s: str) -> str:
    return (s or "").strip()

def _parse_topology(topology_json_text: str) -> dict:
    data = json.loads(topology_json_text)
    # tolerate either {"root":...} or direct root
    root = data.get("root", data)
    objects = root.get("objects", {}) or {}
    services = root.get("services", None)  # optional
    return {"root": root, "objects": objects, "services": services}

def _is_host32(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.version == 4 and net.prefixlen == 32
    except Exception:
        return False

def _cidr_to_ip(cidr: str) -> str:
    # for /32 only
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address)

def _find_containing_subnet(ip_str: str, objects: dict) -> str | None:
    ip = ipaddress.ip_address(ip_str)
    best = None
    best_plen = -1
    for _, cidr in objects.items():
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version != 4:
                continue
            if net.prefixlen == 32:
                continue
            if ip in net and net.prefixlen > best_plen:
                best = str(net)
                best_plen = net.prefixlen
        except Exception:
            continue
    return best

def _resolve_object(obj_name: str, objects: dict):
    """
    Returns (ip, subnet) where ip is host IPv4 or None, subnet is CIDR or None.
    Only uses topology objects mapping. No guessing.
    """
    obj_name = _canon(obj_name)
    if not obj_name or obj_name == "None":
        return None, None

    cidr = objects.get(obj_name)
    if not cidr:
        return None, None

    cidr = _canon(cidr)
    if _is_host32(cidr):
        ip = _cidr_to_ip(cidr)
        subnet = _find_containing_subnet(ip, objects)  # may be None
        return ip, subnet or None
    else:
        # subnet object
        return None, cidr

def resolve_to_8_lines(topology_json_text: str, extracted_5_lines_text: str) -> str:
    """
    Input: topology JSON text, and the LLM's 5-line extraction text.
    Output: EXACT 8 lines based on the original schema.
    """
    topo = _parse_topology(topology_json_text)
    objects = topo["objects"]

    # parse 5 lines
    kv = {}
    for line in extracted_5_lines_text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            kv[_canon(k)] = _canon(v)

    src_obj = kv.get("Source Object", "None")
    dst_obj = kv.get("Destination Object", "None")
    action  = kv.get("Action", "None").lower()
    app     = kv.get("Application", "None").upper()
    proto   = kv.get("Protocol", "None").upper()

    # normalize action
    if action in ("allow", "permit", "enable"):
        action = "permit"
    elif action in ("block", "deny", "prohibit", "disallow", "drop"):
        action = "deny"
    elif action not in ("permit", "deny"):
        action = "deny"  # safest fallback, but you can set None

    # infer protocol/port from application if missing
    port = None
    if app != "NONE" and app in APP_DEFAULTS:
        dproto, dport = APP_DEFAULTS[app]
        if proto in ("", "NONE", "None".upper()):
            proto = dproto
        port = dport
    else:
        # unknown app
        if app in ("NONE", ""):
            app = "None"
        if proto in ("", "NONE"):
            proto = "None"
        port = None

    # resolve src/dst objects using topology only
    src_ip, src_subnet = _resolve_object(src_obj, objects)
    dst_ip, dst_subnet = _resolve_object(dst_obj, objects)

    # format output (exact 8 lines)
    out = [
        f"Source IP: {src_ip if src_ip else 'None'}",
        f"Destination IP: {dst_ip if dst_ip else 'None'}",
        f"Protocol: {proto if proto and proto != 'NONE' else 'None'}",
        f"Port: {port if port else 'None'}",
        f"Action: {action}",
        f"Application: {app if app != 'NONE' else 'None'}",
        f"Source IP Subnet: {src_subnet if src_subnet else 'None'}",
        f"Destination IP Subnet: {dst_subnet if dst_subnet else 'None'}",
    ]
    return "\n".join(out)

def _norm(s: str) -> str:
    """Normalize names for safe comparison."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def ensure_topology_dict(network_topology) -> dict:
    if isinstance(network_topology, dict):
        return network_topology

    if isinstance(network_topology, str):
        topology_text = network_topology.strip()

        if not topology_text:
            raise ValueError("network_topology is an empty string")

        # case 1: file path
        if os.path.isfile(topology_text):
            with open(topology_text, "r", encoding="utf-8") as file:
                return json.load(file)

        # case 2: raw JSON text
        if (
            topology_text.startswith("{")
            or topology_text.startswith("[")
        ):
            return json.loads(topology_text)

        raise ValueError(
            "network_topology is a string, but not valid JSON text "
            f"and not a file path: {topology_text!r}"
        )

    raise TypeError(
        f"Unsupported network_topology type: {type(network_topology)}"
    )

def find_attached_router(topology: dict, host_ip=None, cidr=None):
    """
    Finds the router directly connected to the given host IP or subnet.
    Returns router name like 'r1', 'r2', 'r3', or None.
    """
    interfaces = topology.get("interfaces", {})

    target = None
    try:
        if host_ip:
            target = ipaddress.ip_address(host_ip)
        elif cidr:
            target = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None

    for router_name, intfs in interfaces.items():
        r = router_name.strip().lower()
        for _, meta in intfs.items():
            ip_cidr = meta.get("ip")
            if not ip_cidr:
                continue
            try:
                iface = ipaddress.ip_interface(ip_cidr)
                iface_net = iface.network
            except ValueError:
                continue

            if isinstance(target, ipaddress.IPv4Address):
                if target in iface_net:
                    return r
            else:
                # target is a network
                if target.subnet_of(iface_net) or iface_net.subnet_of(target) or target == iface_net:
                    return r

    return None

def build_router_inventory(topology: dict):
    """
    Returns:
      {
        "routers": ["r1", "r2", "r3"],
        "router_networks": {
            "r1": ["192.168.10.0/24", "10.0.12.0/30"],
            "r2": ["10.0.12.0/30", "10.0.23.0/30", "203.0.113.0/30"],
            "r3": ["10.0.23.0/30", "192.168.20.0/24", "192.168.30.0/24"]
        }
      }
    """
    interfaces = topology.get("interfaces", {})
    router_networks = {}

    for router_name, intfs in interfaces.items():
        r = router_name.strip().lower()
        nets = []

        for _, meta in intfs.items():
            ip_cidr = meta.get("ip")
            if not ip_cidr:
                continue
            try:
                net = str(ipaddress.ip_interface(ip_cidr).network)
                if net not in nets:
                    nets.append(net)
            except ValueError:
                continue

        router_networks[r] = nets

    routers = sorted(router_networks.keys())
    return {
        "routers": routers,
        "router_networks": router_networks
    }

def find_wan_edge_router(topology: dict):
    interfaces = topology.get("interfaces", {})
    for router_name, intfs in interfaces.items():
        for _, meta in intfs.items():
            role = str(meta.get("role", "")).strip().upper()
            connected_to = str(meta.get("connected_to", "")).strip().upper()
            if role == "WAN" or connected_to == "ISP":
                return router_name.strip().lower()
    return None
    

def prepare_device_agent_context(new_intent: str, topology: dict, resolved_names: dict):
    inventory = build_router_inventory(topology)

    src_router = find_attached_router(
        topology,
        host_ip=resolved_names.get("source_host_ip"),
        cidr=resolved_names.get("source_cidr")
    )

    dst_router = find_attached_router(
        topology,
        host_ip=resolved_names.get("destination_host_ip"),
        cidr=resolved_names.get("destination_cidr")
    )

    wan_edge_router = find_wan_edge_router(topology)

    return {
        "new_intent": new_intent,
        "resolved_names": resolved_names,
        "available_routers": inventory["routers"],
        "router_network_map": inventory["router_networks"],
        "src_attached_router": src_router,
        "dst_attached_router": dst_router,
        "wan_edge_router": wan_edge_router,
    }

def resolve_names(intent: str, topology: dict):
    objects = topology.get("objects", {})
    services = topology.get("services", {})

    obj_lookup = {_norm(name): name for name in objects.keys()}

    if isinstance(services, dict):
        svc_lookup = {_norm(name): name for name in services.keys()}
    else:
        svc_lookup = {_norm(name): name for name in services}

    # --- raw IP/CIDR extraction ---
    raw_cidrs = CIDR_RE.findall(intent)
    raw_ips = IP_RE.findall(intent)
    cidr_ips = {c.split("/")[0] for c in raw_cidrs}
    raw_ips = [ip for ip in raw_ips if ip not in cidr_ips]

    # --- token object matching (exact tokens) ---
    words = re.findall(r"[A-Za-z0-9_\-]+", intent)
    ordered_objects, seen = [], set()
    for w in words:
        key = _norm(w)
        if key in obj_lookup:
            obj = obj_lookup[key]
            if obj not in seen:
                seen.add(obj)
                ordered_objects.append(obj)

    # --- service matching ---
    matched_services = []
    for w in words:
        key = _norm(w)
        if key in svc_lookup:
            matched_services.append(svc_lookup[key])

    # --- phrase-based role extraction: "from X" / "to Y" ---
    src_obj = dst_obj = None

    lowered = intent.lower()

    # Build a pattern that can match any known object after from/to/in
    # We match as whole words to avoid substring confusion.
    obj_names_sorted = sorted(objects.keys(), key=len, reverse=True)
    # Escape for regex and allow optional "network" word after LAN, etc. (lightly)
    obj_alt = "|".join(re.escape(n) for n in obj_names_sorted) if obj_names_sorted else None

    def find_after(prep: str):
        """Return first object name that appears after a given preposition."""
        if not obj_alt:
            return None
        m = re.search(rf"\b{prep}\s+({obj_alt})\b", intent, re.IGNORECASE)
        return m.group(1) if m else None

    src_from = find_after("from")
    dst_to = find_after("to")
    dst_into = find_after("into")
    dst_toward = find_after("toward")
    in_obj = find_after("in")  # e.g., "in the DMZ" (context)

    if src_from:
        src_obj = src_from
    if dst_to or dst_into or dst_toward:
        dst_obj = dst_to or dst_into or dst_toward

    # Fallback if not found via phrases:
    if not src_obj or not dst_obj:
        if len(ordered_objects) >= 2:
            # If one role missing, fill from order without overriding phrase decisions
            if not src_obj:
                src_obj = ordered_objects[0]
            if not dst_obj:
                dst_obj = ordered_objects[1]
        elif len(ordered_objects) == 1:
            # default to destination unless "from" clearly indicates source
            if not src_obj and re.search(r"\bfrom\b", lowered):
                src_obj = ordered_objects[0]
            elif not dst_obj:
                dst_obj = ordered_objects[0]

    # --- resolve named object into host/subnet ---
    def resolve_object(obj_name):
        if not obj_name:
            return None, None
        cidr = objects.get(obj_name)
        if not cidr or not isinstance(cidr, str):
            return None, None
        if cidr.endswith("/32"):
            return None, cidr.split("/")[0]  # /32 treated as host
        return cidr, None

    src_cidr, src_host = resolve_object(src_obj)
    dst_cidr, dst_host = resolve_object(dst_obj)

        # --- overlay raw IP/CIDR (mixed endpoints support) ---
        
        # If we have >=2 raw IPs and no explicit "from/to" binding, map in order:
        # first IP = source, second IP = destination.
    # If two raw IPs exist and no "from/to" cues, assume first is source and second is destination
    if len(raw_ips) >= 2:
        ip1, ip2 = raw_ips[0], raw_ips[1]
    
        # If explicit "from/to" exists, prefer that (handled below),
        # but if neither IP is mentioned after "to", assume order.
        to_ip1 = re.search(rf"\bto\s+{re.escape(ip1)}\b", intent, re.IGNORECASE)
        to_ip2 = re.search(rf"\bto\s+{re.escape(ip2)}\b", intent, re.IGNORECASE)
        from_ip1 = re.search(rf"\bfrom\s+{re.escape(ip1)}\b", intent, re.IGNORECASE)
        from_ip2 = re.search(rf"\bfrom\s+{re.escape(ip2)}\b", intent, re.IGNORECASE)
    
        if not (to_ip1 or to_ip2 or from_ip1 or from_ip2):
            src_host, src_cidr = ip1, None
            dst_host, dst_cidr = ip2, None
        else:
            # If "from" binds one IP, treat it as source
            if from_ip1:
                src_host, src_cidr = ip1, None
            if from_ip2:
                src_host, src_cidr = ip2, None
            # If "to" binds one IP, treat it as destination
            if to_ip1:
                dst_host, dst_cidr = ip1, None
            if to_ip2:
                dst_host, dst_cidr = ip2, None
    
    # If only one raw IP exists, use your existing logic (default source unless "to <ip>")
    elif len(raw_ips) == 1:
        ip = raw_ips[0]
        if re.search(rf"\bto\s+{re.escape(ip)}\b", intent, re.IGNORECASE):
            dst_host, dst_cidr = ip, None
        else:
            src_host, src_cidr = ip, None

    # CIDR overlay (keep the existing behavior)
    if raw_cidrs:
        c = raw_cidrs[0]
        if re.search(rf"\bfrom\s+{re.escape(c)}\b", intent, re.IGNORECASE):
            src_cidr, src_host = c, None
        else:
            dst_cidr, dst_host = c, None
        # --- overlay raw IP/CIDR (mixed endpoints support) ---
    if raw_ips:
        ip = raw_ips[0]
        # if "to <ip>" => destination host, else source host
        if re.search(rf"\bto\s+{re.escape(ip)}\b", intent, re.IGNORECASE):
            dst_host, dst_cidr = ip, None
        else:
            src_host, src_cidr = ip, None

    # --- handle "in the DMZ" as context if destination is a host ---
    # If dst is a host (WEB1) and "in DMZ" exists, do NOT override dst host.
    # If dst missing but "in DMZ" exists, use it as destination subnet.
    if in_obj and not dst_obj and not dst_host and not raw_cidrs:
        dst_obj = in_obj
        dst_cidr, dst_host = resolve_object(dst_obj)

    return {
        "source_object": src_obj,
        "destination_object": dst_obj,
        "source_cidr": src_cidr,
        "destination_cidr": dst_cidr,
        "source_host_ip": src_host,
        "destination_host_ip": dst_host,
        "service": matched_services[0] if matched_services else None,
        "matched_objects": ordered_objects,
        "matched_services": matched_services,
        "raw_cidrs": raw_cidrs,
        "raw_ips": raw_ips,
        "context_in_object": in_obj,
    }
    
def parse_config_to_json(config_file: str) -> None:
    config_file_path = config_file + ".cfg"

    with open(config_file_path, "r") as file:
        config_lines = file.readlines()

    router_config = {}
    interfaces_map = {}
    access_lists_map = {}

    current_interface = None
    current_acl = None

    def get_or_create_interface(name: str) -> dict:
        interface_key = normalize_interface_name(name)

        if interface_key not in interfaces_map:
            interfaces_map[interface_key] = {
                "name": interface_key,
                "ip_address": None,
                "subnet_mask": None,
                "access_group": None,
                "dhcp": False,
                "shutdown": False,
                "nat": None,
                "virtual_reassembly": False,
            }

        return interfaces_map[interface_key]

    def get_or_create_acl(name: str) -> dict:
        if name not in access_lists_map:
            access_lists_map[name] = {
                "name": name,
                "rules": [],
            }

        return access_lists_map[name]

    for raw_line in config_lines:
        line = raw_line.strip()

        if not line or line.startswith("!"):
            continue

        # Global router metadata
        if line.startswith("version"):
            router_config["version"] = line.split()[-1]
            continue

        if line.startswith("hostname"):
            router_config["hostname"] = line.split()[-1]
            continue

        # Start interface stanza
        if line.startswith("interface"):
            interface_name = line.split()[-1]
            current_interface = get_or_create_interface(interface_name)
            current_acl = None
            continue

        # Start ACL stanza
        if line.startswith("ip access-list"):
            acl_name = line.split()[-1]
            current_acl = get_or_create_acl(acl_name)
            current_interface = None
            continue

        # Interface subcommands
        if current_interface is not None:
            if line.startswith("ip address"):
                ip_info = line.split()

                if len(ip_info) == 3 and ip_info[2] == "dhcp":
                    current_interface["dhcp"] = True

                elif len(ip_info) >= 4:
                    current_interface["ip_address"] = ip_info[2]
                    current_interface["subnet_mask"] = ip_info[3]

                else:
                    print(f"Warning: Invalid 'ip address' configuration: {line}")

                continue

            if line.startswith("ip access-group"):
                access_group_info = line.split()
                acl_name = access_group_info[2]
                direction = (
                    access_group_info[3]
                    if len(access_group_info) > 3
                    else None
                )

                current_interface["access_group"] = acl_name
                current_interface["direction"] = direction
                continue

            if line == "shutdown":
                current_interface["shutdown"] = True
                continue

            if line.startswith("ip nat inside"):
                current_interface["nat"] = "inside"
                continue

            if line.startswith("ip virtual-reassembly"):
                current_interface["virtual_reassembly"] = True
                continue

            if line.startswith("clock rate"):
                try:
                    current_interface["clock_rate"] = int(line.split()[-1])

                except Exception:
                    pass

                continue

        # ACL rule lines
        is_acl_rule_line = (
            line.startswith("permit")
            or line.startswith("deny")
            or re.match(r"^\d+\s+(permit|deny)\b", line)
        )

        if current_acl is not None and is_acl_rule_line:
            parsed_rule = parse_acl_rule_line(current_acl["name"], line)

            if parsed_rule is not None:
                rule_info = {
                    "action": parsed_rule.action,
                    "protocol": parsed_rule.protocol,
                    "source": {
                        "type": (
                            "host"
                            if parsed_rule.src.endswith("/32")
                            else (
                                "any"
                                if parsed_rule.src == "0.0.0.0/0"
                                else "ip"
                            )
                        ),
                        "address": parsed_rule.src,
                    },
                    "destination": {
                        "type": (
                            "host"
                            if parsed_rule.dst.endswith("/32")
                            else (
                                "any"
                                if parsed_rule.dst == "0.0.0.0/0"
                                else "ip"
                            )
                        ),
                        "address": parsed_rule.dst,
                    },
                }

                if parsed_rule.src_port is not None:
                    rule_info["src_port"] = parsed_rule.src_port

                if parsed_rule.dst_port is not None:
                    rule_info["dst_port"] = parsed_rule.dst_port

                current_acl["rules"].append(rule_info)

            continue

        # OSPF
        if line.startswith("router ospf"):
            ospf_process_id = line.split()[-1]
            router_config["router_ospf"] = {
                "process_id": int(ospf_process_id),
                "networks": [],
            }
            current_interface = None
            current_acl = None
            continue

        if line.startswith("network") and "router_ospf" in router_config:
            network_info = line.split()

            if len(network_info) >= 5:
                network = network_info[1]
                wildcard_mask = network_info[2]
                area = network_info[4]

                router_config["router_ospf"]["networks"].append(
                    {
                        "network": network,
                        "wildcard_mask": wildcard_mask,
                        "area": area,
                    }
                )

            continue

        # Static routes
        if line.startswith("ip route"):
            route_info = line.split()

            if len(route_info) >= 5:
                destination = route_info[2]
                mask = route_info[3]
                next_hop = route_info[4]
                route_name = (
                    route_info[6]
                    if "name" in route_info and len(route_info) > 6
                    else None
                )

                router_config.setdefault("static_routes", []).append(
                    {
                        "destination": destination,
                        "mask": mask,
                        "next_hop": next_hop,
                        "name": route_name,
                    }
                )

            continue

        # Line configs
        if line.startswith("line"):
            line_config = line.split()
            line_type = line_config[1]

            if len(line_config) > 2:
                line_range = line_config[2]
                line_key = f"{line_type}_{line_range}"

            else:
                line_key = f"{line_type}_0"

            router_config.setdefault("lines", {})[line_key] = {}
            current_interface = None
            current_acl = None
            continue

    router_config["interfaces"] = list(interfaces_map.values())
    router_config["access_lists"] = list(access_lists_map.values())

    json_file_path = config_file + ".json"

    with open(json_file_path, "w") as json_file:
        json.dump(router_config, json_file, indent=4)