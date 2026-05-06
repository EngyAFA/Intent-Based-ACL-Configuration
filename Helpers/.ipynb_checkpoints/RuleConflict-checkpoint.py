import re
import json
from pathlib import Path
from dataclasses import dataclass
from ipaddress import ip_network, IPv4Network, IPv4Address
from collections import defaultdict, deque
from typing import Optional, List, Tuple, Dict, Set

# Data classes

@dataclass(frozen=True)
class ACLRule:
    acl_name: str
    sequence: int
    action: str              # permit / deny
    protocol: str            # ip / tcp / udp / icmp
    src: str                 # CIDR
    dst: str                 # CIDR
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    router: Optional[str] = None
    interface: Optional[str] = None
    direction: Optional[str] = None
    raw_line: Optional[str] = None

    def src_net(self) -> IPv4Network:
        return ip_network(self.src, strict=False)

    def dst_net(self) -> IPv4Network:
        return ip_network(self.dst, strict=False)


@dataclass
class ConflictResult:
    new_rule: ACLRule
    existing_rule: ACLRule
    overlap_src: str
    overlap_dst: str
    overlap_protocol: str
    overlap_dst_port: Optional[int]
    kind: str
    reason: str



# IP / wildcard helpers

def wildcard_to_prefix(ip_str: str, wcard: str) -> str:
    """
    Cisco ACL network + wildcard -> CIDR
    Example:
      192.168.40.0 0.0.0.255 -> 192.168.40.0/24
    """
    ip_parts = list(map(int, ip_str.split(".")))
    wc_parts = list(map(int, wcard.split(".")))
    mask_parts = [255 - x for x in wc_parts]
    mask_bin = "".join(f"{x:08b}" for x in mask_parts)
    prefix_len = mask_bin.count("1")
    return f"{ip_str}/{prefix_len}"

def normalize_interface_name(name: str) -> str:
    if not name:
        return name

    n = name.strip().lower()

    n = re.sub(r"^fastethernet", "f", n)
    n = re.sub(r"^fa", "f", n)

    n = re.sub(r"^gigabitethernet", "g", n)
    n = re.sub(r"^gi", "g", n)

    n = re.sub(r"^serial", "s", n)
    n = re.sub(r"^se", "s", n)

    n = re.sub(r"^loopback", "lo", n)

    return n

def parse_acl_address(tokens: List[str], i: int) -> Tuple[str, int]:
    """
    Parse Cisco ACL source/destination address from tokens[i:].

    Supported forms:
      any
      host 1.2.3.4
      192.168.10.0 0.0.0.255
      192.168.10.0/24   # tolerate already-normalized CIDR input
    """
    if i >= len(tokens):
        raise ValueError(f"parse_acl_address: index {i} out of range for tokens={tokens}")

    tok = tokens[i]

    if tok == "any":
        return "0.0.0.0/0", i + 1

    if tok == "host":
        if i + 1 >= len(tokens):
            raise ValueError(f"parse_acl_address: expected host IP after 'host', got tokens={tokens}")
        return f"{tokens[i+1]}/32", i + 2

    # tolerate already-normalized CIDR input
    if "/" in tok:
        return tok, i + 1

    # network wildcard form
    if i + 1 >= len(tokens):
        raise ValueError(f"parse_acl_address: expected wildcard after IP '{tok}', got tokens={tokens}")

    ip_str = tokens[i]
    wcard = tokens[i+1]
    return wildcard_to_prefix(ip_str, wcard), i + 2

# ACL line parser

def parse_acl_rule_line(acl_name: str, line: str) -> Optional[ACLRule]:
    """
    Parse lines like:
      70 permit icmp host 192.168.10.10 host 192.168.10.20
      120 deny tcp host 192.168.10.20 192.168.20.0 0.0.0.255 eq 23
      220 permit ip 192.168.10.0 0.0.0.255 host 192.168.10.40
    """
    if line is None:
        return None

    line = line.strip()
    if not line or line.startswith("!"):
        return None

    m = re.match(
        r"^(?:(\d+)\s+)?(permit|deny)\s+(ip|tcp|udp|icmp)\s+(.+)$",
        line,
        re.IGNORECASE
    )
    if not m:
        return None

    sequence = int(m.group(1)) if m.group(1) is not None else 9999
    action = m.group(2).lower()
    protocol = m.group(3).lower()
    rest = m.group(4).strip()

    tokens = rest.split()
    i = 0

    try:
        src, i = parse_acl_address(tokens, i)
        dst, i = parse_acl_address(tokens, i)
    except Exception as e:
        print(f"[parse_acl_rule_line ERROR] acl={acl_name}, line={line!r}, tokens={tokens}, i={i}, err={e}")
        return None

    # For current evaluation, only parse destination port.
    # Extended ACLs in your dataset appear in forms like:
    #   deny tcp <src> <dst> eq 22
    src_port = None
    dst_port = None

    if protocol in {"tcp", "udp"} and i < len(tokens):
        if tokens[i].lower() == "eq":
            try:
                dst_port = int(tokens[i + 1])
                i += 2
            except (ValueError, IndexError):
                print(f"[parse_acl_rule_line WARN] bad dst port in line: {line!r}")
                dst_port = None

    return ACLRule(
        acl_name=acl_name,
        sequence=sequence,
        action=action,
        protocol=protocol,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        raw_line=line
    )


# Router config parser

def parse_router_config_text(config_text: str, router_name: str) -> Dict[Tuple[str, str, str], List[ACLRule]]:
    """
    Parse ACL definitions, ACL rule lines, and interface bindings from raw config text.

    Returns:
        {(router, interface, direction): [ACLRule, ...]}
    """
    acl_defs: Dict[str, List[ACLRule]] = defaultdict(list)
    acl_bindings: Dict[str, Tuple[str, str]] = {}

    current_acl = None
    current_iface = None

    lines = config_text.splitlines()
    for raw in lines:
        line = raw.rstrip()

        m_acl = re.match(r"^ip access-list extended (\S+)$", line.strip(), re.IGNORECASE)
        if m_acl:
            current_acl = m_acl.group(1)
            current_iface = None
            continue

        m_iface = re.match(r"^interface (\S+)$", line.strip(), re.IGNORECASE)
        if m_iface:
            current_iface = normalize_interface_name(m_iface.group(1))
            current_acl = None
            continue

        if current_acl:
            rule = parse_acl_rule_line(current_acl, line)
            if rule:
                acl_defs[current_acl].append(rule)
            continue

        if current_iface:
            m_bind = re.match(r"^ip access-group (\S+)\s+(in|out)$", line.strip(), re.IGNORECASE)
            if m_bind:
                acl_name = m_bind.group(1)
                direction = m_bind.group(2).lower()
                acl_bindings[acl_name] = (current_iface, direction)

    attached: Dict[Tuple[str, str, str], List[ACLRule]] = defaultdict(list)

    for acl_name, rules in acl_defs.items():
        if acl_name not in acl_bindings:
            continue

        iface, direction = acl_bindings[acl_name]
        key = (router_name, iface, direction)

        for r in rules:
            attached[key].append(
                ACLRule(
                    acl_name=r.acl_name,
                    sequence=r.sequence,
                    action=r.action,
                    protocol=r.protocol,
                    src=r.src,
                    dst=r.dst,
                    src_port=r.src_port,
                    dst_port=r.dst_port,
                    router=router_name,
                    interface=normalize_interface_name(iface),
                    direction=direction,
                    raw_line=r.raw_line,
                )
            )

    for key in attached:
        attached[key].sort(key=lambda x: x.sequence)

    return attached

def parse_router_config(
    router_name: str,
    config_dir: str = "configs",
    filename_pattern: Optional[str] = "{router}.cfg",
    encoding: str = "utf-8",
) -> Dict[Tuple[str, str, str], List[ACLRule]]:
    """
    Load a router config file from disk using router_name, then parse it.

    Example:
        parse_router_config("R1", config_dir="router_configs")
        -> reads router_configs/R1.cfg
    """
    if filename_pattern is None:
        filename = f"{router_name}.cfg"
    else:
        filename = filename_pattern.format(router=router_name)

    path = Path(config_dir) / filename

    if not path.exists():
        raise FileNotFoundError(
            f"Router config file not found for router '{router_name}': {path}"
        )

    config_text = path.read_text(encoding=encoding)
    return parse_router_config_text(config_text, router_name)

# Topology handling

class NetworkTopology:
    def __init__(self, topo: dict):
        self.topo = topo
        self.objects = topo["objects"]
        self.interfaces = topo["interfaces"]
        self.switches = topo.get("switches", {})
        self.graph = self._build_router_graph()

    def _build_router_graph(self) -> Dict[str, List[str]]:
        graph = defaultdict(list)
        for router, ifaces in self.interfaces.items():
            for ifname, meta in ifaces.items():
                conn = meta.get("connected_to")
                if conn and ":" in conn:
                    peer_router = conn.split(":")[0]
                    graph[router].append(peer_router)
        return dict(graph)

    def interface_network(self, router: str, iface: str) -> IPv4Network:
        return ip_network(self.interfaces[router][iface]["ip"], strict=False)

    def find_router_for_ip(self, ip_or_net: str) -> Optional[Tuple[str, str]]:
        """
        Returns the first directly connected router/interface that contains this dst.
        For host or subnet.
        """
        target = ip_network(ip_or_net, strict=False)
        for router, ifaces in self.interfaces.items():
            for iface, meta in ifaces.items():
                iface_net = ip_network(meta["ip"], strict=False)
                # If target is inside directly connected subnet, this router/interface is destination edge
                if target.subnet_of(iface_net) or iface_net.subnet_of(target):
                    return router, iface
        return None

    def shortest_router_path(self, src_router: str, dst_router: str) -> List[str]:
        if src_router == dst_router:
            return [src_router]

        q = deque([[src_router]])
        visited = {src_router}
        while q:
            path = q.popleft()
            node = path[-1]
            for nei in self.graph.get(node, []):
                if nei in visited:
                    continue
                new_path = path + [nei]
                if nei == dst_router:
                    return new_path
                visited.add(nei)
                q.append(new_path)
        return []

    def path_interfaces_for_flow(self, src_net: str, dst_net: str) -> Set[Tuple[str, str, str]]:
        """
        Approximate feasible interfaces on the path from src subnet to dst subnet.

        Strategy:
        - find src edge router/interface
        - find dst edge router/interface
        - compute shortest router path
        - collect ingress/egress interfaces on that path
        """
        src_edge = self.find_router_for_ip(src_net)
        dst_edge = self.find_router_for_ip(dst_net)

        if not src_edge or not dst_edge:
            return set()

        src_router, src_iface = src_edge
        dst_router, dst_iface = dst_edge

        router_path = self.shortest_router_path(src_router, dst_router)
        if not router_path:
            return set()

        feasible = set()

        # add source LAN ingress and destination LAN egress-ish edges conservatively
        feasible.add((src_router, src_iface, "in"))
        feasible.add((src_router, src_iface, "out"))
        feasible.add((dst_router, dst_iface, "in"))
        feasible.add((dst_router, dst_iface, "out"))

        # add transit interfaces along router path
        for idx, router in enumerate(router_path):
            for iface, meta in self.interfaces[router].items():
                conn = meta.get("connected_to")
                if not conn or ":" not in conn:
                    continue
                peer_router, peer_iface = conn.split(":")
                # keep interfaces between adjacent routers in path
                if idx < len(router_path) - 1 and peer_router == router_path[idx + 1]:
                    feasible.add((router, iface, "out"))
                    feasible.add((peer_router, peer_iface, "in"))

        return feasible


# Overlap logic

def protocol_overlap(p1: str, p2: str) -> Optional[str]:
    p1 = p1.lower()
    p2 = p2.lower()
    if p1 == "ip":
        return p2
    if p2 == "ip":
        return p1
    if p1 == p2:
        return p1
    return None


def network_intersection(a: IPv4Network, b: IPv4Network) -> Optional[IPv4Network]:
    if a.subnet_of(b):
        return a
    if b.subnet_of(a):
        return b
    return None


def port_overlap(proto: str, p1: Optional[int], p2: Optional[int]) -> Optional[int]:
    if proto not in {"tcp", "udp"}:
        return None
    if p1 is None and p2 is None:
        return None
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1 == p2:
        return p1
    return None


def rule_overlap(r1: ACLRule, r2: ACLRule) -> Optional[Tuple[str, str, str, Optional[int]]]:
    proto = protocol_overlap(r1.protocol, r2.protocol)
    if proto is None:
        return None

    src_overlap = network_intersection(r1.src_net(), r2.src_net())
    if src_overlap is None:
        return None

    dst_overlap = network_intersection(r1.dst_net(), r2.dst_net())
    if dst_overlap is None:
        return None

    dport = port_overlap(proto, r1.dst_port, r2.dst_port)
    if proto in {"tcp", "udp"}:
        if r1.dst_port is not None and r2.dst_port is not None and dport is None:
            return None

    return str(src_overlap), str(dst_overlap), proto, dport

def rules_equivalent(r1: ACLRule, r2: ACLRule) -> bool:
    return (
        r1.action.lower() == r2.action.lower()
        and r1.protocol.lower() == r2.protocol.lower()
        and r1.src_net() == r2.src_net()
        and r1.dst_net() == r2.dst_net()
        and r1.src_port == r2.src_port
        and r1.dst_port == r2.dst_port
    )
    
def fully_covers(rule_cover: ACLRule, src_cidr: str, dst_cidr: str, proto: str, dport: Optional[int]) -> bool:
    p = protocol_overlap(rule_cover.protocol, proto)
    if p is None:
        return False

    src_ok = ip_network(src_cidr).subnet_of(rule_cover.src_net()) or ip_network(src_cidr) == rule_cover.src_net()
    dst_ok = ip_network(dst_cidr).subnet_of(rule_cover.dst_net()) or ip_network(dst_cidr) == rule_cover.dst_net()
    if not (src_ok and dst_ok):
        return False

    if proto in {"tcp", "udp"}:
        if rule_cover.dst_port is None:
            return True
        return rule_cover.dst_port == dport

    return True


# Conflict detection

def detect_conflicts_for_rule(
    new_rule: ACLRule,
    existing_rules: List[ACLRule],
    topology: NetworkTopology
) -> List[ConflictResult]:
    """
    Detect conflicts for one new rule against ordered existing rules on one ACL attachment.
    - check opposite action
    - check overlap
    - check feasible path
    - check if an earlier rule already fully covers the same overlap
    - if not shadowed, mark conflict
    """
    results: List[ConflictResult] = []

    # candidate must also be on feasible path
    feasible_ifaces = topology.path_interfaces_for_flow(new_rule.src, new_rule.dst)

    for idx, er in enumerate(existing_rules):
        if new_rule.action == er.action:
            continue

        # path validation for the existing rule's interface
        iface_key = (er.router, er.interface, er.direction)
        if iface_key not in feasible_ifaces:
            continue

        ov = rule_overlap(new_rule, er)
        if ov is None:
            continue

        ov_src, ov_dst, ov_proto, ov_dport = ov

        # RM approximation: (------> new)
        # if any earlier rule fully covers this same overlap, then er doesn't truly match it
        shadowed = False
        for prev in existing_rules[:idx]:
            if fully_covers(prev, ov_src, ov_dst, ov_proto, ov_dport):
                shadowed = True
                break

        if shadowed:
            continue

        if new_rule.action == "deny" and er.action == "permit":
            kind = "new_deny_shadows_existing_permit"
        elif new_rule.action == "permit" and er.action == "deny":
            kind = "new_permit_overrides_existing_deny"
        else:
            kind = "other"

        results.append(
            ConflictResult(
                new_rule=new_rule,
                existing_rule=er,
                overlap_src=ov_src,
                overlap_dst=ov_dst,
                overlap_protocol=ov_proto,
                overlap_dst_port=ov_dport,
                kind=kind,
                reason="overlap + not shadowed by earlier rule + feasible path"
            )
        )

    return results


def detect_conflicts(
    new_rule: ACLRule,
    all_existing: Dict[Tuple[str, str, str], List[ACLRule]],
    topology: NetworkTopology
) -> List[ConflictResult]:
    """
    In current dataset, the generated rule already has router/interface/direction.
    So we inspect the target attachment point directly.
    """
    if isinstance(topology, dict):
        topology = NetworkTopology(topology)

    key = (new_rule.router, new_rule.interface, new_rule.direction)
    existing_rules = all_existing.get(key, [])
    return detect_conflicts_for_rule(new_rule, existing_rules, topology)

def normalize_host_or_cidr(value: str) -> str:
    if "/" in value:
        return value
    return f"{value}/32"
    
# Generated rule builder
def build_generated_rule_from_fields(
    acl_name: str,
    router: str,
    interface: str,
    direction: str,
    action: str,
    protocol: str,
    src: str,
    dst: str,
    sequence: int = 9999,
    dst_port: Optional[int] = None,
    src_port: Optional[int] = None,
    raw_line: Optional[str] = None
) -> ACLRule:
    return ACLRule(
        acl_name=acl_name,
        sequence=sequence,
        action=action.lower(),
        protocol=protocol.lower(),
        src=normalize_host_or_cidr(src),
        dst=normalize_host_or_cidr(dst),
        src_port=src_port,
        dst_port=dst_port,
        router=router,
        interface=interface,
        direction=direction.lower(),
        raw_line=raw_line
    )
    
# wrapper to formulate ACL generator output to rule
def convert_generator_output_to_rule(row: dict) -> ACLRule:
    # example only — adapt to your actual row schema
    rule_info = row["Rules"][0]

    return build_generated_rule_from_fields(
        acl_name=row.get("L_Name", "ACL_GEN"),
        router=row["hostname"],
        interface=row["Intf_Name"],
        direction=row["direction"],
        action=rule_info["action"],
        protocol=rule_info["protocol"],
        src=rule_info["src_cidr"],
        dst=rule_info["dst_cidr"],
        dst_port=rule_info.get("dst_port"),
        sequence=9999,
        raw_line=row.get("configuration_response")
    )

def main_conflictDetection(topology_json):
    # 1) Load topology JSON file -> dict
    with open(topology_json, "r", encoding="utf-8") as f:
        topology_dict = json.load(f)

    # 2) Wrap dict in NetworkTopology object
    topo = NetworkTopology(topology_dict)

    # 3) Load all existing ACL rules from router config files
    all_existing = {}
    for router in ["R1", "R2", "R3"]:
        all_existing.update(
            parse_router_config(
                router,
                config_dir="./Groundtruth/Multirouter_generated/router_configs"
            )
        )

    # rows is the outputs from ACL generator Agent
    
    generated = convert_generator_output_to_rule(rows)

    
    
    # 5) Detect conflicts
    conflicts = detect_conflicts(generated, all_existing, topo)
    print("conflicts")
    print(conflicts)

    print("Detected conflicts:", len(conflicts))
    for c in conflicts:
        print("---")
        print("new:", c.new_rule.raw_line or c.new_rule)
        print("existing:", c.existing_rule.raw_line)
        print("existing attachment:", (c.existing_rule.router, c.existing_rule.interface, c.existing_rule.direction))
        print("overlap src:", c.overlap_src)
        print("overlap dst:", c.overlap_dst)
        print("protocol:", c.overlap_protocol)
        print("port:", c.overlap_dst_port)
        print("reason:", c.reason)

# generated = build_generated_rule_from_fields(
    #         acl_name="ACL_R3_G0_1_IOUT",
    #         router="R3",
    #         interface="g0/1",
    #         direction="out",
    #         action="deny",
    #         protocol="icmp",
    #         src="192.168.30.10",
    #         dst="192.168.20.20",
    #         sequence=510
    #     )
    
    # generated = build_generated_rule_from_fields(
    #         acl_name="ACL_R3_G0_2_IN",
    #         router="R3",
    #         interface="g0/2",
    #         direction="in",
    #         action="deny", # "permit",
    #         protocol="tcp",
    #         src="192.168.30.0/24",
    #         dst="192.168.10.30",
    #         sequence=140
    #     )