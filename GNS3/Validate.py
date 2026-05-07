from __future__ import annotations

import os
import re
import csv
import json
import time
import random
import telnetlib
import ipaddress
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple



################## default CONFIG ###########################
OUTPUT_DIR = "GNS3_output"
DEFAULT_TIMEOUT = 5
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

################## DATA MODELS ##################
@dataclass
class Endpoint:
    name: str
    ip: str
    port: int
    dev_type: str  # "PC", "VPCS", "Router", "Linux", etc.


@dataclass
class ACLRuleIntent:
    intent_text: str
    action: str
    protocol: Optional[str] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    src_subnet: Optional[str] = None
    dst_subnet: Optional[str] = None

    port: Optional[int] = None
    application: Optional[str] = None

    acl_name: Optional[str] = None
    router_name: Optional[str] = None
    interface: Optional[str] = None
    direction: Optional[str] = None
    expected_ace_hint: Optional[str] = None


@dataclass
class TrafficTestCase:
    name: str
    src_pc: str
    dst_ip: str
    protocol: str
    command: str
    expected_action: str
    rule_id: Optional[str] = None
    note: Optional[str] = None


@dataclass
class TrafficObservation:
    success: bool
    raw_output: str
    reason: str


@dataclass
class ACLCounterSnapshot:
    raw_output: str
    matched_lines: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    test_name: str
    src_pc: str
    dst_ip: str
    protocol: str
    command: str
    expected_action: str
    observed_success: bool
    observed_reason: str
    pass_result: bool
    acl_counter_matched: bool
    acl_counter_lines: List[str] = field(default_factory=list)
    note: Optional[str] = None


@dataclass
class ValidationReport:
    status: str
    router_name: str
    acl_name: Optional[str]
    config_apply_ok: bool
    config_verify_ok: bool
    precheck_ok: bool
    tests_total: int
    tests_passed: int
    tests_failed: int
    intent_classification: Dict[str, Any] = field(default_factory=dict)
    results: List[TestResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

ANSI_ESCAPE_RE = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

def clean_terminal_output(text: str) -> str:
    """
    Remove ANSI escapes, backspaces, bell chars, carriage artifacts.
    """
    if not text:
        return ""

    # remove ANSI escape sequences
    text = ANSI_ESCAPE_RE.sub("", text)

    # remove bell chars
    text = text.replace("\a", "")

    # apply backspaces
    cleaned = []
    for ch in text:
        if ch == "\b":
            if cleaned:
                cleaned.pop()
        else:
            cleaned.append(ch)
    text = "".join(cleaned)

    # normalize newlines
    text = text.replace("\r", "")
    return text


################## HELPERS ##################
def ensure_output_dir(path: str = OUTPUT_DIR) -> None:
    os.makedirs(path, exist_ok=True)


def safe_filename(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text)


def normalize_action(action: Optional[str]) -> Optional[str]:
    if action is None:
        return None
    action = action.strip().lower()
    if action in {"permit", "allow"}:
        return "permit"
    if action in {"deny", "block"}:
        return "deny"
    return action


def normalize_protocol(proto: Optional[str]) -> Optional[str]:
    if not proto:
        return None
    proto = proto.strip().lower()
    if proto in {"http", "https", "ssh", "telnet"}:
        # app names are not L3/L4 protocols; caller should also set application/port
        return "tcp"
    return proto


def normalize_subnet(subnet: Optional[str]) -> Optional[str]:
    """
    Converts:
      '172.16.10.0/24' -> '172.16.10.0/24'
      '172.16.10.0 0.0.0.255' -> '172.16.10.0/24'
    """
    if not subnet:
        return None
    subnet = subnet.strip()

    # CIDR already
    if "/" in subnet:
        try:
            return str(ipaddress.ip_network(subnet, strict=False))
        except Exception:
            return subnet

    # Cisco network wildcard format: "172.16.10.0 0.0.0.255"
    parts = subnet.split()
    if len(parts) == 2:
        net_ip, wildcard = parts
        try:
            wildcard_octets = [int(x) for x in wildcard.split(".")]
            mask_octets = [255 - x for x in wildcard_octets]
            mask_str = ".".join(str(x) for x in mask_octets)
            network = ipaddress.ip_network(f"{net_ip}/{mask_str}", strict=False)
            return str(network)
        except Exception:
            return subnet

    return subnet


def ip_in_subnet(ip: Optional[str], subnet: Optional[str]) -> bool:
    if not ip or not subnet:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(normalize_subnet(subnet), strict=False)
    except Exception:
        return False


def get_host_network_cidr(host: Dict[str, Any]) -> Optional[str]:
    """
    Tries D_Net first if it contains a network, else infers /24 from D_IP.
    """
    d_net = host.get("D_Net")
    d_ip = host.get("D_IP")

    if d_net:
        norm = normalize_subnet(str(d_net))
        if norm and "/" in norm:
            return norm

    if d_ip:
        try:
            return str(ipaddress.ip_network(f"{d_ip}/24", strict=False))
        except Exception:
            return None
    return None


def find_console_device(console_data: List[Dict[str, Any]], name: str) -> Optional[Endpoint]:
    for item in console_data:
        if item.get("D_Name") == name:
            return Endpoint(
                name=item.get("D_Name"),
                ip=item.get("D_IP"),
                port=int(item.get("D_Port")),
                dev_type=item.get("Type", "Unknown"),
            )
    return None


def get_host_by_ip(hosts: List[Dict[str, Any]], ip: str) -> Optional[Dict[str, Any]]:
    return next((h for h in hosts if h.get("D_IP") == ip), None)


def get_hosts_in_subnet(hosts: List[Dict[str, Any]], subnet: Optional[str]) -> List[Dict[str, Any]]:
    subnet = normalize_subnet(subnet)
    if not subnet:
        return []

    selected = []
    for h in hosts:
        hip = h.get("D_IP")
        if ip_in_subnet(hip, subnet):
            selected.append(h)
    return selected


def get_same_subnet_hosts(
    hosts: List[Dict[str, Any]],
    subnet: str,
    exclude_ip: Optional[str] = None
) -> List[Dict[str, Any]]:
    subnet = normalize_subnet(subnet)
    return [
        h for h in hosts
        if ip_in_subnet(h.get("D_IP"), subnet) and h.get("D_IP") != exclude_ip
    ]


def get_diff_subnet_hosts(
    hosts: List[Dict[str, Any]],
    subnet: str
) -> List[Dict[str, Any]]:
    subnet = normalize_subnet(subnet)
    return [
        h for h in hosts
        if not ip_in_subnet(h.get("D_IP"), subnet)
    ]

class TelnetSession:
    def __init__(self, host: str, port: int, timeout: int = 8):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tn = None

    def open(self) -> None:
        self.tn = telnetlib.Telnet(self.host, self.port, timeout=self.timeout)

    def close(self) -> None:
        if self.tn:
            self.tn.close()
            self.tn = None

    def write_line(self, line: str) -> None:
        if not self.tn:
            raise RuntimeError("Telnet session is not open")
        self.tn.write((line + "\r\n").encode("ascii"))

    def read_some(self) -> str:
        if not self.tn:
            return ""
        try:
            data = self.tn.read_very_eager().decode("ascii", errors="ignore")
            return clean_terminal_output(data)
        except Exception:
            return ""

    def read_until_prompt(self, prompt: str, timeout: Optional[int] = None) -> str:
        if not self.tn:
            raise RuntimeError("Telnet session is not open")
    
        timeout = timeout or self.timeout
        end_time = time.time() + timeout
        chunks = []
    
        while time.time() < end_time:
            time.sleep(0.2)
            chunk = self.read_some()
            if chunk:
                chunks.append(chunk)
                full = "".join(chunks)
                if prompt in full:
                    return full
    
        return "".join(chunks)
    
# detect the actual prompt
def detect_router_prompt(router_name: str) -> str:
    """
    Matches:
      R3#
      R3(config)#
      R3(config-if)#
      R3(config-ext-nacl)#
    """
    return rf"{re.escape(router_name)}(?:\([^)]+\))?#"
################## PC ACCESS ##################
def pc_access(command: str, pc_name: str, consol: List[Dict[str, Any]], timeout: int = DEFAULT_TIMEOUT) -> Optional[str]:
    ensure_output_dir()

    if not pc_name or not command:
        print("Invalid pc_name or command")
        return None

    endpoint = find_console_device(consol, pc_name)
    if endpoint is None:
        print(f"PC {pc_name} not found in console list.")
        return None

    output_file = os.path.join(
        OUTPUT_DIR,
        f"{safe_filename(pc_name)}_{safe_filename(command)}_output.txt"
    )

    try:
        sess = TelnetSession(endpoint.ip, endpoint.port, timeout=timeout)
        sess.open()
        sess.write_line(command)

        prompt = f"{pc_name}>"
        out = sess.read_until_prompt(prompt, timeout=timeout)
        sess.close()

        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"Command: {command}\n")
            f.write(out + "\n")
            f.write("-" * 80 + "\n")

        return out

    except Exception as e:
        print(f"pc_access error on {pc_name}: {e}")
        return None

################### ROUTER ACCESS ##################
def router_send_commands(
    router_name: str,
    commands: List[str],
    consol: List[Dict[str, Any]],
    timeout: int = 8,
) -> Optional[str]:
    ensure_output_dir()

    endpoint = find_console_device(consol, router_name)
    if endpoint is None:
        print(f"Router {router_name} not found in console list.")
        return None

    prompt_pattern = re.compile(rf"{re.escape(router_name)}(?:\([^)]+\))?#\s*$", re.MULTILINE)

    output_file = os.path.join(
        OUTPUT_DIR,
        f"{safe_filename(router_name)}_router_output.txt"
    )

    try:
        sess = TelnetSession(endpoint.ip, endpoint.port, timeout=timeout)
        sess.open()

        combined = []

        # wake up console
        sess.write_line("")
        time.sleep(1.5)

        # read initial prompt/banner
        initial = ""
        for _ in range(10):
            time.sleep(0.3)
            chunk = sess.read_some()
            if chunk:
                initial += chunk
                if prompt_pattern.search(initial):
                    break

        # disable paging
        sess.write_line("terminal length 0")
        time.sleep(1.0)

        tl_out = ""
        for _ in range(10):
            time.sleep(0.3)
            chunk = sess.read_some()
            if chunk:
                tl_out += chunk
                if prompt_pattern.search(tl_out):
                    break

        combined.append(f"\n$ terminal length 0\n{tl_out}")

        for cmd in commands:
            sess.write_line(cmd)
            time.sleep(1.0)

            out = ""
            for _ in range(20):
                time.sleep(0.25)
                chunk = sess.read_some()
                if chunk:
                    out += chunk
                    if prompt_pattern.search(out):
                        break

            combined.append(f"\n$ {cmd}\n{out}")

        sess.close()
        final_output = "\n".join(combined)

        with open(output_file, "a", encoding="utf-8") as f:
            f.write(final_output + "\n")
            f.write("=" * 80 + "\n")

        return final_output

    except Exception as e:
        print(f"router_send_commands error on {router_name}: {e}")
        return None

################## ROUTER-SIDE ACL FUNCTIONS ##################
def apply_acl_config(
    router_name: str,
    acl_commands: List[str],
    consol: List[Dict[str, Any]],
) -> bool:
    if not acl_commands:
        return True  # nothing to apply
        
    # full_cmds = ["enable", "configure terminal"] + acl_commands + ["end", "write memory"] already processed in build_deploy_commands_q0_aware  before
    out = router_send_commands(router_name, acl_commands, consol, timeout=10)
    return out is not None


def verify_acl_applied(
    router_name: str,
    acl_name: str,
    interface: Optional[str],
    direction: Optional[str],
    consol: List[Dict[str, Any]],
) -> Tuple[bool, str]:
    out = router_send_commands(
        router_name,
        [
            "show access-lists",
            "show running-config | include access-group",
        ],
        consol,
        timeout=10,
    )
    if out is None:
        return False, "Router output unavailable"

    out_lower = out.lower()
    acl_present = acl_name.lower() in out_lower
    bind_ok = f"ip access-group {acl_name.lower()} {direction}".lower() in out_lower if direction else True

    return (acl_present and bind_ok), out

def clear_acl_counters(router_name: str, consol: List[Dict[str, Any]]) -> bool:
    out = router_send_commands(router_name, ["clear access-list counters"], consol)
    return out is not None


def get_acl_counters(
    router_name: str,
    acl_name: Optional[str],
    consol: List[Dict[str, Any]],
    expected_ace_hint: Optional[Any] = None,
) -> ACLCounterSnapshot:
    out = router_send_commands(router_name, ["show access-lists"], consol)
    if out is None:
        return ACLCounterSnapshot(raw_output="", matched_lines=[])

    hint_text = None
    if expected_ace_hint is not None:
        hint_text = expected_ace_hint if isinstance(expected_ace_hint, str) else str(expected_ace_hint)
        hint_text = hint_text.lower()

    matched_lines = []
    for line in out.splitlines():
        line_norm = line.strip().lower()
        if acl_name and acl_name.lower() in line_norm:
            matched_lines.append(line.strip())
        elif hint_text and hint_text in line_norm:
            matched_lines.append(line.strip())
        elif "matches" in line_norm:
            matched_lines.append(line.strip())

    return ACLCounterSnapshot(raw_output=out, matched_lines=matched_lines)

################## PRECHECKS ##################
def router_precheck(router_name: str, consol: List[Dict[str, Any]]) -> Tuple[bool, str]:
    out = router_send_commands(
        router_name,
        ["show ip interface brief", "show ip route"],
        consol,
        timeout=10,
    )
    if out is None:
        return False, "Router precheck failed: no output"

    out_lower = out.lower()

    ok = (
        "$ show ip interface brief" in out_lower and
        "$ show ip route" in out_lower and
        router_name.lower() in out_lower
    )

    return ok, out

def baseline_ping_check(
    src_pc: str,
    dst_ip: str,
    consol: List[Dict[str, Any]],
) -> Tuple[bool, str]:
    out = pc_access(f"ping {dst_ip}", src_pc, consol)
    if out is None:
        return False, "No PC output"
    obs = parse_icmp_result(out)
    return obs.success, out

################## INTENT CLASSIFICATION ##################
def classify_intent(
    intent_text: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_subnet: Optional[str] = None,
    dst_subnet: Optional[str] = None,
    sub_net: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    text = str(intent_text or "").strip().lower()
    sub_net = sub_net or []

    src_subnet = normalize_subnet(src_subnet)
    dst_subnet = normalize_subnet(dst_subnet)

    # Match type
    if src_ip and dst_ip:
        match_type = "src_dst"
    elif src_subnet and dst_subnet:
        match_type = "srcnet_dstnet"
    elif src_ip and not (dst_ip or dst_subnet):
        match_type = "src_any"
    elif src_subnet and not (dst_ip or dst_subnet):
        match_type = "srcnet_any"
    elif not (src_ip or src_subnet) and dst_ip:
        match_type = "any_dst"
    elif not (src_ip or src_subnet) and dst_subnet:
        match_type = "any_dstnet"
    else:
        match_type = "any_any"

    # Exclusivity
    exclusivity_keywords = ["only", "just", "exclusively", "except", "no other", "alone"]
    exclusivity = any(k in text for k in exclusivity_keywords)

    # Path type
    through_router_keywords = [
        "exit", "exiting", "leave", "leaving",
        "through router", "through the router",
        "outside", "internet", "remote", "other subnet",
        "other network", "across router", "out of"
    ]
    local_keywords = [
        "same subnet", "same network", "local", "inside lan", "inside the lan"
    ]

    found_keywords = [k for k in through_router_keywords + local_keywords if k in text]

    if any(k in text for k in through_router_keywords):
        path_type = "through_router"
    elif any(k in text for k in local_keywords):
        path_type = "local_or_same_subnet"
    elif src_ip and dst_ip:
        src_host = next((h for h in sub_net if h.get("D_IP") == src_ip), None)
        dst_host = next((h for h in sub_net if h.get("D_IP") == dst_ip), None)
        src_net = get_host_network_cidr(src_host) if src_host else None
        dst_net = get_host_network_cidr(dst_host) if dst_host else None
        path_type = "through_router" if src_net and dst_net and src_net != dst_net else "local_or_same_subnet"
    elif src_subnet and dst_subnet:
        path_type = "through_router" if src_subnet != dst_subnet else "local_or_same_subnet"
    else:
        path_type = "unknown"

    # Scope
    if dst_ip:
        scope = "exact_only"
    elif dst_subnet:
        scope = "remote_only"
    elif path_type == "through_router":
        scope = "remote_only"
    else:
        scope = "mixed"

    needs_negative_test = exclusivity

    return {
        "match_type": match_type,
        "exclusivity": exclusivity,
        "path_type": path_type,
        "scope": scope,
        "needs_negative_test": needs_negative_test,
        "keywords": found_keywords,
        "src_net": src_subnet,
        "dst_net": dst_subnet,
    }

################## TEST TYPE DECISION ##################
def choose_test_method(intent: ACLRuleIntent) -> str:
    """
    Returns:
      - 'icmp'
      - 'tcp'
      - 'udp'
      - 'baseline_only'
    """
    proto = normalize_protocol(intent.protocol)
    app = (intent.application or "").strip().lower()
    text = (intent.intent_text or "").strip().lower()

    if proto == "icmp" or "icmp" in text or "ping" in text:
        return "icmp"

    if app == "http" or (proto == "tcp" and intent.port == 80):
        return "http"

    if app == "https" or (proto == "tcp" and intent.port == 443):
        return "https"

    if proto == "tcp":
        return "tcp"

    if proto == "udp":
        return "udp"

    return "baseline_only"

################## TEST GENERATORS ##################
def pick_src_dst_from_intent(intent: ACLRuleIntent, hosts: List[Dict[str, Any]]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    src_host = None
    dst_host = None

    if intent.src_ip:
        src_host = get_host_by_ip(hosts, intent.src_ip)
    elif intent.src_subnet:
        src_candidates = get_hosts_in_subnet(hosts, intent.src_subnet)
        src_host = src_candidates[0] if src_candidates else None

    if intent.dst_ip:
        dst_host = get_host_by_ip(hosts, intent.dst_ip)
    elif intent.dst_subnet:
        dst_candidates = get_hosts_in_subnet(hosts, intent.dst_subnet)
        dst_host = dst_candidates[0] if dst_candidates else None

    return src_host, dst_host


def generate_icmp_test_cases(intent: ACLRuleIntent, sub_net: List[Dict[str, Any]]) -> List[TrafficTestCase]:
    tests = []
    action = normalize_action(intent.action) or "deny"
    hosts = sub_net[:] if sub_net else []

    cls = classify_intent(
        intent_text=intent.intent_text,
        src_ip=intent.src_ip,
        dst_ip=intent.dst_ip,
        src_subnet=intent.src_subnet,
        dst_subnet=intent.dst_subnet,
        sub_net=sub_net,
    )

    print("Intent classification:", cls)
    match_type = cls["match_type"]

    if match_type in {"src_dst", "srcnet_dstnet"}:
        src, dst = pick_src_dst_from_intent(intent, hosts)
        if src and dst:
            tests.append(
                TrafficTestCase(
                    name="icmp_targeted_flow",
                    src_pc=src["D_Name"],
                    dst_ip=dst["D_IP"],
                    protocol="icmp",
                    command=f"ping {dst['D_IP']}",
                    expected_action=action,
                    note="ICMP targeted test based on IP/subnet intent"
                )
            )

    elif match_type in {"src_any", "srcnet_any"}:
        src = None
        if intent.src_ip:
            src = get_host_by_ip(hosts, intent.src_ip)
        elif intent.src_subnet:
            candidates = get_hosts_in_subnet(hosts, intent.src_subnet)
            src = candidates[0] if candidates else None

        if src:
            src_net = get_host_network_cidr(src)
            diff_hosts = get_diff_subnet_hosts(hosts, src_net) if src_net else []

            if diff_hosts:
                dst = diff_hosts[0]
                tests.append(
                    TrafficTestCase(
                        name="icmp_src_to_remote",
                        src_pc=src["D_Name"],
                        dst_ip=dst["D_IP"],
                        protocol="icmp",
                        command=f"ping {dst['D_IP']}",
                        expected_action=action,
                        note="ICMP source to remote test"
                    )
                )

    elif match_type in {"any_dst", "any_dstnet"}:
        dst = None
        if intent.dst_ip:
            dst = get_host_by_ip(hosts, intent.dst_ip)
        elif intent.dst_subnet:
            candidates = get_hosts_in_subnet(hosts, intent.dst_subnet)
            dst = candidates[0] if candidates else None

        if dst:
            dst_net = get_host_network_cidr(dst)
            diff_hosts = get_diff_subnet_hosts(hosts, dst_net) if dst_net else []

            if diff_hosts:
                src = diff_hosts[0]
                tests.append(
                    TrafficTestCase(
                        name="icmp_any_to_target",
                        src_pc=src["D_Name"],
                        dst_ip=dst["D_IP"],
                        protocol="icmp",
                        command=f"ping {dst['D_IP']}",
                        expected_action=action,
                        note="ICMP any-to-destination test"
                    )
                )

    elif match_type == "any_any":
        if len(hosts) >= 2:
            h1, h2 = hosts[0], hosts[1]
            tests.append(
                TrafficTestCase(
                    name="icmp_any_any",
                    src_pc=h1["D_Name"],
                    dst_ip=h2["D_IP"],
                    protocol="icmp",
                    command=f"ping {h2['D_IP']}",
                    expected_action=action,
                    note="Generic ICMP any-any fallback"
                )
            )

    return tests


def build_tcp_command(dst_ip: str, port: int, application: Optional[str], host_type: str = "linux") -> str:
    app = (application or "").lower()

    if host_type.lower() == "linux":
        if app == "http" or port == 80:
            return f"curl -I --max-time 3 http://{dst_ip}"
        if app == "https" or port == 443:
            return f"curl -k -I --max-time 3 https://{dst_ip}"
        return f"nc -zv -w 3 {dst_ip} {port}"

    # VPCS cannot reliably do TCP app tests
    return f"# UNSUPPORTED_TCP_TEST {dst_ip}:{port}"


def build_udp_command(dst_ip: str, port: int, application: Optional[str], host_type: str = "linux") -> str:
    if host_type.lower() == "linux":
        return f"nc -zvu -w 3 {dst_ip} {port}"
    return f"# UNSUPPORTED_UDP_TEST {dst_ip}:{port}"


def generate_tcp_test_cases(intent: ACLRuleIntent, sub_net: List[Dict[str, Any]], consol: List[Dict[str, Any]]) -> List[TrafficTestCase]:
    tests = []
    action = normalize_action(intent.action) or "deny"
    hosts = sub_net[:] if sub_net else []

    if not intent.port:
        return tests

    src, dst = pick_src_dst_from_intent(intent, hosts)
    if not src or not dst:
        return tests

    endpoint = find_console_device(consol, src["D_Name"])
    src_type = endpoint.dev_type if endpoint else "Unknown"

    if str(src_type).lower() == "vpcs":
        tests.append(
            TrafficTestCase(
                name="tcp_test_not_supported_on_vpcs",
                src_pc=src["D_Name"],
                dst_ip=dst["D_IP"],
                protocol="tcp",
                command="# UNSUPPORTED_TCP_TEST",
                expected_action=action,
                note="TCP validation requires Linux-like host tools; VPCS is insufficient."
            )
        )
        return tests

    cmd = build_tcp_command(dst["D_IP"], int(intent.port), intent.application, host_type=str(src_type))
    tests.append(
        TrafficTestCase(
            name="tcp_targeted_flow",
            src_pc=src["D_Name"],
            dst_ip=dst["D_IP"],
            protocol="tcp",
            command=cmd,
            expected_action=action,
            note="TCP targeted test based on IP/subnet intent"
        )
    )
    return tests


def generate_udp_test_cases(intent: ACLRuleIntent, sub_net: List[Dict[str, Any]], consol: List[Dict[str, Any]]) -> List[TrafficTestCase]:
    tests = []
    action = normalize_action(intent.action) or "deny"
    hosts = sub_net[:] if sub_net else []

    if not intent.port:
        return tests

    src, dst = pick_src_dst_from_intent(intent, hosts)
    if not src or not dst:
        return tests

    endpoint = find_console_device(consol, src["D_Name"])
    src_type = endpoint.dev_type if endpoint else "Unknown"

    if str(src_type).lower() == "vpcs":
        tests.append(
            TrafficTestCase(
                name="udp_test_not_supported_on_vpcs",
                src_pc=src["D_Name"],
                dst_ip=dst["D_IP"],
                protocol="udp",
                command="# UNSUPPORTED_UDP_TEST",
                expected_action=action,
                note="UDP validation requires Linux-like host tools; VPCS is insufficient."
            )
        )
        return tests

    cmd = build_udp_command(dst["D_IP"], int(intent.port), intent.application, host_type=str(src_type))
    tests.append(
        TrafficTestCase(
            name="udp_targeted_flow",
            src_pc=src["D_Name"],
            dst_ip=dst["D_IP"],
            protocol="udp",
            command=cmd,
            expected_action=action,
            note="UDP targeted test based on IP/subnet intent"
        )
    )
    return tests


def generate_negative_icmp_tests(intent: ACLRuleIntent, sub_net: List[Dict[str, Any]]) -> List[TrafficTestCase]:
    tests = []
    hosts = sub_net[:] if sub_net else []

    cls = classify_intent(
        intent_text=intent.intent_text,
        src_ip=intent.src_ip,
        dst_ip=intent.dst_ip,
        src_subnet=intent.src_subnet,
        dst_subnet=intent.dst_subnet,
        sub_net=sub_net,
    )

    if not cls["needs_negative_test"]:
        return tests

    # Example: permit only subnet X to remote subnet Y
    if intent.src_subnet:
        src_hosts = get_hosts_in_subnet(hosts, intent.src_subnet)
        if src_hosts:
            allowed_src = src_hosts[0]
            allowed_src_net = get_host_network_cidr(allowed_src)

            alt_src = next(
                (h for h in hosts if get_host_network_cidr(h) == allowed_src_net and h["D_IP"] != allowed_src["D_IP"]),
                None
            )

            remote_dst = None
            if intent.dst_subnet:
                dst_hosts = get_hosts_in_subnet(hosts, intent.dst_subnet)
                remote_dst = dst_hosts[0] if dst_hosts else None
            elif allowed_src_net:
                diff_hosts = get_diff_subnet_hosts(hosts, allowed_src_net)
                remote_dst = diff_hosts[0] if diff_hosts else None

            if alt_src and remote_dst:
                tests.append(
                    TrafficTestCase(
                        name="negative_other_host_same_subnet_to_remote_icmp",
                        src_pc=alt_src["D_Name"],
                        dst_ip=remote_dst["D_IP"],
                        protocol="icmp",
                        command=f"ping {remote_dst['D_IP']}",
                        expected_action="deny",
                        note="Negative test for exclusive policy"
                    )
                )

    return tests

################## RESULT PARSING ##################
def parse_icmp_result(output: Optional[str]) -> TrafficObservation:
    if output is None:
        return TrafficObservation(False, "", "no output")

    out = output.lower()

    if "bytes from" in out:
        return TrafficObservation(True, output, "reply detected")

    if "administratively prohibited" in out:
        return TrafficObservation(False, output, "acl deny detected")

    if "0% packet loss" in out:
        return TrafficObservation(True, output, "no packet loss")

    if (
        "100% packet loss" in out
        or "timeout" in out
        or "unreachable" in out
        or "failed" in out
    ):
        return TrafficObservation(False, output, "icmp failure")

    return TrafficObservation(False, output, "unknown icmp result")


def parse_tcp_udp_result(output: Optional[str]) -> TrafficObservation:
    if output is None:
        return TrafficObservation(False, "", "no output")

    out = output.lower()

    success_patterns = [
        "connected",
        "open",
        "http/",
        "200 ok",
        "301 moved",
        "302 found",
        "connection to",
        "succeeded",
    ]

    fail_patterns = [
        "refused",
        "timed out",
        "timeout",
        "failed",
        "unreachable",
        "no route",
        "could not resolve",
        "blocked",
        "denied",
    ]

    for p in success_patterns:
        if p in out:
            return TrafficObservation(True, output, f"matched success pattern: {p}")

    for p in fail_patterns:
        if p in out:
            return TrafficObservation(False, output, f"matched failure pattern: {p}")

    return TrafficObservation(False, output, "unknown tcp/udp result")


def evaluate_expected_vs_observed(expected_action: str, observed_success: bool) -> bool:
    expected_action = normalize_action(expected_action) or "deny"
    if expected_action == "permit":
        return observed_success
    if expected_action == "deny":
        return not observed_success
    return False

################## TEST EXECUTION ##################
def extract_acl_hit(output: str) -> Optional[str]:
    for line in output.splitlines():
        if "matches" in line.lower():
            parts = line.split("(")
            if len(parts) > 1 and "matches" in parts[1]:
                try:
                    hits = int(parts[1].split()[0])
                    if hits > 0:
                        return line.strip()
                except Exception:
                    pass
    return None


def run_single_test(
    test_case: TrafficTestCase,
    intent: ACLRuleIntent,
    consol: List[Dict[str, Any]],
) -> TestResult:
    acl_counter_matched = False
    acl_lines: List[str] = []
    rule_hit = None
    snapshot = ACLCounterSnapshot(raw_output="", matched_lines=[])

    if test_case.command.startswith("# UNSUPPORTED"):
        return TestResult(
            test_name=test_case.name,
            src_pc=test_case.src_pc,
            dst_ip=test_case.dst_ip,
            protocol=test_case.protocol,
            command=test_case.command,
            expected_action=test_case.expected_action,
            observed_success=False,
            observed_reason="unsupported test method on current host type",
            pass_result=False,
            acl_counter_matched=False,
            acl_counter_lines=[],
            note=test_case.note,
        )

    if intent.router_name:
        clear_acl_counters(intent.router_name, consol)

    raw = pc_access(test_case.command, test_case.src_pc, consol)

    if test_case.name.startswith("http_"):
        obs = parse_http_result(raw)
    elif test_case.protocol == "icmp":
        obs = parse_icmp_result(raw)
    else:
        obs = parse_tcp_udp_result(raw)

    if intent.router_name:
        snapshot = get_acl_counters(
            router_name=intent.router_name,
            acl_name=intent.acl_name,
            consol=consol,
            expected_ace_hint=intent.expected_ace_hint,
        )

        rule_hit = extract_acl_hit(snapshot.raw_output)
        if rule_hit:
            acl_counter_matched = True
            acl_lines = [rule_hit]

    passed = evaluate_expected_vs_observed(test_case.expected_action, obs.success)

    return TestResult(
        test_name=test_case.name,
        src_pc=test_case.src_pc,
        dst_ip=test_case.dst_ip,
        protocol=test_case.protocol,
        command=test_case.command,
        expected_action=test_case.expected_action,
        observed_success=obs.success,
        observed_reason=obs.reason,
        pass_result=passed,
        acl_counter_matched=acl_counter_matched,
        acl_counter_lines=acl_lines,
        note=test_case.note,
    )


def run_test_suite(
    test_cases: List[TrafficTestCase],
    intent: ACLRuleIntent,
    consol: List[Dict[str, Any]],
    sleep_between_tests: float = 1.0,
) -> List[TestResult]:
    results = []
    for tc in test_cases:
        result = run_single_test(tc, intent, consol)
        results.append(result)
        time.sleep(sleep_between_tests)
    return results

################## REPORTING ##################
def save_report_json(report: ValidationReport, filepath: str) -> None:
    ensure_output_dir()
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2)


def save_report_csv(report: ValidationReport, filepath: str) -> None:
    ensure_output_dir()
    fieldnames = [
        "test_name", "src_pc", "dst_ip", "protocol", "command",
        "expected_action", "observed_success", "observed_reason",
        "pass_result", "acl_counter_matched", "acl_counter_lines", "note"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in report.results:
            row = asdict(r)
            row["acl_counter_lines"] = " | ".join(r.acl_counter_lines)
            writer.writerow(row)


def print_summary(report: ValidationReport) -> None:
    print("\n" + "=" * 80)
    print("ACL VALIDATION SUMMARY")
    print("=" * 80)
    print(f"Status            : {report.status}")
    print(f"Router            : {report.router_name}")
    print(f"ACL               : {report.acl_name}")
    print(f"Config Apply OK   : {report.config_apply_ok}")
    print(f"Config Verify OK  : {report.config_verify_ok}")
    print(f"Precheck OK       : {report.precheck_ok}")
    print(f"Tests Total       : {report.tests_total}")
    print(f"Tests Passed      : {report.tests_passed}")
    print(f"Tests Failed      : {report.tests_failed}")

    if report.errors:
        print("\nErrors:")
        for e in report.errors:
            print(f"- {e}")

    print("\nPer-test results:")
    for r in report.results:
        print(
            f"[{'PASS' if r.pass_result else 'FAIL'}] "
            f"{r.test_name}: {r.src_pc} -> {r.dst_ip} | "
            f"expected={r.expected_action}, observed_success={r.observed_success}, "
            f"reason={r.observed_reason}, acl_hit={r.acl_counter_matched}"
        )

################## MAIN VALIDATION PIPELINE ##################
def validate_acl_in_gns3(
    intent: ACLRuleIntent,
    acl_commands: List[str],
    consol: List[Dict[str, Any]],
    sub_net: List[Dict[str, Any]],
    include_negative_tests: bool = True,
) -> ValidationReport:
    errors: List[str] = []

    if not intent.router_name:
        return ValidationReport(
            status="failed",
            router_name="UNKNOWN",
            acl_name=intent.acl_name,
            config_apply_ok=False,
            config_verify_ok=False,
            precheck_ok=False,
            tests_total=0,
            tests_passed=0,
            tests_failed=0,
            intent_classification={},
            results=[],
            errors=["router_name is required in ACLRuleIntent"],
        )

    # 1) Precheck
    precheck_ok, _ = router_precheck(intent.router_name, consol)
    if not precheck_ok:
        errors.append("Router precheck failed")

    # 2) Apply config
    config_apply_ok = apply_acl_config(intent.router_name, acl_commands, consol)
    if not config_apply_ok:
        errors.append("ACL config apply failed")

    # 3) Verify config
    config_verify_ok = False
    if config_apply_ok and intent.acl_name:
        config_verify_ok, verify_out = verify_acl_applied(
                router_name=intent.router_name,
                acl_name=intent.acl_name,
                interface=intent.interface,
                direction=intent.direction,
                consol=consol,
            )
        print("VERIFY OUT:")
        print(verify_out)
        
        precheck_ok, precheck_out = router_precheck(intent.router_name, consol)
        print("PRECHECK OUT:")
        print(precheck_out)
        if not config_verify_ok:
            errors.append("ACL verification failed")
    else:
        errors.append("Skipped ACL verification: missing acl_name or apply failed")

    # 4) Classify intent
    classification = classify_intent(
        intent_text=intent.intent_text,
        src_ip=intent.src_ip,
        dst_ip=intent.dst_ip,
        src_subnet=intent.src_subnet,
        dst_subnet=intent.dst_subnet,
        sub_net=sub_net,
    )

    # 5) Generate protocol-aware tests
    method = choose_test_method(intent)
    test_cases: List[TrafficTestCase] = []

    if method == "icmp":
        test_cases = generate_icmp_test_cases(intent, sub_net)
        if include_negative_tests:
            test_cases.extend(generate_negative_icmp_tests(intent, sub_net))
    
    elif method == "http":
        test_cases = generate_http_test_cases(intent, sub_net, consol)
    
    elif method == "tcp":
        test_cases = generate_tcp_test_cases(intent, sub_net, consol)
    
    elif method == "udp":
        test_cases = generate_udp_test_cases(intent, sub_net, consol)
    
    else:
        errors.append("No enforceable protocol-specific test available; only baseline checks are possible")

    if not test_cases:
        errors.append("No test cases generated")

    # 6) Run tests
    results = run_test_suite(test_cases, intent, consol) if test_cases else []

    tests_passed = sum(1 for r in results if r.pass_result)
    tests_failed = len(results) - tests_passed

    # 7) Final status
    if config_apply_ok and config_verify_ok and tests_failed == 0 and len(results) > 0:
        status = "ok"
    elif len(results) == 0:
        status = "needs_more_data"
    else:
        status = "failed"

    return ValidationReport(
        status=status,
        router_name=intent.router_name,
        acl_name=intent.acl_name,
        config_apply_ok=config_apply_ok,
        config_verify_ok=config_verify_ok,
        precheck_ok=precheck_ok,
        tests_total=len(results),
        tests_passed=tests_passed,
        tests_failed=tests_failed,
        intent_classification=classification,
        results=results,
        errors=errors,
    )


# Add an HTTP test generator
def generate_http_test_cases(intent: ACLRuleIntent,
                             sub_net: List[Dict[str, Any]],
                             consol: List[Dict[str, Any]]) -> List[TrafficTestCase]:
    tests = []
    action = normalize_action(intent.action) or "deny"
    hosts = sub_net[:] if sub_net else []

    src, dst = pick_src_dst_from_intent(intent, hosts)
    if not src or not dst:
        return tests

    endpoint = find_console_device(consol, src["D_Name"])
    src_type = endpoint.dev_type if endpoint else "Unknown"

    if str(src_type).lower() != "linux":
        tests.append(
            TrafficTestCase(
                name="http_test_not_supported_on_current_host",
                src_pc=src["D_Name"],
                dst_ip=dst["D_IP"],
                protocol="tcp",
                command="# UNSUPPORTED_HTTP_TEST",
                expected_action=action,
                note="HTTP validation requires a Linux-capable source host with curl/wget."
            )
        )
        return tests

    # HEAD request is enough to test reachability to port 80
    cmd = f"curl -I --max-time 5 http://{dst['D_IP']}"
    tests.append(
        TrafficTestCase(
            name="http_targeted_flow",
            src_pc=src["D_Name"],
            dst_ip=dst["D_IP"],
            protocol="tcp",
            command=cmd,
            expected_action=action,
            note="HTTP HEAD request to test TCP/80 ACL enforcement"
        )
    )
    return tests

# Add HTTP-aware result parsing
def parse_http_result(output: Optional[str]) -> TrafficObservation:
    if output is None:
        return TrafficObservation(False, "", "no output")

    out = output.lower()

    success_patterns = [
        "http/",
        "200 ok",
        "301 moved",
        "302 found",
        "403 forbidden",
        "404 not found",
    ]

    fail_patterns = [
        "connection timed out",
        "timed out",
        "failed to connect",
        "could not connect",
        "connection refused",
        "no route to host",
        "network is unreachable",
        "operation timed out",
    ]

    for p in success_patterns:
        if p in out:
            return TrafficObservation(True, output, f"http response detected: {p}")

    for p in fail_patterns:
        if p in out:
            return TrafficObservation(False, output, f"http failure detected: {p}")

    return TrafficObservation(False, output, "unknown http result")

# Add a baseline HTTP test before applying the ACL
def baseline_http_check(src_pc: str, dst_ip: str, consol: List[Dict[str, Any]]) -> Tuple[bool, str]:
    out = pc_access(f"curl -I --max-time 5 http://{dst_ip}", src_pc, consol)
    obs = parse_http_result(out)
    return obs.success, out