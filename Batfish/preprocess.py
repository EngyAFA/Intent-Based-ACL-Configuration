import ipaddress
import re
import random
from Helpers.Formats import normalize_interface_name, normalize_action, _norm_lower
from Helpers.Finder import _find_iface_for_exact_prefix
from Batfish.Questions import find_acl_attachments
#################### Normalization function. ######################
###################################################################
def _is_none_any(value) -> bool:
    normalized_value = _norm_lower(value)

    return normalized_value in (
        "",
        "none",
        "any",
        "null",
    )


def _norm_intf(interface_name: str) -> str:
    if not interface_name:
        return ""

    normalized_name = str(interface_name).strip().lower()

    if normalized_name.startswith("fastethernet"):
        return normalized_name

    if normalized_name.startswith("fa"):
        return "fastethernet" + normalized_name[2:]

    if normalized_name.startswith("f"):
        return "fastethernet" + normalized_name[1:]

    if normalized_name.startswith("gigabitethernet"):
        return normalized_name

    if normalized_name.startswith("gi"):
        return "gigabitethernet" + normalized_name[2:]

    if normalized_name.startswith("g"):
        return "gigabitethernet" + normalized_name[1:]

    if normalized_name.startswith("serial"):
        return normalized_name

    if normalized_name.startswith("se"):
        return "serial" + normalized_name[2:]

    if normalized_name.startswith("s"):
        return "serial" + normalized_name[1:]

    return normalized_name


def _norm_dir(direction: str) -> str:
    normalized_direction = (direction or "").strip().lower()

    if normalized_direction in ("in", "inbound"):
        return "in"

    if normalized_direction in ("out", "outbound"):
        return "out"

    return normalized_direction


def _norm_none(value):
    if value is None:
        return None

    normalized_value = str(value).strip()

    return (
        None
        if normalized_value.lower() in ("none", "")
        else normalized_value
    )
    
############### Batfish may return Interface(hostname='r2_2', interface='FastEthernet1/0') ##############
############### or a string like 'r2_2[FastEthernet1/0]' or just 'FastEthernet1/0'.  ####################
############### --> Normalize to bare interface name. ###################################################
def normalize_iface_name(x) -> str:

    if x is None:
        return ""

    # If it's an Interface object, try common attributes
    # (pybatfish objects vary by version)
    for attr in ("interface", "name"):
        if hasattr(x, attr):
            try:
                v = getattr(x, attr)
                if isinstance(v, str):
                    x = v
                    break
            except Exception:
                pass

    # Fallback: stringify
    s = str(x).strip()

    # If it's "node[iface]" keep only iface
    m = re.search(r"\[(.+?)\]$", s)
    if m:
        return m.group(1).strip()

    # If it's "node iface" or other formats, last token is often iface
    # (optional but helpful)
    return s.split()[-1].strip()

def iface_to_name(interface) -> str:
    # Batfish returns either a string or an Interface(hostname='r2_2', interface='Serial0/0')
    if interface is None:
        return None

    if hasattr(interface, "interface"):
        return str(interface.interface)

    return str(interface)


# find column names (Batfish sometimes uses different casing)
# used inside find_acl_attachments

def _canon_net(network: str):
    """
    Canonicalize a subnet string
    - "172.16.30.0"   -> "172.16.30.0/24"  (assume /24 if mask missing)
    - "172.16.30.0/24"-> "172.16.30.0/24"
    Returns None if invalid/empty.
    """
    if network is None:
        return None

    network_text = str(network).strip()

    if not network_text or network_text.lower() in ("none", "any"):
        return None

    try:
        if "/" not in network_text:
            network_text = f"{network_text}/24"

        return str(ipaddress.ip_network(network_text, strict=False))

    except Exception:
        return None

def _same_net(a: str, b: str) -> bool:
    ca, cb = _canon_net(a), _canon_net(b)
    return (ca is not None) and (cb is not None) and (ca == cb)


######## helping function: Analyze the ip to determine its type and suggest one incase of none to test the flows in Batfish questions ##########
############################################################################################################################

def analyze_ip(ip: str, sub_net: list) -> dict:
    if ip in ["None", "none", "Any"]:
        return {
            "IP_Address": "none",
            "type": "none",
            "suggested_Address": "none",
        }

    for device in sub_net:
        if ip == device["D_IP"]:
            return {
                "IP_Address": ip,
                "type": "Device Address",
                "suggested_Address": ip,
            }

    for device in sub_net:
        suggested_addresses = [
            item
            for item in sub_net
            if (
                item.get("D_Net") == device.get("D_Net")
                and item.get("D_IP") != device.get("D_IP")
            )
        ]

        suggested_address = random.choice(suggested_addresses)

        return {
            "IP_Address": ip,
            "type": "Network Address",
            "suggested_Address": suggested_address["D_IP"],
        }
#     return 
# - src_IP_Address: {source_analysis['IP_Address']}
# - src_type: {source_analysis['type']}
# - src_suggested Address: {source_analysis['suggested_Address']}
# - dst_IP_Address: {destination_analysis['IP_Address']}
# - dst_type: {destination_analysis['type']}
# - dst_suggested Address: {destination_analysis['suggested_Address']}"""


######## helping function: Picks test IPs from Sub_Net deterministically (no randomness). ##########
############################################################################################################################
def choose_any_ip(sub_net: list, avoid_ip: str = None):
    for entry in sub_net or []:
        ip_address = entry.get("D_IP")

        if ip_address and ip_address != avoid_ip:
            return ip_address

    return None


def choose_ip_in_subnet(
    subnet: str,
    sub_net: list,
    avoid_ip: str = None,
):
    for entry in sub_net or []:
        if entry.get("D_Net") == subnet:
            ip_address = entry.get("D_IP")

            if ip_address and ip_address != avoid_ip:
                return ip_address

    return None


def choose_ip_outside_subnet(
    subnet: str,
    sub_net: list,
    avoid_ip: str = None,
):
    for entry in sub_net or []:
        if entry.get("D_Net") != subnet:
            ip_address = entry.get("D_IP")

            if ip_address and ip_address != avoid_ip:
                return ip_address

    return None


# ---------- IP / subnet helpers ----------
def choose_ip_from_subnet(
    subnet: str,
    sub_net: list,
    avoid_ip: str = None,
):
    # Pick a deterministic test IP from Sub_Net for a given subnet.
    if not sub_net:
        return None

    # Prefer IP in requested subnet and != avoid_ip
    if subnet:
        for entry in sub_net:
            device_ip = entry.get("D_IP")
            device_network = entry.get("D_Net")

            if (
                device_network == subnet
                and device_ip
                and device_ip != avoid_ip
            ):
                return device_ip

    # Fallback: any IP different from avoid_ip
    for entry in sub_net:
        device_ip = entry.get("D_IP")

        if device_ip and device_ip != avoid_ip:
            return device_ip

    return None
################ helping function: specify action and its opposite, also to determine the protocol in case of None ##########
############################################################################################################################

def actdef action_test(action: str) -> str:
    # Return the opposite action: permit <-> deny.
    normalized_action = normalize_action(action)

    if normalized_action == "permit":
        return "deny"

    if normalized_action == "deny":
        return "permit"

    return normalized_action


def protocol_test(protocol: str, app: str):
    # ip, None
    if app is None:
        if protocol == "IP" or protocol is None:
            # any application for IP
            app = "http"

    print(app)

    return app

def normalize_acl_line(s: str) -> str:
    # normalize spacing/case to compare safely
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s
    
def _opposite_action(a: str) -> str:
    
    a = normalize_action(a)
    
    return "deny" if a == "permit" else "permit"


################ helping function: working with IP addresses and subnets ##########
############################################################################################################################

def _parse_subnet(cidr: str):
    if _is_none_any(cidr):
        return None

    try:
        return ipaddress.ip_network(str(cidr), strict=False)

    except Exception:
        return None


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(
            cidr,
            strict=False,
        )

    except Exception:
        return False


def _entries(sub_net: list) -> list:
    # expects list of dicts with D_IP, D_Net
    entries = []

    for entry in sub_net or []:
        if entry.get("D_IP") and entry.get("D_Net"):
            entries.append(entry)

    return entries


def _unique_subnets(sub_net: list) -> list:
    networks = []
    seen_networks = set()

    for entry in _entries(sub_net):
        network = str(entry["D_Net"])

        if network not in seen_networks:
            seen_networks.add(network)
            networks.append(network)

    return networks


def _hosts_in_subnet(sub_net: list, subnet_cidr: str) -> list:
    subnet_cidr = str(subnet_cidr)
    hosts = []

    for entry in _entries(sub_net):
        if str(entry["D_Net"]) == subnet_cidr:
            hosts.append(str(entry["D_IP"]))

    return hosts


def _ip_in_prefix(ip: str, prefix: str) -> bool:
    """
    Returns True if IP belongs to the given prefix.
    Example: _ip_in_prefix('172.16.10.3','172.16.10.0/24') -> True
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(
            prefix,
            strict=False,
        )

    except Exception:
        return False


def _prefix_is_inside(prefix: str, inside_prefixes: list) -> bool:
    """
    Checks if a subnet belongs to one of the inside prefixes.
    """
    try:
        network = ipaddress.ip_network(prefix, strict=False)

        for inside_prefix in inside_prefixes:
            inside_network = ipaddress.ip_network(
                inside_prefix,
                strict=False,
            )

            if network.subnet_of(inside_network):
                return True

    except Exception:
        pass

    return False


def _infer_subnet_of_host(sub_net: list, host_ip: str):
    for entry in _entries(sub_net):
        if str(entry.get("D_IP")) == str(host_ip):
            return _canon_net(entry.get("D_Net"))

    return None
    
# def _pick_host_from_subnet(Sub_Net, subnet_cidr, exclude=None):
#     exclude = set(exclude or [])
#     candidates = [h for h in _hosts_in_subnet(Sub_Net, subnet_cidr) if h not in exclude]
#     return random.choice(candidates) if candidates else None
def _pick_host_from_subnet(Sub_Net, subnet, exclude=None):
    exclude = set(exclude or [])
    target = _canon_net(subnet)
    if target is None:
        return None

    for e in _entries(Sub_Net):
        if str(e.get("D_IP")) in exclude:
            continue
        if _same_net(e.get("D_Net"), target):
            return str(e.get("D_IP"))
    return None
    
def _pick_host_any(sub_net: list, exclude=None):
    exclude = set(exclude or [])
    candidates = []

    for entry in _entries(sub_net):
        ip_address = str(entry["D_IP"])

        if ip_address not in exclude:
            candidates.append(ip_address)

    return random.choice(candidates) if candidates else None


def _pick_other_subnet(
    sub_net: list,
    not_this_subnet: str,
    k: int = 2,
) -> list:
    networks = []

    for network in _unique_subnets(sub_net):
        if str(network) != str(not_this_subnet):
            networks.append(network)

    return networks[:k]


def _intent_directionality(intent_text: str) -> str:
    intent_text = (intent_text or "").lower()
    words = set(re.findall(r"[a-z]+", intent_text))

    egress_words = {
        "exit",
        "exiting",
        "egress",
        "outbound",
        "out",
        "outside",
        "internet",
    }
    ingress_words = {
        "enter",
        "entering",
        "ingress",
        "inbound",
        "protect",
        "block",
        "deny",
        "prohibit",
        "to",
        "into",
        "toward",
        "access",
        "inside",
        "in",
    }

    egress = len(words & egress_words) > 0
    ingress = len(words & ingress_words) > 0

    if egress and not ingress:
        return "egress"

    if ingress and not egress:
        return "ingress"

    return "unspecified"


def _restriction_mode(
    intent_text: str,
    src_scope: str,
    dst_scope: str,
    port,
    app,
) -> str:
    normalized_intent = _norm_lower(intent_text)

    only = "only" in normalized_intent
    except_found = "except" in normalized_intent

    if except_found:
        # if except is present, treat as restriction always
        # try to categorize
        if "port" in normalized_intent or re.search(
            r"\b\d{1,5}\b",
            normalized_intent,
        ):
            return "except"

        if any(
            app_name in normalized_intent
            for app_name in ("dns", "http", "https", "ssh", "telnet", "icmp")
        ):
            return "except"

        return "except"

    if only:
        if src_scope == "host" and any(
            word in normalized_intent
            for word in ("host", "source", "src")
        ):
            return "only_host"

        if dst_scope == "host" and any(
            word in normalized_intent
            for word in ("destination", "dst", "server", "host")
        ):
            return "only_dst"

        if (
            not _is_none_any(port)
            or "port" in normalized_intent
            or re.search(r"\b\d{1,5}\b", normalized_intent)
        ):
            return "only_port"

        if (
            not _is_none_any(app)
            or any(
                app_name in normalized_intent
                for app_name in ("dns", "http", "https", "ssh", "icmp")
            )
        ):
            return "only_app"

        return "other"

    return "none"


def _representative_disallowed_app_port(app, port) -> tuple:
    # super simple examples
    if _norm_lower(app) == "dns" or str(port) == "53":
        return "http", "80"

    if _norm_lower(app) == "http" or str(port) == "80":
        return "dns", "53"

    return "http", "80"


def _scope_from_entities(
    src_ip: str,
    src_subnet: str,
    dst_ip: str,
    dst_subnet: str,
) -> tuple:
    # host if specific IP present, else subnet if subnet present, else any
    source_scope = (
        "host"
        if not _is_none_any(src_ip)
        else (
            "subnet"
            if not _is_none_any(src_subnet)
            else "any"
        )
    )
    destination_scope = (
        "host"
        if not _is_none_any(dst_ip)
        else (
            "subnet"
            if not _is_none_any(dst_subnet)
            else "any"
        )
    )

    return source_scope, destination_scope


def _default_app(protocol: str, port, app):
    # previously used http as last resort; keep it optional
    if not _is_none_any(app):
        return app

    # if user specified protocol/port, keep app none
    if not _is_none_any(protocol) or not _is_none_any(port):
        return "none"

    return "none"  # prefer none ( flip to "http" if your helpers require it)


def _infer_iface_subnet_from_subnet_db(
    sub_net: list,
    intf_name: str,
    hostname: str = None,
):
    """
    Best-effort mapping from router interface name to the lab subnet it faces.

    uses the current lab naming:
      R1 f0/1 -> LAN10
      R2 f1/0 -> LAN30
      R3 f0/1 -> LAN50

    Returns CIDR string like '172.16.50.0/24' or None.
    """
    if not intf_name:
        return None

    normalized_interface = _norm_intf(intf_name)
    normalized_hostname = (hostname or "").strip().lower()

    # Normalize hostnames like R3, R3_2, r3_2__configs__r3.cfg -> r3
    if normalized_hostname.startswith("r1"):
        router = "r1"

    elif normalized_hostname.startswith("r2"):
        router = "r2"

    elif normalized_hostname.startswith("r3"):
        router = "r3"

    else:
        router = None

    static_map = {
        ("r1", "fastethernet0/1"): "172.16.10.0/24",
        ("r2", "fastethernet1/0"): "172.16.30.0/24",
        ("r3", "fastethernet0/1"): "172.16.50.0/24",
    }

    if router:
        matched_subnet = static_map.get((router, normalized_interface))

        if matched_subnet:
            return matched_subnet

    return None

################### used to Convert run_result["Q3"]["df"] into a clean list you pass to the prompt ###################
################### (instead of dumping a dataframe object that can become None / not JSON-serializable).##############
#######################################################################################################################
def q3_df_to_rows(q3_df) -> list:
    rows = []

    if q3_df is None or getattr(q3_df, "empty", True):
        return rows

    for _, row in q3_df.iterrows():
        rows.append(
            {
                "Unreachable_Line": str(row.get("Unreachable_Line", "")),
                "Unreachable_Line_Action": str(
                    row.get("Unreachable_Line_Action", "")
                ),
                "Blocking_Lines": str(row.get("Blocking_Lines", "")),
            }
        )

    return rows


############# Helping function : extract ACL block from a given configs (commands) #############
################################################################################################
def extract_acl_block(config_text: str, acl_name: str) -> str:
    if not config_text or not acl_name:
        return ""

    lines = config_text.splitlines()
    output_lines = []
    inside_acl_block = False

    for line in lines:
        stripped_line = line.strip()

        # start
        if (
            stripped_line.lower()
            == f"ip access-list extended {acl_name}".lower()
        ):
            inside_acl_block = True
            output_lines.append(line)
            continue

        if inside_acl_block:
            # stop at next top-level section
            if stripped_line and not line.startswith(" ") and (
                stripped_line.lower().startswith("interface ")
                or stripped_line.lower().startswith("router ")
                or stripped_line.lower().startswith("line ")
                or stripped_line.lower().startswith("ip access-list ")
            ):
                break

            output_lines.append(line)

    return "\n".join(output_lines).strip()
    
################    Extract the full interface stanza (from 'interface X' until next 'interface' or end). ################
####################################    Returns the exact text block.             ########################################
##########################################################################################################################
def extract_interface_stanza(
    config_text: str,
    interface_name: str,
) -> str:
    if not config_text or not interface_name:
        return ""

    # Normalize for safe matching
    lines = config_text.splitlines()
    result_lines = []
    inside_interface = False

    for line in lines:
        stripped_line = line.strip()

        # Start of target interface
        if stripped_line.lower().startswith("interface "):
            if stripped_line.lower() == f"interface {interface_name}".lower():
                inside_interface = True
                result_lines.append(line)
                continue

            if inside_interface:
                # If we were inside and a new interface starts -> stop
                break

        if inside_interface:
            # Stop if new top-level block starts
            if (
                stripped_line.lower().startswith("interface ")
                and stripped_line.lower() != f"interface {interface_name}".lower()
            ):
                break

            result_lines.append(line)

    return "\n".join(result_lines).strip()


###### matches from "ip access-list extended <name>" until next top-level "interface/router/line/ip access-list" or EOF #######
###############################################################################################################################
def replace_acl_block(
    config_text: str,
    acl_name: str,
    new_acl_block: str,
) -> str:
    pattern = (
        rf"(?ms)^(ip access-list extended {re.escape(acl_name)}\s*\n.*?)"
        r"(?=^\S|\Z)"
    )

    if re.search(pattern, config_text):
        return re.sub(
            pattern,
            new_acl_block.strip() + "\n",
            config_text,
            count=1,
        )

    # ACL not found: append at end
    return config_text.rstrip() + "\n\n" + new_acl_block.strip() + "\n"


###### validate_reorder_only is a safety gate: when stage == "Q3" you want to ensure the LLM did not delete/change any ACL, only reordered.
###########################################################################################################################################
def ace_lines(acl_text: str) -> list:
    lines = []

    for line in (acl_text or "").splitlines():
        stripped_line = line.strip()

        if not stripped_line:
            continue

        # skip header line
        if stripped_line.lower().startswith("ip access-list extended"):
            continue

        lines.append(stripped_line)

    return lines


#############  True if the ACL entries are identical as a multiset (same lines), #############
################   ignoring order. Assumes first line is the header.  ########################
##############################################################################################
def validate_reorder_only(
    old_acl_text: str,
    new_acl_text: str,
) -> bool:
    old_lines = ace_lines(old_acl_text)
    new_lines = ace_lines(new_acl_text)

    return sorted(old_lines) == sorted(new_lines)


def _infer_stage_from_results(run_result: dict) -> str:
    q0 = run_result.get("Q0", {})
    if not q0:
        return "Q0"
    if q0.get("found_attachments") == []:
        return "Q0"
    if q0.get("ok_expected_vs_snapshot") is False:
        return "Q0"
    q1 = run_result.get("Q1", {}).get("positive", {})
    if isinstance(q1, dict) and q1.get("ok") is False:
        return "Q1"
    q2 = run_result.get("Q2", {}).get("violation_checks", [])
    if any((r.get("violations_empty") is False) for r in q2 if isinstance(r, dict)):
        return "Q2"
    q3_df = run_result.get("Q3", {}).get("df")
    if getattr(q3_df, "empty", True) is False:
        return "Q3"
    return "Q1"

def derive_q2_space(
    src_scope: str,
    dst_scope: str,
    src_ip: str,
    dst_ip: str,
    src_subnet: str,
    dst_subnet: str,
) -> dict:
    if src_scope == "host" and dst_scope == "any":
        return {
            "src": "0.0.0.0/0",
            "dst": "0.0.0.0/0",
            "exclude_src": src_ip,
            "violation_action": "permit",
        }

    if src_scope == "any" and dst_scope == "subnet":
        return {
            "src": "0.0.0.0/0",
            "dst": dst_subnet,
            "violation_action": "permit",
        }

    if src_scope == "host" and dst_scope == "host":
        return {
            "src": "0.0.0.0/0",
            "dst": dst_ip,
            "exclude_src": src_ip,
            "violation_action": "permit",
        }

    return {
        "src": src_subnet or "0.0.0.0/0",
        "dst": dst_subnet or "0.0.0.0/0",
        "violation_action": "deny",
    }


def _iface_prefix(router_interfaces: list, intf_name: str):
    if not intf_name:
        return None

    target_interface = _norm_intf(intf_name)

    for interface in router_interfaces or []:
        name = interface.get("name")

        if name and _norm_intf(name) == target_interface:
            prefix = interface.get("prefix")

            if prefix and str(prefix).lower() != "dhcp":
                return prefix

    return None


def _pick_host_from_prefix(
    sub_net: list,
    prefix: str,
    exclude=None,
):
    exclude = set(exclude or [])
    network = _parse_subnet(prefix)

    if network is None:
        return None

    for entry in _entries(sub_net):
        ip_address = str(entry.get("D_IP"))

        if ip_address in exclude:
            continue

        try:
            if ipaddress.ip_address(ip_address) in network:
                return ip_address

        except Exception:
            continue

    return None


def _pick_host_not_in_prefix(
    sub_net: list,
    prefix: str,
    exclude=None,
):
    exclude = set(exclude or [])
    network = _parse_subnet(prefix)

    if network is None:
        return None

    for entry in _entries(sub_net):
        ip_address = str(entry.get("D_IP"))

        if ip_address in exclude:
            continue

        try:
            if ipaddress.ip_address(ip_address) not in network:
                return ip_address

        except Exception:
            continue

    return None


def build_batfish_test_plan(context_variables: dict) -> dict:
    """
    Returns a dict with keys matching your LLM plan output:
    Plan_Status, Device, ACL_Name, Q1..., Q2..., Expected_Action, Opposite_Action, etc.
    """
    intent = context_variables.get("new_intent")
    hostname = context_variables.get("hostname")
    intent_dir = context_variables.get("intent_dir") or "unspecified"

    acl_name = context_variables.get("L_Name") or context_variables.get("ACLname")
    interface_name = context_variables.get("Intf_Name")
    direction = context_variables.get("direction")

    src_ip = context_variables.get("src_ip")
    dst_ip = context_variables.get("dst_ip")
    src_subnet = context_variables.get("src_subnet")
    dst_subnet = context_variables.get("dst_subnet")
    protocol = context_variables.get("protocol")
    port = context_variables.get("port")
    action = context_variables.get("action")
    app = context_variables.get("app")

    sub_net = context_variables.get("Sub_Net") or []

    expected_action = normalize_action(action)
    opposite_action = action_test(expected_action)
    notes = ""

    # print("inside build plan:")
    # print(expected_action,opposite_action)

    # scopes
    src_scope, dst_scope = _scope_from_entities(
        src_ip,
        src_subnet,
        dst_ip,
        dst_subnet,
    )
    print(
        "scopes:",
        src_scope,
        dst_scope,
        "src_ip:",
        src_ip,
        "src_subnet:",
        src_subnet,
    )

    restriction_mode = _restriction_mode(
        intent,
        src_scope,
        dst_scope,
        port,
        app,
    )

    # If restriction is about app/port (ONLY/EXCEPT + app/port mentioned), choose a disallowed example
    disallowed_app = "none"
    disallowed_port = "none"

    if restriction_mode in ("only_port", "only_app", "except", "other"):
        disallowed_app, disallowed_port = _representative_disallowed_app_port(
            app,
            port,
        )

    # Validate we have address space
    if not _entries(sub_net):
        return {
            "Plan_Status": "needs_more_data",
            "Notes": (
                "Sub_Net is empty or missing; "
                "cannot choose valid lab addresses."
            ),
        }

    # -------------------------
    # A) Positive src host
    # -------------------------
    positive_source = None

    if src_scope == "host" and not _is_none_any(src_ip):
        # must be in Sub_Net
        if any(str(entry["D_IP"]) == str(src_ip) for entry in _entries(sub_net)):
            positive_source = str(src_ip)

        else:
            # fall back to subnet or any
            src_scope = "subnet" if not _is_none_any(src_subnet) else "any"

    if (
        positive_source is None
        and src_scope == "subnet"
        and not _is_none_any(src_subnet)
    ):
        positive_source = _pick_host_from_subnet(
            sub_net,
            src_subnet,
        )

    if positive_source is None:
        positive_source = _pick_host_any(sub_net)

    # infer src subnet if missing
    inferred_src_subnet = (
        src_subnet
        if not _is_none_any(src_subnet)
        else _infer_subnet_of_host(sub_net, positive_source)
    )

    # -------------------------
    # B) Positive dst host
    # -------------------------
    positive_destination = None

    if dst_scope == "host" and not _is_none_any(dst_ip):
        if any(str(entry["D_IP"]) == str(dst_ip) for entry in _entries(sub_net)):
            positive_destination = str(dst_ip)

        else:
            dst_scope = "subnet" if not _is_none_any(dst_subnet) else "any"

    if (
        positive_destination is None
        and dst_scope == "subnet"
        and not _is_none_any(dst_subnet)
    ):
        # destination inside protected subnet
        positive_destination = _pick_host_from_subnet(
            sub_net,
            dst_subnet,
        )

    # ensure source is NOT in same subnet
    if inferred_src_subnet == dst_subnet or positive_source is None:
        for network in _unique_subnets(sub_net):
            if network != dst_subnet:
                positive_source = _pick_host_from_subnet(sub_net, network)
                break

    if positive_destination is None:
        # for egress: pick a host in a different subnet than src
        if intent_dir == "egress" and inferred_src_subnet:
            other_networks = _pick_other_subnet(
                sub_net,
                inferred_src_subnet,
                k=3,
            )

            if other_networks:
                positive_destination = _pick_host_from_subnet(
                    sub_net,
                    other_networks[0],
                    exclude=[positive_source],
                )

        # fallback: any host in different subnet
        if positive_destination is None and inferred_src_subnet:
            for network in _unique_subnets(sub_net):
                if network != inferred_src_subnet:
                    positive_destination = _pick_host_from_subnet(
                        sub_net,
                        network,
                        exclude=[positive_source],
                    )

                    if positive_destination:
                        break

        if positive_destination is None:
            positive_destination = _pick_host_any(
                sub_net,
                exclude=[positive_source],
            )

    inferred_dst_subnet = (
        dst_subnet
        if not _is_none_any(dst_subnet)
        else _infer_subnet_of_host(sub_net, positive_destination)
    )

    # ---------- Placement-aware Q1 anchoring ----------
    # Q1 uses testFilters pinned to @enter(hostname[intf]).
    # Therefore, the generated positive flow must be consistent with the chosen interface.
    router_interfaces = context_variables.get("router_interfaces") or []
    interface_prefix = _iface_prefix(router_interfaces, interface_name)

    if _is_none_any(interface_prefix):
        interface_prefix = context_variables.get("Intf_Subnet")

    normalized_direction = (direction or "").strip().lower()

    if normalized_direction not in ("in", "out"):
        return {
            "Plan_Status": "needs_more_data",
            "Notes": f"Invalid Direction={direction}. Must be 'in' or 'out'.",
        }

    if not _is_none_any(interface_prefix):
        if normalized_direction == "in":
            # Flow must enter the chosen interface, so source should be in that interface subnet.
            anchored_source = _pick_host_from_prefix(
                sub_net,
                interface_prefix,
                exclude=[positive_destination],
            )

            if anchored_source:
                positive_source = anchored_source
                inferred_src_subnet = _infer_subnet_of_host(
                    sub_net,
                    positive_source,
                )

            else:
                # If no PC exists on that interface subnet, Q1 cannot be flow-tested there.
                # This prevents false EMPTY testFilters failures.
                notes += (
                    ", Q1 skipped/weak: no source host found in "
                    f"ingress interface prefix {interface_prefix}"
                )

        elif normalized_direction == "out":
            # Flow must exit the chosen interface, so destination should be in that interface subnet.
            anchored_destination = _pick_host_from_prefix(
                sub_net,
                interface_prefix,
                exclude=[positive_source],
            )

            if anchored_destination:
                positive_destination = anchored_destination
                inferred_dst_subnet = _infer_subnet_of_host(
                    sub_net,
                    positive_destination,
                )

            else:
                notes += (
                    ", Q1 skipped/weak: no destination host found in "
                    f"egress interface prefix {interface_prefix}"
                )

    # Final sanity.
    if (
        positive_source
        and positive_destination
        and positive_source == positive_destination
    ):
        alternative_destination = _pick_host_any(
            sub_net,
            exclude=[positive_source],
        )

        if alternative_destination:
            positive_destination = alternative_destination
            inferred_dst_subnet = _infer_subnet_of_host(
                sub_net,
                positive_destination,
            )

    # -------------------------
    # C) Negative src host (for restriction tests)
    # -------------------------
    negative_source = "none"
    negative_destination = "none"
    negative_expected = "none"

    if restriction_mode != "none":
        # default: vary source unless destination restriction
        if restriction_mode in ("only_dst",):
            # vary destination; keep source same
            negative_source = positive_source

        else:
            # "only_host": pick another host in same src subnet (preferred)
            if restriction_mode == "only_host" and inferred_src_subnet:
                negative_host = _pick_host_from_subnet(
                    sub_net,
                    inferred_src_subnet,
                    exclude=[positive_source],
                )

                if negative_host:
                    negative_source = negative_host

            # Fallback: pick a host from a DIFFERENT subnet (but not equal to pos_dst)
            if negative_source == "none" and inferred_src_subnet:
                for network in _unique_subnets(sub_net):
                    if network != inferred_src_subnet:
                        negative_host = _pick_host_from_subnet(
                            sub_net,
                            network,
                            exclude=[positive_source, positive_destination],
                        )

                        if negative_host:
                            negative_source = negative_host
                            break

        # destination for negative flow
        if restriction_mode == "only_dst":
            # pick a different destination from a different subnet
            if inferred_dst_subnet:
                for network in _unique_subnets(sub_net):
                    if network != inferred_dst_subnet:
                        negative_host = _pick_host_from_subnet(
                            sub_net,
                            network,
                            exclude=[positive_source, positive_destination],
                        )

                        if negative_host:
                            negative_destination = negative_host
                            break

            if negative_destination == "none":
                negative_destination = _pick_host_any(
                    sub_net,
                    exclude=[positive_source, positive_destination],
                )

        else:
            # keep dst same
            negative_destination = positive_destination

            # Final guard: avoid neg_src == neg_dst
            if (
                negative_source != "none"
                and negative_destination != "none"
                and negative_source == negative_destination
            ):
                alternative = _pick_host_any(
                    sub_net,
                    exclude=[
                        positive_source,
                        positive_destination,
                        negative_source,
                    ],
                )

                if alternative:
                    negative_destination = alternative

                else:
                    negative_source = "none"
                    negative_destination = "none"
                    negative_expected = "none"

        # negative expected behavior depends on "only" allow vs deny policies.
        # Most common: "only X is permitted" => negative should be denied
        # For "only X is denied" => negative should be permitted
        # We'll interpret based on expected_action:
        if expected_action == "permit":
            negative_expected = "deny"

        else:
            negative_expected = "permit"

    # -------------------------
    # Q2 base subnets list (used by your executor)
    # -------------------------
    q2 = derive_q2_space(
        src_scope,
        dst_scope,
        src_ip,
        dst_ip,
        src_subnet,
        dst_subnet,
    )

    # default app choice
    planned_app = _default_app(protocol, port, app)

    # Notes summarizing the plan
    notes = (
        f"placement_dir={direction}, "
        f"src_scope={src_scope}, "
        f"dst_scope={dst_scope}, "
        f"restriction_mode={restriction_mode}"
    )

    if disallowed_app != "none" or disallowed_port != "none":
        notes += (
            f", disallowed_example_app={disallowed_app}, "
            f"disallowed_example_port={disallowed_port}"
        )

    if _is_none_any(interface_name) or _is_none_any(direction):
        return {
            "Plan_Status": "needs_more_data",
            "Notes": (
                "Missing Intf_Name or direction; required for "
                "placement-aware Batfish tests (@in/@out)."
            ),
        }

    return {
        "Plan_Status": "ok",
        "Device": hostname,
        "ACL_Name": acl_name,
        "Intf_Name": interface_name,
        "Direction": direction,
        "Q1_Pos_Src_Host": positive_source,
        "Q1_Pos_Dst_Host": positive_destination,
        "Q1_Pos_Expected_Action": expected_action,
        "Q1_Neg_Src_Host": negative_source,
        "Q1_Neg_Dst_Host": negative_destination,
        "Q1_Neg_Expected_Action": negative_expected,
        "q2_src_subnet": q2["src"],
        "q2_dst_subnets": [q2["dst"]],
        "q2_violation_action": q2["violation_action"],
        "Expected_Action": expected_action,
        "Opposite_Action": opposite_action,
        "Application": planned_app,
        "Protocol": _norm_lower(protocol) or "none",
        "Port": str(port).strip() if not _is_none_any(port) else "none",
        "Q2_Restriction_Mode": restriction_mode,
        "Notes": notes,
        "Disallowed_Example_App": disallowed_app,
        "Disallowed_Example_Port": disallowed_port,
    }


def q0_validate_flexible(
    attachments: list,
    acceptable: list,
) -> tuple:
    """
    attachments: list of {"interface": "...", "direction": "..."} from find_acl_attachments
    acceptable: list of (intf_name, direction) pairs
    Returns: (ok: bool, details: dict)
    """
    acceptable_set = {
        (interface, direction.lower())
        for interface, direction in acceptable
    }

    actual = []

    for attachment in attachments or []:
        interface = iface_to_name(attachment.get("interface"))
        direction = (attachment.get("direction") or "").lower()

        actual.append((interface, direction))

    matches = [
        item
        for item in actual
        if item in acceptable_set
    ]

    return len(matches) > 0, {
        "acceptable": list(acceptable_set),
        "actual": actual,
        "matches": matches,
        "issue": (
            "ok"
            if matches
            else (
                "acl_not_attached"
                if not actual
                else "no_acceptable_attachment_found"
            )
        ),
    }


def set_acl_attachment_raw(
    cfg_text: str,
    acl_name: str,
    intf_name: str,
    direction: str,
) -> str:
    direction = direction.strip().lower()

    assert direction in ("in", "out")

    lines = cfg_text.splitlines()
    output_lines = []

    target_interface = normalize_interface_name(intf_name)

    index = 0

    while index < len(lines):
        line = lines[index]
        stripped_line = line.strip()

        if stripped_line.lower().startswith("interface "):
            interface_name = stripped_line.split(None, 1)[1].strip()
            interface_norm = normalize_interface_name(interface_name)

            block = [line]
            index += 1

            while index < len(lines):
                block.append(lines[index])

                if lines[index].strip() == "!":
                    index += 1
                    break

                index += 1

            # remove all attachments of this ACL from this block
            cleaned_block = []

            for block_line in block:
                block_line_stripped = block_line.strip().lower()
                pattern = (
                    rf"^ip access-group\s+{re.escape(acl_name.lower())}"
                    r"\s+(in|out)$"
                )

                if re.match(pattern, block_line_stripped):
                    continue

                cleaned_block.append(block_line)

            if interface_norm == target_interface:
                insert_position = len(cleaned_block)

                if cleaned_block and cleaned_block[-1].strip() == "!":
                    insert_position -= 1

                cleaned_block.insert(
                    insert_position,
                    f" ip access-group {acl_name} {direction}",
                )

            output_lines.extend(cleaned_block)
            continue

        output_lines.append(line)
        index += 1

    return "\n".join(output_lines) + "\n"


def build_acceptable_attachments(
    router_interfaces: list,
    default_route_iface,
    inside_prefixes: list,
    intent_dir: str,
    src_ip: str = None,
    src_subnet: str = None,
    dst_ip: str = None,
    dst_subnet: str = None,
) -> list:
    acceptable = []

    placement_interface, placement_direction = choose_acl_attachment(
        router_interfaces,
        default_route_iface,
        inside_prefixes,
        intent_dir,
        src_ip,
        src_subnet,
        dst_ip,
        dst_subnet,
    )

    if placement_interface and placement_direction:
        acceptable.append(
            (
                _norm_intf(placement_interface),
                _norm_dir(placement_direction),
            )
        )

    inside_prefixes = inside_prefixes or []

    src_ip = _norm_none(src_ip)
    dst_ip = _norm_none(dst_ip)
    src_subnet = _norm_none(src_subnet)
    dst_subnet = _norm_none(dst_subnet)

    # Destination inside: also accept transit inbound as a valid choke point.
    destination_inside = False

    if dst_ip:
        destination_inside = any(
            _ip_in_prefix(dst_ip, prefix)
            for prefix in inside_prefixes
            if prefix and prefix != "dhcp"
        )

    if dst_subnet:
        destination_inside = _prefix_is_inside(
            dst_subnet,
            set(inside_prefixes),
        )

    if destination_inside:
        # Accept destination LAN outbound.
        target = dst_subnet or dst_ip
        destination_lan = _iface_matching_prefix(
            router_interfaces,
            target,
            role="LAN",
        )

        if destination_lan:
            acceptable.append(
                (
                    _norm_intf(destination_lan),
                    "out",
                )
            )

        # Accept transit inbound.
        transit_interface = _first_iface_by_role(
            router_interfaces,
            "TRANSIT",
        )

        if transit_interface:
            acceptable.append(
                (
                    _norm_intf(transit_interface),
                    "in",
                )
            )

    # Source inside: accept source LAN inbound.
    source_inside = False

    if src_ip:
        source_inside = any(
            _ip_in_prefix(src_ip, prefix)
            for prefix in inside_prefixes
            if prefix and prefix != "dhcp"
        )

    if src_subnet:
        source_inside = _prefix_is_inside(
            src_subnet,
            set(inside_prefixes),
        )

    if source_inside:
        target = src_subnet or src_ip
        source_lan = _iface_matching_prefix(
            router_interfaces,
            target,
            role="LAN",
        )

        if source_lan:
            acceptable.append(
                (
                    _norm_intf(source_lan),
                    "in",
                )
            )

    output = []
    seen = set()

    for interface, direction in acceptable:
        item = (
            _norm_intf(interface),
            _norm_dir(direction),
        )

        if item[0] and item[1] and item not in seen:
            seen.add(item)
            output.append(item)

    return output

def q0_pick_working_attachment(
    attachments: list,
    acceptable: list,
) -> tuple:
    """
    Returns (ok, chosen_intf, chosen_dir, details)
    ok=True if any actual attachment matches acceptable set
    chosen_* is the first matching attachment; if no match, None
    """
    acceptable_set = {
        (_norm_intf(interface), _norm_dir(direction))
        for interface, direction in acceptable or []
    }

    actual = []
    actual_raw = []

    for attachment in attachments or []:
        raw_interface = None
        raw_direction = None

        if isinstance(attachment, dict):
            raw_interface = (
                attachment.get("interface")
                or attachment.get("Interface")
                or attachment.get("intf")
                or attachment.get("Intf_Name")
                or attachment.get("iface")
            )
            raw_direction = (
                attachment.get("direction")
                or attachment.get("Direction")
                or attachment.get("dir")
                or attachment.get("filter_type")
                or attachment.get("Filter_Type")
            )

        elif isinstance(attachment, (tuple, list)) and len(attachment) >= 2:
            raw_interface = attachment[0]
            raw_direction = attachment[1]

        else:
            raw_interface = str(attachment)

        normalized_interface = _norm_intf(
            iface_to_name(raw_interface)
            if raw_interface
            else raw_interface
        )
        normalized_direction = _norm_dir(raw_direction)

        actual_raw.append(
            {
                "raw": attachment,
                "parsed_intf": raw_interface,
                "parsed_dir": raw_direction,
            }
        )
        actual.append((normalized_interface, normalized_direction))

    matches = [
        item
        for item in actual
        if item in acceptable_set
    ]

    print("Q0 acceptable_set:", acceptable_set)
    print("Q0 actual_raw:", actual_raw)
    print("Q0 actual_norm:", actual)
    print("Q0 matches:", matches)

    if matches:
        return True, matches[0][0], matches[0][1], {
            "acceptable": list(acceptable_set),
            "actual": actual,
            "actual_raw": actual_raw,
            "matches": matches,
        }

    return False, None, None, {
        "acceptable": list(acceptable_set),
        "actual": actual,
        "actual_raw": actual_raw,
        "matches": [],
    }


def _first_lan_iface_name(lan_ifaces: list):
    if lan_ifaces and lan_ifaces[0].get("name"):
        return lan_ifaces[0]["name"]

    return None


# -------- helpers for choose_acl_attachment --------
def _pick_outside_iface(
    default_route_iface,
    router_interfaces: list,
):
    if default_route_iface and str(default_route_iface).strip():
        return str(default_route_iface).strip()

    # prefer role WAN, else any non-LAN, else first interface
    # Prefer explicit WAN role
    for interface in router_interfaces or []:
        if (
            (interface.get("role") or "").upper() == "WAN"
            and interface.get("name")
        ):
            return interface["name"]

    # Else pick any non-LAN interface
    for interface in router_interfaces or []:
        if (
            (interface.get("role") or "").upper() != "LAN"
            and interface.get("name")
        ):
            return interface["name"]

    # Else last resort: first interface
    if router_interfaces and router_interfaces[0].get("name"):
        return router_interfaces[0]["name"]

    return None


def _iface_matching_prefix(
    router_interfaces: list,
    target_prefix: str,
    role: str = None,
):
    """
    Return interface name whose prefix overlaps/matches target_prefix.
    Optionally restrict by role.
    """
    if not target_prefix:
        return None

    target_network = _parse_subnet(target_prefix)

    if target_network is None:
        return None

    for interface in router_interfaces or []:
        if role and (interface.get("role") or "").upper() != role.upper():
            continue

        prefix = interface.get("prefix")

        if not prefix or str(prefix).lower() == "dhcp":
            continue

        prefix_network = _parse_subnet(prefix)

        if prefix_network is None:
            continue

        if (
            target_network == prefix_network
            or target_network.subnet_of(prefix_network)
            or prefix_network.subnet_of(target_network)
            or target_network.overlaps(prefix_network)
        ):
            return interface.get("name")

    return None


def _first_iface_by_role(
    router_interfaces: list,
    role: str,
):
    for interface in router_interfaces or []:
        if (
            (interface.get("role") or "").upper() == role.upper()
            and interface.get("name")
        ):
            return interface.get("name")

    return None


def choose_acl_attachment(
    router_interfaces: list,
    default_route_iface,
    inside_prefixes: list,
    intent_dir: str,
    src_ip: str = None,
    src_subnet: str = None,
    dst_ip: str = None,
    dst_subnet: str = None,
) -> tuple:
    """
    Choose best ACL attachment for validation/fine-tune.

    Rules:
      - Destination inside/protected subnet:
          prefer destination LAN interface outbound.
          fallback to transit inbound.
          fallback to internet/upstream inbound.
      - Source inside:
          prefer source LAN interface inbound.
      - Internet/external source:
          prefer internet/upstream inbound.
      - Otherwise:
          prefer transit inbound, then outside inbound.
    """
    src_ip = _norm_none(src_ip)
    dst_ip = _norm_none(dst_ip)
    src_subnet = _norm_none(src_subnet)
    dst_subnet = _norm_none(dst_subnet)

    src_ip = str(src_ip).strip() if src_ip else None
    dst_ip = str(dst_ip).strip() if dst_ip else None
    src_subnet = str(src_subnet).strip() if src_subnet else None
    dst_subnet = str(dst_subnet).strip() if dst_subnet else None

    inside_prefixes = inside_prefixes or []
    inside_set = {
        prefix
        for prefix in inside_prefixes
        if prefix and str(prefix).lower() != "dhcp"
    }

    source_inside = False
    destination_inside = False

    if src_ip and inside_set:
        source_inside = any(
            _ip_in_prefix(src_ip, prefix)
            for prefix in inside_set
        )

    if src_subnet and inside_set:
        source_inside = _prefix_is_inside(
            src_subnet,
            inside_set,
        )

    if dst_ip and inside_set:
        destination_inside = any(
            _ip_in_prefix(dst_ip, prefix)
            for prefix in inside_set
        )

    if dst_subnet and inside_set:
        destination_inside = _prefix_is_inside(
            dst_subnet,
            inside_set,
        )

    outside_interface = _pick_outside_iface(
        default_route_iface,
        router_interfaces,
    )
    transit_interface = _first_iface_by_role(
        router_interfaces,
        "TRANSIT",
    )

    # 1. Protect traffic going TO an inside destination.
    # Best single-router placement: outbound on destination LAN interface.
    if destination_inside:
        target = dst_subnet or dst_ip
        destination_lan_interface = _iface_matching_prefix(
            router_interfaces,
            target,
            role="LAN",
        )

        if destination_lan_interface:
            return destination_lan_interface, "out"

        if transit_interface:
            return transit_interface, "in"

        if outside_interface:
            return outside_interface, "in"

    # 2. Control traffic FROM an inside source.
    if source_inside:
        target = src_subnet or src_ip
        source_lan_interface = _iface_matching_prefix(
            router_interfaces,
            target,
            role="LAN",
        )

        if source_lan_interface:
            return source_lan_interface, "in"

    # 3. Explicit egress wording: traffic leaving internal networks.
    if intent_dir == "egress":
        if transit_interface:
            return transit_interface, "out"

        if outside_interface:
            return outside_interface, "out"

    # 4. Explicit ingress wording: traffic entering from upstream.
    if intent_dir == "ingress":
        if transit_interface:
            return transit_interface, "in"

        if outside_interface:
            return outside_interface, "in"

    # 5. Fallback.
    if transit_interface:
        return transit_interface, "in"

    if outside_interface:
        return outside_interface, "in"

    return None, None