import ipaddress
import re
import random
from Helpers.Formats import normalize_interface_name, normalize_action, _norm_lower
from Helpers.Finder import _find_iface_for_exact_prefix
from Batfish.Questions import find_acl_attachments
#################### Normalization function. ######################
###################################################################
def _is_none_any(v):
    v = _norm_lower(v)
    return v in ("", "none", "any", "null")



def _norm_intf(i):
    if not i:
        return ""

    n = str(i).strip().lower()

    if n.startswith("fastethernet"):
        return n
    if n.startswith("fa"):
        return "fastethernet" + n[2:]
    if n.startswith("f"):
        return "fastethernet" + n[1:]

    if n.startswith("gigabitethernet"):
        return n
    if n.startswith("gi"):
        return "gigabitethernet" + n[2:]
    if n.startswith("g"):
        return "gigabitethernet" + n[1:]

    if n.startswith("serial"):
        return n
    if n.startswith("se"):
        return "serial" + n[2:]
    if n.startswith("s"):
        return "serial" + n[1:]

    return n
    
def _norm_dir(d):
    d = (d or "").strip().lower()
    return "in" if d in ("in", "inbound") else "out" if d in ("out", "outbound") else d

def _norm_none(x):
    if x is None:
        return None
    x = str(x).strip()
    return None if x.lower() in ("none", "") else x  
    
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

def iface_to_name(x):
    # Batfish returns either a string or an Interface(hostname='r2_2', interface='Serial0/0')
    if x is None:
        return None
    if hasattr(x, "interface"):   # Batfish Interface object
        return str(x.interface)
    return str(x)

# find column names (Batfish sometimes uses different casing) 
# used inside find_acl_attachments
    
def _canon_net(net: str):
    """
    Canonicalize a subnet string 
    - "172.16.30.0"   -> "172.16.30.0/24"  (assume /24 if mask missing)
    - "172.16.30.0/24"-> "172.16.30.0/24"
    Returns None if invalid/empty.
    """
    if net is None:
        return None
    s = str(net).strip()
    if not s or s.lower() in ("none", "any"):
        return None
    try:
        if "/" not in s:
            s = f"{s}/24"
        return str(ipaddress.ip_network(s, strict=False))
    except Exception:
        return None

def _same_net(a: str, b: str) -> bool:
    ca, cb = _canon_net(a), _canon_net(b)
    return (ca is not None) and (cb is not None) and (ca == cb)


######## helping function: Analyze the ip to determine its type and suggest one incase of none to test the flows in Batfish questions ##########
############################################################################################################################

def analyze_ip(ip,Sub_Net):
    if ip in ["None", "none", "Any"]:
        return {"IP_Address": "none", "type": "none", "suggested_Address": "none"}
    else:    
        for device in Sub_Net:
            if ip == device["D_IP"]: # device add
                return {
                    "IP_Address": ip,
                    "type": "Device Address",
                    "suggested_Address": ip
                }
        for device in Sub_Net:
            suggested_address = random.choice([item for item in Sub_Net if item.get("D_Net") == device.get("D_Net") and item.get("D_IP") != device.get("D_IP")])
            return {
                    "IP_Address": ip,
                    "type": "Network Address",
                    "suggested_Address": suggested_address['D_IP']
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
def choose_any_ip(Sub_Net, avoid_ip=None):
    for e in Sub_Net or []:
        ip = e.get("D_IP")
        if ip and ip != avoid_ip:
            return ip
    return None

def choose_ip_in_subnet(subnet, Sub_Net, avoid_ip=None):
    for e in Sub_Net or []:
        if e.get("D_Net") == subnet:
            ip = e.get("D_IP")
            if ip and ip != avoid_ip:
                return ip
    return None

def choose_ip_outside_subnet(subnet, Sub_Net, avoid_ip=None):
    for e in Sub_Net or []:
        if e.get("D_Net") != subnet:
            ip = e.get("D_IP")
            if ip and ip != avoid_ip:
                return ip
    return None

# ---------- IP / subnet helpers ---------- 
def choose_ip_from_subnet(subnet, Sub_Net, avoid_ip = None):
    # Pick a deterministic test IP from Sub_Net for a given subnet.
    if not Sub_Net:
        return None

    # Prefer IP in requested subnet and != avoid_ip
    if subnet:
        for entry in Sub_Net:
            d_ip = entry.get("D_IP")
            d_net = entry.get("D_Net")
            if d_net == subnet and d_ip and d_ip != avoid_ip:
                return d_ip

    # Fallback: any IP different from avoid_ip
    for entry in Sub_Net:
        d_ip = entry.get("D_IP")
        if d_ip and d_ip != avoid_ip:
            return d_ip

    return None
    
################ helping function: specify action and its opposite, also to determine the protocol in case of None ##########
############################################################################################################################

def action_test(action):
    # Return the opposite action: permit <-> deny.
    a = normalize_action(action)
    if a == "permit":
        return "deny"
    if a == "deny":
        return "permit"
    return a

def protocol_test(protocol, app):    # ip, None     
    if app == None:
        if protocol == "IP" or protocol == None: #protocol.lower() == "none":
            app = "http" # any application for IP
    
    print(app)
    return app

def normalize_acl_line(s: str) -> str:
    # normalize spacing/case to compare safely
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s
    
def _opposite_action(a):
    
    a = normalize_action(a)
    
    return "deny" if a == "permit" else "permit"


################ helping function: working with IP addresses and subnets ##########
############################################################################################################################

def _parse_subnet(cidr):
    if _is_none_any(cidr):
        return None
    try:
        return ipaddress.ip_network(str(cidr), strict=False)
    except Exception:
        return None

def _ip_in_cidr(ip, cidr):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False

def _entries(Sub_Net):
    # expects list of dicts with D_IP, D_Net
    return [e for e in (Sub_Net or []) if e.get("D_IP") and e.get("D_Net")]

def _unique_subnets(Sub_Net):
    nets = []
    seen = set()
    for e in _entries(Sub_Net):
        n = str(e["D_Net"])
        if n not in seen:
            seen.add(n)
            nets.append(n)
    return nets

def _hosts_in_subnet(Sub_Net, subnet_cidr):
    subnet_cidr = str(subnet_cidr)
    out = []
    for e in _entries(Sub_Net):
        if str(e["D_Net"]) == subnet_cidr:
            out.append(str(e["D_IP"]))
    return out

def _ip_in_prefix(ip, prefix):
    """
    Returns True if IP belongs to the given prefix.
    Example: _ip_in_prefix('172.16.10.3','172.16.10.0/24') -> True
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(prefix, strict=False)
    except Exception:
        return False

def _prefix_is_inside(prefix, inside_prefixes):
    """
    Checks if a subnet belongs to one of the inside prefixes.
    """
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        for p in inside_prefixes:
            if net.subnet_of(ipaddress.ip_network(p, strict=False)):
                return True
    except Exception:
        pass
    return False
    
        
def _infer_subnet_of_host(Sub_Net, host_ip):
    for e in _entries(Sub_Net):
        if str(e.get("D_IP")) == str(host_ip):
            return _canon_net(e.get("D_Net"))
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
    
def _pick_host_any(Sub_Net, exclude=None):
    exclude = set(exclude or [])
    candidates = [str(e["D_IP"]) for e in _entries(Sub_Net) if str(e["D_IP"]) not in exclude]
    return random.choice(candidates) if candidates else None

def _pick_other_subnet(Sub_Net, not_this_subnet, k=2):
    nets = [n for n in _unique_subnets(Sub_Net) if str(n) != str(not_this_subnet)]
    return nets[:k]

def _intent_directionality(intent_text: str):
    t = (intent_text or "").lower()
    words = set(re.findall(r"[a-z]+", t))  # tokenized words

    egress_words  = {"exit", "exiting", "egress", "outbound", "out", "outside", "internet"}
    ingress_words = {"enter", "entering","ingress", "inbound", "protect", "block", "deny", "prohibit", "to", "into", "toward", "access", "inside", "in"}

    egress  = len(words & egress_words) > 0
    ingress = len(words & ingress_words) > 0

    if egress and not ingress:
        return "egress"
    if ingress and not egress:
        return "ingress"
    return "unspecified"


def _restriction_mode(intent_text: str, src_scope: str, dst_scope: str, port, app):
    t = _norm_lower(intent_text)

    only = "only" in t
    exc  = "except" in t

    if exc:
        # if except is present, treat as restriction always
        # try to categorize
        if "port" in t or re.search(r"\b\d{1,5}\b", t):
            return "except"
        if any(x in t for x in ("dns", "http", "https", "ssh", "telnet", "icmp")):
            return "except"
        return "except"

    if only:
        if src_scope == "host" and any(x in t for x in ("host", "source", "src")):
            return "only_host"
        if dst_scope == "host" and any(x in t for x in ("destination", "dst", "server", "host")):
            return "only_dst"
        if not _is_none_any(port) or "port" in t or re.search(r"\b\d{1,5}\b", t):
            return "only_port"
        if not _is_none_any(app) or any(x in t for x in ("dns", "http", "https", "ssh", "icmp")):
            return "only_app"
        return "other"

    return "none"


def _representative_disallowed_app_port(app, port):
    # super simple examples
    if _norm_lower(app) == "dns" or str(port) == "53":
        return ("http", "80")
    if _norm_lower(app) == "http" or str(port) == "80":
        return ("dns", "53")
    return ("http", "80")
    

def _scope_from_entities(src_ip, src_subnet, dst_ip, dst_subnet):
    # host if specific IP present, else subnet if subnet present, else any
    src_scope = "host" if (not _is_none_any(src_ip)) else ("subnet" if (not _is_none_any(src_subnet)) else "any")
    dst_scope = "host" if (not _is_none_any(dst_ip)) else ("subnet" if (not _is_none_any(dst_subnet)) else "any")
    return src_scope, dst_scope

def _default_app(protocol, port, app):
    # previously used http as last resort; keep it optional
    if not _is_none_any(app):
        return app
    # if user specified protocol/port, keep app none
    if not _is_none_any(protocol) or not _is_none_any(port):
        return "none"
    return "none"  # prefer none ( flip to "http" if your helpers require it)

def _infer_iface_subnet_from_subnet_db(Sub_Net, intf_name, hostname=None):
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

    n = _norm_intf(intf_name)
    h = (hostname or "").strip().lower()

    # Normalize hostnames like R3, R3_2, r3_2__configs__r3.cfg -> r3
    if h.startswith("r1"):
        router = "r1"
    elif h.startswith("r2"):
        router = "r2"
    elif h.startswith("r3"):
        router = "r3"
    else:
        router = None

    static_map = {
        ("r1", "fastethernet0/1"): "172.16.10.0/24",
        ("r2", "fastethernet1/0"): "172.16.30.0/24",
        ("r3", "fastethernet0/1"): "172.16.50.0/24",
    }

    if router:
        hit = static_map.get((router, n))
        if hit:
            return hit

    return None


################### used to Convert run_result["Q3"]["df"] into a clean list you pass to the prompt ###################
################### (instead of dumping a dataframe object that can become None / not JSON-serializable).##############
#######################################################################################################################
def q3_df_to_rows(q3_df):
    rows = []
    if q3_df is None or getattr(q3_df, "empty", True):
        return rows
    for _, r in q3_df.iterrows():
        rows.append({
            "Unreachable_Line": str(r.get("Unreachable_Line", "")),
            "Unreachable_Line_Action": str(r.get("Unreachable_Line_Action", "")),
            "Blocking_Lines": str(r.get("Blocking_Lines", "")),
        })
    return rows

############# Helping function : extract ACL block from a given configs (commands) #############
################################################################################################
def extract_acl_block(config_text, acl_name) :
    if not config_text or not acl_name:
        return ""

    lines = config_text.splitlines()
    out = []
    inside = False

    for line in lines:
        s = line.strip()

        # start
        if s.lower() == f"ip access-list extended {acl_name}".lower():
            inside = True
            out.append(line)
            continue

        if inside:
            # stop at next top-level section
            if s and not line.startswith(" ") and (
                s.lower().startswith("interface ")
                or s.lower().startswith("router ")
                or s.lower().startswith("line ")
                or s.lower().startswith("ip access-list ")
            ):
                break
            out.append(line)

    return "\n".join(out).strip()

################    Extract the full interface stanza (from 'interface X' until next 'interface' or end). ################
####################################    Returns the exact text block.             ########################################
##########################################################################################################################
def extract_interface_stanza(config_text , interface_name):
    if not config_text or not interface_name:
        return ""

    # Normalize for safe matching
    lines = config_text.splitlines()
    result_lines = []
    inside = False

    for line in lines:
        stripped = line.strip()

        # Start of target interface
        if stripped.lower().startswith("interface "):
            if stripped.lower() == f"interface {interface_name}".lower():
                inside = True
                result_lines.append(line)
                continue
            else:
                # If we were inside and a new interface starts -> stop
                if inside:
                    break

        if inside:
            # Stop if new top-level block starts
            if stripped.lower().startswith("interface ") and \
               stripped.lower() != f"interface {interface_name}".lower():
                break
            result_lines.append(line)

    return "\n".join(result_lines).strip()


###### matches from "ip access-list extended <name>" until next top-level "interface/router/line/ip access-list" or EOF #######
###############################################################################################################################
def replace_acl_block(config_text , acl_name , new_acl_block ):
    
    pattern = rf"(?ms)^(ip access-list extended {re.escape(acl_name)}\s*\n.*?)(?=^\S|\Z)"
    if re.search(pattern, config_text):
        return re.sub(pattern, new_acl_block.strip() + "\n", config_text, count=1)
    else:
        # ACL not found: append at end
        return config_text.rstrip() + "\n\n" + new_acl_block.strip() + "\n"


###### validate_reorder_only is a safety gate: when stage == "Q3" you want to ensure the LLM did not delete/change any ACL, only reordered.
###########################################################################################################################################
def ace_lines(acl_text):
        lines = []
        for ln in (acl_text or "").splitlines():
            s = ln.strip()
            if not s:
                continue
            # skip header line
            if s.lower().startswith("ip access-list extended"):
                continue
            lines.append(s)
        return lines

#############  True if the ACL entries are identical as a multiset (same lines), #############
################   ignoring order. Assumes first line is the header.  ########################
##############################################################################################
def validate_reorder_only(old_acl_text, new_acl_text): # return bool    
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

def derive_q2_space(src_scope, dst_scope, src_ip, dst_ip, src_subnet, dst_subnet):
    
    if src_scope == "host" and dst_scope == "any":
        return {
            "src": "0.0.0.0/0",
            "dst": "0.0.0.0/0",
            "exclude_src": src_ip,
            "violation_action": "permit"
        }

    if src_scope == "any" and dst_scope == "subnet":
        return {
            "src": "0.0.0.0/0",
            "dst": dst_subnet,
            "violation_action": "permit"
        }

    if src_scope == "host" and dst_scope == "host":
        return {
            "src": "0.0.0.0/0",
            "dst": dst_ip,
            "exclude_src": src_ip,
            "violation_action": "permit"
        }

    return {
        "src": src_subnet or "0.0.0.0/0",
        "dst": dst_subnet or "0.0.0.0/0",
        "violation_action": "deny"
    }


def _iface_prefix(router_interfaces, intf_name):
    if not intf_name:
        return None

    target = _norm_intf(intf_name)

    for i in router_interfaces or []:
        name = i.get("name")
        if name and _norm_intf(name) == target:
            pfx = i.get("prefix")
            if pfx and str(pfx).lower() != "dhcp":
                return pfx

    return None


def _pick_host_from_prefix(Sub_Net, prefix, exclude=None):
    exclude = set(exclude or [])
    net = _parse_subnet(prefix)
    if net is None:
        return None

    for e in _entries(Sub_Net):
        ip = str(e.get("D_IP"))
        if ip in exclude:
            continue
        try:
            if ipaddress.ip_address(ip) in net:
                return ip
        except Exception:
            continue

    return None


def _pick_host_not_in_prefix(Sub_Net, prefix, exclude=None):
    exclude = set(exclude or [])
    net = _parse_subnet(prefix)
    if net is None:
        return None

    for e in _entries(Sub_Net):
        ip = str(e.get("D_IP"))
        if ip in exclude:
            continue
        try:
            if ipaddress.ip_address(ip) not in net:
                return ip
        except Exception:
            continue

    return None
    
def build_batfish_test_plan(context_variables: dict):
    """
    Returns a dict with keys matching your LLM plan output:
    Plan_Status, Device, ACL_Name, Q1..., Q2..., Expected_Action, Opposite_Action, etc.
    """

    intent     = context_variables.get("new_intent")
    hostname   = context_variables.get("hostname")
    intent_dir = context_variables.get("intent_dir") or "unspecified"
    
    L_Name = context_variables.get("L_Name") or context_variables.get("ACLname")
    Intf_Name = context_variables.get("Intf_Name")
    direction = context_variables.get("direction")  # interface placement ( in/ out)

    src_ip     = context_variables.get("src_ip")
    dst_ip     = context_variables.get("dst_ip")
    src_subnet = context_variables.get("src_subnet")
    dst_subnet = context_variables.get("dst_subnet")
    protocol   = context_variables.get("protocol")
    port       = context_variables.get("port")
    action     = context_variables.get("action")
    app        = context_variables.get("app")

    Sub_Net = context_variables.get("Sub_Net") or []

    expected_action = normalize_action(action)
    opposite_action = action_test(expected_action)
    notes = ""
    # print("inside build plan:")
    # print(expected_action,opposite_action)
    # scopes
    src_scope, dst_scope = _scope_from_entities(src_ip, src_subnet, dst_ip, dst_subnet)
    print("scopes:", src_scope, dst_scope, "src_ip:", src_ip, "src_subnet:", src_subnet)  # a debug print

    # intent_dir = _intent_directionality(intent)  # intent meaning ( egress/ ingress/ unspecified)
    # if intent_dir in ("egress", "ingress") and not _is_none_any(direction):
    #     dir_norm = direction.strip().lower()
    #     if intent_dir == "egress" and dir_norm == "in":
    #         notes += ", NOTE: egress intent enforced via inbound ACL (valid Cisco pattern)"
    #     if intent_dir == "ingress" and dir_norm == "out":
    #         notes += ", NOTE: ingress intent enforced via outbound ACL (valid Cisco pattern)"
        # if intent_dir == "egress" and dir_norm != "out":
        #     return {"Plan_Status": "needs_more_data",
        #         "Notes": "Intent is egress but direction is not 'out'. Fix placement."}
        # if intent_dir == "ingress" and dir_norm != "in":
        #     return {"Plan_Status": "needs_more_data",
        #         "Notes": "Intent is ingress but direction is not 'in'. Fix placement."}

    restriction_mode = _restriction_mode(intent, src_scope, dst_scope, port, app)
    # If restriction is about app/port (ONLY/EXCEPT + app/port mentioned), choose a disallowed example
    disallowed_app = "none"
    disallowed_port = "none"
    if restriction_mode in ("only_port", "only_app", "except", "other"):
        da, dp = _representative_disallowed_app_port(app, port)
        disallowed_app, disallowed_port = da, dp
    
    # Validate we have address space
    if not _entries(Sub_Net):
        return {
            "Plan_Status": "needs_more_data",
            "Notes": "Sub_Net is empty or missing; cannot choose valid lab addresses.",
        }

    # -------------------------
    # A) Positive src host
    # -------------------------
    pos_src = None
    if src_scope == "host" and not _is_none_any(src_ip):
        # must be in Sub_Net
        if any(str(e["D_IP"]) == str(src_ip) for e in _entries(Sub_Net)):
            pos_src = str(src_ip)
        else:
            # fall back to subnet or any
            src_scope = "subnet" if not _is_none_any(src_subnet) else "any"

    if pos_src is None and src_scope == "subnet" and not _is_none_any(src_subnet):
        pos_src = _pick_host_from_subnet(Sub_Net, src_subnet)

    if pos_src is None:
        pos_src = _pick_host_any(Sub_Net)
    
    # infer src subnet if missing
    inferred_src_subnet = src_subnet if not _is_none_any(src_subnet) else _infer_subnet_of_host(Sub_Net, pos_src)

    # -------------------------
    # B) Positive dst host
    # -------------------------
    pos_dst = None
    if dst_scope == "host" and not _is_none_any(dst_ip):
        if any(str(e["D_IP"]) == str(dst_ip) for e in _entries(Sub_Net)):
            pos_dst = str(dst_ip)
        else:
            dst_scope = "subnet" if not _is_none_any(dst_subnet) else "any"

    # if pos_dst is None and dst_scope == "subnet" and not _is_none_any(dst_subnet):
    #     pos_dst = _pick_host_from_subnet(Sub_Net, dst_subnet, exclude=[pos_src])
    if pos_dst is None and dst_scope == "subnet" and not _is_none_any(dst_subnet):
    # destination inside protected subnet
        pos_dst = _pick_host_from_subnet(Sub_Net, dst_subnet)

    # ensure source is NOT in same subnet
    if inferred_src_subnet == dst_subnet or pos_src is None:
        for n in _unique_subnets(Sub_Net):
            if n != dst_subnet:
                pos_src = _pick_host_from_subnet(Sub_Net, n)
                break
                
    if pos_dst is None:
        # for egress: pick a host in a different subnet than src
        if intent_dir == "egress" and inferred_src_subnet:
            other_nets = _pick_other_subnet(Sub_Net, inferred_src_subnet, k=3)
            if other_nets:
                pos_dst = _pick_host_from_subnet(Sub_Net, other_nets[0], exclude=[pos_src])
        # fallback: any host in different subnet
        if pos_dst is None and inferred_src_subnet:
            for n in _unique_subnets(Sub_Net):
                if n != inferred_src_subnet:
                    pos_dst = _pick_host_from_subnet(Sub_Net, n, exclude=[pos_src])
                    if pos_dst:
                        break
        if pos_dst is None:
            pos_dst = _pick_host_any(Sub_Net, exclude=[pos_src])

    inferred_dst_subnet = dst_subnet if not _is_none_any(dst_subnet) else _infer_subnet_of_host(Sub_Net, pos_dst)
        # ---------- Placement-aware Q1 anchoring ----------
    # Q1 uses testFilters pinned to @enter(hostname[intf]).
    # Therefore, the generated positive flow must be consistent with the chosen interface.
    router_interfaces = context_variables.get("router_interfaces") or []
    intf_prefix = _iface_prefix(router_interfaces, Intf_Name)

    if _is_none_any(intf_prefix):
        intf_prefix = context_variables.get("Intf_Subnet")

    dir_norm = (direction or "").strip().lower()
    if dir_norm not in ("in", "out"):
        return {
            "Plan_Status": "needs_more_data",
            "Notes": f"Invalid Direction={direction}. Must be 'in' or 'out'.",
        }

    if not _is_none_any(intf_prefix):
        if dir_norm == "in":
            # Flow must enter the chosen interface, so source should be in that interface subnet.
            anchored_src = _pick_host_from_prefix(Sub_Net, intf_prefix, exclude=[pos_dst])

            if anchored_src:
                pos_src = anchored_src
                inferred_src_subnet = _infer_subnet_of_host(Sub_Net, pos_src)

            else:
                # If no PC exists on that interface subnet, Q1 cannot be flow-tested there.
                # This prevents false EMPTY testFilters failures.
                notes += f", Q1 skipped/weak: no source host found in ingress interface prefix {intf_prefix}"

        elif dir_norm == "out":
            # Flow must exit the chosen interface, so destination should be in that interface subnet.
            anchored_dst = _pick_host_from_prefix(Sub_Net, intf_prefix, exclude=[pos_src])

            if anchored_dst:
                pos_dst = anchored_dst
                inferred_dst_subnet = _infer_subnet_of_host(Sub_Net, pos_dst)

            else:
                notes += f", Q1 skipped/weak: no destination host found in egress interface prefix {intf_prefix}"

    # Final sanity.
    if pos_src and pos_dst and pos_src == pos_dst:
        alt_dst = _pick_host_any(Sub_Net, exclude=[pos_src])
        if alt_dst:
            pos_dst = alt_dst
            inferred_dst_subnet = _infer_subnet_of_host(Sub_Net, pos_dst)
    # -------------------------
    # C) Negative src host (for restriction tests)
    # -------------------------
    neg_src = "none"
    neg_dst = "none"
    neg_expected = "none"

    if restriction_mode != "none":
        # default: vary source unless destination restriction
        if restriction_mode in ("only_dst",):
            # vary destination; keep source same
            neg_src = pos_src
        else:
            # "only_host": pick another host in same src subnet (preferred)
            if restriction_mode == "only_host" and inferred_src_subnet:
                nh = _pick_host_from_subnet(Sub_Net, inferred_src_subnet, exclude=[pos_src])
                if nh:
                    neg_src = nh
            # Fallback: pick a host from a DIFFERENT subnet (but not equal to pos_dst)
            if neg_src == "none" and inferred_src_subnet:
                for n in _unique_subnets(Sub_Net):
                    if n != inferred_src_subnet:
                        nh = _pick_host_from_subnet(Sub_Net, n, exclude=[pos_src, pos_dst])
                        if nh:
                            neg_src = nh
                            break


        # destination for negative flow
        if restriction_mode == "only_dst":
            # pick a different destination from a different subnet
            if inferred_dst_subnet:
                for n in _unique_subnets(Sub_Net):
                    if n != inferred_dst_subnet:
                        nd = _pick_host_from_subnet(Sub_Net, n, exclude=[pos_src, pos_dst])
                        if nd:
                            neg_dst = nd
                            break
            if neg_dst == "none":
                neg_dst = _pick_host_any(Sub_Net, exclude=[pos_src, pos_dst])
        else:
            # keep dst same
            neg_dst = pos_dst
            # Final guard: avoid neg_src == neg_dst
            if neg_src != "none" and neg_dst != "none" and neg_src == neg_dst:
                alt = _pick_host_any(Sub_Net, exclude=[pos_src, pos_dst, neg_src])#, neg_dst])
                if alt:
                    neg_dst = alt
                else:
                    neg_src = "none"
                    neg_dst = "none"
                    neg_expected = "none"

        # negative expected behavior depends on "only" allow vs deny policies.
        # Most common: "only X is permitted" => negative should be denied
        # For "only X is denied" => negative should be permitted
        # We'll interpret based on expected_action:
        if expected_action == "permit":
            neg_expected = "deny"
        else:
            neg_expected = "permit"

    # -------------------------
    # Q2 base subnets list (used by your executor)
    # -------------------------
    q2 = derive_q2_space(src_scope, dst_scope, src_ip, dst_ip, src_subnet, dst_subnet)


    # # q2_src_subnet = inferred_src_subnet or "0.0.0.0/0"
    # if dst_scope == "subnet":
    #     q2_src_subnet = "0.0.0.0/0"
    # else:
    #     # q2_src_subnet = inferred_src_subnet or "0.0.0.0/0"
    #     if src_scope == "host" and dst_scope == "any":
    #     # policy allows only one host
    #         q2_src_subnet = "0.0.0.0/0"
    #         q2_violation_action = "permit"   # look for unauthorized permits
    #     else:
    #         q2_src_subnet = inferred_src_subnet or "0.0.0.0/0"
    #         q2_violation_action = opposite_action
    
    # q2_dst_subnets = []
    # # Placement-aware Q2 dst space adjustments
    # # For OUT: destinations should be those that would exit Intf_Subnet (best effort: use Intf_Subnet as dst space)
    # # For IN:  sources should be Intf_Subnet (already pinned via q2_src_subnet below)
    # if dir_norm == "out" and not _is_none_any(intf_subnet):
    # # OUT filter: verify what leaves that interface subnet
    #     q2_dst_subnets = [str(intf_subnet)]
    # else:
    #     if not _is_none_any(dst_subnet):
    #         q2_dst_subnets = [str(dst_subnet)]
    #     else:
    #         if inferred_src_subnet:
    #             q2_dst_subnets = _pick_other_subnet(Sub_Net, inferred_src_subnet, k=3)
    #         else:
    #             q2_dst_subnets = _unique_subnets(Sub_Net)[:3]
    # if not _is_none_any(dst_subnet):
    #     q2_dst_subnets = [str(dst_subnet)]
    # else:
    #     # choose 1–3 other subnets (different from src)
    #     if inferred_src_subnet:
    #         q2_dst_subnets = _pick_other_subnet(Sub_Net, inferred_src_subnet, k=3)
    #     else:
    #         q2_dst_subnets = _unique_subnets(Sub_Net)[:3]

    # default app choice
    planned_app = _default_app(protocol, port, app)

    # Violation action for Q2A is ALWAYS "opposite of expected action"
    # q2_violation_action = opposite_action

    # Notes summarizing the plan
    notes = (
        # f"intent_dir={intent_dir}, "
        f"placement_dir={direction}, "
        f"src_scope={src_scope}, "
        f"dst_scope={dst_scope}, "
        f"restriction_mode={restriction_mode}"
    )  #+notes
    if disallowed_app != "none" or disallowed_port != "none":
        notes += f", disallowed_example_app={disallowed_app}, disallowed_example_port={disallowed_port}"

    if _is_none_any(Intf_Name) or _is_none_any(direction):
        return {
        "Plan_Status": "needs_more_data",
        "Notes": "Missing Intf_Name or direction; required for placement-aware Batfish tests (@in/@out).",
    }

    
    return {
        "Plan_Status": "ok",
        "Device": hostname,
        "ACL_Name": L_Name,
        "Intf_Name": Intf_Name,
        "Direction": direction,

        "Q1_Pos_Src_Host": pos_src,
        "Q1_Pos_Dst_Host": pos_dst,
        "Q1_Pos_Expected_Action": expected_action,

        "Q1_Neg_Src_Host": neg_src,
        "Q1_Neg_Dst_Host": neg_dst,
        "Q1_Neg_Expected_Action": neg_expected,

        # "Q2_Src_Subnet": q2_src_subnet,
        # "Q2_Dst_Subnets": ",".join(q2_dst_subnets),
        "q2_src_subnet" : q2["src"],
        "q2_dst_subnets" : [q2["dst"]],
       
        "q2_violation_action" : q2["violation_action"],

        "Expected_Action": expected_action,
        "Opposite_Action": opposite_action,

        "Application": planned_app,
        "Protocol": _norm_lower(protocol) or "none",
        "Port": str(port).strip() if not _is_none_any(port) else "none",

        # "Q2_Violation_Action": q2_violation_action,
        "Q2_Restriction_Mode": restriction_mode,
        "Notes": notes,

        "Disallowed_Example_App": disallowed_app,
        "Disallowed_Example_Port": disallowed_port,
    }

def q0_validate_flexible(attachments, acceptable):
    """
    attachments: list of {"interface": "...", "direction": "..."} from find_acl_attachments
    acceptable: list of (intf_name, direction) pairs
    Returns: (ok: bool, details: dict)
    """
    acceptable_set = {(i, d.lower()) for (i, d) in acceptable}

    actual = []
    for a in (attachments or []):
        intf = iface_to_name(a.get("interface"))
        direc = (a.get("direction") or "").lower()
        actual.append((intf, direc))

    matches = [x for x in actual if x in acceptable_set]

    return (len(matches) > 0), {
        "acceptable": list(acceptable_set),
        "actual": actual,
        "matches": matches,
        "issue": "ok" if matches else ("acl_not_attached" if not actual else "no_acceptable_attachment_found")
    }

def set_acl_attachment_raw(cfg_text, acl_name, intf_name, direction):
    direction = direction.strip().lower()
    assert direction in ("in", "out")

    lines = cfg_text.splitlines()
    out = []

    current_iface = None
    target_norm = normalize_interface_name(intf_name)

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.lower().startswith("interface "):
            iface_header = line
            iface_name = stripped.split(None, 1)[1].strip()
            iface_norm = normalize_interface_name(iface_name)

            block = [line]
            i += 1
            while i < len(lines):
                block.append(lines[i])
                if lines[i].strip() == "!":
                    i += 1
                    break
                i += 1

            # remove all attachments of this ACL from this block
            cleaned = []
            for b in block:
                bs = b.strip().lower()
                pat = rf"^ip access-group\s+{re.escape(acl_name.lower())}\s+(in|out)$"
                if re.match(pat, bs):
                    continue
                cleaned.append(b)

            if iface_norm == target_norm:
                insert_pos = len(cleaned)
                if cleaned and cleaned[-1].strip() == "!":
                    insert_pos -= 1
                cleaned.insert(insert_pos, f" ip access-group {acl_name} {direction}")

            out.extend(cleaned)
            continue

        out.append(line)
        i += 1

    return "\n".join(out) + "\n"
    

def build_acceptable_attachments(
    router_interfaces,
    default_route_iface,
    inside_prefixes,
    intent_dir,
    src_ip=None,
    src_subnet=None,
    dst_ip=None,
    dst_subnet=None,
):
    acceptable = []

    pi, pd = choose_acl_attachment(
        router_interfaces,
        default_route_iface,
        inside_prefixes,
        intent_dir,
        src_ip,
        src_subnet,
        dst_ip,
        dst_subnet,
    )

    if pi and pd:
        acceptable.append((_norm_intf(pi), _norm_dir(pd)))

    inside_prefixes = inside_prefixes or []

    src_ip = _norm_none(src_ip)
    dst_ip = _norm_none(dst_ip)
    src_subnet = _norm_none(src_subnet)
    dst_subnet = _norm_none(dst_subnet)

    # Destination inside: also accept transit inbound as a valid choke point.
    dst_inside = False
    if dst_ip:
        dst_inside = any(_ip_in_prefix(dst_ip, p) for p in inside_prefixes if p and p != "dhcp")
    if dst_subnet:
        dst_inside = _prefix_is_inside(dst_subnet, set(inside_prefixes))

    if dst_inside:
        # Accept destination LAN outbound.
        target = dst_subnet or dst_ip
        dst_lan = _iface_matching_prefix(router_interfaces, target, role="LAN")
        if dst_lan:
            acceptable.append((_norm_intf(dst_lan), "out"))

        # Accept transit inbound.
        transit = _first_iface_by_role(router_interfaces, "TRANSIT")
        if transit:
            acceptable.append((_norm_intf(transit), "in"))

    # Source inside: accept source LAN inbound.
    src_inside = False
    if src_ip:
        src_inside = any(_ip_in_prefix(src_ip, p) for p in inside_prefixes if p and p != "dhcp")
    if src_subnet:
        src_inside = _prefix_is_inside(src_subnet, set(inside_prefixes))

    if src_inside:
        target = src_subnet or src_ip
        src_lan = _iface_matching_prefix(router_interfaces, target, role="LAN")
        if src_lan:
            acceptable.append((_norm_intf(src_lan), "in"))

    # De-dup while preserving order.
    out, seen = [], set()
    for intf, direction in acceptable:
        item = (_norm_intf(intf), _norm_dir(direction))
        if item[0] and item[1] and item not in seen:
            seen.add(item)
            out.append(item)

    return out

def q0_pick_working_attachment(attachments, acceptable):
    """
    Returns (ok, chosen_intf, chosen_dir, details)
    ok=True if any actual attachment matches acceptable set
    chosen_* is the first matching attachment; if no match, None
    """
    acceptable_set = {(_norm_intf(i), _norm_dir(d)) for (i, d) in (acceptable or [])}

    actual = []
    actual_raw = []

    for a in (attachments or []):
        raw_intf = None
        raw_dir = None

        if isinstance(a, dict):
            raw_intf = (
                a.get("interface")
                or a.get("Interface")
                or a.get("intf")
                or a.get("Intf_Name")
                or a.get("iface")
            )
            raw_dir = (
                a.get("direction")
                or a.get("Direction")
                or a.get("dir")
                or a.get("filter_type")
                or a.get("Filter_Type")
            )
        elif isinstance(a, (tuple, list)) and len(a) >= 2:
            raw_intf, raw_dir = a[0], a[1]
        else:
            raw_intf = str(a)

        norm_intf = _norm_intf(iface_to_name(raw_intf) if raw_intf else raw_intf)
        norm_dir = _norm_dir(raw_dir)

        actual_raw.append({"raw": a, "parsed_intf": raw_intf, "parsed_dir": raw_dir})
        actual.append((norm_intf, norm_dir))

    matches = [x for x in actual if x in acceptable_set]

    print("Q0 acceptable_set:", acceptable_set)
    print("Q0 actual_raw:", actual_raw)
    print("Q0 actual_norm:", actual)
    print("Q0 matches:", matches)

    if matches:
        return True, matches[0][0], matches[0][1], {
            "acceptable": list(acceptable_set),
            "actual": actual,
            "actual_raw": actual_raw,
            "matches": matches
        }

    return False, None, None, {
        "acceptable": list(acceptable_set),
        "actual": actual,
        "actual_raw": actual_raw,
        "matches": []
    }

def _first_lan_iface_name(lan_ifaces):
    return lan_ifaces[0]["name"] if lan_ifaces and lan_ifaces[0].get("name") else None
    

# -------- helpers for choose_acl_attachment --------
def _pick_outside_iface(default_route_iface, router_interfaces):
    if default_route_iface and str(default_route_iface).strip():
        return str(default_route_iface).strip()
    # prefer role WAN, else any non-LAN, else first interface
    # Prefer explicit WAN role
    for i in router_interfaces or []:
        if (i.get("role") or "").upper() == "WAN" and i.get("name"):
            return i["name"]
    # Else pick any non-LAN interface
    for i in router_interfaces or []:
        if (i.get("role") or "").upper() != "LAN" and i.get("name"):
            return i["name"]
    # Else last resort: first interface
    if router_interfaces and router_interfaces[0].get("name"):
        return router_interfaces[0]["name"]
    return None
    
def _iface_matching_prefix(router_interfaces, target_prefix, role=None):
    """
    Return interface name whose prefix overlaps/matches target_prefix.
    Optionally restrict by role.
    """
    if not target_prefix:
        return None

    target_net = _parse_subnet(target_prefix)
    if target_net is None:
        return None

    for i in router_interfaces or []:
        if role and (i.get("role") or "").upper() != role.upper():
            continue

        pfx = i.get("prefix")
        if not pfx or str(pfx).lower() == "dhcp":
            continue

        pnet = _parse_subnet(pfx)
        if pnet is None:
            continue

        if target_net == pnet or target_net.subnet_of(pnet) or pnet.subnet_of(target_net) or target_net.overlaps(pnet):
            return i.get("name")

    return None


def _first_iface_by_role(router_interfaces, role):
    for i in router_interfaces or []:
        if (i.get("role") or "").upper() == role.upper() and i.get("name"):
            return i.get("name")
    return None


def choose_acl_attachment(
    router_interfaces,
    default_route_iface,
    inside_prefixes,
    intent_dir,
    src_ip=None,
    src_subnet=None,
    dst_ip=None,
    dst_subnet=None,
):
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
    inside_set = set(p for p in inside_prefixes if p and str(p).lower() != "dhcp")

    src_inside = False
    dst_inside = False

    if src_ip and inside_set:
        src_inside = any(_ip_in_prefix(src_ip, p) for p in inside_set)
    if src_subnet and inside_set:
        src_inside = _prefix_is_inside(src_subnet, inside_set)

    if dst_ip and inside_set:
        dst_inside = any(_ip_in_prefix(dst_ip, p) for p in inside_set)
    if dst_subnet and inside_set:
        dst_inside = _prefix_is_inside(dst_subnet, inside_set)

    outside_iface = _pick_outside_iface(default_route_iface, router_interfaces)
    transit_iface = _first_iface_by_role(router_interfaces, "TRANSIT")

    # 1. Protect traffic going TO an inside destination.
    # Best single-router placement: outbound on destination LAN interface.
    if dst_inside:
        target = dst_subnet or dst_ip
        dst_lan_iface = _iface_matching_prefix(router_interfaces, target, role="LAN")
        if dst_lan_iface:
            return dst_lan_iface, "out"

        if transit_iface:
            return transit_iface, "in"

        if outside_iface:
            return outside_iface, "in"

    # 2. Control traffic FROM an inside source.
    if src_inside:
        target = src_subnet or src_ip
        src_lan_iface = _iface_matching_prefix(router_interfaces, target, role="LAN")
        if src_lan_iface:
            return src_lan_iface, "in"

    # 3. Explicit egress wording: traffic leaving internal networks.
    if intent_dir == "egress":
        if transit_iface:
            return transit_iface, "out"
        if outside_iface:
            return outside_iface, "out"

    # 4. Explicit ingress wording: traffic entering from upstream.
    if intent_dir == "ingress":
        if transit_iface:
            return transit_iface, "in"
        if outside_iface:
            return outside_iface, "in"

    # 5. Fallback.
    if transit_iface:
        return transit_iface, "in"

    if outside_iface:
        return outside_iface, "in"

    return None, None
    
    
# def choose_acl_attachment(router_interfaces, default_route_iface, inside_prefixes,
#                           intent_dir, src_ip=None, src_subnet=None, dst_ip=None, dst_subnet=None):
#     """
#     intent_dir: "egress" | "ingress" | "unspecified"
#     Returns: (intf_name, direction)  where direction is "in" or "out"
#     """
#     src_ip = _norm_none(src_ip)
#     dst_ip = _norm_none(dst_ip)
#     src_subnet = _norm_none(src_subnet)
#     dst_subnet = _norm_none(dst_subnet)

#     # Normalize values to avoid whitespace / datatype issues
#     src_ip = str(src_ip).strip() if src_ip else None
#     dst_ip = str(dst_ip).strip() if dst_ip else None
#     src_subnet = str(src_subnet).strip() if src_subnet else None
#     dst_subnet = str(dst_subnet).strip() if dst_subnet else None
    
#     inside_prefixes = inside_prefixes or []
#     inside_set = set(p for p in inside_prefixes if p and str(p).lower() != "dhcp")
    
#     outside_iface = _pick_outside_iface(default_route_iface, router_interfaces)

#     # Prefer LAN interfaces that match inside_prefixes if provided
#     lan_ifaces = [i for i in (router_interfaces or []) if (i.get("role") or "").upper() == "LAN"]
#     if inside_set:
#         lan_ifaces = [i for i in (router_interfaces or [])
#                       if i.get("prefix") in inside_set] or lan_ifaces
#      # -------- Decision logic --------
#     # First infer from entities (more reliable than NLP intent_dir)
#     src_inside = False
#     dst_inside = False
    
#     if src_ip and inside_set:
#         src_inside = any(_ip_in_prefix(src_ip, p) for p in inside_set)
#     if src_subnet and inside_set:
#         src_inside = _prefix_is_inside(src_subnet, inside_set)
    
#     if dst_ip and inside_set:
#         dst_inside = any(_ip_in_prefix(dst_ip, p) for p in inside_set)
#     if dst_subnet and inside_set:
#         dst_inside = _prefix_is_inside(dst_subnet, inside_set)
    
#     # Destination inside → protect inside
#     if dst_inside:
#         return (outside_iface, "in")
    
#     # Source inside → control inside users
#     if src_inside:
#         lan_name = _first_lan_iface_name(lan_ifaces)
#         if lan_name:
#             return (lan_name, "in")
#         return (outside_iface, "out")
#     # If entities don't help, fall back to intent_dir
#     if (intent_dir or "").lower() == "ingress":
#         return (outside_iface, "in")

#     if (intent_dir or "").lower() == "egress":
#         lan_name = _first_lan_iface_name(lan_ifaces)
#         # If src subnet/IP is inside, put ACL inbound on LAN interface (classic ACL placement)
#         # This blocks unwanted traffic as it ENTERS the router from inside.
#         if lan_name:
#             return (lan_name, "in")
#         # Fallback: apply outbound on default route interface
#         return (outside_iface, "out")
    
#     # UNSPECIFIED: infer based on whether src/dst are inside
#     src_inside = False
#     dst_inside = False

#     if src_ip and inside_set:
#         src_inside = any(_ip_in_prefix(src_ip, p) for p in inside_set)
#     if src_subnet and inside_set:
#         src_inside = _prefix_is_inside(src_subnet, inside_set)

#     if dst_ip and inside_set:
#         dst_inside = any(_ip_in_prefix(dst_ip, p) for p in inside_set)
#     if dst_subnet and inside_set:
#         dst_inside = _prefix_is_inside(dst_subnet, inside_set)

#     # Case 1: destination is inside (classic "protect inside") -> outside IN
#     if dst_inside:
#         return (outside_iface, "in")
    
#     # Case 2: source is inside (classic "control inside users") -> LAN IN (closest)
#     if src_inside:
#         # If we can find the specific LAN interface matching src_subnet, use it
#         if src_subnet:
#             si = _find_iface_for_exact_prefix(src_subnet,router_interfaces)
#             if si and (si.get("role") or "").upper() == "LAN":
#                 return (si["name"], "in")
#         lan_name = _first_lan_iface_name(lan_ifaces)
#         if lan_name:
#             return (lan_name, "in")
#         return (outside_iface, "out")
    
#     # Case 3: Neither clearly inside -> safe fallback
#     # If dst_subnet exactly matches a LAN prefix, apply OUT on that LAN interface (destination-side)
#     # (This is optional behavior; remove if you want only outside-based defaults.)
#     if dst_subnet:
#         di = _find_iface_for_exact_prefix(dst_subnet,router_interfaces)
#         if di and (di.get("role") or "").upper() == "LAN":
#             return (di["name"], "out")

#     return (outside_iface, "out")