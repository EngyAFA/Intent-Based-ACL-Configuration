import json
import random
from copy import deepcopy
from pathlib import Path

##########################################################
# TOPOLOGY MODEL
# Topology 2: three routers: tests entity extraction, placement(interface, direction), syntax, and device selection too
# ##########################################################


# ##########################################################
# MULTI-ROUTER TOPOLOGY MODEL
# ##########################################################

OBJECTS = {
    "LAN_A": {
        "kind": "subnet",
        "ip": "192.168.10.0",
        "cidr": "192.168.10.0/24",
        "wildcard": "0.0.0.255",
        "zone": "LAN_A"
    },
    "PC1": {
        "kind": "host",
        "ip": "192.168.10.10",
        "cidr": "192.168.10.10/32",
        "wildcard": "0.0.0.0",
        "zone": "LAN_A"
    },
    "PC2": {
        "kind": "host",
        "ip": "192.168.10.20",
        "cidr": "192.168.10.20/32",
        "wildcard": "0.0.0.0",
        "zone": "LAN_A"
    },
    "PC3": {
        "kind": "host",
        "ip": "192.168.10.30",
        "cidr": "192.168.10.30/32",
        "wildcard": "0.0.0.0",
        "zone": "LAN_A"
    },
    "PC6": {
        "kind": "host",
        "ip": "192.168.10.40",
        "cidr": "192.168.10.40/32",
        "wildcard": "0.0.0.0",
        "zone": "LAN_A"
    },

    "DMZ": {
        "kind": "subnet",
        "ip": "192.168.20.0",
        "cidr": "192.168.20.0/24",
        "wildcard": "0.0.0.255",
        "zone": "DMZ"
    },
    "WEB1": {
        "kind": "host",
        "ip": "192.168.20.10",
        "cidr": "192.168.20.10/32",
        "wildcard": "0.0.0.0",
        "zone": "DMZ"
    },
    "APP1": {
        "kind": "host",
        "ip": "192.168.20.20",
        "cidr": "192.168.20.20/32",
        "wildcard": "0.0.0.0",
        "zone": "DMZ"
    },

    "LAN_B": {
        "kind": "subnet",
        "ip": "192.168.30.0",
        "cidr": "192.168.30.0/24",
        "wildcard": "0.0.0.255",
        "zone": "LAN_B"
    },
    "PC4": {
        "kind": "host",
        "ip": "192.168.30.10",
        "cidr": "192.168.30.10/32",
        "wildcard": "0.0.0.0",
        "zone": "LAN_B"
    },
    "PC5": {
        "kind": "host",
        "ip": "192.168.30.20",
        "cidr": "192.168.30.20/32",
        "wildcard": "0.0.0.0",
        "zone": "LAN_B"
    },
    "PC7": {
        "kind": "host",
        "ip": "192.168.30.30",
        "cidr": "192.168.30.30/32",
        "wildcard": "0.0.0.0",
        "zone": "LAN_B"
    },
    "PC8": {
        "kind": "host",
        "ip": "192.168.30.40",
        "cidr": "192.168.30.40/32",
        "wildcard": "0.0.0.0",
        "zone": "LAN_B"
    },

    "ISP": {
        "kind": "host",
        "ip": "203.0.113.1",
        "cidr": "203.0.113.1/32",
        "wildcard": "0.0.0.0",
        "zone": "Internet"
    },

    "Internet": {
        "kind": "any",
        "ip": "any",
        "cidr": "0.0.0.0/0",
        "wildcard": None,
        "zone": "Internet"
    }
    #     "R1_R2_LINK": {
    #     "kind": "subnet",
    #     "ip": "10.0.12.0",
    #     "cidr": "10.0.12.0/30",
    #     "wildcard": "0.0.0.3",
    #     "zone": "TRANSIT"
    # },
    # "R2_R3_LINK": {
    #     "kind": "subnet",
    #     "ip": "10.0.23.0",
    #     "cidr": "10.0.23.0/30",
    #     "wildcard": "0.0.0.3",
    #     "zone": "TRANSIT"
    # },
    # "WAN_ISP_LINK": {
    #     "kind": "subnet",
    #     "ip": "203.0.113.0",
    #     "cidr": "203.0.113.0/30",
    #     "wildcard": "0.0.0.3",
    #     "zone": "Internet"
    # }
}

SERVICES = {
    "HTTP":   {"protocol": "tcp",  "port": 80},
    "HTTPS":  {"protocol": "tcp",  "port": 443},
    "DNS":    {"protocol": "udp",  "port": 53},
    "SSH":    {"protocol": "tcp",  "port": 22},
    "TELNET": {"protocol": "tcp",  "port": 23},
    "ICMP":   {"protocol": "icmp", "port": None},
    "ANY":    {"protocol": "ip",   "port": None},
}

CONTEXT_FILE = "multirouter_topology.json"

# ##########################################################
# ROUTER OWNERSHIP / ENFORCEMENT POLICY
# closest-to-source policy
# ##########################################################

ZONE_SOURCE_DEVICE = {
    "LAN_A": "R1",
    "Internet": "R2",
    "DMZ": "R3",
    "LAN_B": "R3",
}

# ingress interface for traffic ENTERING the chosen device from source side
SOURCE_INGRESS_INTERFACE = {
    ("R1", "LAN_A"): "f0/0",
    ("R2", "Internet"): "f0/0",
    ("R3", "DMZ"): "f0/1",
    ("R3", "LAN_B"): "f0/0",
}

# egress interface on chosen device toward destination side
# only needed if you also want out-direction datasets
DEST_EGRESS_INTERFACE = {
    ("R1", "LAN_A"): "f0/0",
    ("R1", "Internet"): "s0/1",   # toward R2
    ("R1", "DMZ"): "s0/1",        # toward R2
    ("R1", "LAN_B"): "s0/1",      # toward R2

    ("R2", "Internet"): "f0/0",
    ("R2", "LAN_A"): "s0/0",
    ("R2", "DMZ"): "s0/1",
    ("R2", "LAN_B"): "s0/1",

    ("R3", "DMZ"): "f0/1",
    ("R3", "LAN_B"): "f0/0",
    ("R3", "Internet"): "s0/0",   # toward R2
    ("R3", "LAN_A"): "s0/0",      # toward R2
}

# ##########################################################
# HELPERS
# ##########################################################

def zone_of(obj_name: str) -> str:
    return OBJECTS[obj_name]["zone"]

def format_acl_addr(obj_name: str) -> str:
    obj = OBJECTS[obj_name]
    if obj["kind"] == "any":
        return "any"
    if obj["kind"] == "host":
        return f"host {obj['ip']}"
    return f"{obj['ip']} {obj['wildcard']}"

def clean(x):
    return str(x).strip()
    
def object_ir(obj_name: str) -> dict:
    obj = OBJECTS[obj_name]

    if obj["kind"] == "any":
        return {
            "object": clean(obj_name),
            "ip": clean(obj["cidr"])
        }

    if obj["kind"] == "host":
        return {
            "object": clean(obj_name),
            "ip": clean(obj["ip"]),
            "wildcard": clean(obj["wildcard"])
        }

    if obj["kind"] == "subnet":
        return {
            "object": clean(obj_name),
            "ip": clean(obj["cidr"]),
            "wildcard": clean(obj["wildcard"])
        }

    return {
        "object": clean(obj_name),
        "ip": clean(obj["ip"])
    }
    
def build_rule_line(seq: int, action: str, protocol: str, src: str, dst: str, port: int | None) -> str:
    src_txt = format_acl_addr(src)
    dst_txt = format_acl_addr(dst)

    if protocol in {"ip", "icmp"} or port is None:
        return f" {seq} {action} {protocol} {src_txt} {dst_txt}"
    return f" {seq} {action} {protocol} {src_txt} {dst_txt} eq {port}"

def valid_pair(src: str, dst: str) -> bool:
    if src == dst:
        return False
    if src == "Internet" and dst == "Internet":
        return False
    if zone_of(src) == zone_of(dst):
        return False
    return True

def choose_device_closest_to_source(src: str) -> str:
    return ZONE_SOURCE_DEVICE[zone_of(src)]

def make_acl_name(device: str, interface: str, direction: str) -> str:
    iface = interface.upper().replace("/", "_")
    return f"ACL_{device}_{iface}_{direction.upper()}"

def natural_name(obj_name: str) -> str:
    # obj = OBJECTS[obj_name]

    # if obj["kind"] == "any":
    #     return "any"
    # if obj["kind"] == "host":
    #     return obj["ip"]          # plain IP for hosts
    # if obj["kind"] == "subnet":
    #     return obj["cidr"]        # CIDR for subnets

    return obj_name

# ##########################################################
# INTERFACE / DIRECTION CHOICE
# ##########################################################

def choose_in_placement(src: str, dst: str) -> dict:
    _ = dst
    src_zone = zone_of(src)
    device = choose_device_closest_to_source(src)
    interface = SOURCE_INGRESS_INTERFACE[(device, src_zone)]
    direction = "in"
    acl = make_acl_name(device, interface, direction)
    return {
        "device": device,
        "interface": interface,
        "direction": direction,
        "acl": acl
    }

def choose_out_placement(src: str, dst: str) -> dict:
    device = choose_device_closest_to_source(src)
    dst_zone = zone_of(dst)
    interface = DEST_EGRESS_INTERFACE[(device, dst_zone)]
    direction = "out"
    acl = make_acl_name(device, interface, direction)
    return {
        "device": device,
        "interface": interface,
        "direction": direction,
        "acl": acl
    }

def choose_mixed_placement(src: str, dst: str, rng: random.Random) -> dict:
    if rng.random() < 0.5:
        return choose_in_placement(src, dst)
    return choose_out_placement(src, dst)
    
# ##########################################################
# NATURAL LANGUAGE TEMPLATES
# ##########################################################

GENERAL_TEMPLATES = {
    "permit": [
        "Allow {src} to access {dst} on {svc}.",
        "Permit {src} to reach {dst} using {svc}.",
        "Allow traffic from {src} to {dst} over {svc}.",
        "Permit {src} to use {svc} toward {dst}.",
    ],
    "deny": [
        "Block {src} from accessing {dst} on {svc}.",
        "Deny {src} from reaching {dst} using {svc}.",
        "Prevent {src} from using {svc} toward {dst}.",
        "Block traffic from {src} to {dst} over {svc}.",
    ]
}

ICMP_TEMPLATES = {
    "permit": [
        "Allow {src} to ping {dst}.",
        "Permit ICMP from {src} to {dst}.",
    ],
    "deny": [
        "Block {src} from pinging {dst}.",
        "Deny ICMP from {src} to {dst}.",
    ]
}

ANY_TEMPLATES = {
    "permit": [
        "Allow {src} to access {dst}.",
        "Permit all IP traffic from {src} to {dst}.",
    ],
    "deny": [
        "Block {src} from accessing {dst}.",
        "Deny all IP traffic from {src} to {dst}.",
    ]
}

EGRESS_HINT_TEMPLATES = {
    "permit": [
        "Allow {src} to reach {dst} on {svc} as traffic exits the selected router.",
        "Permit {src} to use {svc} toward {dst} at egress.",
    ],
    "deny": [
        "Block {src} from reaching {dst} on {svc} as traffic exits the selected router.",
        "Deny {src} from using {svc} toward {dst} at egress.",
    ]
}

def choose_templates(service_name: str, action: str, egress_hint: bool) -> list[str]:
    if egress_hint:
        if service_name in {"HTTP", "HTTPS", "DNS", "SSH", "TELNET"}:
            return EGRESS_HINT_TEMPLATES[action]

    if service_name == "ICMP":
        return ICMP_TEMPLATES[action]
    if service_name == "ANY":
        return ANY_TEMPLATES[action]
    return GENERAL_TEMPLATES[action]

def make_nl_query(src: str, dst: str, service_name: str, action: str, rng: random.Random, egress_hint: bool) -> str:
    template = rng.choice(choose_templates(service_name, action, egress_hint))
    return template.format(src=natural_name(src), dst=natural_name(dst), svc=service_name)


def service_valid_for_pair(src: str, dst: str, service_name: str) -> bool:
    if service_name in {"HTTP", "HTTPS", "SSH", "TELNET"}:
        # These are often more meaningful when destination is a host or Internet
        if dst in {"DMZ", "LAN_A", "LAN_B"}:
            return False
    return True

def valid_combo(src: str, dst: str, service_name: str, action: str) -> bool:
    if action not in {"permit", "deny"}:
        return False
    if not valid_pair(src, dst):
        return False
    if not service_valid_for_pair(src, dst, service_name):
        return False
    return True
    
# BUILD INTENT
# ###########

def build_intent(idx: int,
                 src: str,
                 dst: str,
                 service_name: str,
                 action: str,
                 placement: dict,
                 rng: random.Random,
                 intent_prefix: str = "mr") -> dict:

    svc = SERVICES[service_name]
    seq = idx * 10
    protocol = svc["protocol"]
    port = svc["port"]

    src_text = natural_name(src)
    dst_text = natural_name(dst)

    nl_query = make_nl_query(
        src, dst, service_name, action, rng,
        egress_hint=(placement["direction"] == "out")
    )

    expected_cli = (
        f"ip access-list extended {placement['acl']}\n"
        f"{build_rule_line(seq, action, protocol, src, dst, port)}\n"
        f"interface {placement['interface']}\n"
        f" ip access-group {placement['acl']} {placement['direction']}"
    )

    return {
        "id": f"{intent_prefix}_{idx:04d}",
        "description": f"{action.title()} {service_name} from {src_text} to {dst_text}",
        "context_file": CONTEXT_FILE,
        "nl_query": nl_query,
        "expected_ir": {
            "rules": [
                {
                    "id": placement["acl"],
                    "acl_type": "extended",
                    "action": action,
                    "protocol": protocol,
                    "src": object_ir(src),
                    "dst": object_ir(dst),
                    "dst_port": None if port is None else {"op": "eq", "port": port},
                    "device": placement["device"],
                    "apply": {
                        "interface": placement["interface"],
                        "direction": placement["direction"]
                    },
                    "sequence": seq,
                    "log": False
                }
            ],
            "metadata": {
                "raw_policy": f"{action.title()} {src_text} to {dst_text} on {service_name}",
                "warnings": []
            }
        },
        "expected_cli": expected_cli
    }

# ##########################################################
# PARAPHRASES
# ##########################################################

def paraphrase_variants(intent: dict, count: int, rng: random.Random) -> list[dict]:
    rule = intent["expected_ir"]["rules"][0]
    src = rule["src"]["object"]
    dst = rule["dst"]["object"]
    action = rule["action"]
    protocol = rule["protocol"]
    port = None if rule["dst_port"] is None else rule["dst_port"]["port"]

    service_name = None
    for name, svc in SERVICES.items():
        if svc["protocol"] == protocol and svc["port"] == port:
            service_name = name
            break
    if service_name is None:
        service_name = "ANY" if protocol == "ip" else "ICMP"

    egress_hint = rule["apply"]["direction"] == "out"

    variants = []
    seen = {intent["nl_query"]}

    for i in range(1, count + 1):
        for _ in range(20):
            nl = make_nl_query(src, dst, service_name, action, rng, egress_hint)
            if nl not in seen:
                seen.add(nl)
                x = deepcopy(intent)
                x["id"] = f"{intent['id']}_p{i}"
                x["nl_query"] = nl
                x["description"] = f"{intent['description']} (paraphrase {i})"
                variants.append(x)
                break

    return variants

# ##########################################################
# DATASET GENERATORS
# ##########################################################

def enumerate_candidates():
    for src in OBJECTS:
        for dst in OBJECTS:
            if not valid_pair(src, dst):
                continue
            for service_name in SERVICES:
                for action in ("permit", "deny"):
                    yield src, dst, service_name, action

def generate_dataset(limit_base: int = 500,
                     mode: str = "mixed",
                     paraphrases_per_intent: int = 0,
                     seed: int = 7) -> list[dict]:

    rng = random.Random(seed)
    place_rng = random.Random(seed + 999)

    candidates = list(enumerate_candidates())
    rng.shuffle(candidates)

    dataset = []
    used = set()
    idx = 1
    base_count = 0

    for src, dst, service_name, action in candidates:
        if mode == "in":
            placement = choose_in_placement(src, dst)
        elif mode == "out":
            placement = choose_out_placement(src, dst)
        elif mode == "mixed":
            placement = choose_mixed_placement(src, dst, place_rng)
        else:
            raise ValueError("mode must be one of: in, out, mixed")

        sig = (
            placement["device"],
            placement["interface"],
            placement["direction"],
            src,
            dst,
            service_name,
            action,
        )
        if sig in used:
            continue
        used.add(sig)

        intent = build_intent(
            idx=idx,
            src=src,
            dst=dst,
            service_name=service_name,
            action=action,
            placement=placement,
            rng=rng,
            intent_prefix=f"mr_{mode}"
        )
        dataset.append(intent)
        base_count += 1

        if paraphrases_per_intent > 0:
            dataset.extend(paraphrase_variants(intent, paraphrases_per_intent, rng))

        idx += 1
        if base_count >= limit_base:
            break

    return dataset

# ##########################################################
# OPTIONAL: semantic signature for evaluation
# ##########################################################

def semantic_signature(intent: dict) -> dict:
    rule = intent["expected_ir"]["rules"][0]
    return {
        "device": rule["device"],
        "interface": rule["apply"]["interface"],
        "direction": rule["apply"]["direction"],
        "action": rule["action"],
        "protocol": rule["protocol"],
        "src_ip": rule["src"]["ip"],
        "src_wc": rule["src"].get("wildcard"),
        "dst_ip": rule["dst"]["ip"],
        "dst_wc": rule["dst"].get("wildcard"),
        "port": None if rule["dst_port"] is None else rule["dst_port"]["port"],
    }

# ##########################################################
# SAVE
# ##########################################################

def save_json(data, path):
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

def save_jsonl(data, path):
    with open(path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")

# ##########################################################
# MAIN
# ##########################################################

if __name__ == "__main__":
    outdir = Path("Multirouter_generated")
    outdir.mkdir(exist_ok=True)

    BASE_COUNT = 182
    PARAPHRASES_PER_INTENT = 3

    # in_data = generate_dataset(limit_base=BASE_COUNT, mode="in", paraphrases_per_intent=PARAPHRASES_PER_INTENT, seed=7)
    # out_data = generate_dataset(limit_base=BASE_COUNT, mode="out", paraphrases_per_intent=PARAPHRASES_PER_INTENT, seed=11)
    mixed_data = generate_dataset(limit_base=BASE_COUNT, mode="mixed", paraphrases_per_intent=PARAPHRASES_PER_INTENT, seed=21)

    # save_json(in_data, outdir / "multirouter_intents_in.json")
    # save_json(out_data, outdir / "multirouter_intents_out.json")
    save_json(mixed_data, outdir / "multirouter_intents_mixed.json")
    
    # save_jsonl(in_data, outdir / "multirouter_intents_in.jsonl")
    # save_jsonl(out_data, outdir / "multirouter_intents_out.jsonl")
    # save_jsonl(mixed_data, outdir / "multirouter_intents_mixed.jsonl")

    print("Generated:")
    # print(" -", outdir / "multirouter_intents_in.json")
    # print(" -", outdir / "multirouter_intents_out.json")
    print(" -", outdir / "multirouter_intents_mixed.json")
    # print("Counts:", len(in_data), len(out_data), len(mixed_data))
    print("Counts:", len(mixed_data))