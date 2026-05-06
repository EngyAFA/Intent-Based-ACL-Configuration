import json
import random
from copy import deepcopy
from pathlib import Path

# =========================================================
# TOPOLOGY MODEL 
# Topology 1: single router : tests entity extraction, interface, direction, syntax
# =========================================================

OBJECTS = {
    "LAN": {"kind": "subnet", "ip": "192.168.10.0", "wildcard": "0.0.0.255"},
    "PC1": {"kind": "host", "ip": "192.168.10.10", "wildcard": "0.0.0.0"},
    "PC2": {"kind": "host", "ip": "192.168.10.20", "wildcard": "0.0.0.0"},
    "PC3": {"kind": "host", "ip": "192.168.10.30", "wildcard": "0.0.0.0"},
    "DMZ": {"kind": "subnet", "ip": "192.168.20.0", "wildcard": "0.0.0.255"},
    "WEB1": {"kind": "host", "ip": "192.168.20.10", "wildcard": "0.0.0.0"},
    "Internet": {"kind": "any", "ip": "any", "wildcard": None},
}

SERVICES = {
    "HTTP": {"protocol": "tcp", "port": 80},
    "HTTPS": {"protocol": "tcp", "port": 443},
    "DNS": {"protocol": "udp", "port": 53},
    "SSH": {"protocol": "tcp", "port": 22},
    "TELNET": {"protocol": "tcp", "port": 23},
    "ICMP": {"protocol": "icmp", "port": None},
    "ANY": {"protocol": "ip", "port": None},
}

CONTEXT_FILE = "one_router_topology.json"
DEVICE = "R1"


# =========================================================
# HELPERS
# =========================================================

def zone_of(obj_name: str) -> str:
    if obj_name in {"LAN", "PC1", "PC2", "PC3"}:
        return "LAN"
    if obj_name in {"DMZ", "WEB1"}:
        return "DMZ"
    if obj_name == "Internet":
        return "WAN"
    raise ValueError(f"Unknown object: {obj_name}")


def is_host(obj_name: str) -> bool:
    return OBJECTS[obj_name]["kind"] == "host"


def is_subnet(obj_name: str) -> bool:
    return OBJECTS[obj_name]["kind"] == "subnet"


def is_any(obj_name: str) -> bool:
    return OBJECTS[obj_name]["kind"] == "any"


def natural_name(obj_name: str) -> str:
    mapping = {
        "LAN": "LAN",
        "DMZ": "DMZ",
        "WEB1": "WEB1",
        "Internet": "Internet",
        "PC1": "PC1",
        "PC2": "PC2",
        "PC3": "PC3",
    }
    return mapping.get(obj_name, obj_name)


def object_ir(obj_name: str) -> dict:
    obj = OBJECTS[obj_name]
    out = {"object": obj_name, "ip": obj["ip"]}
    if obj["kind"] != "any":
        out["wildcard"] = obj["wildcard"]
    return out


def format_acl_addr(obj_name: str) -> str:
    obj = OBJECTS[obj_name]
    if obj["kind"] == "any":
        return "any"
    if obj["kind"] == "host":
        return f"host {obj['ip']}"
    return f"{obj['ip']} {obj['wildcard']}"


def build_rule_line(seq: int, action: str, protocol: str, src: str, dst: str, port: int | None) -> str:
    src_txt = format_acl_addr(src)
    dst_txt = format_acl_addr(dst)

    if protocol in {"ip", "icmp"} or port is None:
        return f" {seq} {action} {protocol} {src_txt} {dst_txt}"

    return f" {seq} {action} {protocol} {src_txt} {dst_txt} eq {port}"


def semantic_signature(intent: dict) -> dict:
    rule = intent["expected_ir"]["rules"][0]
    return {
        "action": rule["action"],
        "protocol": rule["protocol"],
        "src_ip": rule["src"]["ip"],
        "src_wc": rule["src"].get("wildcard"),
        "dst_ip": rule["dst"]["ip"],
        "dst_wc": rule["dst"].get("wildcard"),
        "port": None if rule["dst_port"] is None else rule["dst_port"]["port"],
        "interface": rule["apply"]["interface"],
        "direction": rule["apply"]["direction"],
    }


# =========================================================
# VALIDITY RULES
# =========================================================

def valid_pair(src: str, dst: str) -> bool:
    if src == dst:
        return False

    # no Internet -> Internet
    if src == "Internet" and dst == "Internet":
        return False

    return True


def service_valid_for_pair(src: str, dst: str, service_name: str) -> bool:
    # Keep this permissive, but you can prune here.
    _ = src, dst, service_name
    return True


def valid_combo(src: str, dst: str, service_name: str, action: str) -> bool:
    if action not in {"permit", "deny"}:
        return False
    if not valid_pair(src, dst):
        return False
    if not service_valid_for_pair(src, dst, service_name):
        return False
    return True


# =========================================================
# PLACEMENT LOGIC
# =========================================================

def choose_in_placement(src: str) -> dict:
    z = zone_of(src)
    if z == "LAN":
        return {"interface": "g0/0", "direction": "in", "acl": "ACL_LAN_IN"}
    if z == "DMZ":
        return {"interface": "g0/1", "direction": "in", "acl": "ACL_DMZ_IN"}
    if z == "WAN":
        return {"interface": "g0/2", "direction": "in", "acl": "ACL_WAN_IN"}
    raise ValueError(f"Cannot choose IN placement for source {src}")


def choose_out_placement(dst: str) -> dict:
    z = zone_of(dst)
    if z == "LAN":
        return {"interface": "g0/0", "direction": "out", "acl": "ACL_LAN_OUT"}
    if z == "DMZ":
        return {"interface": "g0/1", "direction": "out", "acl": "ACL_DMZ_OUT"}
    if z == "WAN":
        return {"interface": "g0/2", "direction": "out", "acl": "ACL_WAN_OUT"}
    raise ValueError(f"Cannot choose OUT placement for destination {dst}")


def choose_mixed_placement(src: str, dst: str, mode_rng: random.Random) -> dict:
    """
    Mixed dataset:
    - sometimes ingress based on source side
    - sometimes egress based on destination side
    """
    if mode_rng.random() < 0.5:
        return choose_in_placement(src)
    return choose_out_placement(dst)


# =========================================================
# NL TEMPLATE ENGINE
# =========================================================

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
        "Block traffic from {src} to {dst} over {svc}.",
        "Prevent {src} from using {svc} toward {dst}.",
    ],
}

ICMP_TEMPLATES = {
    "permit": [
        "Allow {src} to ping {dst}.",
        "Permit ICMP from {src} to {dst}.",
        "Allow ping traffic from {src} to {dst}.",
        "Permit {src} to send ICMP traffic to {dst}.",
    ],
    "deny": [
        "Block {src} from pinging {dst}.",
        "Deny ICMP from {src} to {dst}.",
        "Prevent ping traffic from {src} to {dst}.",
        "Block {src} from sending ICMP traffic to {dst}.",
    ],
}

ANY_TEMPLATES = {
    "permit": [
        "Allow {src} to access {dst}.",
        "Permit all IP traffic from {src} to {dst}.",
        "Allow any protocol from {src} to {dst}.",
        "Permit unrestricted IP traffic from {src} toward {dst}.",
    ],
    "deny": [
        "Block {src} from accessing {dst}.",
        "Deny all IP traffic from {src} to {dst}.",
        "Prevent any protocol from {src} to {dst}.",
        "Block unrestricted IP traffic from {src} toward {dst}.",
    ],
}

EGRESS_HINT_TEMPLATES = {
    "permit": [
        "Allow {src} to reach {dst} on {svc} as traffic exits toward the destination interface.",
        "Permit {src} to use {svc} toward {dst} at egress.",
        "Allow {src} traffic for {svc} to be forwarded toward {dst} on the outgoing interface.",
    ],
    "deny": [
        "Block {src} from reaching {dst} on {svc} as traffic exits toward the destination interface.",
        "Deny {src} from using {svc} toward {dst} at egress.",
        "Prevent {src} traffic for {svc} from being forwarded toward {dst} on the outgoing interface.",
    ],
}

ICMP_EGRESS_HINT_TEMPLATES = {
    "permit": [
        "Allow {src} to ping {dst} as traffic exits toward the destination interface.",
        "Permit ICMP from {src} to {dst} at egress.",
    ],
    "deny": [
        "Block {src} from pinging {dst} as traffic exits toward the destination interface.",
        "Deny ICMP from {src} to {dst} at egress.",
    ],
}

ANY_EGRESS_HINT_TEMPLATES = {
    "permit": [
        "Allow {src} to access {dst} as traffic exits toward the destination interface.",
        "Permit all IP traffic from {src} to {dst} at egress.",
    ],
    "deny": [
        "Block {src} from accessing {dst} as traffic exits toward the destination interface.",
        "Deny all IP traffic from {src} to {dst} at egress.",
    ],
}


def choose_template_bank(service_name: str, direction_style: str, action: str) -> list[str]:
    if direction_style == "egress":
        if service_name == "ICMP":
            return ICMP_EGRESS_HINT_TEMPLATES[action]
        if service_name == "ANY":
            return ANY_EGRESS_HINT_TEMPLATES[action]
        return EGRESS_HINT_TEMPLATES[action]

    if service_name == "ICMP":
        return ICMP_TEMPLATES[action]
    if service_name == "ANY":
        return ANY_TEMPLATES[action]
    return GENERAL_TEMPLATES[action]


def make_nl_query(src: str, dst: str, service_name: str, action: str, rng: random.Random, direction_style: str) -> str:
    templates = choose_template_bank(service_name, direction_style, action)
    template = rng.choice(templates)
    return template.format(src=natural_name(src), dst=natural_name(dst), svc=service_name)


# =========================================================
# INTENT BUILDER
# =========================================================

def build_intent(
    idx: int,
    src: str,
    dst: str,
    service_name: str,
    action: str,
    placement: dict,
    rng: random.Random,
    direction_style: str = "neutral",
    intent_prefix: str = "gen",
) -> dict:
    svc = SERVICES[service_name]
    seq = idx * 10
    protocol = svc["protocol"]
    port = svc["port"]

    nl_query = make_nl_query(src, dst, service_name, action, rng, direction_style)

    description = f"{action.title()} {service_name} from {src} to {dst}"

    expected_cli = (
        f"ip access-list extended {placement['acl']}\n"
        f"{build_rule_line(seq, action, protocol, src, dst, port)}\n"
        f"interface {placement['interface']}\n"
        f" ip access-group {placement['acl']} {placement['direction']}"
    )

    rule = {
        "id": placement["acl"],
        "acl_type": "extended",
        "action": action,
        "protocol": protocol,
        "src": object_ir(src),
        "dst": object_ir(dst),
        "dst_port": None if port is None else {"op": "eq", "port": port},
        "device": DEVICE,
        "apply": {
            "interface": placement["interface"],
            "direction": placement["direction"],
        },
        "sequence": seq,
        "log": False,
    }

    return {
        "id": f"{intent_prefix}_{idx:03d}",
        "description": description,
        "context_file": CONTEXT_FILE,
        "nl_query": nl_query,
        "expected_ir": {
            "rules": [rule],
            "metadata": {
                "raw_policy": f"{action.title()} {src} to {dst} on {service_name}",
                "warnings": [],
            },
        },
        "expected_cli": expected_cli,
    }


# =========================================================
# PARAPHRASE GENERATION
# =========================================================

def paraphrase_variants(intent: dict, count: int, rng: random.Random) -> list[dict]:
    """
    Create extra intents with same semantics, different NL phrasing.
    """
    rule = intent["expected_ir"]["rules"][0]
    src = rule["src"]["object"]
    dst = rule["dst"]["object"]
    action = rule["action"]
    protocol = rule["protocol"]

    # recover service name
    service_name = "ANY"
    for svc_name, svc in SERVICES.items():
        if svc["protocol"] == protocol:
            if svc["port"] is None and rule["dst_port"] is None:
                if svc_name in {"ANY", "ICMP"}:
                    # choose exact one later
                    pass
            elif rule["dst_port"] is not None and svc["port"] == rule["dst_port"]["port"]:
                service_name = svc_name

    if protocol == "icmp":
        service_name = "ICMP"
    elif protocol == "ip":
        service_name = "ANY"

    direction = rule["apply"]["direction"]
    direction_style = "egress" if direction == "out" else "neutral"

    variants = []
    seen_queries = {intent["nl_query"]}

    base_id = intent["id"]
    for i in range(1, count + 1):
        for _ in range(20):
            nl = make_nl_query(src, dst, service_name, action, rng, direction_style)
            if nl not in seen_queries:
                seen_queries.add(nl)
                new_intent = deepcopy(intent)
                new_intent["id"] = f"{base_id}_p{i}"
                new_intent["nl_query"] = nl
                new_intent["description"] = f"{intent['description']} (paraphrase {i})"
                variants.append(new_intent)
                break

    return variants


# =========================================================
# DATASET GENERATORS
# =========================================================

def enumerate_candidates():
    for src in OBJECTS:
        for dst in OBJECTS:
            for service_name in SERVICES:
                for action in ("permit", "deny"):
                    if valid_combo(src, dst, service_name, action):
                        yield src, dst, service_name, action


def generate_in_dataset(limit: int = 100, seed: int = 7, paraphrases_per_intent: int = 0) -> list[dict]:
    rng = random.Random(seed)
    candidates = list(enumerate_candidates())
    rng.shuffle(candidates)

    dataset = []
    used = set()
    idx = 1

    for src, dst, service_name, action in candidates:
        sig = ("in", src, dst, service_name, action)
        if sig in used:
            continue
        used.add(sig)

        placement = choose_in_placement(src)
        intent = build_intent(
            idx=idx,
            src=src,
            dst=dst,
            service_name=service_name,
            action=action,
            placement=placement,
            rng=rng,
            direction_style="neutral",
            intent_prefix="in",
        )
        dataset.append(intent)

        if paraphrases_per_intent > 0:
            dataset.extend(paraphrase_variants(intent, paraphrases_per_intent, rng))

        idx += 1
        if len([x for x in dataset if not x["id"].endswith(tuple(f"_p{i}" for i in range(1, paraphrases_per_intent + 1)))]) >= limit:
            break

    return dataset


def generate_out_dataset(limit: int = 100, seed: int = 11, paraphrases_per_intent: int = 0) -> list[dict]:
    rng = random.Random(seed)
    candidates = list(enumerate_candidates())
    rng.shuffle(candidates)

    dataset = []
    used = set()
    idx = 1

    for src, dst, service_name, action in candidates:
        sig = ("out", src, dst, service_name, action)
        if sig in used:
            continue
        used.add(sig)

        placement = choose_out_placement(dst)
        intent = build_intent(
            idx=idx,
            src=src,
            dst=dst,
            service_name=service_name,
            action=action,
            placement=placement,
            rng=rng,
            direction_style="egress",
            intent_prefix="out",
        )
        dataset.append(intent)

        if paraphrases_per_intent > 0:
            dataset.extend(paraphrase_variants(intent, paraphrases_per_intent, rng))

        idx += 1
        if len([x for x in dataset if not x["id"].endswith(tuple(f"_p{i}" for i in range(1, paraphrases_per_intent + 1)))]) >= limit:
            break

    return dataset


def generate_mixed_dataset(limit: int = 100, seed: int = 21, paraphrases_per_intent: int = 0) -> list[dict]:
    rng = random.Random(seed)
    mode_rng = random.Random(seed + 1000)
    candidates = list(enumerate_candidates())
    rng.shuffle(candidates)

    dataset = []
    used = set()
    idx = 1

    for src, dst, service_name, action in candidates:
        placement = choose_mixed_placement(src, dst, mode_rng)
        sig = (placement["direction"], placement["interface"], src, dst, service_name, action)
        if sig in used:
            continue
        used.add(sig)

        direction_style = "egress" if placement["direction"] == "out" else "neutral"
        intent = build_intent(
            idx=idx,
            src=src,
            dst=dst,
            service_name=service_name,
            action=action,
            placement=placement,
            rng=rng,
            direction_style=direction_style,
            intent_prefix="mix",
        )
        dataset.append(intent)

        if paraphrases_per_intent > 0:
            dataset.extend(paraphrase_variants(intent, paraphrases_per_intent, rng))

        idx += 1
        if len([x for x in dataset if not x["id"].endswith(tuple(f"_p{i}" for i in range(1, paraphrases_per_intent + 1)))]) >= limit:
            break

    return dataset


# =========================================================
# EXPORT
# =========================================================

def save_json(data: list[dict], path: str | Path) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def save_jsonl(data: list[dict], path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")


def split_base_and_paraphrases(data: list[dict]) -> tuple[list[dict], list[dict]]:
    base = []
    paras = []
    for item in data:
        if "_p" in item["id"]:
            paras.append(item)
        else:
            base.append(item)
    return base, paras


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    OUTPUT_DIR = Path("acl_generated_datasets")
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Change these as needed
    BASE_COUNT = 60
    PARAPHRASES_PER_INTENT = 3

    in_data = generate_in_dataset(limit=BASE_COUNT, seed=7, paraphrases_per_intent=PARAPHRASES_PER_INTENT)
    out_data = generate_out_dataset(limit=BASE_COUNT, seed=11, paraphrases_per_intent=PARAPHRASES_PER_INTENT)
    mixed_data = generate_mixed_dataset(limit=BASE_COUNT, seed=21, paraphrases_per_intent=PARAPHRASES_PER_INTENT)

    save_json(in_data, OUTPUT_DIR / "intents_in.json")
    save_json(out_data, OUTPUT_DIR / "intents_out.json")
    save_json(mixed_data, OUTPUT_DIR / "intents_mixed.json")

    save_jsonl(in_data, OUTPUT_DIR / "intents_in.jsonl")
    save_jsonl(out_data, OUTPUT_DIR / "intents_out.jsonl")
    save_jsonl(mixed_data, OUTPUT_DIR / "intents_mixed.jsonl")

    in_base, in_para = split_base_and_paraphrases(in_data)
    out_base, out_para = split_base_and_paraphrases(out_data)
    mixed_base, mixed_para = split_base_and_paraphrases(mixed_data)

    save_json(in_base, OUTPUT_DIR / "intents_in_base.json")
    save_json(in_para, OUTPUT_DIR / "intents_in_paraphrases.json")
    save_json(out_base, OUTPUT_DIR / "intents_out_base.json")
    save_json(out_para, OUTPUT_DIR / "intents_out_paraphrases.json")
    save_json(mixed_base, OUTPUT_DIR / "intents_mixed_base.json")
    save_json(mixed_para, OUTPUT_DIR / "intents_mixed_paraphrases.json")

    print("Generated files:")
    for p in sorted(OUTPUT_DIR.glob("*")):
        print(" -", p)

    # Example semantic signature
    if mixed_base:
        print("\nExample semantic signature:")
        print(json.dumps(semantic_signature(mixed_base[0]), indent=2))