import json
import os
import copy
import random
import ipaddress
from typing import Dict, Any, List, Optional, Tuple

#
# Expected functions already available from the current script:
# - parse_router_config
# - load_topology_context
# - create_single_benchmark_case
# - load_ground_truth_cases
# - load_router_configs_from_folder
# - norm_device            (optional; if absent, local fallback is used)
# - norm_interface         (optional; if absent, local fallback is used)
# - network_obj
# - rule_traffic_overlaps
# - is_duplicate
#
# If the current file is ConflictDetectionGT.py, use:
#
# from ConflictDetectionGT import (
#     parse_router_config,
#     load_topology_context,
#     create_single_benchmark_case,
#     load_ground_truth_cases,
#     load_router_configs_from_folder,
#     network_obj,
#     rule_traffic_overlaps,
#     is_duplicate,
# )
#
# ------------------------------------------------------------
# for Rule Conflict Detection Module call create_single_benchmark_case

from RuleConflict import (
    ACLRule,
    ConflictResult,
    NetworkTopology,
    parse_router_config,
    normalize_interface_name,
    rules_equivalent,
    rule_overlap,
    detect_conflicts,
)


# ============================================================
# Local safe helpers
# ============================================================


# Compute metrics Use standard classification metrics.
def norm_device(x: Optional[str]) -> str:
    if not x:
        return ""
    s = str(x).strip().lower()
    aliases = {
        "router1": "r1",
        "router2": "r2",
        "router3": "r3",
    }
    return aliases.get(s, s)


def norm_interface(if_name: Optional[str]) -> str:
    if not if_name:
        return ""
    s = str(if_name).strip().lower()

    aliases = {
        "fa": "fastethernet",
        "f": "fastethernet",
        "gi": "gigabitethernet",
        "g": "gigabitethernet",
        "se": "serial",
        "s": "serial",
        "eth": "ethernet",
    }

    for short, full in aliases.items():
        if s.startswith(short) and not s.startswith(full):
            rest = s[len(short):]
            if rest and rest[0].isdigit():
                return full + rest
    return s


def network_obj(net: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(net, strict=False)


def protocol_overlap(p1: str, p2: str) -> bool:
    return p1 == p2 or p1 == "ip" or p2 == "ip"


def networks_overlap(net1: str, net2: str) -> bool:
    return network_obj(net1).overlaps(network_obj(net2))


def port_sets_overlap(op1, port1, op2, port2) -> bool:
    if port1 is None or port2 is None:
        return True

    if op1 == "eq" and op2 == "eq":
        return port1 == port2

    if op1 == "range" and op2 == "eq":
        return port1[0] <= port2 <= port1[1]

    if op1 == "eq" and op2 == "range":
        return port2[0] <= port1 <= port2[1]

    if op1 == "range" and op2 == "range":
        return not (port1[1] < port2[0] or port2[1] < port1[0])

    return True


def rule_traffic_overlaps(rule_a: Dict[str, Any], rule_b: Dict[str, Any]) -> bool:
    return (
        protocol_overlap(rule_a["protocol"], rule_b["protocol"])
        and networks_overlap(rule_a["src_ip"], rule_b["src_ip"])
        and networks_overlap(rule_a["dst_ip"], rule_b["dst_ip"])
        and port_sets_overlap(
            rule_a.get("dst_port_op"), rule_a.get("dst_port"),
            rule_b.get("dst_port_op"), rule_b.get("dst_port")
        )
    )


def ports_equal(op1, port1, op2, port2) -> bool:
    return op1 == op2 and port1 == port2


def is_duplicate(candidate: Dict[str, Any], existing: Dict[str, Any]) -> bool:
    return (
        candidate["action"] == existing["action"]
        and candidate["protocol"] == existing["protocol"]
        and candidate["src_ip"] == existing["src_ip"]
        and candidate["dst_ip"] == existing["dst_ip"]
        and ports_equal(
            candidate.get("dst_port_op"), candidate.get("dst_port"),
            existing.get("dst_port_op"), existing.get("dst_port"),
        )
    )


def find_target_acl_and_rules(
    rule: Dict[str, Any],
    parsed_router_config: Dict[str, Any]
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    key = (norm_interface(rule["interface"]), rule["direction"].lower())
    target_acl = parsed_router_config["bindings"].get(key)
    existing_rules = parsed_router_config["acls"].get(target_acl, []) if target_acl else []
    return target_acl, existing_rules


def gt_rule_to_candidate(gt_case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build candidate rule directly from GT expected_ir.
    Similar purpose to extract_gt_rule(), but self-contained for synthetic generation.
    """
    rule = gt_case["expected_ir"]["rules"][0]

    src = rule.get("src", {}) or {}
    dst = rule.get("dst", {}) or {}
    dst_port = rule.get("dst_port", {}) or {}
    apply = rule.get("apply", {}) or {}

    def normalize_ip_to_cidr(ip_str: str, wildcard: Optional[str] = None) -> str:
        if ip_str is None:
            raise ValueError("ip_str is None")

        ip_str = ip_str.strip()

        if "/" in ip_str:
            return str(ipaddress.ip_network(ip_str, strict=False))

        if wildcard is None:
            return str(ipaddress.ip_network(f"{ip_str}/32", strict=False))

        wildcard = wildcard.strip()
        wildcard_ip = ipaddress.IPv4Address(wildcard)
        netmask_int = (~int(wildcard_ip)) & 0xFFFFFFFF
        netmask_str = str(ipaddress.IPv4Address(netmask_int))
        return str(ipaddress.ip_network(f"{ip_str}/{netmask_str}", strict=False))

    src_ip = normalize_ip_to_cidr(src.get("ip"), src.get("wildcard"))
    dst_ip = normalize_ip_to_cidr(dst.get("ip"), dst.get("wildcard"))

    return {
        "case_id": gt_case["id"],
        "description": gt_case.get("description", ""),
        "context_file": gt_case.get("context_file"),
        "nl_query": gt_case.get("nl_query"),
        "device": norm_device(rule["device"]),
        "interface": norm_interface(apply.get("interface", "")),
        "direction": apply.get("direction", "").lower(),
        "action": rule["action"].lower(),
        "protocol": rule["protocol"].lower(),
        "src_ip": str(ipaddress.ip_network(src_ip, strict=False)),
        "dst_ip": str(ipaddress.ip_network(dst_ip, strict=False)),
        "dst_port_op": dst_port.get("op"),
        "dst_port": dst_port.get("port"),
        "sequence": rule.get("sequence"),
        "rule_id": rule.get("id"),
        "src_object": src.get("object"),
        "dst_object": dst.get("object"),
    }


def candidate_to_gt_like_case(candidate: Dict[str, Any], source_gt_case: Dict[str, Any], synthetic_id: str) -> Dict[str, Any]:
    """
    Converts a synthetic candidate back into the mini GT-like schema expected by create_single_benchmark_case().
    """
    def cidr_to_ip_wildcard(cidr: str) -> Tuple[str, str]:
        net = ipaddress.ip_network(cidr, strict=False)
        ip_str = str(net.network_address)
        wildcard_int = (~int(net.netmask)) & 0xFFFFFFFF
        wildcard = str(ipaddress.IPv4Address(wildcard_int))
        return ip_str, wildcard

    src_ip, src_wc = cidr_to_ip_wildcard(candidate["src_ip"])
    dst_ip, dst_wc = cidr_to_ip_wildcard(candidate["dst_ip"])

    return {
        "id": synthetic_id,
        "description": f"SYNTHETIC from {source_gt_case.get('id')}",
        "context_file": source_gt_case.get("context_file"),
        "nl_query": source_gt_case.get("nl_query"),
        "expected_ir": {
            "rules": [
                {
                    "id": synthetic_id,
                    "device": candidate["device"],
                    "action": candidate["action"],
                    "protocol": candidate["protocol"],
                    "sequence": candidate.get("sequence"),
                    "src": {
                        "ip": src_ip,
                        "wildcard": src_wc,
                        "object": candidate.get("src_object"),
                    },
                    "dst": {
                        "ip": dst_ip,
                        "wildcard": dst_wc,
                        "object": candidate.get("dst_object"),
                    },
                    "dst_port": {
                        "op": candidate.get("dst_port_op"),
                        "port": candidate.get("dst_port"),
                    } if candidate.get("dst_port") is not None else {},
                    "apply": {
                        "interface": candidate["interface"],
                        "direction": candidate["direction"],
                    }
                }
            ]
        }
    }


# ============================================================
# Candidate generators
# ============================================================

def clone_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    return copy.deepcopy(rule)


def flip_action(action: str) -> str:
    return "deny" if action == "permit" else "permit"


def set_host_dst(candidate: Dict[str, Any], host_ip: str) -> Dict[str, Any]:
    c = clone_rule(candidate)
    c["dst_ip"] = f"{host_ip}/32"
    return c


def set_host_src(candidate: Dict[str, Any], host_ip: str) -> Dict[str, Any]:
    c = clone_rule(candidate)
    c["src_ip"] = f"{host_ip}/32"
    return c


def set_protocol(candidate: Dict[str, Any], protocol: str) -> Dict[str, Any]:
    c = clone_rule(candidate)
    c["protocol"] = protocol
    if protocol not in {"tcp", "udp"}:
        c["dst_port_op"] = None
        c["dst_port"] = None
    return c


def set_port(candidate: Dict[str, Any], port: Optional[int]) -> Dict[str, Any]:
    c = clone_rule(candidate)
    if port is None:
        c["dst_port_op"] = None
        c["dst_port"] = None
    else:
        c["dst_port_op"] = "eq"
        c["dst_port"] = int(port)
    return c

# Generation part : creates synthetic rules:

# generate_duplicate_candidates(...)
# generate_conflict_candidates(...)
# generate_valid_candidates(...)


def generate_duplicate_candidates(base_rule: Dict[str, Any], existing_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []

    # Use exact GT/base rule
    out.append(clone_rule(base_rule))

    # Also use exact existing rules from same ACL, in case GT is not already exact
    for r in existing_rules[:]:
        candidate = clone_rule(base_rule)
        candidate["action"] = r["action"]
        candidate["protocol"] = r["protocol"]
        candidate["src_ip"] = r["src_ip"]
        candidate["dst_ip"] = r["dst_ip"]
        candidate["dst_port_op"] = r.get("dst_port_op")
        candidate["dst_port"] = r.get("dst_port")
        out.append(candidate)

    return out


def generate_conflict_candidates(base_rule: Dict[str, Any], existing_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []

    # Strategy 1: flip exact existing rules
    for r in existing_rules:
        candidate = clone_rule(base_rule)
        candidate["action"] = flip_action(r["action"])
        candidate["protocol"] = r["protocol"]
        candidate["src_ip"] = r["src_ip"]
        candidate["dst_ip"] = r["dst_ip"]
        candidate["dst_port_op"] = r.get("dst_port_op")
        candidate["dst_port"] = r.get("dst_port")
        out.append(candidate)

    # Strategy 2: keep base traffic, flip base action
    c = clone_rule(base_rule)
    c["action"] = flip_action(c["action"])
    out.append(c)

    # Strategy 3: target sub-traffic of existing rule with opposite action
    for r in existing_rules:
        candidate = clone_rule(base_rule)
        candidate["action"] = flip_action(r["action"])
        candidate["protocol"] = r["protocol"]

        # make narrower host-like versions to increase overlap probability
        src_net = ipaddress.ip_network(r["src_ip"], strict=False)
        dst_net = ipaddress.ip_network(r["dst_ip"], strict=False)

        candidate["src_ip"] = f"{src_net.network_address}/32" if src_net.prefixlen < 32 else r["src_ip"]
        candidate["dst_ip"] = f"{dst_net.network_address}/32" if dst_net.prefixlen < 32 else r["dst_ip"]
        candidate["dst_port_op"] = r.get("dst_port_op")
        candidate["dst_port"] = r.get("dst_port")
        out.append(candidate)

    return out


def candidate_conflicts_with_existing(candidate: Dict[str, Any], existing_rules: List[Dict[str, Any]]) -> bool:
    for r in existing_rules:
        if candidate["action"] != r["action"] and rule_traffic_overlaps(candidate, r):
            return True
    return False


def candidate_duplicates_existing(candidate: Dict[str, Any], existing_rules: List[Dict[str, Any]]) -> bool:
    for r in existing_rules:
        if is_duplicate(candidate, r):
            return True
    return False


def generate_valid_candidates(base_rule: Dict[str, Any], existing_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []

    # deterministic pool of "safe-ish" destinations/ports to try
    test_dst_hosts = [
        "192.168.10.250",
        "192.168.20.250",
        "192.168.30.250",
        "198.51.100.10",
        "198.51.100.20",
        "198.51.100.30",
    ]
    test_src_hosts = [
        "192.168.10.250",
        "192.168.20.250",
        "192.168.30.250",
        "198.51.100.40",
        "198.51.100.50",
    ]
    test_ports = [21, 25, 81, 110, 123, 161, 389, 8080, 8443]
    test_protocols = ["tcp", "udp", "icmp"]

    # Mutate destination only
    for host in test_dst_hosts:
        out.append(set_host_dst(base_rule, host))

    # Mutate source only
    for host in test_src_hosts:
        out.append(set_host_src(base_rule, host))

    # Mutate port
    for p in test_ports:
        c = clone_rule(base_rule)
        if c["protocol"] in {"tcp", "udp"}:
            out.append(set_port(c, p))

    # Mutate protocol
    for proto in test_protocols:
        out.append(set_protocol(base_rule, proto))

    # Combined mutations
    for host in test_dst_hosts:
        for p in test_ports[:4]:
            c = set_host_dst(base_rule, host)
            if c["protocol"] in {"tcp", "udp"}:
                c = set_port(c, p)
            out.append(c)

    # Remove trivial invalids and prefer ones that do not even raw-overlap
    dedup = []
    seen = set()
    for c in out:
        sig = (
            c["action"], c["protocol"], c["src_ip"], c["dst_ip"],
            c.get("dst_port_op"), json.dumps(c.get("dst_port"), sort_keys=True) if isinstance(c.get("dst_port"), dict) else str(c.get("dst_port"))
        )
        if sig not in seen:
            seen.add(sig)
            dedup.append(c)

    # Prefer candidates with no duplicate and no raw opposite overlap
    preferred = []
    fallback = []
    for c in dedup:
        if candidate_duplicates_existing(c, existing_rules):
            continue
        if candidate_conflicts_with_existing(c, existing_rules):
            fallback.append(c)
        else:
            preferred.append(c)

    return preferred + fallback


# ============================================================
# Verification loop
# ============================================================

def verify_candidate_label(
    candidate: Dict[str, Any],
    source_gt_case: Dict[str, Any],
    parsed_router_config: Dict[str, Any],
    topology_model: Optional[Dict[str, Any]],
    synthetic_id: str,
) -> Dict[str, Any]:
    synthetic_case = candidate_to_gt_like_case(candidate, source_gt_case, synthetic_id)
    result = create_single_benchmark_case(
        gt_case=synthetic_case,
        parsed_router_config=parsed_router_config,
        topology_model=topology_model,
    )
    return result



# Filtering to ensures:
# duplicate cases are truly duplicates
# conflict cases are truly conflicts
# valid cases are truly valid

def choose_verified_candidate(
    desired_label: str,
    candidate_pool: List[Dict[str, Any]],
    source_gt_case: Dict[str, Any],
    parsed_router_config: Dict[str, Any],
    topology_model: Optional[Dict[str, Any]],
    synthetic_id_prefix: str,
) -> Optional[Dict[str, Any]]:
    for idx, candidate in enumerate(candidate_pool, start=1):
        verified = verify_candidate_label(
            candidate=candidate,
            source_gt_case=source_gt_case,
            parsed_router_config=parsed_router_config,
            topology_model=topology_model,
            synthetic_id=f"{synthetic_id_prefix}_{idx}",
        )
        if verified["expected_label"] == desired_label:
            return verified
    return None


# ============================================================
# Main benchmark builder
# ============================================================

def build_balanced_synthetic_benchmark(
    gt_json_path: str,
    config_folder: str,
    context_path: Optional[str] = None,
    per_class_target: int = 150,
    seed: int = 42,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    random.seed(seed)

    gt_cases = load_ground_truth_cases(gt_json_path)
    parsed_router_configs = load_router_configs_from_folder(config_folder)
    topology_model = load_topology_context(context_path) if context_path else None

    gt_cases = gt_cases[:]
    random.shuffle(gt_cases)

    collected = {
        "duplicate": [],
        "conflict": [],
        "valid": [],
    }
    skipped = []

    for gt_case in gt_cases:
        # stop if balanced target reached
        if all(len(collected[k]) >= per_class_target for k in collected):
            break

        try:
            base_rule = gt_rule_to_candidate(gt_case)
            device = norm_device(base_rule["device"])

            if device not in parsed_router_configs:
                skipped.append({
                    "source_gt_case_id": gt_case.get("id"),
                    "reason": f"Missing parsed router config for device '{device}'",
                })
                continue

            parsed_router_config = parsed_router_configs[device]
            _, existing_rules = find_target_acl_and_rules(base_rule, parsed_router_config)

            if not existing_rules:
                skipped.append({
                    "source_gt_case_id": gt_case.get("id"),
                    "reason": "No existing rules found for target ACL",
                })
                continue

            # DUPLICATE
            if len(collected["duplicate"]) < per_class_target:
                pool = generate_duplicate_candidates(base_rule, existing_rules)
                verified = choose_verified_candidate(
                    desired_label="duplicate",
                    candidate_pool=pool,
                    source_gt_case=gt_case,
                    parsed_router_config=parsed_router_config,
                    topology_model=topology_model,
                    synthetic_id_prefix=f"{gt_case['id']}_dup",
                )
                if verified is not None:
                    verified["synthetic_target_class"] = "duplicate"
                    verified["source_gt_case_id"] = gt_case["id"]
                    collected["duplicate"].append(verified)

            # CONFLICT
            if len(collected["conflict"]) < per_class_target:
                pool = generate_conflict_candidates(base_rule, existing_rules)
                verified = choose_verified_candidate(
                    desired_label="conflict",
                    candidate_pool=pool,
                    source_gt_case=gt_case,
                    parsed_router_config=parsed_router_config,
                    topology_model=topology_model,
                    synthetic_id_prefix=f"{gt_case['id']}_conf",
                )
                if verified is not None:
                    verified["synthetic_target_class"] = "conflict"
                    verified["source_gt_case_id"] = gt_case["id"]
                    collected["conflict"].append(verified)

            # VALID
            if len(collected["valid"]) < per_class_target:
                pool = generate_valid_candidates(base_rule, existing_rules)
                verified = choose_verified_candidate(
                    desired_label="valid",
                    candidate_pool=pool,
                    source_gt_case=gt_case,
                    parsed_router_config=parsed_router_config,
                    topology_model=topology_model,
                    synthetic_id_prefix=f"{gt_case['id']}_val",
                )
                if verified is not None:
                    verified["synthetic_target_class"] = "valid"
                    verified["source_gt_case_id"] = gt_case["id"]
                    collected["valid"].append(verified)

        except Exception as e:
            skipped.append({
                "source_gt_case_id": gt_case.get("id"),
                "reason": str(e),
            })

    benchmark = (
        collected["duplicate"][:per_class_target]
        + collected["conflict"][:per_class_target]
        + collected["valid"][:per_class_target]
    )

    summary = {
        "requested_per_class": per_class_target,
        "generated_total": len(benchmark),
        "class_counts": {
            "duplicate": len(collected["duplicate"][:per_class_target]),
            "conflict": len(collected["conflict"][:per_class_target]),
            "valid": len(collected["valid"][:per_class_target]),
        },
        "source_gt_cases": len(gt_cases),
        "skipped_cases": len(skipped),
        "seed": seed,
    }

    result = {
        "SyntheticConflictBenchmark": benchmark,
        "summary": summary,
        "skipped": skipped,
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    gt_json_path = "./Multirouter_generated/multirouter_intents_mixed.json"
    config_folder = "./Multirouter_generated/router_configs"
    context_path = "./multirouter_topology.json"
    output_path = "synthetic_acl_conflict_benchmark.json"

    result = build_balanced_synthetic_benchmark(
        gt_json_path=gt_json_path,
        config_folder=config_folder,
        context_path=context_path,
        per_class_target=150,
        seed=42,
        output_path=output_path,
    )

    print("Synthetic benchmark generation complete.")
    print(json.dumps(result["summary"], indent=2))