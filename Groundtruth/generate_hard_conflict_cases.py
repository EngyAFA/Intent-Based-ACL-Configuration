import json
import random
import ipaddress
from pathlib import Path
from typing import Dict, Tuple, List, Any, Optional

from RuleConflict import (
    ACLRule,
    ConflictResult,
    NetworkTopology,
    parse_router_config,
    normalize_interface_name,
    detect_conflicts,
    fully_covers,
)


# ============================================================
# Helpers
# ============================================================

def flip_action(action: str) -> str:
    return "deny" if str(action).lower() == "permit" else "permit"


def norm_router(x: str) -> str:
    return str(x).strip().upper()


def rule_signature(rule: ACLRule) -> Tuple:
    return (
        norm_router(rule.router),
        normalize_interface_name(rule.interface),
        rule.direction.lower(),
        rule.action.lower(),
        rule.protocol.lower(),
        rule.src,
        rule.dst,
        rule.src_port,
        rule.dst_port,
    )


def aclrule_to_input_rule(rule: ACLRule) -> Dict[str, Any]:
    return {
        "action": rule.action,
        "protocol": rule.protocol,
        "src_ip": rule.src,
        "dst_ip": rule.dst,
        "dst_port": rule.dst_port,
        "interface": rule.interface,
        "direction": rule.direction,
        "sequence": rule.sequence,
    }


def aclrule_to_existing_dict(rule: ACLRule) -> Dict[str, Any]:
    return {
        "router": rule.router,
        "interface": rule.interface,
        "direction": rule.direction,
        "acl_name": rule.acl_name,
        "sequence": rule.sequence,
        "action": rule.action,
        "protocol": rule.protocol,
        "src": rule.src,
        "dst": rule.dst,
        "dst_port": rule.dst_port,
        "raw_line": rule.raw_line,
    }


# ============================================================
# Local duplicate / overlap / classification
# ============================================================

def rules_equivalent_local(r1: ACLRule, r2: ACLRule) -> bool:
    return (
        r1.action.lower() == r2.action.lower()
        and r1.protocol.lower() == r2.protocol.lower()
        and ipaddress.ip_network(r1.src, strict=False) == ipaddress.ip_network(r2.src, strict=False)
        and ipaddress.ip_network(r1.dst, strict=False) == ipaddress.ip_network(r2.dst, strict=False)
        and r1.src_port == r2.src_port
        and r1.dst_port == r2.dst_port
    )


def protocol_overlap_local(p1: str, p2: str) -> bool:
    p1 = p1.lower()
    p2 = p2.lower()
    return p1 == p2 or p1 == "ip" or p2 == "ip"


def rule_overlap_local(r1: ACLRule, r2: ACLRule) -> bool:
    if not protocol_overlap_local(r1.protocol, r2.protocol):
        return False

    if not ipaddress.ip_network(r1.src, strict=False).overlaps(ipaddress.ip_network(r2.src, strict=False)):
        return False

    if not ipaddress.ip_network(r1.dst, strict=False).overlaps(ipaddress.ip_network(r2.dst, strict=False)):
        return False

    # Port logic
    if r1.protocol in {"tcp", "udp"} or r2.protocol in {"tcp", "udp"}:
        if r1.dst_port is not None and r2.dst_port is not None and r1.dst_port != r2.dst_port:
            return False

    return True


def detect_duplicate_local(
    new_rule: ACLRule,
    all_existing: Dict[Tuple[str, str, str], List[ACLRule]]
) -> Optional[ACLRule]:
    key = (
        norm_router(new_rule.router),
        normalize_interface_name(new_rule.interface),
        new_rule.direction.lower(),
    )
    existing_rules = all_existing.get(key, [])

    for er in existing_rules:
        if rules_equivalent_local(new_rule, er):
            return er
    return None


def detect_conflicts_naive_local(
    new_rule: ACLRule,
    all_existing: Dict[Tuple[str, str, str], List[ACLRule]]
) -> List[ConflictResult]:
    key = (
        norm_router(new_rule.router),
        normalize_interface_name(new_rule.interface),
        new_rule.direction.lower(),
    )
    existing_rules = all_existing.get(key, [])
    results = []

    for er in existing_rules:
        if new_rule.action.lower() == er.action.lower():
            continue
        if not rule_overlap_local(new_rule, er):
            continue

        results.append(
            ConflictResult(
                new_rule=new_rule,
                existing_rule=er,
                overlap_src=str(
                    ipaddress.ip_network(new_rule.src, strict=False)
                    if ipaddress.ip_network(new_rule.src, strict=False).subnet_of(ipaddress.ip_network(er.src, strict=False))
                    else ipaddress.ip_network(er.src, strict=False)
                ),
                overlap_dst=str(
                    ipaddress.ip_network(new_rule.dst, strict=False)
                    if ipaddress.ip_network(new_rule.dst, strict=False).subnet_of(ipaddress.ip_network(er.dst, strict=False))
                    else ipaddress.ip_network(er.dst, strict=False)
                ),
                overlap_protocol=new_rule.protocol if new_rule.protocol != "ip" else er.protocol,
                overlap_dst_port=new_rule.dst_port if new_rule.dst_port is not None else er.dst_port,
                kind="naive_overlap",
                reason="naive overlap only",
            )
        )

    return results


def classify_naive_local(
    new_rule: ACLRule,
    all_existing: Dict[Tuple[str, str, str], List[ACLRule]],
) -> str:
    dup = detect_duplicate_local(new_rule, all_existing)
    if dup is not None:
        return "duplicate"

    confs = detect_conflicts_naive_local(new_rule, all_existing)
    return "conflict" if confs else "valid"


def classify_pathaware_local(
    new_rule: ACLRule,
    all_existing: Dict[Tuple[str, str, str], List[ACLRule]],
    topo: NetworkTopology,
) -> str:
    dup = detect_duplicate_local(new_rule, all_existing)
    if dup is not None:
        return "duplicate"

    confs = detect_conflicts(new_rule, all_existing, topo)
    return "conflict" if confs else "valid"


# ============================================================
# Load existing ACLs
# ============================================================

def load_all_existing(config_dir: str) -> Dict[Tuple[str, str, str], List[ACLRule]]:
    all_existing = {}
    for router in ["R1", "R2", "R3"]:
        parsed = parse_router_config(router, config_dir=config_dir)
        normalized = {}
        for key, rules in parsed.items():
            r, iface, direction = key
            normalized[(norm_router(r), normalize_interface_name(iface), direction.lower())] = rules
        all_existing.update(normalized)
    return all_existing


# ============================================================
# Shadowed hard cases
# ============================================================

def generate_shadowed_cases(
    all_existing: Dict[Tuple[str, str, str], List[ACLRule]],
    topo: NetworkTopology,
    max_cases: int = 15,
) -> List[Dict[str, Any]]:
    cases = []
    seen = set()

    for key, rules in all_existing.items():
        if len(cases) >= max_cases:
            break

        for idx in range(1, len(rules)):
            later = rules[idx]

            for earlier in rules[:idx]:
                if earlier.action.lower() == later.action.lower():
                    continue
                if not rule_overlap_local(earlier, later):
                    continue

                # Check whether earlier fully covers later's matched traffic
                if not fully_covers(earlier, later.src, later.dst, later.protocol, later.dst_port):
                    continue

                candidate = ACLRule(
                    acl_name=later.acl_name,
                    sequence=9999,
                    action=flip_action(later.action),
                    protocol=later.protocol,
                    src=later.src,
                    dst=later.dst,
                    src_port=later.src_port,
                    dst_port=later.dst_port,
                    router=norm_router(later.router),
                    interface=normalize_interface_name(later.interface),
                    direction=later.direction.lower(),
                    raw_line=None,
                )

                sig = rule_signature(candidate)
                if sig in seen:
                    continue
                seen.add(sig)

                naive_label = classify_naive_local(candidate, all_existing)
                path_label = classify_pathaware_local(candidate, all_existing, topo)

                if naive_label == "conflict" and path_label == "valid":
                    cases.append({
                        "case_id": f"hard_shadow_{len(cases)+1:03d}",
                        "hard_type": "shadowed_conflict",
                        "expected_label": "valid",
                        "naive_prediction_expected": "conflict",
                        "pathaware_prediction_expected": "valid",
                        "device": candidate.router,
                        "target_acl": candidate.acl_name,
                        "target_acl_attachment": {
                            "router": candidate.router,
                            "interface": candidate.interface,
                            "direction": candidate.direction,
                        },
                        "input_rule": aclrule_to_input_rule(candidate),
                        "shadowing_context": {
                            "earlier_rule": aclrule_to_existing_dict(earlier),
                            "later_rule": aclrule_to_existing_dict(later),
                        },
                    })

                    if len(cases) >= max_cases:
                        break

            if len(cases) >= max_cases:
                break

    return cases


# ============================================================
# Off-path hard cases
# ============================================================

def clone_to_new_attachment(base_rule: ACLRule, new_key: Tuple[str, str, str]) -> ACLRule:
    router, iface, direction = new_key
    return ACLRule(
        acl_name=base_rule.acl_name,
        sequence=9999,
        action=flip_action(base_rule.action),
        protocol=base_rule.protocol,
        src=base_rule.src,
        dst=base_rule.dst,
        src_port=base_rule.src_port,
        dst_port=base_rule.dst_port,
        router=norm_router(router),
        interface=normalize_interface_name(iface),
        direction=direction.lower(),
        raw_line=None,
    )


def generate_offpath_cases(
    all_existing: Dict[Tuple[str, str, str], List[ACLRule]],
    topo: NetworkTopology,
    max_cases: int = 15,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    random.seed(seed)
    cases = []
    seen = set()

    attachments = list(all_existing.keys())
    random.shuffle(attachments)

    for src_key in attachments:
        if len(cases) >= max_cases:
            break

        src_rules = all_existing[src_key]
        if not src_rules:
            continue

        for er in src_rules:
            if len(cases) >= max_cases:
                break

            for dst_key in attachments:
                if len(cases) >= max_cases:
                    break

                if dst_key == src_key:
                    continue

                candidate = clone_to_new_attachment(er, dst_key)
                sig = rule_signature(candidate)
                if sig in seen:
                    continue
                seen.add(sig)

                if detect_duplicate_local(candidate, all_existing) is not None:
                    continue

                naive_label = classify_naive_local(candidate, all_existing)
                path_label = classify_pathaware_local(candidate, all_existing, topo)

                if naive_label == "conflict" and path_label == "valid":
                    cases.append({
                        "case_id": f"hard_offpath_{len(cases)+1:03d}",
                        "hard_type": "off_path_conflict",
                        "expected_label": "valid",
                        "naive_prediction_expected": "conflict",
                        "pathaware_prediction_expected": "valid",
                        "device": candidate.router,
                        "target_acl": candidate.acl_name,
                        "target_acl_attachment": {
                            "router": candidate.router,
                            "interface": candidate.interface,
                            "direction": candidate.direction,
                        },
                        "input_rule": aclrule_to_input_rule(candidate),
                        "source_existing_rule": aclrule_to_existing_dict(er),
                    })

                    if len(cases) >= max_cases:
                        break

    return cases


# ============================================================
# Main hard benchmark builder
# ============================================================

def build_hard_cases_benchmark(
    config_dir: str,
    topology_json: str,
    output_path: str,
    shadowed_target: int = 15,
    offpath_target: int = 15,
    seed: int = 42,
) -> Dict[str, Any]:
    with open(topology_json, "r", encoding="utf-8") as f:
        topo_dict = json.load(f)

    topo = NetworkTopology(topo_dict)
    all_existing = load_all_existing(config_dir)

    shadowed_cases = generate_shadowed_cases(
        all_existing=all_existing,
        topo=topo,
        max_cases=shadowed_target,
    )

    offpath_cases = generate_offpath_cases(
        all_existing=all_existing,
        topo=topo,
        max_cases=offpath_target,
        seed=seed,
    )

    benchmark = shadowed_cases + offpath_cases

    result = {
        "HardCasesBenchmark": benchmark,
        "summary": {
            "generated_total": len(benchmark),
            "shadowed_conflict_cases": len(shadowed_cases),
            "off_path_conflict_cases": len(offpath_cases),
            "seed": seed,
        }
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent

    result = build_hard_cases_benchmark(
        config_dir=str(BASE_DIR / "Multirouter_generated" / "router_configs"),
        topology_json=str(BASE_DIR / "multirouter_topology.json"),
        output_path=str(BASE_DIR / "hard_cases_benchmark.json"),
        shadowed_target=15,
        offpath_target=15,
        seed=42,
    )

    print("Hard benchmark generation complete.")
    print(json.dumps(result["summary"], indent=2))