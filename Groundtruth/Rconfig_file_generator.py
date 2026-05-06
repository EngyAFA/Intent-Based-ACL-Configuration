import json
import os
from collections import defaultdict


def wildcard_to_acl_addr(ip, wildcard):
    """
    Convert IR source/destination fields into Cisco ACL address syntax.
    Examples:
      ip='any'                  -> 'any'
      ip='192.168.10.10', wc=0  -> 'host 192.168.10.10'
      ip='192.168.10.0', wc=.255 -> '192.168.10.0 0.0.0.255'
    """
    if ip is None:
        return "any"

    ip_str = str(ip).strip().lower()
    if ip_str == "any":
        return "any"

    if wildcard in (None, "", "0.0.0.0"):
        return f"host {ip}"

    return f"{ip} {wildcard}"


def build_acl_rule_line(rule):
    """
    Build one ACL sequence line from expected_ir rule.
    Example:
      10 permit tcp host 1.1.1.1 host 2.2.2.2 eq 22
    """
    seq = rule.get("sequence")
    action = rule.get("action", "").lower()
    protocol = rule.get("protocol", "").lower()

    src = rule.get("src", {}) or {}
    dst = rule.get("dst", {}) or {}

    src_addr = wildcard_to_acl_addr(src.get("ip"), src.get("wildcard"))
    dst_addr = wildcard_to_acl_addr(dst.get("ip"), dst.get("wildcard"))

    line = f"{seq} {action} {protocol} {src_addr} {dst_addr}"

    dst_port = rule.get("dst_port")
    if dst_port:
        op = dst_port.get("op")
        port = dst_port.get("port")
        if op and port is not None:
            line += f" {op} {port}"

    if rule.get("log"):
        line += " log"

    return line.strip()


def generate_router_configs(intents, output_dir="router_configs"):
    """
    Create one config file per router using expected_ir field.
    
    Inputs:
      intents: list of dicts loaded from GT JSON
      output_dir: folder where config files will be written

    Output:
      writes files like:
        router_configs/R1.cfg
        router_configs/R2.cfg
        router_configs/R3.cfg

    Dedup behavior:
      - deduplicates paraphrases
      - merges rules under same ACL
      - adds interface binding only once
    """
    os.makedirs(output_dir, exist_ok=True)

    # router -> acl_name -> {"type": "...", "rules": set(), "rule_map": {seq: line}}
    router_acls = defaultdict(lambda: defaultdict(lambda: {
        "acl_type": "extended",
        "rule_map": {}
    }))

    # router -> set of (interface, acl_name, direction)
    router_bindings = defaultdict(set)

    for item in intents:
        expected_ir = item.get("expected_ir", {})
        rules = expected_ir.get("rules", [])

        for rule in rules:
            router = rule.get("device")
            acl_name = rule.get("id")
            acl_type = rule.get("acl_type", "extended")
            apply_info = rule.get("apply", {}) or {}
            interface = apply_info.get("interface")
            direction = apply_info.get("direction")

            if not router or not acl_name:
                continue

            acl_line = build_acl_rule_line(rule)

            router_acls[router][acl_name]["acl_type"] = acl_type
            router_acls[router][acl_name]["rule_map"][rule.get("sequence")] = acl_line

            if interface and direction:
                router_bindings[router].add((interface, acl_name, direction))

    written_files = []

    for router in sorted(router_acls.keys()):
        lines = []

        # Write ACL sections
        for acl_name in sorted(router_acls[router].keys()):
            acl_info = router_acls[router][acl_name]
            acl_type = acl_info["acl_type"]
            rule_map = acl_info["rule_map"]

            lines.append(f"ip access-list {acl_type} {acl_name}")
            for seq in sorted(rule_map.keys()):
                lines.append(f" {rule_map[seq]}")
            lines.append("!")

        # Write interface bindings
        for interface, acl_name, direction in sorted(router_bindings[router]):
            lines.append(f"interface {interface}")
            lines.append(f" ip access-group {acl_name} {direction}")
            lines.append("!")

        config_text = "\n".join(lines).rstrip() + "\n"

        file_path = os.path.join(output_dir, f"{router}.cfg")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(config_text)

        written_files.append(file_path)

    return written_files


# Example usage
if __name__ == "__main__":
    with open("Multirouter_generated/multirouter_intents_mixed.json", "r", encoding="utf-8") as f:
        intents = json.load(f)

    files = generate_router_configs(intents, output_dir="router_configs")
    print("Created files:")
    for fp in files:
        print(" -", fp)