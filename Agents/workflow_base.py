import re
from Helpers.Formats import normalize_interface_name

def validate_acl_generator_inputs(
    action: str,
    protocol: str,
    port,
    src_ip: str,
    dst_ip: str,
    src_subnet: str,
    dst_subnet: str,
    intf_name: str,
    direction: str,
) -> list:
    errors = []

    if action not in {"permit", "deny"}:
        errors.append(f"invalid action: {action!r}")

    if not intf_name:
        errors.append(f"invalid interface: {intf_name!r}")

    if direction not in {"in", "out"}:
        errors.append(f"invalid direction: {direction!r}")

    if (
        port is not None
        and protocol not in {"tcp", "udp"}
    ):
        errors.append(
            "port requires tcp/udp, "
            f"got protocol={protocol!r}, port={port!r}"
        )

    return errors

def build_deploy_commands_q0_aware(
    acl_snippet: str,
    intf_name: str,
    direction: str,
    acl_name: str,
    config_text: str,
    force_rebuild_acl: bool = False,
    include_save: bool = False,

    # Q0-specific optional fields
    q0_mode: bool = False,
    old_acl_name: str = None,
    old_intf_name: str = None,
    old_direction: str = None,
    remove_old_acl_if_renamed: bool = False,
):
    """
    Build minimal CLI commands for GNS3 deployment.

    Supports:
      - normal incremental deploy
      - Q0 placement-fix deploy

    Parameters
    ----------
    acl_snippet : str
        Generated ACL block or ACL ACE lines.

    intf_name : str
        Correct target interface.

    direction : str
        Correct target direction ('in' or 'out').

    acl_name : str
        Correct target ACL name.

    config_text : str
        Current router config BEFORE applying this change.

    force_rebuild_acl : bool
        Rebuild ACL block instead of incremental add. Useful for Q3 reorder.

    include_save : bool
        Append 'write memory'.

    q0_mode : bool
        If True, perform placement-fix logic:
          - remove old attachment if needed
          - optionally remove old ACL if renamed
          - rebuild target ACL if necessary

    old_acl_name : str
        Previous/wrong ACL name before Q0 fix.

    old_intf_name : str
        Previous/wrong interface before Q0 fix.

    old_direction : str
        Previous/wrong direction before Q0 fix.

    remove_old_acl_if_renamed : bool
        If True and old_acl_name != acl_name, send:
            no ip access-list extended OLD_ACL

    Returns
    -------
    list[str]
        Minimal IOS CLI commands.
    """
    if not acl_snippet:
        raise ValueError("acl_snippet is empty")
    if not acl_name:
        raise ValueError("acl_name is empty")
    if not intf_name:
        raise ValueError("intf_name is empty")

    direction = (direction or "").strip().lower()
    if direction not in {"in", "out"}:
        raise ValueError(f"Invalid direction: {direction!r}")

    if old_direction is not None:
        old_direction = old_direction.strip().lower()
        if old_direction not in {"in", "out"}:
            raise ValueError(f"Invalid old_direction: {old_direction!r}")

    norm_target_intf = normalize_interface_name(intf_name)
    norm_old_intf = normalize_interface_name(old_intf_name) if old_intf_name else None

    def _normalize_rule_line(line: str) -> str:
        s = re.sub(r"\s+", " ", line.strip()).lower()
        s = re.sub(r"^\d+\s+", "", s)
        return s

    def _extract_acl_block(text: str, target_acl_name: str) -> str:
        if not text or not target_acl_name:
            return ""
        pat = (
            rf"(?ms)^ip access-list extended {re.escape(target_acl_name)}\n"
            rf"(.*?)(?=^ip access-list extended |\Z|^interface )"
        )
        m = re.search(pat, text)
        if not m:
            return ""
        return f"ip access-list extended {target_acl_name}\n{m.group(1)}"

    def _extract_acl_lines(snippet: str, target_acl_name: str):
        lines = []
        for ln in (snippet or "").splitlines():
            s = ln.rstrip()
            if not s.strip():
                continue
            if s.strip() == "!":
                continue
            if re.match(rf"^\s*ip access-list extended\s+{re.escape(target_acl_name)}\s*$", s, re.I):
                continue
            lines.append(s)
        return lines

    def _acl_exists(text: str, target_acl_name: str) -> bool:
        return bool(re.search(
            rf"(?mi)^\s*ip access-list extended\s+{re.escape(target_acl_name)}\s*$",
            text or "",
        ))

    def _current_attachments(text: str, target_acl_name: str):
        """
        Return list of (normalized_intf, direction) where target ACL is attached.
        """
        attachments = []
        lines = (text or "").splitlines()
        current_intf = None

        for line in lines:
            stripped = line.strip()

            if re.match(r"(?i)^interface\s+", stripped):
                parts = stripped.split(None, 1)
                current_intf = normalize_interface_name(parts[1]) if len(parts) > 1 else None
                continue

            m = re.match(
                rf"(?i)^\s*ip access-group\s+{re.escape(target_acl_name)}\s+(in|out)\s*$",
                stripped,
            )
            if m and current_intf:
                attachments.append((current_intf, m.group(1).lower()))
        return attachments

    def _has_attachment(text: str, acl: str, intf: str, dirn: str) -> bool:
        if not acl or not intf or not dirn:
            return False
        norm_intf = normalize_interface_name(intf)
        all_atts = _current_attachments(text, acl)
        return (norm_intf, dirn) in all_atts

    def _dedupe_preserve_order(cmds):
        out = []
        seen = set()
        for c in cmds:
            key = c.strip().lower()
            if key not in seen:
                seen.add(key)
                out.append(c)
        return out

    def _get_acl_on_intf_dir(text: str, intf: str, dirn: str):
        """Return the ACL name currently bound on intf+dirn, or None."""
        lines = (text or "").splitlines()
        current_intf = None
        for line in lines:
            stripped = line.strip()
            if re.match(r"(?i)^interface\s+", stripped):
                parts = stripped.split(None, 1)
                current_intf = normalize_interface_name(parts[1]) if len(parts) > 1 else None
                continue
            if current_intf != normalize_interface_name(intf):
                continue
            m = re.match(r"(?i)^\s*ip access-group\s+(\S+)\s+(in|out)\s*$", stripped)
            if m and m.group(2).lower() == dirn:
                return m.group(1)
        return None

    generated_acl_lines = _extract_acl_lines(acl_snippet, acl_name)
    if not generated_acl_lines:
        raise ValueError("No ACE lines found in acl_snippet")

    existing_target_acl_block = _extract_acl_block(config_text, acl_name)
    existing_target_acl_exists = bool(existing_target_acl_block)
    existing_target_acl_lines = _extract_acl_lines(existing_target_acl_block, acl_name) if existing_target_acl_block else []
    existing_target_norm_set = {_normalize_rule_line(x) for x in existing_target_acl_lines}

    commands = ["enable", "configure terminal"]

    conflicting_acl = _get_acl_on_intf_dir(config_text, norm_target_intf, direction)
    if conflicting_acl and conflicting_acl != acl_name:
        commands.append(f"interface {intf_name}")
        commands.append(f" no ip access-group {conflicting_acl} {direction}")
        
    # ============================================================
    # Q0 MODE
    # ============================================================
    if q0_mode:
        # 1) Remove old wrong attachment if known and actually present
        if old_acl_name and norm_old_intf and old_direction:
            if _has_attachment(config_text, old_acl_name, norm_old_intf, old_direction):
                commands.append(f"interface {old_intf_name}")
                commands.append(f" no ip access-group {old_acl_name} {old_direction}")

        # 2) Decide whether target ACL must be rebuilt
        #    Rebuild when:
        #      - force_rebuild_acl is True
        #      - target ACL does not exist
        #      - old ACL renamed to new ACL
        renamed = bool(old_acl_name and old_acl_name != acl_name)
        must_rebuild_target = force_rebuild_acl or (not existing_target_acl_exists) or renamed

        if must_rebuild_target:
            # If target ACL already exists and we want clean rebuild
            if existing_target_acl_exists:
                commands.append(f"no ip access-list extended {acl_name}")

            commands.append(f"ip access-list extended {acl_name}")
            for line in generated_acl_lines:
                commands.append(line.strip())
        else:
            # incremental add only missing lines
            missing_lines = []
            for line in generated_acl_lines:
                if _normalize_rule_line(line) not in existing_target_norm_set:
                    missing_lines.append(line)

            if missing_lines:
                commands.append(f"ip access-list extended {acl_name}")
                for line in missing_lines:
                    commands.append(line.strip())

        # 3) Optionally remove old ACL block if renamed
        if remove_old_acl_if_renamed and renamed and _acl_exists(config_text, old_acl_name):
            commands.append(f"no ip access-list extended {old_acl_name}")

        # 4) Ensure correct attachment exists
        if not _has_attachment(config_text, acl_name, norm_target_intf, direction):
            commands.append(f"interface {intf_name}")
            commands.append(f" ip access-group {acl_name} {direction}")

        commands = _dedupe_preserve_order(commands)

        if commands == ["enable", "configure terminal"]:
            return []

        commands.append("end")
        if include_save:
            commands.append("write memory")
        return commands

    # ============================================================
    # NORMAL / NON-Q0 MODE
    # ============================================================
    if force_rebuild_acl:
        if existing_target_acl_exists:
            commands.append(f"no ip access-list extended {acl_name}")

        commands.append(f"ip access-list extended {acl_name}")
        for line in generated_acl_lines:
            commands.append(line.strip())

        if not _has_attachment(config_text, acl_name, norm_target_intf, direction):
            commands.append(f"interface {intf_name}")
            commands.append(f" ip access-group {acl_name} {direction}")

        commands = _dedupe_preserve_order(commands)
        commands.append("end")
        if include_save:
            commands.append("write memory")
        return commands

    if not existing_target_acl_exists:
        commands.append(f"ip access-list extended {acl_name}")
        for line in generated_acl_lines:
            commands.append(line.strip())

        if not _has_attachment(config_text, acl_name, norm_target_intf, direction):
            commands.append(f"interface {intf_name}")
            commands.append(f" ip access-group {acl_name} {direction}")

        commands = _dedupe_preserve_order(commands)
        commands.append("end")
        if include_save:
            commands.append("write memory")
        return commands

    missing_lines = []
    for line in generated_acl_lines:
        if _normalize_rule_line(line) not in existing_target_norm_set:
            missing_lines.append(line)

    if missing_lines:
        commands.append(f"ip access-list extended {acl_name}")
        for line in missing_lines:
            commands.append(line.strip())

    if not _has_attachment(config_text, acl_name, norm_target_intf, direction):
        commands.append(f"interface {intf_name}")
        commands.append(f" ip access-group {acl_name} {direction}")

    commands = _dedupe_preserve_order(commands)

    if commands == ["enable", "configure terminal"]:
        return []

    commands.append("end")
    if include_save:
        commands.append("write memory")

    return commands