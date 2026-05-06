########### Import Libraries ###########
########################################

import os
import sys
import re
import json
import random
import subprocess
import time
import traceback
import pandas as pd

from pprint import pprint
from tabulate import tabulate

import Helpers.env
from Helpers.Formats import wrap_text, wrap_dataframe, extract_table_info, parse_kv_response, csv_to_list,to_none_if_noneish, _norm_nl, strip_code_fences
from Helpers.Read_Files import read_all_files_in_folder, read_all_json_files_in_folder, read_all_vpc_files_in_folder, read_topology_file, read_all_json_files_in_folder_Eval
from Helpers.Parse import parse_config_to_json, resolve_names, ensure_topology_dict
from Helpers.Finder import find_pcs_in_same_network, get_device_info, get_pc_name_by_ip, extract_router_facts_from_json#, choose_device_only
from Helpers.configs import process_configuration, generate_config2_file, generate_config2_file_apply_only, add_updated_router_cmd, extract_acl_name_and_rule, extract_rule_and_ACL_lines
from Helpers.RuleConflict import (
    ACLRule,
    parse_acl_rule_line,
    rules_equivalent,
    detect_conflicts,
    parse_router_config,
    NetworkTopology,
    normalize_interface_name
)

from Agents.Agents import * #client, get_direction, Answer_Query, File_Finder_caller, ACL_generator_caller, Entity_Extractor_caller
from Helpers.device_selection import choose_device_only_deterministic

from swarm import Swarm, Agent


# %run startup.py


# ################################################## Program Workflow  #################################################################
# Read Intents --> Resolve_names --> (1) entity extraction Agent    -->  (2)device Selection Module
# 
# (3)ACL Placement Resolver Agent  --> (4) ACL generator Agent --> (5)Rule Conflict Detection Module --> (6) generate updated config 
#
# (7) Stage1: BF validation --> (8) Finetuning (if needed) --> (9) Stage2: GNS3 validation 
#
# --> (10) Finetuning (if needed) (11) Deployment
# #######################################################################################################################################
def validate_acl_generator_inputs(action, protocol, port, src_ip, dst_ip, src_subnet, dst_subnet, intf_name, direction):
    errors = []

    if action not in {"permit", "deny"}:
        errors.append(f"invalid action: {action!r}")

    if not intf_name:
        errors.append(f"invalid interface: {intf_name!r}")

    if direction not in {"in", "out"}:
        errors.append(f"invalid direction: {direction!r}")

    if port is not None and protocol not in {"tcp", "udp"}:
        errors.append(f"port requires tcp/udp, got protocol={protocol!r}, port={port!r}")

    return errors
    

####### To evaluate the whole system LLM_Batfish_GNS3 , activate this function ###########
#############################################################################

def run_ACL_workflow(context_variables):
    topology_file      = context_variables.get("topology_file")          # folder path containing .json
    network_topology   = context_variables.get("network_topology")          
    new_intent         = context_variables.get("new_intent")         
    file_path          = context_variables.get("file_path")

    enable_conflict_detection = context_variables.get("enable_conflict_detection", False)

    # print("User intent is : " + new_intent)
    print("new_intent =", repr(new_intent))
    if not new_intent:
        raise ValueError("new_intent is None or empty")
    ############ resolve_names : mapping the obj and IPs ############
    topo = ensure_topology_dict(network_topology)
    # print("topo")
    # print(topo)
    resolved_names = resolve_names(new_intent, topo)
    # print("resolved_names")
    # print(resolved_names)

    context_variables.update({
          "resolved_names" : resolved_names,  
                    })       
    ############## Step 1: EntityExtraction Agent - extract entities of the user intent ##############      
    extraction_result = Entity_Extractor_Evalcaller(context_variables)#, llm_client)
    # print("extraction_result:", extraction_result)
    source_ip, destination_ip, protocol, port, action, app, src_Subnet, dst_Subnet = extract_entities(extraction_result)
   
    if action is not None:
        a = str(action).strip().lower()
        if a in {"block", "deny", "drop", "reject"}:
            action = "deny"
        elif a in {"allow", "permit"}:
            action = "permit"
    if protocol is not None:
        protocol = str(protocol).strip().lower()

    resolved = context_variables.get("resolved_names", {}) or {}

    # Prefer resolved topology-grounded values
    if resolved.get("source_host_ip"):
        source_ip = resolved["source_host_ip"]
        src_Subnet = None
    elif resolved.get("source_cidr"):
        source_ip = None
        src_Subnet = resolved["source_cidr"]
    
    if resolved.get("destination_host_ip"):
        destination_ip = resolved["destination_host_ip"]
        dst_Subnet = None
    elif resolved.get("destination_cidr"):
        destination_ip = None
        dst_Subnet = resolved["destination_cidr"]
        
    if src_Subnet == "0.0.0.0/0":
        source_ip = None
        src_Subnet = None
    
    if dst_Subnet == "0.0.0.0/0":
        destination_ip = None
        dst_Subnet = None
    # print(source_ip, destination_ip, protocol, port, action, app, src_Subnet, dst_Subnet)

    ########################### Step 2: Find the related Device (Python module) ##########################
    device_override = None #extract_device_override(new_intent)
    if device_override:
        hostname = device_override
    else:
        # signature: source_ip, src_subnet, dst_ip, dst_subnet, network_topology
        hostname = choose_device_only_deterministic(source_ip, src_Subnet, destination_ip, dst_Subnet, network_topology)
    
        
    hostname = str(hostname).strip()
    File_name = hostname.upper()
    hostname = File_name           
    # print("File_name")
    # print(File_name)

    cfg_path = f"{file_path}/{File_name}.cfg"
    
    topology_content = read_topology_file(cfg_path) 
    if isinstance(topology_content, list):
        config_text = "".join(topology_content)
    else:
        config_text = topology_content or ""
      
    ########################### Step 3: ACL Placement Resolver Agent: interface, direction, existing ACL name on that interface ##########################
    ### before adding a rule, we must determine:
        # 1- Where does the traffic enter the router?
        # 2- In which direction do we want to filter it?
        # 3- Is there already an ACL applied there?
    ### then you can pick the correct ACL name or create a new one
    #######################################################################################################################
    
    topo_prompt = network_topology if network_topology is not None else topo
    # print("before placement **************")
    placement = resolve_acl_placement(
                topo=topo,
                new_intent=new_intent,
                hostname=hostname,
                config_text=config_text,
                )
    # print("##################################")
    # print("DEBUG placement:", placement)
    # print("TYPE:", type(placement))
    if placement is None:
        raise ValueError("Placement resolver returned None")
    
    # Intf_Name = placement["Intf_Name"]
    Intf_Name  = placement.get("Intf_Name")
    direction  = placement["direction"]
    ACLname    = placement["ACLname"]
    List_Found = placement["List_Found"]
    
    if Intf_Name is None:
        raise ValueError("Interface resolution failed")

    if direction not in {"in", "out"}:
        raise ValueError(f"Invalid direction: {direction}")

########################### Step 4: ACL Generator agent ##########################
    # Build the generated rule first using the previous agent output
    # generate ACL config
    context_variables.update({
                  "mode": "generate",
             "direction": direction,
            "List_Found": List_Found,
                "L_Name": ACLname,
            "Intf_Name" : Intf_Name,
                "src_ip": source_ip,        
                "dst_ip": destination_ip,        
            "src_subnet": src_Subnet,    
            "dst_subnet": dst_Subnet,      
              "protocol": protocol,      
                  "port": port ,        
                "action": action ,
        })
    errors = validate_acl_generator_inputs(
    action, protocol, port,
    source_ip, destination_ip,
    src_Subnet, dst_Subnet,
    Intf_Name, direction
)

    if errors:
        raise ValueError("Generator input validation failed: " + "; ".join(errors))

    configuration_response = ACL_generator_caller(context_variables)
    configuration_response = strip_code_fences(configuration_response)
   
    # explicitly store ACL snippet
    acl_snippet = configuration_response

    gen_acl_name, generated_rule_line = extract_acl_name_and_rule(configuration_response)

    # print("gen_acl_name:", gen_acl_name)
    # print("generated_rule_line:", repr(generated_rule_line))
    
    ACLname = gen_acl_name or ACLname
    List_Found = ACLname is not None

    context_variables["L_Name"] = ACLname
    context_variables["ACLname"] = ACLname
    
    if not generated_rule_line:
        raise ValueError(
        f"Could not extract generated ACL rule line from configuration_response:\n{configuration_response}"
    )

    parsed_generated = parse_acl_rule_line(ACLname or "ACL_in", generated_rule_line)

    if parsed_generated is None:
        raise ValueError(
            f"Could not parse generated ACL rule line: {generated_rule_line}")

    generated = ACLRule(
                 acl_name=parsed_generated.acl_name,
                 sequence=parsed_generated.sequence,
                   action=parsed_generated.action,
                 protocol=parsed_generated.protocol,
                      src=parsed_generated.src,
                      dst=parsed_generated.dst,
                 src_port=parsed_generated.src_port,
                 dst_port=parsed_generated.dst_port,
                   router=hostname,
                interface=normalize_interface_name(Intf_Name),
                direction=direction.lower(),
                 raw_line=parsed_generated.raw_line,
    )
  
    # print("generated")
    # print(generated)

    if enable_conflict_detection:

        ########################### Step 5: Conflict Detection Module ##########################
        # Load topology JSON/dict into NetworkTopology object
        topo_obj = NetworkTopology(topo)
    
        # Load all existing ACL rules from router config files
        # Adjust the router list if your topology has different router names
        all_existing = {}
        for router in ["R1", "R2", "R3"]:
            try:
                all_existing.update(
                    parse_router_config(
                        router,
                        config_dir=file_path
                    )
                )
            except Exception as e:
                print(f"Warning: could not parse router config for {router}: {e}")
    
        # Detect semantic conflicts between the generated rule and existing deployed ACL rules
        conflicts = detect_conflicts(generated, all_existing, topo_obj)
    
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
    
        print("\n=== DEBUG ===")
        print("Generated key:", (generated.router, generated.interface, generated.direction))
    
        print("\nAll existing keys:")
        for k in all_existing.keys():
            print(k)
    
        print("\nMatching rules:")
        print(all_existing.get((generated.router, generated.interface, generated.direction), []))
    
       # If conflict exists -> stop before file update / apply
        if conflicts:
            print("Conflict detected. No configuration will be written/applied.")
            return {
                "Rules": None,
                "hostname": hostname,
                "config_text": config_text,
                "acl_snippet": acl_snippet,
                "full_config": config_text,              #
                "configuration_response": config_text,   # keep full config semantics
                "Whole_configuration": None,
                "extraction_result": extraction_result,
                "generated_rule": generated,
                "ACLname": ACLname,
                "L_Name": ACLname, 
                "direction": direction,
                "Intf_Name": Intf_Name,
                "File_name": File_name,
                "List_Found": List_Found,
                "conflict_detected": True,
                "conflicts": conflicts,
                "already_exists": False,
            }
        # No conflict: inspect current target attachment
        target_key = (
            hostname,
            normalize_interface_name(Intf_Name),
            direction.lower()
        )
        target_rules = all_existing.get(target_key, [])
    
        existing_same_rule = next(
            (r for r in target_rules if rules_equivalent(r, generated)),
            None
        )
    
        if existing_same_rule:
            print("The rule already exists and is applied correctly. Exiting.")
            return {
                "Rules": existing_same_rule.raw_line,
                "hostname": hostname,
                "config_text": config_text,
                "acl_snippet": None,                    # nothing to deploy
                "full_config": config_text,             # 
                "configuration_response": config_text,  # full config semantics
                "Whole_configuration": None,
                "extraction_result": extraction_result,
                "ACLname": existing_same_rule.acl_name,
                "direction": direction,
                "Intf_Name": Intf_Name,
                "File_name": File_name,
                "List_Found": True,
                "conflict_detected": False,
                "already_exists": True,
            }

    Whole_configuration = process_configuration(configuration_response)

    Rules = generate_config2_file(
        file_path,
        configuration_response,
        Intf_Name,
        config_text,
        File_name
    )

    # read candidate full config written by generate_config2_file
    candidate_cfg_path = os.path.join(file_path, f"{File_name}_2.cfg")
    if os.path.exists(candidate_cfg_path):
        with open(candidate_cfg_path, "r", encoding="utf-8") as f:
            full_config = f.read()
    else:
        # fallback, but ideally this file should exist
        full_config = configuration_response

    return {
        "Rules": Rules,
        "hostname": hostname,
        "config_text": config_text,                # original config BEFORE change
        "acl_snippet": acl_snippet,                # ACL block only
        "full_config": full_config,                # full candidate router config
        "configuration_response": full_config,     # keep compatibility, but now full config
        "Whole_configuration": Whole_configuration,
        "extraction_result": extraction_result,
        "ACLname": ACLname,
        "direction": direction,
        "Intf_Name": Intf_Name,
        "File_name": File_name,
        "List_Found": List_Found,
        "src_ip": source_ip,
        "dst_ip": destination_ip,
        "src_Subnet": src_Subnet,
        "dst_Subnet": dst_Subnet,
        "conflict_detected": False,
        "already_exists": False,
    }        
    
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

    generated_acl_lines = _extract_acl_lines(acl_snippet, acl_name)
    if not generated_acl_lines:
        raise ValueError("No ACE lines found in acl_snippet")

    existing_target_acl_block = _extract_acl_block(config_text, acl_name)
    existing_target_acl_exists = bool(existing_target_acl_block)
    existing_target_acl_lines = _extract_acl_lines(existing_target_acl_block, acl_name) if existing_target_acl_block else []
    existing_target_norm_set = {_normalize_rule_line(x) for x in existing_target_acl_lines}

    commands = ["enable", "configure terminal"]

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


def build_deploy_commands(
    acl_snippet: str,
    intf_name: str,
    direction: str,
    acl_name: str,
    config_text: str,
    force_rebuild_acl: bool = False,
    include_save: bool = False,
):
    """
    Build minimal CLI commands for GNS3 deployment.

    Inputs:
        acl_snippet:
            Generated ACL text from LLM, ideally something like:
                ip access-list extended ACL_R2_F0_0_IN
                 10 permit tcp host 1.1.1.1 host 2.2.2.2 eq 443
                 20 deny ip any any

            It may also be only ACE lines.

        intf_name:
            Target interface, e.g. 'FastEthernet0/0'

        direction:
            'in' or 'out'

        acl_name:
            ACL name, e.g. 'ACL_R2_F0_0_IN'

        config_text:
            Current full router config from file before applying change.

        force_rebuild_acl:
            True for reorder/refinement cases where full ACL block should be rebuilt.
            False for normal incremental addition.

        include_save:
            If True, append 'end' and 'write memory'

    Returns:
        List[str] of CLI commands, already minimized.
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

    norm_intf = normalize_interface_name(intf_name)

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
        """
        Accept either full ACL block or only ACE lines.
        Return ACE lines only.
        """
        lines = []
        raw_lines = (snippet or "").splitlines()

        for ln in raw_lines:
            s = ln.rstrip()
            if not s.strip():
                continue
            if s.strip() == "!":
                continue
            if re.match(rf"^\s*ip access-list extended\s+{re.escape(target_acl_name)}\s*$", s, re.I):
                continue
            lines.append(s)

        return lines

    def _current_attachment(text: str, target_acl_name: str):
        """
        Return list of (interface_name_normalized, direction) where ACL is attached.
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

    def _acl_exists(text: str, target_acl_name: str) -> bool:
        return bool(re.search(
            rf"(?mi)^\s*ip access-list extended\s+{re.escape(target_acl_name)}\s*$",
            text or "",
        ))

    # Parse current ACL state
    existing_acl_block = _extract_acl_block(config_text, acl_name)
    existing_acl_exists = bool(existing_acl_block)
    existing_acl_lines = _extract_acl_lines(existing_acl_block, acl_name) if existing_acl_block else []
    existing_norm_set = {_normalize_rule_line(x) for x in existing_acl_lines}

    generated_acl_lines = _extract_acl_lines(acl_snippet, acl_name)
    if not generated_acl_lines:
        raise ValueError("No ACE lines found in acl_snippet")

    generated_norm_set = {_normalize_rule_line(x) for x in generated_acl_lines}

    current_attachments = _current_attachment(config_text, acl_name)
    already_attached_correctly = (norm_intf, direction) in current_attachments

    commands = ["enable", "configure terminal"]

    # ------------------------------------------------------------
    # Case 1: force rebuild (useful for Q3 reorder fixes)
    # ------------------------------------------------------------
    if force_rebuild_acl:
        if existing_acl_exists:
            commands.append(f"no ip access-list extended {acl_name}")

        commands.append(f"ip access-list extended {acl_name}")
        for line in generated_acl_lines:
            commands.append(line.strip())

        if not already_attached_correctly:
            commands.append(f"interface {intf_name}")
            commands.append(f" ip access-group {acl_name} {direction}")

        commands.append("end")
        if include_save:
            commands.append("write memory")
        return commands

    # ------------------------------------------------------------
    # Case 2: ACL does not exist yet
    # ------------------------------------------------------------
    if not existing_acl_exists:
        commands.append(f"ip access-list extended {acl_name}")
        for line in generated_acl_lines:
            commands.append(line.strip())

        commands.append(f"interface {intf_name}")
        commands.append(f" ip access-group {acl_name} {direction}")

        commands.append("end")
        if include_save:
            commands.append("write memory")
        return commands

    # ------------------------------------------------------------
    # Case 3: ACL exists; add only missing ACE lines
    # ------------------------------------------------------------
    missing_lines = []
    for line in generated_acl_lines:
        if _normalize_rule_line(line) not in existing_norm_set:
            missing_lines.append(line)

    if missing_lines:
        commands.append(f"ip access-list extended {acl_name}")
        for line in missing_lines:
            commands.append(line.strip())

    # ------------------------------------------------------------
    # Case 4: ensure attachment only if missing on target
    # ------------------------------------------------------------
    if not already_attached_correctly:
        commands.append(f"interface {intf_name}")
        commands.append(f" ip access-group {acl_name} {direction}")

    # If nothing changed beyond entering config mode, return empty
    if commands == ["enable", "configure terminal"]:
        return []

    commands.append("end")
    if include_save:
        commands.append("write memory")

    return commands