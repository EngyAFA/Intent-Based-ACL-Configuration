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

from Agents.AgentsDS import * #client, get_direction, Answer_Query, File_Finder_caller, ACL_generator_caller, Entity_Extractor_caller
from Helpers.device_selection import choose_device_only_deterministic
from Agents.workflow_base import validate_acl_generator_inputs

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



####### To evaluate the whole system LLM_Batfish_GNS3 , activate this function ###########
#############################################################################

def run_ACL_workflow(context_variables: dict) -> dict:
    topology_file = context_variables.get("topology_file")
    network_topology = context_variables.get("network_topology")
    new_intent = context_variables.get("new_intent")
    file_path = context_variables.get("file_path")

    enable_conflict_detection = context_variables.get(
        "enable_conflict_detection",
        False,
    )

    # print("User intent is : " + new_intent)
    print("new_intent =", repr(new_intent))

    if not new_intent:
        raise ValueError("new_intent is None or empty")

    ############ resolve_names : mapping the obj and IPs ############
    topology = ensure_topology_dict(network_topology)
    # print("topo")
    # print(topo)

    resolved_names = resolve_names(new_intent, topology)
    # print("resolved_names")
    # print(resolved_names)

    context_variables.update(
        {
            "resolved_names": resolved_names,
        }
    )

    ############## Step 1: EntityExtraction Agent - extract entities of the user intent ##############
    # extraction_result = Entity_Extractor_Evalcaller(context_variables)
    # print("LLM client type:", type(llm_client))
    # print("LLM client repr:", llm_client)

    extraction_result = Entity_Extractor_Evalcaller(context_variables)
    print("extraction_result:", extraction_result)

    source_ip, destination_ip, protocol, port, action, app, src_subnet, dst_subnet = (
        extract_entities(extraction_result)
    )

    if action is not None:
        normalized_action = str(action).strip().lower()

        if normalized_action in {"block", "deny", "drop", "reject"}:
            action = "deny"

        elif normalized_action in {"allow", "permit"}:
            action = "permit"

    if protocol is not None:
        protocol = str(protocol).strip().lower()

    resolved = context_variables.get("resolved_names", {}) or {}

    # Prefer resolved topology-grounded values
    if resolved.get("source_host_ip"):
        source_ip = resolved["source_host_ip"]
        src_subnet = None

    elif resolved.get("source_cidr"):
        source_ip = None
        src_subnet = resolved["source_cidr"]

    if resolved.get("destination_host_ip"):
        destination_ip = resolved["destination_host_ip"]
        dst_subnet = None

    elif resolved.get("destination_cidr"):
        destination_ip = None
        dst_subnet = resolved["destination_cidr"]

    if src_subnet == "0.0.0.0/0":
        source_ip = None
        src_subnet = None

    if dst_subnet == "0.0.0.0/0":
        destination_ip = None
        dst_subnet = None

    # print(source_ip, destination_ip, protocol, port, action, app, src_subnet, dst_subnet)

    ########################### Step 2: Find the related Device (Python module) ##########################
    device_override = None  # extract_device_override(new_intent)

    if device_override:
        hostname = device_override

    else:
        # signature: source_ip, src_subnet, dst_ip, dst_subnet, network_topology
        hostname = choose_device_only_deterministic(
            source_ip,
            src_subnet,
            destination_ip,
            dst_subnet,
            network_topology,
        )

    hostname = str(hostname).strip()
    file_name = hostname.upper()
    hostname = file_name

    print("File_name")
    print(file_name)

    config_file_path = f"{file_path}/{file_name}.cfg"

    topology_content = read_topology_file(config_file_path)

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

    topo_prompt = network_topology if network_topology is not None else topology
    # print("before placement **************")

    placement = resolve_acl_placement(
        topo=topology,
        new_intent=new_intent,
        hostname=hostname,
        config_text=config_text,
    )
    # print("##################################")
    # print("DEBUG placement:", placement)
    # print("TYPE:", type(placement))

    if placement is None:
        raise ValueError("Placement resolver returned None")

    interface_name = placement.get("Intf_Name")
    direction = placement["direction"]
    acl_name = placement["ACLname"]
    list_found = placement["List_Found"]

    if interface_name is None:
        raise ValueError("Interface resolution failed")

    if direction not in {"in", "out"}:
        raise ValueError(f"Invalid direction: {direction}")

    ########################### Step 4: ACL Generator agent ##########################
    # Build the generated rule first using the previous agent output
    # generate ACL config
    context_variables.update(
        {
            "mode": "generate",
            "direction": direction,
            "List_Found": list_found,
            "L_Name": acl_name,
            "Intf_Name": interface_name,
            "src_ip": source_ip,
            "dst_ip": destination_ip,
            "src_subnet": src_subnet,
            "dst_subnet": dst_subnet,
            "protocol": protocol,
            "port": port,
            "action": action,
        }
    )

    errors = validate_acl_generator_inputs(
        action,
        protocol,
        port,
        source_ip,
        destination_ip,
        src_subnet,
        dst_subnet,
        interface_name,
        direction,
    )

    if errors:
        raise ValueError(
            "Generator input validation failed: " + "; ".join(errors)
        )

    configuration_response = ACL_generator_caller(context_variables)
    configuration_response = strip_code_fences(configuration_response)

    # explicitly store ACL snippet
    acl_snippet = configuration_response

    generated_acl_name, generated_rule_line = extract_acl_name_and_rule(
        configuration_response
    )

    # print("gen_acl_name:", gen_acl_name)
    # print("generated_rule_line:", repr(generated_rule_line))

    acl_name = generated_acl_name or acl_name
    list_found = acl_name is not None

    context_variables["L_Name"] = acl_name
    context_variables["ACLname"] = acl_name

    if not generated_rule_line:
        raise ValueError(
            "Could not extract generated ACL rule line from "
            f"configuration_response:\n{configuration_response}"
        )

    parsed_generated = parse_acl_rule_line(
        acl_name or "ACL_in",
        generated_rule_line,
    )

    if parsed_generated is None:
        raise ValueError(
            f"Could not parse generated ACL rule line: {generated_rule_line}"
        )

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
        interface=normalize_interface_name(interface_name),
        direction=direction.lower(),
        raw_line=parsed_generated.raw_line,
    )

    print("generated")
    print(generated)

    if enable_conflict_detection:
        ########################### Step 5: Conflict Detection Module ##########################
        # Load topology JSON/dict into NetworkTopology object
        topology_object = NetworkTopology(topology)

        # Load all existing ACL rules from router config files
        # Adjust the router list if your topology has different router names
        all_existing = {}

        for router in ["R1", "R2", "R3"]:
            try:
                all_existing.update(
                    parse_router_config(
                        router,
                        config_dir=file_path,
                    )
                )

            except Exception as error:
                print(
                    f"Warning: could not parse router config for "
                    f"{router}: {error}"
                )

        # Detect semantic conflicts between the generated rule and existing deployed ACL rules
        conflicts = detect_conflicts(
            generated,
            all_existing,
            topology_object,
        )

        print("Detected conflicts:", len(conflicts))

        for conflict in conflicts:
            print("---")
            print("new:", conflict.new_rule.raw_line or conflict.new_rule)
            print("existing:", conflict.existing_rule.raw_line)
            print(
                "existing attachment:",
                (
                    conflict.existing_rule.router,
                    conflict.existing_rule.interface,
                    conflict.existing_rule.direction,
                ),
            )
            print("overlap src:", conflict.overlap_src)
            print("overlap dst:", conflict.overlap_dst)
            print("protocol:", conflict.overlap_protocol)
            print("port:", conflict.overlap_dst_port)
            print("reason:", conflict.reason)

        print("\n=== DEBUG ===")
        print(
            "Generated key:",
            (
                generated.router,
                generated.interface,
                generated.direction,
            ),
        )

        print("\nAll existing keys:")

        for key in all_existing.keys():
            print(key)

        print("\nMatching rules:")
        print(
            all_existing.get(
                (
                    generated.router,
                    generated.interface,
                    generated.direction,
                ),
                [],
            )
        )

        # If conflict exists -> stop before file update / apply
        if conflicts:
            print("Conflict detected. No configuration will be written/applied.")

            return {
                "Rules": None,
                "hostname": hostname,
                "config_text": config_text,
                "acl_snippet": acl_snippet,
                "full_config": config_text,
                "configuration_response": config_text,
                "Whole_configuration": None,
                "extraction_result": extraction_result,
                "generated_rule": generated,
                "ACLname": acl_name,
                "L_Name": acl_name,
                "direction": direction,
                "Intf_Name": interface_name,
                "File_name": file_name,
                "List_Found": list_found,
                "conflict_detected": True,
                "conflicts": conflicts,
                "already_exists": False,
            }

        # No conflict: inspect current target attachment
        target_key = (
            hostname,
            normalize_interface_name(interface_name),
            direction.lower(),
        )
        target_rules = all_existing.get(target_key, [])

        existing_same_rule = next(
            (
                rule
                for rule in target_rules
                if rules_equivalent(rule, generated)
            ),
            None,
        )

        if existing_same_rule:
            print("The rule already exists and is applied correctly. Exiting.")

            return {
                "Rules": existing_same_rule.raw_line,
                "hostname": hostname,
                "config_text": config_text,
                "acl_snippet": None,
                "full_config": config_text,
                "configuration_response": config_text,
                "Whole_configuration": None,
                "extraction_result": extraction_result,
                "ACLname": existing_same_rule.acl_name,
                "direction": direction,
                "Intf_Name": interface_name,
                "File_name": file_name,
                "List_Found": True,
                "conflict_detected": False,
                "already_exists": True,
            }

    whole_configuration = process_configuration(configuration_response)

    rules = generate_config2_file(
        file_path,
        configuration_response,
        interface_name,
        config_text,
        file_name,
    )

    # NEW: read candidate full config written by generate_config2_file
    candidate_config_path = os.path.join(file_path, f"{file_name}_2.cfg")

    if os.path.exists(candidate_config_path):
        with open(candidate_config_path, "r", encoding="utf-8") as file:
            full_config = file.read()

    else:
        # fallback, but ideally this file should exist
        full_config = configuration_response

    return {
        "Rules": rules,
        "hostname": hostname,
        "config_text": config_text,              # original config BEFORE change 
        "acl_snippet": acl_snippet,               # ACL block only 
        "full_config": full_config,                # full candidate router config 
        "configuration_response": full_config,       # keep compatibility, but now full config
        "Whole_configuration": whole_configuration,
        "extraction_result": extraction_result,
        "ACLname": acl_name,
        "direction": direction,
        "Intf_Name": interface_name,
        "File_name": file_name,
        "List_Found": list_found,
        "src_ip": source_ip,
        "dst_ip": destination_ip,
        "src_Subnet": src_subnet,
        "dst_Subnet": dst_subnet,
        "conflict_detected": False,
        "already_exists": False,
    }