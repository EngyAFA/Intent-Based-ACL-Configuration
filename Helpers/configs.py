import re

from Helpers.Read_Files import *
from Helpers.Parse import parse_config_to_json
from Helpers.Formats import normalize_interface_name
from Batfish.preprocess import set_acl_attachment_raw
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

############# Helping function : extract ACL name from a given configs (commands) ############## 
################################################################################################

def extract_acl_name_and_rule(configuration_response: str):
    acl_name = None
    rule_line = None
    inside_acl = False

    for raw in configuration_response.splitlines():
        line = raw.strip()

        if not line:
            continue

        m_acl = re.match(r"^ip access-list extended (\S+)$", line, re.IGNORECASE)
        if m_acl:
            acl_name = m_acl.group(1)
            inside_acl = True
            continue

        if inside_acl:
            if re.match(r"^(\d+\s+)?(permit|deny)\s+(ip|tcp|udp|icmp)\s+", line, re.IGNORECASE):
                rule_line = line
                break

            if re.match(r"^interface\s+\S+", line, re.IGNORECASE):
                inside_acl = False

    return acl_name, rule_line

#################### Helping function : format the generated configuration to make it applicable in GNS3 ####################
#############################################################################################################################
def process_configuration(input_conf: str) -> str:
    if input_conf is None:
        return ""
        
    # remove code fences if the model ever includes them
    s = str(input_conf).strip()

    # remove surrounding triple backticks blocks (simple safe cleanup)
    s = s.strip("`\n")
    # If the text contains literal "\n", convert them into real newlines
    if "\\n" in s:
        s = s.replace("\\n", "\n")

    # Split into real lines and drop empty ones
    lines = [ln.rstrip() for ln in s.splitlines() if ln.strip()]

    processed_conf = "\n\nenable\nconfigure terminal\n"
    processed_conf += "\n".join(lines)
    processed_conf += "\n\nexit\nexit\nwrite\n\ncopy running-config startup-config\n\n"
    return processed_conf
    
####################### Generate updated config file of a router = config2 ########################
####################################################################################################
def generate_config2_file(
    file_path: str,
    Whole_configuration: str,
    Interface_ACL: str,
    topology_file: str,
    File_name: str,
) -> list:
    extra_rule, extra_ACL = extract_rule_and_ACL_lines(Whole_configuration)
    rules = Rule_ACname(extra_ACL)

    config_file_path = file_path + "/" + File_name + ".cfg"
    topology_content = read_topology_file(config_file_path)
    topology_file = "".join(topology_content) if topology_content else ""

    context_variables = {
        "topology_file": topology_file,
        "interface_name": Interface_ACL,
        "Rule": extra_rule,
        "ACL": extra_ACL,
    }

    updated_config = add_updated_router_cmd(context_variables)
    updated_file_path = file_path + "/" + File_name + "_2.cfg"

    with open(updated_file_path, "w") as file:
        file.write(updated_config)

    parse_config_to_json(file_path + "/" + File_name + "_2")

    return rules
####################### Generate updated config file of a router = config2  in case applied on Interface without generating all configs ########################
####################################################################################################
def generate_config2_file_apply_only(
    file_path: str,
    Whole_configuration: str,
    File_name: str,
) -> dict:
    """
    Whole_configuration: LLM output that contains ONLY:
        interface X
         ip access-group ACL in|out
    Writes updated config to File_name_2.cfg and parses it.
    """
    # Load original config
    config_file_path = "./configs/" + File_name + ".cfg"
    topology_content = read_topology_file(config_file_path)
    original_config = "".join(topology_content) if topology_content else ""

    # Append the interface apply lines (or merge smarter if you want)
    updated_config = (
        original_config.rstrip()
        + "\n!\n"
        + Whole_configuration.strip()
        + "\n"
    )

    # Write _2.cfg
    output_file_path = "./configs/" + File_name + "_2.cfg"

    with open(output_file_path, "w") as file:
        file.write(updated_config)

    parse_config_to_json("./configs/" + File_name + "_2")

    return {"applied_only": True}
    
# #### extract the 'rule line' and 'ACL block' from the generated configuration
def extract_rule_and_ACL_lines(config: str) -> tuple:
    """
    Extract:
      - ACL block (only the generated one)
      - interface apply rule (ip access-group ...)
    """
    lines = config.splitlines()

    rule = None
    acl_lines = []

    for line in lines:
        stripped_line = line.strip()

        if stripped_line.startswith("ip access-group"):
            rule = stripped_line

        elif (
            stripped_line.startswith("ip access-list")
            or stripped_line.startswith("permit")
            or stripped_line.startswith("deny")
        ):
            acl_lines.append(stripped_line)

    acl = "\n".join(acl_lines) if acl_lines else None

    if acl:
        acl = acl.strip() + "\n!"

    return rule, acl


################ extract the rule from the generated function ################
##############################################################################
# by help of the function(extract_rule_and_ACL_lines)
def Rule_ACname(Rule: str) -> list:
    rules = []
    rule_lines = Rule.splitlines()

    for line in rule_lines:
        stripped_line = line.strip()

        if (
            stripped_line.startswith("permit")
            or stripped_line.startswith("deny")
        ):
            rules.append(stripped_line)

    return rules

# #### generate an updated configuration file for the router by adding the lines corresponding to the user intents. ###
#######################################################################################################################

def add_updated_router_cmd(context_variables: dict) -> str:
    topology_file = context_variables.get("topology_file", "") or ""
    interface_name = context_variables.get("interface_name", "") or ""
    rule = context_variables.get("Rule", "") or ""
    acl = context_variables.get("ACL", "") or ""

    interface_name = interface_name.strip()

    if interface_name.lower().startswith("interface "):
        interface_name = interface_name.split(None, 1)[1].strip()

    print("interface_name in add_updated_router_cmd")
    print(interface_name)

    # extract ACL name from ACL block
    acl_name = None
    acl = acl.strip()
    acl_lines = acl.splitlines()

    for line in acl_lines:
        stripped_line = line.strip()
        match = re.match(
            r"^ip access-list extended (\S+)$",
            stripped_line,
            re.IGNORECASE,
        )

        if match:
            acl_name = match.group(1)
            break

    # 1) rename hostname
    lines = topology_file.splitlines()
    renamed_lines = []

    for line in lines:
        if line.startswith("hostname"):
            parts = line.split()

            if len(parts) == 2 and not parts[1].endswith("_2"):
                line = f"hostname {parts[1]}_2"

        renamed_lines.append(line)

    config_text = "\n".join(renamed_lines) + "\n"

    # 2) replace ACL block if exists, else insert once before first interface
    if acl and acl_name:
        acl_block = acl + "\n!"
        acl_pattern = (
            rf"(?ms)^ip access-list extended {re.escape(acl_name)}\n"
            r".*?(?=^ip access-list extended |\Z|^interface )"
        )

        if re.search(acl_pattern, config_text):
            config_text = re.sub(
                acl_pattern,
                acl_block + "\n",
                config_text,
            )

        else:
            first_interface_match = re.search(
                r"(?m)^interface\s+\S+",
                config_text,
            )

            if first_interface_match:
                config_text = (
                    config_text[:first_interface_match.start()]
                    + acl_block
                    + "\n"
                    + config_text[first_interface_match.start():]
                )

            else:
                config_text = config_text.rstrip() + "\n" + acl_block + "\n"

    # 3) apply interface rule cleanly using set_acl_attachment_raw
    if rule.strip() and acl_name:
        rule_match = re.search(
            r"\b(in|out)\b\s*$",
            rule.strip(),
            re.IGNORECASE,
        )

        if rule_match:
            direction = rule_match.group(1).lower()
            config_text = set_acl_attachment_raw(
                cfg_text=config_text,
                acl_name=acl_name,
                intf_name=interface_name,
                direction=direction,
            )

    return config_text