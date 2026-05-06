import re

from Helpers.Read_Files import *
from Helpers.Parse import parse_config_to_json
from Helpers.Formats import normalize_interface_name
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
from Batfish.preprocess import set_acl_attachment_raw

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
def generate_config2_file(file_path, Whole_configuration, Interface_ACL, topology_file, File_name):
    extra_rule, extra_ACL = extract_rule_and_ACL_lines(Whole_configuration)
    rules = Rule_ACname(extra_ACL)

    file_path2 = file_path + '/' + File_name + '.cfg'
    topology_content = read_topology_file(file_path2)
    topology_file = ''.join(topology_content) if topology_content else ""

    context_variables = {
        "topology_file": topology_file,
        "interface_name": Interface_ACL,
        "Rule": extra_rule,
        "ACL": extra_ACL,
    }

    updated_config = add_updated_router_cmd(context_variables)

    with open(file_path + '/' + File_name + "_2.cfg", "w") as file:
        file.write(updated_config)

    parse_config_to_json(file_path + '/' + File_name + "_2")
    return rules
####################### Generate updated config file of a router = config2  in case applied on Interface without generating all configs ########################
####################################################################################################
def generate_config2_file_apply_only(file_path,Whole_configuration, File_name):
    """
    Whole_configuration: LLM output that contains ONLY:
        interface X
         ip access-group ACL in|out
    Writes updated config to File_name_2.cfg and parses it.
    """
    # Load original config
    file_path2 = "./configs/" + File_name + ".cfg"
    topology_content = read_topology_file(file_path2)
    original_cfg = ''.join(topology_content) if topology_content else ""

    # Append the interface apply lines (or merge smarter if you want)
    updated_cfg = original_cfg.rstrip() + "\n!\n" + Whole_configuration.strip() + "\n"

    # Write _2.cfg
    out_path = "./configs/" + File_name + "_2.cfg"
    with open(out_path, "w") as f:
        f.write(updated_cfg)

    parse_config_to_json("./configs/" + File_name + "_2")
    return {"applied_only": True}
    
# #### extract the 'rule line' and 'ACL block' from the generated configuration
def extract_rule_and_ACL_lines(config):
    """
    Extract:
      - ACL block (only the generated one)
      - interface apply rule (ip access-group ...)
    """
    lines = config.splitlines()
    Rule = None
    ACL_lines = []

    for line in lines:
        s = line.strip()
        if s.startswith("ip access-group"):
            Rule = s
        elif s.startswith("ip access-list") or s.startswith("permit") or s.startswith("deny"):
            ACL_lines.append(s)

    ACL = "\n".join(ACL_lines) if ACL_lines else None
    if ACL:
        ACL = ACL.strip() + "\n!"
    return Rule, ACL


################ extract the rule from the generated function ################
##############################################################################
# by help of the function(extract_rule_and_ACL_lines)
def Rule_ACname(Rule):
    rules = []
    S_lines = Rule.splitlines()
    # Iterate through each line to find the rule that starts with 'permit' or 'deny'
    for line in S_lines:
        line = line.strip()
        if line.startswith('permit') or line.startswith('deny'):
            rules.append(line)
    return rules

# #### generate an updated configuration file for the router by adding the lines corresponding to the user intents. ###
#######################################################################################################################

def add_updated_router_cmd(context_variables):
    topology_file   = context_variables.get("topology_file", "") or ""
    interface_name  = context_variables.get("interface_name", "") or ""
    Rule            = context_variables.get("Rule", "") or ""
    ACL             = context_variables.get("ACL", "") or ""

    interface_name = interface_name.strip()
    if interface_name.lower().startswith("interface "):
        interface_name = interface_name.split(None, 1)[1].strip()

    print("interface_name in add_updated_router_cmd")
    print(interface_name)

    # extract ACL name from ACL block
    acl_name = None
    ACL = ACL.strip()
    acl_lines = ACL.splitlines()
    for ln in acl_lines:
        s = ln.strip()
        m = re.match(r"^ip access-list extended (\S+)$", s, re.IGNORECASE)
        if m:
            acl_name = m.group(1)
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

    cfg_text = "\n".join(renamed_lines) + "\n"

    # 2) replace ACL block if exists, else insert once before first interface
    if ACL and acl_name:
        acl_block = ACL + "\n!"
        acl_pat = rf"(?ms)^ip access-list extended {re.escape(acl_name)}\n.*?(?=^ip access-list extended |\Z|^interface )"

        if re.search(acl_pat, cfg_text):
            cfg_text = re.sub(acl_pat, acl_block + "\n", cfg_text)
        else:
            m_first_intf = re.search(r"(?m)^interface\s+\S+", cfg_text)
            if m_first_intf:
                cfg_text = (
                    cfg_text[:m_first_intf.start()]
                    + acl_block + "\n"
                    + cfg_text[m_first_intf.start():]
                )
            else:
                cfg_text = cfg_text.rstrip() + "\n" + acl_block + "\n"

    # 3) apply interface rule cleanly using set_acl_attachment_raw
    if Rule.strip() and acl_name:
        m_rule = re.search(r"\b(in|out)\b\s*$", Rule.strip(), re.IGNORECASE)
        if m_rule:
            direction = m_rule.group(1).lower()
            cfg_text = set_acl_attachment_raw(
                cfg_text=cfg_text,
                acl_name=acl_name,
                intf_name=interface_name,
                direction=direction,
            )

    return cfg_text