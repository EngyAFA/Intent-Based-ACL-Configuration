import json
from typing import Dict, Any, Optional

########################################## Instructions Functions: Prompt Engineering in LLM #############################
################################################# work on the JSON File ##################################################
##########################################################################################################################

# #######################################################################################################################
# ##### instructions for answering any questions regarding the configuration file (extracting some useful information) ##   
# #####                                  for ACL Placement Resolver Agent 
# #######################################################################################################################
def build_interface_query_prompt(
    topo: Dict[str, Any],
    new_intent: str,
    hostname: str,
) -> str:
    topo_prompt_text = json.dumps(topo, indent=2)

    prompt = f"""
        Topology (JSON):
        {topo_prompt_text}
        
        Intent:
        {new_intent}
        
        Chosen device:
        {hostname}
        
        Question:
        On which interface of the chosen device does the described traffic ENTER the router?
        
        Return the interface name only.
        """.strip()

    return prompt

def build_direction_query_prompt(
    new_intent: str,
    hostname: str,
    ingress_interface: str,
) -> str:
    prompt = f"""
        Intent:
        {new_intent}
        
        Chosen device:
        {hostname}
        
        Ingress interface:
        {ingress_interface}
        
        Question:
        Should the ACL be applied inbound or outbound on that interface?
        
        Return only: in OR out
        """.strip()
    return prompt
    
def build_acl_name_query_prompt(
    config_text: str,
    interface_name: str,
    direction: str,
) -> str:
    prompt = f"""
        Router configuration:
        {config_text}
        
        Interface:
        {interface_name}
        
        Direction:
        {direction}
        
        Question:
        If an ACL is applied on that interface in that direction, return the ACL name only.
        If no ACL is applied, return None.
        
        Return only one token.
        """.strip()

    return prompt
    
def Network_LLM(context_variables):
    topology_file = context_variables.get("topology_file", None)
    question      = context_variables.get("question", None)
    new_intent      = context_variables.get("new_intent", None)
    
    # return f"""
    #     You are an expert network engineer. You will answer any questions {question} based on the following router configuration:
    
    #     {topology_file}
    
    #     Please answer the user's question based on this configuration. 
    #     show a very short answer without explanation or details.
    #  """
    return f"""
    You are an expert network engineer.
    
    You must answer the QUESTION using ONLY the provided TEXT (router configuration or topology JSON).
    If the answer is not explicitly derivable from the provided TEXT, return: None
    
    QUESTION:
    {question}
    
    TEXT:
    {topology_file}

    Intent:
    {new_intent}
    
    OUTPUT RULES (STRICT):
        - Output must be ONE LINE ONLY.
        - Do NOT add explanations, punctuation, labels, or extra words.
        - If the question requests True/False: output exactly True or False.
        - If the question requests in/out: output exactly in or out.
        - If the question requests an interface name: output only the interface token (e.g., g0/0).
        - If the question requests an ACL name: output only the ACL name token (e.g., ACL_LAN_IN).
        - If no such ACL/rule/interface exists in the TEXT: output None.
"""

# ####################################################################################################
# ################ instructions for extracting the entities from the user intent  ####################    
# ###              for Entity Extractor Agent 
# ####################################################################################################

def entity_extraction_Evaluation(context_variables):
    new_intent = context_variables.get("new_intent")
    resolved_names = context_variables.get("resolved_names")
    resolved_names_json = json.dumps(resolved_names, indent=2)


    return f"""
        You are a deterministic entity extraction engine for network policy intents.
        
        Your job is to extract exactly 8 fields from the given data.
        
        IMPORTANT:
        - Use the Resolved dictionary as the ONLY ground truth for source, destination, and service.
        - Use the Intent text ONLY for action extraction.
        - Do NOT let wording in the intent override source/destination/service values from the Resolved dictionary.
        
        Intent:
        {new_intent}
        
        Resolved dictionary (GROUND TRUTH):
        {resolved_names_json}
        
        OUTPUT FORMAT:
        Return PLAIN TEXT ONLY.
        Return EXACTLY 8 lines in the following order and nothing else:
        
        Source IP: <value>
        Destination IP: <value>
        Protocol: <value>
        Port: <value>
        Action: <value>
        Application: <value>
        Source IP Subnet: <value>
        Destination IP Subnet: <value>
        
        GLOBAL RULES (STRICT):
        1. Missing values MUST be written exactly as: None
        2. Do NOT invent values.
        3. Do NOT output explanations, comments, JSON, bullets, code fences, or extra lines.
        4. Source and Destination must never be swapped.
        5. If the Intent conflicts with the Resolved dictionary, the Resolved dictionary wins.
        6. For source/destination/service extraction, ignore natural-language ambiguity in the Intent and follow only the Resolved dictionary.

        ANTI-SWAP RULES (VERY STRICT):
        1. source_host_ip belongs only to Source IP.
        2. source_cidr belongs only to Source IP Subnet.
        3. destination_host_ip belongs only to Destination IP.
        4. destination_cidr belongs only to Destination IP Subnet.
        5. Never copy a destination_* value into any source field.
        6. Never copy a source_* value into any destination field.
        7. If one side is missing, output None for that side. Do not borrow the other side's value.
        
        SOURCE RULES:
        - If source_host_ip exists and is not None:
          Source IP = source_host_ip
          Source IP Subnet = None
        - Else if source_cidr exists and is not None:
          Source IP = None
          Source IP Subnet = source_cidr
        - Else if source is Internet or Any:
          Source IP = None
          Source IP Subnet = 0.0.0.0/0
        - Else:
          Source IP = None
          Source IP Subnet = None
        
        DESTINATION RULES:
        - If destination_host_ip exists and is not None:
          Destination IP = destination_host_ip
          Destination IP Subnet = None
        - Else if destination_cidr exists and is not None:
          Destination IP = None
          Destination IP Subnet = destination_cidr
        - Else if destination is Internet or Any:
          Destination IP = None
          Destination IP Subnet = 0.0.0.0/0
        - Else:
          Destination IP = None
          Destination IP Subnet = None
          
        - EXPLICIT PROTOCOL RULES:
            - If the Intent explicitly mentions "protocol ip", "IP traffic", or "all IP", then Protocol = ip.
            - If Protocol = ip, then Port = None and Application = None unless the Intent explicitly specifies otherwise.
            - If the Intent explicitly mentions ICMP or ping, then Protocol = icmp, Port = None, Application = None.
            - Only infer tcp/udp from service names when the protocol is not explicitly stated in the Intent.

          
        SERVICE RULES:
        - Read the service value only from the Resolved dictionary.
        
        SERVICE SAFETY RULES:
        - Do not guess randomly.
        - Only infer protocol/port for widely known standard services.
        - If uncertain or ambiguous, return None for Protocol, Port, and Application.
        
        ACTION RULES:
        - Determine Action from the Intent text only.
        - allow / permit / enable / accept -> permit
        - deny / block / prohibit / prevent -> deny
        - Action must not be None.
        - If multiple action-like words appear, choose the one that best represents the requested policy.
        
        CONSISTENCY RULES:
        1. If Source IP is filled, Source IP Subnet MUST be None.
        2. If Source IP Subnet is filled, Source IP MUST be None.
        3. If Destination IP is filled, Destination IP Subnet MUST be None.
        4. If Destination IP Subnet is filled, Destination IP MUST be None.
        5. Never fill both IP and Subnet for the same endpoint.
        
        Now produce the 8 output lines only.
        """.strip()

# # ####################################################################################################
# # ############ instructions for generating the configuration commands based on user intent ###########    
#  #####            for ACL Generator Agent 
# # ####################################################################################################
def get_Generate_ACL_instructions(context_variables):
    """
    Builds the prompt for:
      - mode="generate"
      - mode="applyonintf"
      - mode="fix_attachment"
      - mode="fix_order"
    """
    topology_file = context_variables.get("topology_file", None)

    direction     = context_variables.get("direction", None)
    List_Found    = context_variables.get("List_Found", None)
    L_Name        = context_variables.get("L_Name", None)
    Intf_Name     = context_variables.get("Intf_Name", None)
    
    src_ip        = context_variables.get("src_ip", None)
    dst_ip        = context_variables.get("dst_ip", None)
    src_subnet    = context_variables.get("src_subnet", None)   # must already be "net wildcard"
    dst_subnet    = context_variables.get("dst_subnet", None)   # must already be "net wildcard"
    protocol      = context_variables.get("protocol", None)
    port          = context_variables.get("port", None)
    action        = context_variables.get("action", None)

    mode          = (context_variables.get("mode") or "generate").strip().lower()

    # Used only in fix_attachment mode / reorder mode
    config_text        = context_variables.get("config_text", None)
    planned_intf       = context_variables.get("planned_intf", None)
    planned_dir        = context_variables.get("planned_dir", None)
    suggest_Intf_Name  = context_variables.get("suggest_Intf_Name", None)
    suggest_dir        = context_variables.get("suggest_dir", None)

    evidence           = context_variables.get("batfish_evidence", {})

    if mode == "generate":
        action_n = None if action is None else str(action).strip().lower()
        protocol_n = None if protocol is None else str(protocol).strip().lower()
        direction_n = None if direction is None else str(direction).strip().lower()
        intf_n = None if Intf_Name is None else str(Intf_Name).strip()
        return f"""     You are a Cisco IOS ACL CONFIG RENDERER.
            You MUST generate configuration commands ONLY from the provided entities.
            You MUST NOT use or infer anything beyond the entities.
            You MUST NOT change any entity values.
            You MUST NOT add extra ACL lines (no catch-all).
            No explanations. No comments. Output commands only.
            
            ========================
            PROVIDED ENTITIES (SOURCE OF TRUTH)
            ========================
            Action: {action_n}
            Protocol: {protocol_n}
            Port: {port}
            Source IP: {src_ip}
            Destination IP: {dst_ip}
            Source Subnet: {src_subnet}
            Destination Subnet: {dst_subnet}
            Interface: {intf_n}
            Direction: {direction_n}
            ========================
            VALIDATION (NO GUESSING)
            ========================
            If ANY of these is missing/invalid:
            - Action not in {{permit, deny}}
            - Interface is None/empty
            - Direction not in {{in, out}}
            - Port is not None AND Protocol is not tcp/udp
            - Source Subnet is provided but is not a valid CIDR or Cisco wildcard subnet
            - Destination Subnet is provided but is not a valid CIDR or Cisco wildcard subnet
            Then output EXACTLY one line:
            ERROR: INVALID_OR_INCOMPLETE_ENTITIES
            
            ========================
            ACL NAME
            ========================
            If {List_Found} is True:
            ACL_NAME = {L_Name}
            Else:
            ACL_NAME = ACL_{Intf_Name}_{direction}
            Apply naming rules:
            - Uppercase
            - Replace non [A-Z0-9_] with "_"
            - If starts with digit, prefix "ACL_"
            - Direction token must be IN or OUT (uppercase) in ACL_NAME only
            
            ========================
            BUILD SOURCE TOKEN
            ========================
            If Source IP is not None -> "host <Source IP>"
            Else if Source Subnet is not None  -> convert CIDR to Cisco network wildcard
            Else -> "any"
            
            ========================
            BUILD DESTINATION TOKEN
            ========================
            If Destination IP is not None -> "host <Destination IP>"
            Else if Destination Subnet is not None -> convert CIDR to Cisco network wildcard
            Else -> "any"
            
            ========================
            BUILD PROTOCOL TOKEN
            ========================
            If Port is not None -> use Protocol as-is
            Else if Protocol is None -> "ip"
            Else -> Protocol as-is
            
            ========================
            BUILD PORT TOKEN
            ========================
            If Port is None -> no port token
            Else -> "eq <Port>"
            
            ========================
            OUTPUT (COMMANDS ONLY)
            ========================
            ip access-list extended <ACL_NAME>
             <Action> <ProtocolToken> <SourceToken> <DestinationToken> [PortToken]
            
            interface <Interface>
             ip access-group <ACL_NAME> <Direction>

            ========================
            EXISTING CONFIG (REFERENCE ONLY; DO NOT EXTRACT/INFER)
            ========================
            {topology_file}
            """
    elif mode == "applyonintf":
        return f"""You are a Cisco IOS ACL APPLICATION RENDERER.

            You MUST output ONLY Cisco IOS configuration commands.
            No explanations. No comments. No extra text.
            
            You MUST NOT create, modify, or repeat any ACL rules.
            You MUST NOT redefine the ACL.
            You MUST ONLY apply the EXISTING ACL to the PROVIDED interface and direction.
            You MUST NOT correct or change the provided interface/direction/ACL name.
            
            ========================
            INPUTS (SOURCE OF TRUTH)
            ========================
            ACL Name: {L_Name}
            Interface: {Intf_Name}
            Direction: {direction}
            
            ========================
            VALIDATION (NO GUESSING)
            ========================
            If ANY of these is missing/invalid:
            - ACL Name is None/empty
            - Interface is None/empty
            - Direction not exactly "in" or "out"
            Then output EXACTLY one line:
            ERROR: INVALID_OR_INCOMPLETE_PLACEMENT
            
            ========================
            OUTPUT (COMMANDS ONLY)
            ========================
            interface {Intf_Name}
             ip access-group {L_Name} {direction}
            
            ========================
            EXISTING CONFIG (REFERENCE ONLY; DO NOT INFER)
            ========================
            {topology_file}
            """
    elif mode == "fix_attachment":
        # acl_name_rule = f"change the ACL name to: ACL_{suggest_Intf_Name}_{suggest_dir}".upper().replace("/", "_").replace("-", "_")
        return f"""
        GOAL:
        Fix ONLY the ACL attachment for ACL "{L_Name}" using the provided correct interface and direction.
        
        HARD RULES:
        - Do NOT change any ACL rule lines or sequencing.
        - Copy the ACL definition block exactly.
        - Do NOT rename the ACL.
        - Do NOT add or remove anything inside the ACL definition block.
        - Do NOT infer interface or direction from the snippet.
        - Use ONLY the provided correct attachment.
        - You MAY delete wrong ip access-group lines from interface blocks.
        - Final output must contain exactly:
          1) The unchanged ACL definition block  
          2) A blank line
          3) ONE interface block:
             interface {suggest_Intf_Name}
              ip access-group {L_Name} {suggest_dir}
        - Do NOT include "no ip access-group" lines.
        - Do NOT include any other interface blocks.
        
        INPUT SNIPPET:
        {config_text}
        
        CORRECT ATTACHMENT:
        Interface: {suggest_Intf_Name}
        Direction: {suggest_dir}
        
        VALIDATION:
        If you cannot find an "ip access-list extended {L_Name}" block in the input snippet, output EXACTLY:
        ERROR: ACL_BLOCK_NOT_FOUND
        """.strip()

    elif mode == "fix_order":
        acl_text = context_variables["acl_text"]
        q3_rows = context_variables["q3_df_rows"]
    
        evidence_lines = []
        for i, r in enumerate(q3_rows, 1):
            evidence_lines.append(
                f"{i}) Unreachable_Line={r.get('Unreachable_Line')} | "
                f"Blocking_Lines={r.get('Blocking_Lines')}"
            )
        evidence = "\n".join(evidence_lines)
    
        return f"""
            GOAL:
            Fix unreachable ACL lines using REORDERING ONLY.
            
            HARD RULES:
            - Do NOT add lines.
            - Do NOT remove lines.
            - Do NOT edit any line.
            - Do NOT rename the ACL.
            - Keep every line exactly as written.
            - Output only the reordered ACL block.
            - Do NOT output interface text.
            - Do NOT output explanations.
            - Do NOT output markdown fences.
            
            INPUT ACL BLOCK:
            {acl_text}
            
            BATFISH Q3 EVIDENCE:
            {evidence}
            
            VALIDATION:
            - The output must be an exact permutation of the input ACL block lines.
            - If impossible, output exactly:
            ERROR: CANNOT_REORDER_WITHOUT_EDITING
            """.strip()
    # elif mode == "fix_order":
    #     acl_text = context_variables["acl_text"]
    #     # interface_text = context_variables.get("interface_text", "")
    #     q3_rows = context_variables["q3_df_rows"]

    #     evidence_lines = []
    #     for i, r in enumerate(q3_rows, 1):
    #         evidence_lines.append(
    #             f"{i}) Unreachable_Line={r.get('Unreachable_Line')} | "
    #             f"Blocking_Lines={r.get('Blocking_Lines')}"
    #         )
    #     evidence = "\n".join(evidence_lines)
    
    #     # Also enumerate ACL lines for clarity
    #     acl_lines = acl_text.splitlines()
    #     numbered_acl = "\n".join(f"{i+1}) {line}" for i, line in enumerate(acl_lines))

    #     prompt = f"""
    #     GOAL:
    #     Fix unreachable ACL lines using REORDERING ONLY, based on Batfish Q3 evidence.
        
    #     ABSOLUTE HARD CONSTRAINTS:
    #     - Do NOT add any new line.
    #     - Do NOT remove any existing line.
    #     - Do NOT edit any line.
    #     - Do NOT rename the ACL.
    #     - Do NOT change spacing, capitalization, or tokens in any line.
    #     - The output must contain exactly the same lines as the input ACL block.
    #     - The output must be only a permutation of the input ACL block lines.
    #     - Every line in the output must be copied verbatim from the input ACL block.
    #     - Do NOT output the interface stanza.
    #     - Do NOT output explanations.
    #     - Do NOT output markdown fences.
    #     - Do NOT output anything except the final reordered ACL block.
        
    #     INPUT ACL BLOCK (verbatim lines):
    #     {acl_text}
        
    #     NUMBERED VIEW OF INPUT ACL BLOCK:
    #     {numbered_acl}
        
    #     BATFISH Q3 EVIDENCE:
    #     {evidence}
        
    #     REORDERING REQUIREMENTS:
    #     - Each Unreachable_Line must appear before each of its Blocking_Lines.
    #     - Preserve the relative order of unrelated lines whenever possible.
    #     - Keep broad catch-all rules near the end whenever possible.
    #     - If a line cannot be made reachable without editing, still keep it, but move it as low as possible.
        
    #     VALIDATION RULE:
    #     If you cannot produce an output that is an exact permutation of the input ACL block lines, output EXACTLY:
    #     ERROR: CANNOT_REORDER_WITHOUT_EDITING
    #     """.strip()