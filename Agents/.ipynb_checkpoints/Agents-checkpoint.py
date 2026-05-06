import os
import traceback

from swarm import Swarm, Agent
from .prompts import * 
from Batfish.Questions import *

from typing import Optional
from Agents.prompts import *#build_interface_query_prompt,
from openai import OpenAI
from typing import Optional

########### Initialize Swarm with GPT model ###########
client = Swarm()


########### Helping function: normalization functions ###########
#################################################################

def normalize_interface_name(name):
    if name is None:
        return None

    name = str(name).strip()
    if not name:
        return None

    name = name.splitlines()[0].strip()
    name = name.lower()

    if name.startswith("interface "):
        name = name[len("interface "):].strip()

    return name
    
def clean_single_line(text):
    if text is None:
        return None
    text = str(text).strip()
    if not text:
        return None
    return text.splitlines()[0].strip()

def normalize_direction_token(text: str) -> str:
    t = clean_single_line(text).lower()
    if t.startswith("in"):
        return "in"
    if t.startswith("out"):
        return "out"
    return "None"

def normalize_acl_name_token(text: str) -> Optional[str]:
    t = clean_single_line(text)
    if t.lower() == "none":
        return None
    return t

############# call the ACL placement resolver to get an answer for specific Query on the given topology #############
########################################################################################################################

def gpt_acl_resolver(prompt: str, task: str) -> str: ## for ACL placement resolver
    task = (task or "").strip().lower()

    if task == "interface":
        system_prompt = """
            You are a network ACL placement resolver.
            
            Determine the ingress interface on the chosen device for the described traffic.
            
            Output rules:
            - Return exactly one interface name only.
            - No explanation.
            - No punctuation.
            - No markdown.
            - Examples: g0/0, g0/1, fa0/0
            - If not derivable from the provided text, return exactly: None
            """.strip()

    elif task == "direction":
        system_prompt = """
            You are a network ACL placement resolver.
            
            Determine whether the ACL should be applied inbound or outbound on the specified interface.
            
            Output rules:
            - Return exactly one token only: in or out
            - No explanation.
            - No punctuation.
            - No markdown.
            - If not derivable from the provided text, return exactly: None
            """.strip()

    elif task == "acl_name":
        system_prompt = """
            You are reading Cisco IOS router configuration.
            
            Determine whether an ACL is already applied on the specified interface and direction.
            
            Output rules:
            - Return exactly one token only:
              - the ACL name, or
              - None
            - No explanation.
            - No punctuation.
            - No markdown.
            """.strip()

    else:
        return "ERROR: UNKNOWN_RESOLVER_TASK"

    return Answer_Query(
        prompt,
        system_prompt=system_prompt,
        model="gpt-40",
    )

def Answer_Query(
    prompt: str,
    *,
    system_prompt: str,
    model: str = "gpt-4o",
) -> str:
    
    if prompt is None:
        return "ERROR: PROMPT_IS_NONE"
    print(f"[GPT:{model}] Processing: {prompt[:120]!r} ...")

    try:
        response = client.run(
                        agent = Query_agent, ## for ACL placement resolver
                     messages = [{"role": "system", "content": system_prompt},
                                {"role": "user", "content": prompt},],
        )

        content = response.messages[-1]["content"]
        if content is None:
            return "ERROR: EMPTY_RESPONSE"

        content = content.strip()
        if not content:
            return "ERROR: EMPTY_RESPONSE"

        print("[GPT RAW OUTPUT]:", repr(content))
        return content

    except Exception as e:
        return f"ERROR: API_FAILURE: {str(e)}"

def resolve_acl_placement(*, topo, new_intent, hostname, config_text):
    '''
    it returns the following entities:
        "Intf_Name"
        "direction"
        "ACLname"
        "List_Found" to shower whether the list existed before or not 
    '''
    try:
        # print("=== resolve_acl_placement: start ===")
        # print("topo type:", type(topo))
        # print("hostname:", hostname)
        # print("intent:", new_intent)

        # Built the interface prompt ( system prmpt here inside gpt_acl_resolver and user prmpt there inside prompt.py)
        intf_q = build_interface_query_prompt(
                  topo= topo,
            new_intent= new_intent,
              hostname= hostname,
        )

        intf_name_raw = gpt_acl_resolver(intf_q, task="interface")
        # print("A: got raw interface")
        # print("intf_name_raw repr:", repr(intf_name_raw))
        # print("intf_name_raw type:", type(intf_name_raw))

        tmp = clean_single_line(intf_name_raw)
        # print("B: after clean_single_line")
        # print("tmp repr:", repr(tmp))
        # print("tmp type:", type(tmp))

        intf_name = normalize_interface_name(tmp)
        # print("C: after normalize_interface_name")
        # print("intf_name:", repr(intf_name))
        
        # Built the direction prompt ( system prmpt here inside gpt_acl_resolver and user prmpt there inside prompt.py)
        dir_q = build_direction_query_prompt(
                   new_intent= new_intent,
                     hostname= hostname,
            ingress_interface= intf_name,
        )
        # print("built direction prompt")
        # print("dir_q:", repr(dir_q))

        direction_raw = gpt_acl_resolver(dir_q, task="direction")
        # print("direction_raw:", repr(direction_raw))

        direction = normalize_direction_token(direction_raw)
        # print("direction:", repr(direction))
        
        # Built the acl_name prompt ( system prmpt here inside gpt_acl_resolver and user prmpt there inside prompt.py)
        acl_q = build_acl_name_query_prompt(
               config_text= config_text,
            interface_name= intf_name,
                 direction= direction,
        )
        # print("built acl-name prompt")

        acl_name_raw = gpt_acl_resolver(acl_q, task="acl_name")
        print("acl_name_raw:", repr(acl_name_raw))

        acl_name = normalize_acl_name_token(acl_name_raw)
        # print("acl_name:", repr(acl_name))

        result = {
            "Intf_Name": intf_name,
            "direction": direction,
              "ACLname": acl_name,
            "List_Found": acl_name is not None,
        }
        # print("placement result:", result)
        return result

    except Exception as e:
        print("ERROR inside resolve_acl_placement:", repr(e))
        traceback.print_exc()
        raise
        
############# call the Entity_extractor_agent to get the entities for the user intent  #############
#####################################################################################################
def Entity_Extractor_Evalcaller(context_variables):
    resolved_names = context_variables.get("resolved_names")
    new_intent     = context_variables.get("new_intent")   

    entities_response = client.run( 
                                    agent = EntitiesAgentEval,
                                 messages = [{"role": "system", "content": new_intent}],
                        context_variables = context_variables,
                        )
    extraction_result = entities_response.messages[-1]["content"].strip()
    return extraction_result

############# call the ACL_generator_agent to generate the ACL for the given intent with topology  #############
##################################################################################################################
def ACL_generator_caller(context_variables):
    topology_file = context_variables.get("topology_file", None)
    new_intent    = context_variables.get("new_intent", None) 
    L_Name        = context_variables.get("L_Name", None) 
    mode          = context_variables.get("mode", None) 
    direction         = context_variables.get("direction", None) 
    List_Found        = context_variables.get("List_Found", None) 
     
    configuration_response = client.run(
                                    agent = ACL_agent,
                                 messages = [{"role": "system", "content": get_Generate_ACL_instructions(context_variables)}],
                        context_variables = context_variables,
                        )
    configuration_response = configuration_response.messages[-1]["content"]
    return configuration_response

########### Helping function: extract entities regarding the rule and list existence ###########
################################################################################################

# check if List exists and if Rule exists
def extract_Foundentities(output):
    entities = {}
    # Split the output into lines and process each line
    for line in output.strip().split('\n'):
        # Remove leading dashes and check for key-value format
        line = line.lstrip('- ').strip()  # Remove leading dash and whitespace
        if ': ' in line:  # Ensure there's a colon
            key, value = line.split(': ', 1)  # Split on the first occurrence of ": "
            entities[key.strip()] = value.strip() if value.strip() != "None" else None

    List_exists = entities.get("List_Found")   
    Rule_exists = entities.get("Rule_Found")  # Default to 'false' if not found
    
    return List_exists, Rule_exists
    
###########################################################################################
### Helping Function : Split the output into lines and extract entities to use them later ##
###########################################################################################

def extract_entities(output):
    entities = {}
    # Split the output into lines and process each line
    for line in output.strip().split('\n'):
        # Remove leading dashes and check for key-value format
        line = line.lstrip('- ').strip()  # Remove leading dash and whitespace
        if ': ' in line:  # Ensure there's a colon
            key, value = line.split(': ', 1)  # Split on the first occurrence of ": "
            entities[key.strip()] = value.strip() if value.strip() != "None" else None

    # Accessing the variables
    source_ip = entities.get("Source IP")
    destination_ip = entities.get("Destination IP")
    
    # Print the extracted values for debugging
    # print(f"Destination IP: {destination_ip}")  # Debug print
    protocol = entities.get("Protocol")
    port = entities.get("Port")
    action = entities.get("Action")
    app = entities.get("Application")
    src_Subnet = entities.get("Source IP Subnet")
    dst_Subnet = entities.get("Destination IP Subnet")
    # if src_Subnet != None:
    #     src_Subnet = src_Subnet.split('/')[0]
    # if dst_Subnet != None:
    #     dst_Subnet = dst_Subnet.split('/')[0]

    return source_ip, destination_ip, protocol, port, action, app, src_Subnet, dst_Subnet

########################################## AI Agents ##########################################
###############################################################################################

#################################
## Entity Extractor Agent (1) ##
#################################

EntitiesAgentEval = Agent(
                        name = "Rule Pre-Processing Agent",
                instructions = entity_extraction_Evaluation,
                        model= "gpt-4o",
                   functions = [extract_entities],
)

######################################
## ACL Placement Resolver Agent (2) ##
######################################

# This agent help to extract specific information from a given configuration file/block 
Query_agent = Agent(
                    name = "Answer question/query about the configuration file",
                    model= "gpt-4o",
            instructions = Network_LLM,
)


#############################
## ACL Generator Agent (3) ##
#############################

ACL_agent = Agent(
                    name = "ACL Generator",
                    model= "gpt-4o", # message=[{"role": "user", "content": File_name}]
            instructions = get_Generate_ACL_instructions,
)

       