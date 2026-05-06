import os

from swarm import Swarm, Agent
from Agents.promptsDS import *#build_interface_query_prompt, build_direction_query_prompt,  build_acl_name_query_prompt, build_entity_extraction_prompt
from Agents.deepseek_tool import *  # Import the DeepSeek function
from openai import OpenAI
from typing import Optional


# ########### Initialize Swarm with DeepSeek model ###########
# swarm_client = Swarm()

# Initialize OpenAI client with DeepSeek API
deepseek_client = OpenAI(
    api_key  = os.getenv("OPENAI_API_KEY"),  # Your DeepSeek API key
    base_url = os.getenv("OPENAI_BASE_URL")
)

# ########### Initialize Swarm with DeepSeek model ###########
client = Swarm(client=deepseek_client)#, model="deepseek-coder")

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

def resolve_acl_placement(*, topo, new_intent, hostname, config_text):
    import traceback

    try:
        # print("=== resolve_acl_placement: start ===")
        # print("topo type:", type(topo))
        # print("hostname:", hostname)
        # print("intent:", new_intent)
        
        # Built the interface prompt ( system prmpt inside promptDS.py and user prmpt there inside prompt.py)
        intf_q = build_interface_query_prompt(
            topo=topo,
            new_intent=new_intent,
            hostname=hostname,
        )
        # print("built interface prompt")

        intf_name_raw = deepseek_acl_resolver(intf_q, task="interface")
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

        # Built the direction prompt ( system prmpt inside promptDS.py and user prmpt there inside prompt.py)
        dir_q = build_direction_query_prompt(
            new_intent=new_intent,
            hostname=hostname,
            ingress_interface=intf_name,
        )
        # print("built direction prompt")
        # print("dir_q:", repr(dir_q))

        direction_raw = deepseek_acl_resolver(dir_q, task="direction")
        # print("direction_raw:", repr(direction_raw))

        direction = normalize_direction_token(direction_raw)
        # print("direction:", repr(direction))
       
        # Built the acl_name prompt ( system prmpt inside promptDS.py and user prmpt there inside prompt.py)
        acl_q = build_acl_name_query_prompt(
            config_text=config_text,
            interface_name=intf_name,
            direction=direction,
        )
        # print("built acl-name prompt")

        acl_name_raw = deepseek_acl_resolver(acl_q, task="acl_name")
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
    # Step 1: build prompt
    prompt = build_entity_extraction_prompt(context_variables)

    # Step 2: call LLM
    result = deepseek_extract_entities(prompt)

    return result

############# call the ACL_generator_agent to generate the ACL for the given intent with topology  #############
##################################################################################################################

def ACL_generator_caller(context_variables):
            prompt = build_acl_generator_prompt(context_variables)
            mode = (context_variables.get("mode") or "generate").strip().lower()
    return deepseek_acl_generator(prompt, mode)

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
    app = entities.get("application")
    src_Subnet = entities.get("Source IP Subnet")
    dst_Subnet = entities.get("Destination IP Subnet")
    if src_Subnet != None:
        src_Subnet = src_Subnet.split('/')[0]
    if dst_Subnet != None:
        dst_Subnet = dst_Subnet.split('/')[0]

    return source_ip, destination_ip, protocol, port, action, app, src_Subnet, dst_Subnet

