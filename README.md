# Reliable ACL Configuration

This project translates a natural-language security intent into Cisco ACL configuration, validates the generated policy with Batfish, and then validates it again on a Network Digital Twin in GNS3.

The workflow is:

Intent → LLM ACL generation → Batfish verification/fine-tuning → GNS3 verification → final approved router configuration

<img width="841" height="408" alt="image" src="https://github.com/user-attachments/assets/1f424248-b280-4404-8e14-051f7d36cea5" />

---

## Project Entry Point

Use:

`ACL_generate_System.ipynb`

This notebook runs the full framework:

- LLM-based ACL generation
  
- Batfish verification

  
- GNS3 / Network Digital Twin verification

---

## Models Supported

The project supports both:

- GPT
  
- DeepSeek

You should activate only one model setup at a time.

---

## 1. Environment Setup

Update the API keys in:

`Helpers/env.py`

### For GPT

Activate:

```python
os.environ["OPENAI_API_KEY"] = "YOUR_OPENAI_API_KEY_HERE"
```

### For DeepSeek

Activate:
```python
os.environ["OPENAI_API_KEY"] = "YOUR_deepSeek_API_KEY_HERE"
os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com/v1"
```

DeepSeek uses the OpenAI-compatible client, so both variables are required.

## 2. Topology and Configuration Files

Put the router configuration files inside the configs/ folder.

Also place the network topology file inside the same folder.

Typical files in configs/ include:

R1.cfg

R2.cfg

R3.cfg

TopologyFile.json

The system reads these files to:

understand the network structure

choose the relevant router

generate ACL placement

build candidate updated router configs such as R1_2.cfg, R2_2.cfg, or R3_2.cfg

## 3. GNS3 Device Information

Inside the notebook, update the GNS3 console connection information (console variable).

This includes:

console IP

console port

device name

device type

These values must match your actual GNS3 lab and server setup.

You also need to define the subnet and endpoint information used by the validation stage (Sub_Net variable).

## 4. Running the System

Inside ACL_generate_System.ipynb, prepare the input variables and build context_variables.

Then run:
```python
result = run_llm_batfish_gns3_cycle(
    context_variables=context_variables,
    batfish_host="your Batfish server IP",
    devices=Consol,
    max_gns3_repairs=3, 
    max_batfish_iters=3, 
    include_save=True,
    cleanup_candidate_on_success=False,
    verbose=True,
)

```

This step translates the user intent into ACL configuration using (run_ACL_workflow) and produces:

generated ACL rules

selected router

interface and direction

ACL name

updated candidate configuration

The full pipeline then validates the candidate using Batfish (Batfish_validate_until_ok) and GNS3 (validate_acl_in_gns3).

## 5. Candidate File Strategy

The system does not overwrite the original router file immediately.

If the selected router is, for example, R3, the system works on a candidate file:
```
R3_2.cfg
```
After Batfish and GNS3 both succeed, the final candidate is copied back to:
```
R3.cfg
```
At the final promotion step, the hostname inside the file must also be restored from:
```hostname R3_2``` to ```hostname R3```

This is important to keep the final router configuration consistent with the original device name.

## 6. Files Used for GPT

Use these files in the import section for the GPT version:

Agents.py

multiAgent.py

prompts.py

## 7. Files Used for DeepSeek

Use these files in the import section for the DeepSeek version:

AgentsDS.py

multiAgentDS.py

promptDS.py



## 8. Verification Stages
Batfish Verification

Batfish checks:

ACL placement

expected traffic behavior

violation space

unreachable or shadowed ACL lines

GNS3 Verification

GNS3 checks:

ACL deployment on the router

router-side ACL attachment

traffic behavior from test hosts

ACL hit counters when applicable

## 9. Notes
Use a clean original router config before each full test run.

Candidate files such as R1_2.cfg should be treated as temporary working files.

Batfish and GNS3 must both succeed before promoting the candidate file to the original router file.

Only one model setup should be active at a time: GPT or DeepSeek.

## 10. Example Usage
Set API keys in Helpers/env.py

Put topology and router configs in configs/

Update GNS3 console information in the notebook

Open ACL_generate_System.ipynb

Enter a natural-language intent

Run the notebook cells

Review Batfish and GNS3 validation results

If validation succeeds, promote the candidate config to the original router config

*Note:
If you use another topology, be sure about the changes in the topology inside :
```
Helpers.env
Helpers.norm_device
Helpers.Finder.extract_router_facts_from_json
Helpers.Formats.normalize_interface_name
Batfish.preprocess._norm_intf
Batfish.preprocess._infer_iface_subnet_from_subnet_db
GNS3.GNS3.Router_Access
GNS3.Validate -> default CONFIG variable and class Endpoint values
input variables + default variables  (e.x, Sub_Net, Consol, etc) in ACL_generate_System , ACL_generate_Evaluation_DeepSeek and ACL_generate_Evaluation_GPT
```

## Network Topology

We used the topology saved in .\config folder to test the system :
<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/8cc33ea5-11c8-47bb-95c2-f5af19d09907" />

