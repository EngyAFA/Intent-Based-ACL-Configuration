### Dataset Generation

# Multi-Router ACL Intent Generator

DS_generate_multi_router_topo.py generates large ACL intent datasets programmatically for the proposed topology (multirouter_topology.jso).

It is designed for evaluating an ACL-generation multi-agent system and test whether the agent correctly identifies:

- intents entities (src, dst, protocol, port, action (`permit` or `deny`))
- enforcement device (`R1`, `R2`, or `R3`)
- interface
- direction (`in` or `out`)
- final generated Cisco ACL CLI

---

## 1. Topology Model

The generator assumes a topology (multirouter_topology.json) with these security zones:

- `LAN_A`
- `DMZ`
- `LAN_B`
- `Internet`

Example hosts:

- `PC1`, `PC2`, `PC3`, `PC6` in `LAN_A`
- `WEB1`, `APP1` in `DMZ`
- `PC4`, `PC5`, `PC7`, `PC8` in `LAN_B`

The generator uses an internal `OBJECTS` dictionary that defines:

- object type: `host`, `subnet`, or `any`
- IP address
- wildcard mask
- zone ownership

Example:

```python
"PC1": {"kind": "host", "ip": "192.168.10.10", "wildcard": "0.0.0.0", "zone": "LAN_A"}
```

## 2. Output Structure

Each generated test case contains:
- id
- description
- context_file
- nl_query
- expected_ir
- expected_cli

- Example:
```python
{
  "id": "mr_mixed_0001",
  "description": "Permit HTTPS from PC1 to WEB1",
  "context_file": "multirouter_topology.json",
  "nl_query": "Allow PC1 to access WEB1 on HTTPS.",
  "expected_ir": {
    "rules": [
      {
        "id": "ACL_R1_F0_0_IN",
        "acl_type": "extended",
        "action": "permit",
        "protocol": "tcp",
        "src": { "object": "PC1", "ip": "192.168.10.10", "wildcard": "0.0.0.0" },
        "dst": { "object": "WEB1", "ip": "192.168.20.10", "wildcard": "0.0.0.0" },
        "dst_port": { "op": "eq", "port": 443 },
        "device": "R1",
        "apply": { "interface": "f0/0", "direction": "in" },
        "sequence": 10,
        "log": false
      }
    ],
    "metadata": {
      "raw_policy": "Permit PC1 to WEB1 on HTTPS",
      "warnings": []
    }
  },
  "expected_cli": "ip access-list extended ACL_R1_F0_0_IN\n 10 permit tcp host 192.168.10.10 host 192.168.20.10 eq 443\ninterface f0/0\n ip access-group ACL_R1_F0_0_IN in"
}
```

## 3. Device Selection Policy

The generator uses a closest-to-source policy which means the enforcement router is selected based on the source zone:
- LAN_A → R1
- Internet → R2
- DMZ → R3
- LAN_B → R3
This makes the process of getting the expected device deterministic and easy to evaluate.

## 4. Supported Services

The generator supports these services:
- HTTP → tcp/80
- HTTPS → tcp/443
- DNS → udp/53
- SSH → tcp/22
- TELNET → tcp/23
- ICMP
- ANY → ip
These are defined in the SERVICES dictionary.

## 5. Placement direction

1- mode="in" : Apply the ACL on the ingress interface of the selected device.

Example:
```python
traffic from PC1 in LAN_A → ACL placed on R1 f0/0 in
```
2- mode="out" : Apply the ACL on the egress interface of the selected device toward the destination.

Example:
```python
traffic from PC1 to Internet → ACL may be placed on R1 s0/1 out
```
3- mode="mixed"

Randomly choose between in and out placement.

This is useful for building a harder benchmark.

## 6. Files Generated

The generator produces both JSON and JSONL versions:
1- *_in.json → ingress placement dataset
2- *_out.json → egress placement dataset
3- *_mixed.json → mixed placement dataset
If paraphrases are enabled, the files contain both:
  base intents
  paraphrased variants

## 7. Run

Run the script normally with Python:
```python
python3 DS_generate_multi_router_topo.py
```
## 8. Variables
- BASE_COUNT = the number of base intents needed to be generated

- PARAPHRASES_PER_INTENT = the number of paraphrases for each base intent

### Single-Router Topology

In addition to the multi-router topology, the project also includes a simpler **single-router topology** (one_router_topology.json) used for initial experiments. In this setup, all networks (LAN, DMZ, and Internet) connect to a single router (`R1`).
Run:
```python
python3 DS_generate_one_router_topo.py
```

#### To generate Routers Configurations Files

Run Rconfig_file_generator.py to generate the config files for R1, R2, and R3 based on our topology in multirouter_topology.json

### Dataset Generation to evaluate the performance the Rule Conflict Detection Module

WE generate two additional datasets derived from the GT:
- First, a balanced synthetic benchmark consisting of 450 cases (150 duplicate, 150 conflict, and 150 valid), by generating candidate rules and labeling them as {duplicate}, \emph{conflict}, or \emph{valid}
This dataset is used to test whether the module can correctly classify standard cases, i.e., rules with direct overlaps and no ambiguity in rule ordering or path.

Run
```python
python3 build_synthetic_conflict_benchmark.py
```
- Second, smaller set of 30 hard test cases to evaluate the robustness of the module.
These cases include {shadowed overlaps}, where earlier rules already handle the traffic, and {off-path overlaps}, where overlapping traffic does not pass through the interface where the rule is applied.
These scenarios are designed to highlight the limitations of simple overlap-based detection and to demonstrate the benefit of the proposed path-aware approach.

Run
```python
python3 generate_hard_conflict_cases.py
```
