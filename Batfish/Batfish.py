import os
import re
import shutil
import traceback
import json
from Helpers.Parse import parse_config_to_json

from pybatfish.client.session import Session  
from pybatfish.datamodel import Edge, Interface  
from pybatfish.datamodel.answer import TableAnswer
from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints  
from pybatfish.datamodel.route import BgpRoute 
from Batfish.preprocess import _intent_directionality, _infer_stage_from_results, _norm_intf, _norm_dir
from Batfish.preprocess import *
from Batfish.Questions import *

from pybatfish.util import get_html

# from Agents.AgentsDS import *  # activae for Deep Seek
from Agents.Agents import Entity_Extractor_Evalcaller, ACL_generator_caller, extract_entities#*  # activae for GPT

from Helpers.Read_Files import *
import Helpers.env
from Helpers.Formats import *
from Helpers.Read_Files import *
from Helpers.Parse import *
from Helpers.Finder import *
from Helpers.configs import *


########## Initialization BF Session ###########
################################################
def Initialization_Batfish_session(host, SNAPSHOT_NAME, hostname):
    bf = Session(host= host)
    # Initialize a network and a snapshot
    bf.set_network("network_ACL")
    SNAPSHOT_NAME = SNAPSHOT_NAME #"current"
    SNAPSHOT_PATH = "." 
    bf.init_snapshot(SNAPSHOT_PATH, name=SNAPSHOT_NAME, overwrite=True)
    node_name = hostname
    # AccessList_name = L_name
    return bf, node_name, SNAPSHOT_PATH, SNAPSHOT_NAME

########## Ensure we have a config file and initialize Batfish.############
    # - Prefer <hostname>_2.cfg if it exists, otherwise <hostname>.cfg.
    # - Returns: (bf, node_name, snapshot_name, config_file_path)
###########################################################################

def prepare_batfish_context(batfish_host, hostname, config_dir = "configs"):
    
    cfg2_path = os.path.join(config_dir, f"{hostname}_2.cfg")
    if os.path.exists(cfg2_path):
        config_file_path = cfg2_path
        node_name = f"{hostname}_2"
        parse_config_to_json(os.path.join(config_dir, f"{hostname}_2"))
    else:
        cfg_path = os.path.join(config_dir, f"{hostname}.cfg")
        if not os.path.exists(cfg_path):
            raise FileNotFoundError(f"No config file found for {hostname} in {config_dir}")
        config_file_path = cfg_path
        node_name = hostname
        parse_config_to_json(os.path.join(config_dir, hostname))

    SNAPSHOT_NAME = config_dir  # using "configs" as snapshot name
    bf, node_name, SNAPSHOT_PATH, SNAPSHOT_NAME = Initialization_Batfish_session(
        batfish_host, SNAPSHOT_NAME, node_name
    )

    return bf, node_name, SNAPSHOT_NAME, config_file_path



def Batfish_validate_once(client, context_variables, batfish_host, snapshot_name="configs", verbose=True):
    """
    Validates the LLM-generated ACL in 3 layers:

    Q0 (Placement): interface + direction correctness
    Q1 (FlowPoint check): testFilters for positive (and optional negative) flow
    Q2 (PolicySpace check): searchFilters violation hunting
    Q3 (Structure): unreachable/shadowed ACL lines

    Returns dict with status:
      - needs_more_data
      - needs_finetune
      - failed
      - ran
    """
    extraction_result = context_variables.get("extraction_result")
    new_intent = context_variables.get("new_intent")
    file_path = context_variables.get("file_path")
    File_name = context_variables.get("File_name")
    Sub_Net = context_variables.get("Sub_Net")
    configuration_response = context_variables.get("configuration_response")
    hostname = f"{File_name}_2" if File_name else None
    print("hostname:",hostname)
    if not file_path or not File_name:
        return make_batfish_result(
            status="needs_more_data",
            final_status="needs_more_data",
            stage="precheck",
            reason="Missing file_path or File_name in context_variables.",
            reasons=["Missing file_path or File_name in context_variables."],
        )

    if extraction_result is None:
        if verbose:
            print("inside extraction_result is None")
        extraction_result = Entity_Extractor_Evalcaller(context_variables)
        context_variables["extraction_result"] = extraction_result
        if extraction_result is None:
            return make_batfish_result(
                status="needs_more_data",
                final_status="needs_more_data",
                stage="precheck",
                reason="Missing extraction_result",
                reasons=["Missing extraction_result"],
            )

    if new_intent is None:
        if verbose:
            print("inside new_intent is None")
        # return {
        #         "status": "needs_more_data",
        #         "reason": "Missing user intent",
        #         "final": {
        #             "status": "needs_more_data",
        #             "stage": "precheck",
        #             "reason": "Missing user intent",
        #         },
        #     }
            return make_batfish_result(
                status="needs_more_data",
                final_status="needs_more_data",
                stage="precheck",
                reason="Missing user intent",
                reasons=["Missing user intent"],
            )
    cfg_path = os.path.join(file_path, f"{hostname}.cfg")
    if not os.path.exists(cfg_path):
        if verbose:
            print(f" Config file missing for {hostname}: {cfg_path}")

        original_cfg_path = os.path.join(file_path, f"{File_name}.cfg")
        topology_content = read_topology_file(original_cfg_path)
        topology_file = "".join(topology_content) if topology_content else ""

        if not configuration_response:
            return make_batfish_result(
                status="needs_more_data",
                final_status="needs_more_data",
                stage="precheck",
                reason="Missing configuration_response; cannot generate candidate config.",
                reasons=["Missing configuration_response; cannot generate candidate config."],
            )

        generate_config2_file(
            file_path,
            configuration_response,
            context_variables.get("Intf_Name"),
            topology_file,
            File_name,
        )
        parse_config_to_json(os.path.join(file_path, hostname))

    source_ip, destination_ip, protocol, port, action, app, src_Subnet, dst_Subnet = extract_entities(extraction_result)
    user_action = action

    if verbose:
        print("src_ip, dst_ip, protocol, port, action, app, src_Subnet, dst_Subnet")
        print(source_ip, destination_ip, protocol, port, action, app, src_Subnet, dst_Subnet)

    file_path2 = os.path.join(file_path, f"{hostname}.json")
    topology_content2 = read_topology_file(file_path2)
    if not topology_content2:
        return make_batfish_result(
                status="needs_more_data",
                final_status="needs_more_data",
                stage="facts",
                reason=f"Missing or unreadable JSON facts file: {file_path2}",
                reasons=[f"Missing or unreadable JSON facts file: {file_path2}"],
            )
        # return {
        #     "status": "needs_more_data",
        #     "reason": f"Missing or unreadable JSON facts file: {file_path2}",
        # }

    config_json = json.loads("".join(topology_content2))
    print("\n=== CONFIG JSON DEBUG ===")
    print(json.dumps(config_json, indent=2)[:3000])
    
    facts = extract_router_facts_from_json(config_json)
    print("\n=== FACTS DEBUG ===")
    print(json.dumps(facts, indent=2, default=str))

    router_interfaces = facts.get("router_interfaces", [])
    default_route_iface = facts.get("default_route_iface")
    inside_prefixes = facts.get("inside_prefixes", [])
    intent_dir = _intent_directionality(new_intent)

    context_variables["intent_dir"] = intent_dir

    if verbose:
        print("intent_dir:", intent_dir)
        print("src_ip:", source_ip)
        print("src_subnet:", src_Subnet)
        print("dst_ip:", destination_ip)
        print("dst_subnet:", dst_Subnet)
        print("router_interfaces:", router_interfaces)

    expected_intf, expected_dir = choose_acl_attachment(
            router_interfaces=router_interfaces,
            default_route_iface=default_route_iface,
            inside_prefixes=inside_prefixes,
            intent_dir=intent_dir,
            src_ip=source_ip,
            src_subnet=src_Subnet,
            dst_ip=destination_ip,
            dst_subnet=dst_Subnet,
        )

        # Preserve workflow placement if Batfish-side inference cannot determine one
    final_intf = expected_intf or context_variables.get("Intf_Name")
    final_dir = expected_dir or context_variables.get("direction")
    
    context_variables.update({
        "action": user_action,
        "src_ip": source_ip,
        "src_subnet": src_Subnet,
        "dst_ip": destination_ip,
        "dst_subnet": dst_Subnet,
        "hostname": hostname,
        "new_intent": new_intent,
        "intent_dir": intent_dir,
        "Intf_Name": final_intf,
        "direction": final_dir,
        "router_interfaces": router_interfaces,
        "default_route_iface": default_route_iface,
        "inside_prefixes": inside_prefixes,
    })

    plan = build_batfish_test_plan(context_variables)

    if verbose:
        print("\n=== Batfish Test Plan ===")
        print(plan)

    plan_status = (plan.get("Plan_Status") or "").strip().lower()
    if plan_status != "ok":
        msg = plan.get("Notes", f"Plan_Status not ok: {plan.get('Plan_Status')}")
        return make_batfish_result(
            status="needs_more_data",
            final_status="needs_more_data",
            stage="plan",
            reason=msg,
            reasons=[msg],
            plan=plan,
        )

    node_name = (plan.get("Device") or "").strip().lower()
    L_Name = (plan.get("ACL_Name") or "").strip()

    if not node_name or not L_Name:
        return make_batfish_result(
            status="needs_more_data",
            final_status="needs_more_data",
            stage="plan",
            reason="Missing Device or ACL_Name in plan",
            reasons=["Missing Device or ACL_Name in plan"],
            plan=plan,
        )
        # return {
        #     "status": "needs_more_data",
        #     "plan": plan,
        #     "reason": "Missing Device or ACL_Name in plan",
        #     "final": {
        #         "status": "needs_more_data",
        #         "stage": "plan",
        #         "reason": "Missing Device or ACL_Name in plan",
        #     },
        # }

    q1_pos_src = plan.get("Q1_Pos_Src_Host")
    q1_pos_dst = plan.get("Q1_Pos_Dst_Host")
    restriction_mode = (plan.get("Q2_Restriction_Mode") or "none").strip().lower()
    expected_action = (plan.get("Expected_Action") or "").strip().lower()
    opposite_action = (plan.get("Opposite_Action") or "").strip().lower()
    plan_app = (plan.get("Application", "none") or "none").strip().lower()
    plan_port = (plan.get("Port", "none") or "none").strip().lower()

    q2_src_subnet = plan.get("Q2_Src_Subnet")
    q2_dst_subnets = csv_to_list(plan.get("Q2_Dst_Subnets"))

    bf, node_name, SNAPSHOT_PATH, SNAPSHOT_NAME = Initialization_Batfish_session(
        batfish_host, snapshot_name, node_name
    )
    node_name = node_name.strip().lower()
    cfg_path = os.path.join(file_path, f"{hostname}.cfg")
    # print("\n=== CFG BEFORE BATFISH ===")
    # with open(cfg_path, "r") as f:
    #     print(f.read())
    print("hostname used for Batfish:", hostname)
    print("cfg_path:", cfg_path)
    print("ACL searched in Batfish:", L_Name)
    attachments, props_df = find_acl_attachments(
        bf=bf,
        hostname=node_name,
        acl_name=L_Name,
        snapshot_name=SNAPSHOT_NAME,
    )
    
    
    try:
        print("Interface properties DF:")
        print(props_df)
    except Exception:
        print("Could not print props_df")

    acceptable = build_acceptable_attachments(
        router_interfaces=router_interfaces,
        default_route_iface=default_route_iface,
        inside_prefixes=inside_prefixes,
        intent_dir=intent_dir,
        src_ip=source_ip,
        src_subnet=src_Subnet,
        dst_ip=destination_ip,
        dst_subnet=dst_Subnet,
    )
    print("\n=== Q0 DEBUG ===")
    print("ACL name from plan:", repr(L_Name))
    print("Expected acceptable:", acceptable)
    print("Raw attachments from Batfish:", attachments)
    
    q0_ok, chosen_intf, chosen_dir, q0_dbg = q0_pick_working_attachment(attachments, acceptable)
    
    def _prefer_q1_attachment(q0_dbg, fallback_intf, fallback_dir):
        """
        For Q1 testing, prefer inbound transit ACLs when multiple acceptable
        attachments exist. This avoids testing routed traffic against an outbound
        LAN ACL with a wrong startLocation.
        """
        matches = q0_dbg.get("matches") or []
    
        # 1) Prefer Serial/Transit inbound, e.g. serial0/0 in
        for intf, direction in matches:
            intf_l = str(intf).lower()
            dir_l = str(direction).lower()
            if dir_l == "in" and intf_l.startswith("serial"):
                return intf, direction
    
        # 2) Then prefer any inbound match
        for intf, direction in matches:
            if str(direction).lower() == "in":
                return intf, direction
    
        # 3) Otherwise keep original choice
        return fallback_intf, fallback_dir
    
    print("Q0 debug details:", q0_dbg)
    results = {
        "status": "ran",
        "plan": plan,
        "Q0": {
            "ok_expected_vs_snapshot": q0_ok,
            "expected": {
                "Intf_Name": (final_intf or "").strip(),
                "Direction": (final_dir or "").strip().lower(),
            },
            "planned": {
                "Intf_Name": (plan.get("Intf_Name") or final_intf or "").strip(),
                "Direction": (plan.get("Direction") or final_dir or "").strip().lower(),
            },
            "expected_best": {
                "Intf_Name": (final_intf or "").strip(),
                "Direction": (final_dir or "").strip().lower(),
            },
            "acceptable": q0_dbg.get("acceptable"),
            "actual_list": q0_dbg.get("actual"),
            "matches": q0_dbg.get("matches"),
            "found_attachments": attachments,
            "interface_properties": props_df,
            "issue": "ok" if q0_ok else ("acl_not_attached" if not attachments else "no_acceptable_attachment_found"),
        },
        "Q1": {},
        "Q2": {},
        "Q3": {},
        "errors": [],
    }

    if not q0_ok:
        suggest_intf, suggest_dir = (acceptable[0] if acceptable else (expected_intf, expected_dir))
        results["failed_verifier"] = "Q0"
        results["reason"] = "No acceptable ACL attachment found."
        results["final"] = {
            "status": "needs_finetune",
            "stage": "Q0",
            "summary": "Needs finetune",
            "reasons": ["No acceptable ACL attachment found."],
            "suggest_fix": {
                "Intf_Name": suggest_intf,
                "Direction": suggest_dir,
            },
        }
        return results

    # Intf_Name = chosen_intf
    # direction = chosen_dir
    Intf_Name, direction = _prefer_q1_attachment(q0_dbg, chosen_intf, chosen_dir)

    context_variables["Intf_Name"] = Intf_Name
    context_variables["direction"] = direction
    
    results["Q0"]["chosen_for_q1"] = {
                                    "Intf_Name": Intf_Name,
                                    "Direction": direction,
                                }

    q1_pos_df = check_Rule_access_at_iface(
        bf=bf,
        src_ip=q1_pos_src,
        dst_ip=q1_pos_dst,
        application=None if plan_app == "none" else plan_app,
        hostname=node_name,
        intf_name=Intf_Name,
        direction=direction,
        snapshot_name=SNAPSHOT_NAME,
    )

    expected_rule_line = context_variables.get("Rule")
    if isinstance(expected_rule_line, (list, tuple)):
        expected_rule_line = expected_rule_line[0] if expected_rule_line else None

    pos_ok, pos_details = q1_validate_result(
        q1_pos_df,
        expected_action=expected_action,
        expected_rule_text=expected_rule_line,
        require_explicit_match=False,
    )
    results["Q1"]["positive"] = {"df": q1_pos_df, "ok": pos_ok, "details": pos_details}

    q2_all_checks = []
    authorized_src_prefix = (
        f"{q1_pos_src}/32"
        if restriction_mode == "only_host"
        else (q2_src_subnet or f"{q1_pos_src}/32")
    )

    q2_all_checks.extend(run_q2_violation_check(
        bf=bf,
        node_name=node_name,
        intf_name=Intf_Name,
        direction=direction,
        snapshot_name=SNAPSHOT_NAME,
        src_prefix=authorized_src_prefix,
        dst_prefixes=q2_dst_subnets,
        action_to_search=opposite_action,
        application=None if plan_app == "none" else plan_app,
        port=None if plan_port == "none" else plan_port,
        label="Q2A(Expected-behavior violations)",
        verbose=verbose,
    ))
    results["Q2"]["violation_checks"] = q2_all_checks

    q3_df = check_Reachibility(bf, node_name)
    results["Q3"]["df"] = q3_df

    # final_status, summary, reasons = decide_from_batfish_results(results)
        # final_status, summary, reasons = decide_from_batfish_results(results)
    final_status, summary, reasons, failed_stage = decide_from_batfish_results(results)
    
    results["status"] = "ran"
    results["failed_verifier"] = failed_stage
    results["final"] = {
        "status": final_status,
        "stage": failed_stage,
        "summary": summary,
        "reasons": reasons if isinstance(reasons, list) else [str(reasons)],
    }
    
    if reasons:
        results["reason"] = reasons[0]
    
    return results

def make_batfish_result(
    status,
    final_status,
    stage=None,
    summary=None,
    reasons=None,
    reason=None,
    failed_verifier=None,
    **extra
):
    """
    Standardized Batfish return payload.

    status:
        top-level execution status: "ran" | "needs_more_data" | "failed"

    final_status:
        validation outcome: "ok" | "needs_finetune" | "needs_more_data" | "failed"

    stage:
        None | "Q0" | "Q1" | "Q2" | "Q3" | "precheck" | "facts" | "plan" | ...
        Only Q0-Q3 count as failed_verifier.

    reason:
        optional single-string reason for backward compatibility

    reasons:
        optional list of reasons for final block
    """
    if reasons is None:
        reasons = []
    elif isinstance(reasons, str):
        reasons = [reasons]

    if summary is None:
        if final_status == "ok":
            summary = "OK"
        elif final_status == "needs_finetune":
            summary = "Needs finetune"
        elif final_status == "needs_more_data":
            summary = "Needs more data"
        else:
            summary = "Failed"

    # Only real verifier stages count
    if failed_verifier is None:
        failed_verifier = stage if stage in {"Q0", "Q1", "Q2", "Q3"} else None

    out = {
        "status": status,
        "failed_verifier": failed_verifier,
        "final": {
            "status": final_status,
            "stage": stage,
            "summary": summary,
            "reasons": reasons,
        },
    }

    # keep old top-level reason for backward compatibility
    if reason is not None:
        out["reason"] = reason

    # attach any other payload such as plan, Q0, Q1, Q2, Q3, errors...
    out.update(extra)

    return out
    

def _save_candidate_to_original(context_variables, verbose=True):
    """
    Copy <File_name>_2.cfg -> <File_name>.cfg
    and rewrite the hostname inside the config from <File_name>_2 to <File_name>.
    """
    File_name = context_variables.get("File_name")
    file_path = context_variables.get("file_path")

    if not File_name or not file_path:
        raise ValueError("Missing File_name or file_path in context_variables")

    candidate_hostname = f"{File_name}_2"
    original_hostname = File_name

    candidate_cfg = os.path.join(file_path, f"{candidate_hostname}.cfg")
    original_cfg = os.path.join(file_path, f"{original_hostname}.cfg")

    if not os.path.exists(candidate_cfg):
        raise FileNotFoundError(f"Candidate config not found: {candidate_cfg}")

    with open(candidate_cfg, "r", encoding="utf-8") as src:
        candidate_content = src.read()

    # Rewrite hostname line only
    candidate_content = re.sub(
        rf"(?mi)^hostname\s+{re.escape(candidate_hostname)}\s*$",
        f"hostname {original_hostname}",
        candidate_content,
        count=1,
    )

    with open(original_cfg, "w", encoding="utf-8") as dst:
        dst.write(candidate_content)

    if verbose:
        print(f"Saved candidate config: {candidate_cfg} -> {original_cfg}")
        print(f"Rewrote hostname: {candidate_hostname} -> {original_hostname}")

    return original_cfg

def _result(status, reason=None, stage=None, **kwargs):
    out = {"status": status, **kwargs}

    if reason is not None:
        out["reason"] = reason

    # Only Q0-Q3 are actual verifier failures
    out["failed_verifier"] = stage if stage in {"Q0", "Q1", "Q2", "Q3"} else None

    out["final"] = {
        "status": status,
        "stage": stage,
        "reason": reason,
    }
    return out
def _attach_failed_verifier(payload, stage=None):
    """
    Ensure every Batfish_validate_once return includes failed_verifier.
    stage should be one of: Q0, Q1, Q2, Q3, or None.
    """
    if payload is None:
        payload = {}

    payload["failed_verifier"] = stage

    final = payload.get("final")
    if isinstance(final, dict):
        final.setdefault("stage", stage)

    return payload

def _result_with_stage(status, reason=None, stage=None, **kwargs):
    out = {"status": status, **kwargs}
    if reason is not None:
        out["reason"] = reason

    out["failed_verifier"] = stage if stage in {"Q0", "Q1", "Q2", "Q3"} else None

    final = out.get("final")
    if isinstance(final, dict):
        final.setdefault("stage", stage)
    elif stage is not None or reason is not None:
        out["final"] = {
            "status": status,
            "stage": stage,
            "reason": reason,
        }

    return out

# Helper : normalize config for repeat detection
def normalize_cli_text(text):
    if not text:
        return ""
    lines = [x.strip().lower() for x in text.splitlines() if x.strip()]
    return "\n".join(lines)
    

# a fallback infer helper
def _infer_failed_verifier_from_result(run_result):
    if not isinstance(run_result, dict):
        return None

    fv = run_result.get("failed_verifier")
    if fv in {"Q0", "Q1", "Q2", "Q3"}:
        return fv

    final = run_result.get("final", {})
    stage = final.get("stage")
    if stage in {"Q0", "Q1", "Q2", "Q3"}:
        return stage

    # fallback logic
    q1 = run_result.get("Q1", {})
    if q1 and not q1.get("positive", {}).get("ok", True):
        return "Q1"

    q2 = run_result.get("Q2", {})
    if q2:
        checks = q2.get("violation_checks", [])
        if any(c.get("violations_empty") is False for c in checks):
            return "Q2"

    q3 = run_result.get("Q3", {})
    q3df = q3.get("df")
    if q3df is not None:
        try:
            if not q3df.empty:
                return "Q3"
        except Exception:
            pass

    return None
    
def normalize_batfish_result_schema(run_result):
    if run_result is None:
        return {
            "status": "failed",
            "failed_verifier": None,
            "final": {
                "status": "failed",
                "stage": None,
                "summary": "Failed",
                "reasons": ["Batfish_validate_once returned None"],
            },
            "reason": "Batfish_validate_once returned None",
        }

    status = run_result.get("status", "failed")
    final = run_result.get("final", {}) or {}

    final_status = final.get("status", status if status in {"ok", "needs_more_data", "failed"} else "failed")
    stage = final.get("stage")
    failed_verifier = run_result.get("failed_verifier")
    if failed_verifier not in {"Q0", "Q1", "Q2", "Q3"}:
        failed_verifier = stage if stage in {"Q0", "Q1", "Q2", "Q3"} else None

    summary = final.get("summary")
    if summary is None:
        if final_status == "ok":
            summary = "OK"
        elif final_status == "needs_finetune":
            summary = "Needs finetune"
        elif final_status == "needs_more_data":
            summary = "Needs more data"
        else:
            summary = "Failed"

    reasons = final.get("reasons")
    if reasons is None:
        reason = run_result.get("reason") or final.get("reason")
        reasons = [reason] if reason else []
    elif isinstance(reasons, str):
        reasons = [reasons]

    run_result["failed_verifier"] = failed_verifier
    run_result["final"] = {
        "status": final_status,
        "stage": stage,
        "summary": summary,
        "reasons": reasons,
    }

    return run_result
    
def Batfish_validate_until_ok(client, context_variables, batfish_host, snapshot_name="configs", max_iters=5, verbose=True):
    """
    Run -> (if issue) finetune -> apply to file -> rebuild snapshot -> re-run
    until OK or max iterations (max_iters) reached.
    """
    history = []

    for i in range(1, max_iters + 1):
        if verbose:
            print(f"\n================ ITERATION {i}/{max_iters} ================")

        run_result = Batfish_validate_once(
            client=client,
            context_variables=context_variables,
            batfish_host=batfish_host,
            snapshot_name=snapshot_name,
            verbose=verbose,
        ) or {
            "status": "failed",
            "reason": "Batfish_validate_once returned None",
            "final": {"status": "failed", "stage": "unknown"},
        }
        run_result = normalize_batfish_result_schema(run_result)
        run_result["failed_verifier"] = _infer_failed_verifier_from_result(run_result)

        history.append(run_result)

        final = run_result.get("final") or {}
        top_status = (run_result.get("status") or "").strip().lower()
        final_status = (final.get("status") or top_status).strip().lower()

        if verbose:
            print("run_result status:", run_result.get("status"))
            print("top_status:", top_status)
            print("final, final_status")
            print(final, final_status)
            print("reason:", run_result.get("reason"))

        if final_status in ("ok", "ran_ok", "fully_correct"):
            try:
                _save_candidate_to_original(context_variables, verbose=verbose)
                parse_config_to_json(os.path.join(context_variables["file_path"], context_variables["File_name"]))
            except Exception as e:
                print("Validation succeeded but saving candidate to original failed:", repr(e))
                traceback.print_exc()
                return {
                    "status": "failed",
                    "history": history,
                    "last": run_result,
                    "reason": f"Validation OK, but failed to save hostname_2 to hostname: {repr(e)}",
                }

            return {"status": "ok", "history": history, "last": run_result}

        if final_status == "needs_more_data":
            return {
                "status": "needs_more_data",
                "history": history,
                "last": run_result,
                "reason": run_result.get("reason") or final.get("reason"),
                "failed_verifier": None,
            }

        stage = (final.get("stage") or _infer_stage_from_results(run_result) or "unknown").strip()
        if verbose:
            print("Finetune required. stage =", stage)

        acl_name = run_result.get("plan", {}).get("ACL_Name")

        try:
            corrected_snippet = None
            File_name = context_variables.get("File_name")
            file_path = context_variables.get("file_path")

            if not File_name or not file_path:
                return {
                    "status": "needs_more_data",
                    "history": history,
                    "last": run_result,
                    "reason": "Missing File_name or file_path",
                    "failed_verifier": None,
                }

            hostname = f"{File_name}_2"
            cfg_path = os.path.join(file_path, f"{hostname}.cfg")

            if stage == "Q0":
                print("Q0 stage issue")
                suggest = final.get("suggest_fix") or {}
            
                expected_intf = _norm_intf(
                    suggest.get("Intf_Name")
                    or run_result.get("Q0", {}).get("expected_best", {}).get("Intf_Name")
                    or context_variables.get("Intf_Name")
                )
                expected_dir = _norm_dir(
                    suggest.get("Direction")
                    or run_result.get("Q0", {}).get("expected_best", {}).get("Direction")
                    or context_variables.get("direction")
                )
                            
                print("Q0 fix inputs:", acl_name, expected_intf, expected_dir)
            
                if not expected_intf or not expected_dir or not acl_name:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": f"Q0 needs attachment fix but missing expected_intf={expected_intf}, expected_dir={expected_dir}, acl_name={acl_name}",
                    }
            
                with open(cfg_path, "r") as f:
                    current_cfg = f.read()
                
                new_cfg = set_acl_attachment_raw(
                    cfg_text=current_cfg,
                    acl_name=acl_name,
                    intf_name=expected_intf,
                    direction=expected_dir,
                )
                
                if new_cfg == current_cfg:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": f"Q0 fix produced no config change for acl_name={acl_name}, intf={expected_intf}, dir={expected_dir}",
                    }
                
                with open(cfg_path, "w") as f:
                    f.write(new_cfg)
                
                print("\n=== UPDATED CFG ===")
                print(new_cfg)
                
                parse_config_to_json(os.path.join(file_path, hostname))
                context_variables["configuration_response"] = new_cfg
                
                if verbose:
                    print(f"Applied Q0 attachment fix: {acl_name} -> {expected_intf} {expected_dir}")
                
                continue              

            # elif stage in ("Q1", "Q2"):
            #     print("Q1/Q2 stage issue")
            #     fix_ctx = dict(context_variables)
            #     fix_ctx.update({
            #         "mode": "generate",
            #         "batfish_evidence": run_result.get(stage, {}),
            #         "List_Found": True,
            #         "L_Name": acl_name,
            #     })
            #     corrected_snippet = ACL_generator_caller(fix_ctx)

            #     if not corrected_snippet:
            #         return {
            #             "status": "failed",
            #             "history": history,
            #             "last": run_result,
            #             "reason": f"ACL_generator_caller returned empty output for stage {stage}",
            #         }

            #     with open(cfg_path, "r") as f:
            #         current_cfg = f.read()

            #     new_cfg = replace_acl_block(current_cfg, acl_name, corrected_snippet)

            #     with open(cfg_path, "w") as f:
            #         f.write(new_cfg)

            #     parse_config_to_json(os.path.join(file_path, hostname))
            #     context_variables["configuration_response"] = corrected_snippet
            #     continue
            elif stage in {"Q1", "Q2"}:
                print("Q1/Q2 stage issue")
            
                final = run_result.get("final", {}) or {}
                reasons = final.get("reasons", []) or []
                reason_text = " | ".join(str(r) for r in reasons)
            
                q1_df = (
                    run_result.get("Q1", {})
                    .get("positive", {})
                    .get("df")
                )
            
                q1_empty = getattr(q1_df, "empty", False) is True
            
                # ------------------------------------------------------------
                # Important:
                # EMPTY testFilters usually means the test plan/startLocation
                # is inconsistent with the selected interface, not that the ACL
                # needs rewriting.
                # ------------------------------------------------------------
                if stage == "Q1" and q1_empty:
                    print("Q1 produced EMPTY testFilters result.")
                    print("Treating this as a planner/test-location issue, not an ACL rewrite issue.")
            
                    q0 = run_result.get("Q0", {}) or {}
                    q0_ok = q0.get("ok_expected_vs_snapshot") is True
                    q0_matches = q0.get("matches") or []
            
                    if q0_ok and q0_matches:
                        # Prefer serial/transit inbound for Q1 testing.
                        preferred = None
            
                        for intf, direction in q0_matches:
                            intf_l = str(intf).lower()
                            dir_l = str(direction).lower()
                            if dir_l == "in" and intf_l.startswith("serial"):
                                preferred = (intf, direction)
                                break
            
                        if preferred is None:
                            for intf, direction in q0_matches:
                                if str(direction).lower() == "in":
                                    preferred = (intf, direction)
                                    break
            
                        if preferred is not None:
                            preferred_intf, preferred_dir = preferred
            
                            old_intf = context_variables.get("Intf_Name")
                            old_dir = context_variables.get("direction")
            
                            context_variables["Intf_Name"] = preferred_intf
                            context_variables["direction"] = preferred_dir
            
                            print(
                                f"Retrying Batfish with Q1-preferred attachment: "
                                f"{preferred_intf} {preferred_dir} "
                                f"(was {old_intf} {old_dir})"
                            )
            
                            # Do NOT modify config. Just retry validation with better Q1 anchor.
                            continue
            
                    # If no better Q1 anchor exists, stop cleanly.
                    return {
                        "status": "needs_more_data",
                        "history": history,
                        "last": run_result,
                        "reason": (
                            "Q1 testFilters returned EMPTY. This is likely a test-planning "
                            "or startLocation issue, not an ACL-generation issue. "
                            f"Reason: {reason_text}"
                        ),
                    }
            
                # ------------------------------------------------------------
                # Q2 failures should not blindly rewrite config either.
                # Q2 means policy-space violation; return evidence for the
                # outer controller / LLM only if you intentionally support Q2 repair.
                # ------------------------------------------------------------
                if stage == "Q2":
                    return {
                        "status": "needs_finetune",
                        "history": history,
                        "last": run_result,
                        "reason": (
                            "Q2 policy-space validation failed. Not rewriting config "
                            "inside Batfish loop to avoid corrupting the ACL. "
                            f"Reason: {reason_text}"
                        ),
                    }
            
                # Fallback for non-empty Q1 failure.
                return {
                    "status": "needs_finetune",
                    "history": history,
                    "last": run_result,
                    "reason": (
                        "Q1 validation failed, but it was not an EMPTY testFilters planner issue. "
                        f"Reason: {reason_text}"
                    ),
                }
    
            elif stage == "Q3":
                print("Q3 stage issue")

                with open(cfg_path, "r") as f:
                    topology_file = f.read()

                suggest_fix = final.get("suggest_fix") or {}
                expected_intf = (
                    suggest_fix.get("Intf_Name")
                    or run_result.get("plan", {}).get("Intf_Name")
                    or run_result.get("Q0", {}).get("expected_best", {}).get("Intf_Name")
                    or context_variables.get("Intf_Name")
                )

                if not expected_intf or not acl_name:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": f"Q3 missing expected_intf={expected_intf} or acl_name={acl_name}",
                    }

                old_acl_text = extract_acl_block(topology_file, acl_name)
                interface_text = extract_interface_stanza(topology_file, expected_intf)

                if not old_acl_text:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": f"Could not extract ACL block '{acl_name}' from config file.",
                    }

                q3_df = (run_result.get("Q3", {}) or {}).get("df")
                q3_rows = q3_df_to_rows(q3_df)
                if not q3_rows:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": "Q3 stage selected but Q3 df is empty/no rows.",
                    }

                fix_ctx = dict(context_variables)
                fix_ctx.update({
                    "mode": "fix_order",
                    "L_Name": acl_name,
                    "interface_text": interface_text,
                    "acl_text": old_acl_text,
                    "q3_df_rows": q3_rows,
                    "List_Found": True,
                })

                corrected_snippet = ACL_generator_caller(fix_ctx)
                if not corrected_snippet:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": "ACL_generator_caller returned empty output for stage Q3",
                    }

                new_acl_text = extract_acl_block(corrected_snippet, acl_name)
                if not new_acl_text:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": "LLM fix_order output did not include the ACL block.",
                    }

                if not validate_reorder_only(old_acl_text, new_acl_text):
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": "LLM fix_order changed ACL lines (not reorder-only). Rejecting.",
                        "old_acl": old_acl_text,
                        "new_acl": new_acl_text,
                    }

                new_config = replace_acl_block(topology_file, acl_name, corrected_snippet)

                with open(cfg_path, "w") as f:
                    f.write(new_config)

                parse_config_to_json(os.path.join(file_path, hostname))
                context_variables["configuration_response"] = corrected_snippet

                if verbose:
                    print("Applied Q3 reorder fix. Re-running...")

                continue

            else:
                return {
                    "status": "failed_unknown_stage",
                    "history": history,
                    "last": run_result,
                    "reason": f"Unsupported stage: {stage}",
                }

        except Exception as e:
            print(" Finetune/apply crashed:", repr(e))
            traceback.print_exc()
            return {"status": "failed", "history": history, "last": run_result, "error": repr(e)}
    print("\n=== FULL run_result ===")
    print(run_result)
    return {
        "status": "max_iters_reached",
        "history": history,
        "last": history[-1] if history else None,
    }