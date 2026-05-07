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
def Initialization_Batfish_session(
    host: str,
    SNAPSHOT_NAME: str,
    hostname: str,
) -> tuple:
    batfish_session = Session(host=host)

    # Initialize a network and a snapshot
    batfish_session.set_network("network_ACL")

    snapshot_name = SNAPSHOT_NAME
    snapshot_path = "."

    batfish_session.init_snapshot(
        snapshot_path,
        name=snapshot_name,
        overwrite=True,
    )

    node_name = hostname

    # AccessList_name = L_name
    return batfish_session, node_name, snapshot_path, snapshot_name

########## Ensure we have a config file and initialize Batfish.############
    # - Prefer <hostname>_2.cfg if it exists, otherwise <hostname>.cfg.
    # - Returns: (bf, node_name, snapshot_name, config_file_path)
###########################################################################

def prepare_batfish_context(
    batfish_host: str,
    hostname: str,
    config_dir: str = "configs",
) -> tuple:
    config_file_path = None

    candidate_config_path = os.path.join(
        config_dir,
        f"{hostname}_2.cfg",
    )

    if os.path.exists(candidate_config_path):
        config_file_path = candidate_config_path
        node_name = f"{hostname}_2"

        parse_config_to_json(
            os.path.join(config_dir, f"{hostname}_2")
        )

    else:
        original_config_path = os.path.join(
            config_dir,
            f"{hostname}.cfg",
        )

        if not os.path.exists(original_config_path):
            raise FileNotFoundError(
                f"No config file found for {hostname} in {config_dir}"
            )

        config_file_path = original_config_path
        node_name = hostname

        parse_config_to_json(
            os.path.join(config_dir, hostname)
        )

    snapshot_name = config_dir  # using "configs" as snapshot name

    batfish_session, node_name, snapshot_path, snapshot_name = (
        Initialization_Batfish_session(
            batfish_host,
            snapshot_name,
            node_name,
        )
    )

    return (
        batfish_session,
        node_name,
        snapshot_name,
        config_file_path,
    )



def Batfish_validate_once(
    client,
    context_variables: dict,
    batfish_host: str,
    snapshot_name: str = "configs",
    verbose: bool = True,
) -> dict:
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
    file_name = context_variables.get("File_name")
    sub_net = context_variables.get("Sub_Net")
    configuration_response = context_variables.get("configuration_response")
    hostname = f"{file_name}_2" if file_name else None

    print("hostname:", hostname)

    if not file_path or not file_name:
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

        return make_batfish_result(
            status="needs_more_data",
            final_status="needs_more_data",
            stage="precheck",
            reason="Missing user intent",
            reasons=["Missing user intent"],
        )

    config_path = os.path.join(file_path, f"{hostname}.cfg")

    if not os.path.exists(config_path):
        if verbose:
            print(f" Config file missing for {hostname}: {config_path}")

        original_config_path = os.path.join(file_path, f"{file_name}.cfg")
        topology_content = read_topology_file(original_config_path)
        topology_file = "".join(topology_content) if topology_content else ""

        if not configuration_response:
            return make_batfish_result(
                status="needs_more_data",
                final_status="needs_more_data",
                stage="precheck",
                reason=(
                    "Missing configuration_response; "
                    "cannot generate candidate config."
                ),
                reasons=[
                    "Missing configuration_response; "
                    "cannot generate candidate config."
                ],
            )

        generate_config2_file(
            file_path,
            configuration_response,
            context_variables.get("Intf_Name"),
            topology_file,
            file_name,
        )

        parse_config_to_json(os.path.join(file_path, hostname))

    source_ip, destination_ip, protocol, port, action, app, src_subnet, dst_subnet = (
        extract_entities(extraction_result)
    )
    user_action = action

    if verbose:
        print("src_ip, dst_ip, protocol, port, action, app, src_Subnet, dst_Subnet")
        print(
            source_ip,
            destination_ip,
            protocol,
            port,
            action,
            app,
            src_subnet,
            dst_subnet,
        )

    json_file_path = os.path.join(file_path, f"{hostname}.json")
    topology_content = read_topology_file(json_file_path)

    if not topology_content:
        return make_batfish_result(
            status="needs_more_data",
            final_status="needs_more_data",
            stage="facts",
            reason=f"Missing or unreadable JSON facts file: {json_file_path}",
            reasons=[f"Missing or unreadable JSON facts file: {json_file_path}"],
        )

    config_json = json.loads("".join(topology_content))

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
        print("src_subnet:", src_subnet)
        print("dst_ip:", destination_ip)
        print("dst_subnet:", dst_subnet)
        print("router_interfaces:", router_interfaces)

    expected_interface, expected_direction = choose_acl_attachment(
        router_interfaces=router_interfaces,
        default_route_iface=default_route_iface,
        inside_prefixes=inside_prefixes,
        intent_dir=intent_dir,
        src_ip=source_ip,
        src_subnet=src_subnet,
        dst_ip=destination_ip,
        dst_subnet=dst_subnet,
    )

    # Preserve workflow placement if Batfish-side inference cannot determine one
    final_interface = expected_interface or context_variables.get("Intf_Name")
    final_direction = expected_direction or context_variables.get("direction")

    context_variables.update(
        {
            "action": user_action,
            "src_ip": source_ip,
            "src_subnet": src_subnet,
            "dst_ip": destination_ip,
            "dst_subnet": dst_subnet,
            "hostname": hostname,
            "new_intent": new_intent,
            "intent_dir": intent_dir,
            "Intf_Name": final_interface,
            "direction": final_direction,
            "router_interfaces": router_interfaces,
            "default_route_iface": default_route_iface,
            "inside_prefixes": inside_prefixes,
        }
    )

    plan = build_batfish_test_plan(context_variables)

    if verbose:
        print("\n=== Batfish Test Plan ===")
        print(plan)

    plan_status = (plan.get("Plan_Status") or "").strip().lower()

    if plan_status != "ok":
        message = plan.get(
            "Notes",
            f"Plan_Status not ok: {plan.get('Plan_Status')}",
        )

        return make_batfish_result(
            status="needs_more_data",
            final_status="needs_more_data",
            stage="plan",
            reason=message,
            reasons=[message],
            plan=plan,
        )

    node_name = (plan.get("Device") or "").strip().lower()
    acl_name = (plan.get("ACL_Name") or "").strip()

    if not node_name or not acl_name:
        return make_batfish_result(
            status="needs_more_data",
            final_status="needs_more_data",
            stage="plan",
            reason="Missing Device or ACL_Name in plan",
            reasons=["Missing Device or ACL_Name in plan"],
            plan=plan,
        )

    q1_positive_source = plan.get("Q1_Pos_Src_Host")
    q1_positive_destination = plan.get("Q1_Pos_Dst_Host")
    restriction_mode = (
        plan.get("Q2_Restriction_Mode") or "none"
    ).strip().lower()
    expected_action = (plan.get("Expected_Action") or "").strip().lower()
    opposite_action = (plan.get("Opposite_Action") or "").strip().lower()
    plan_application = (
        plan.get("Application", "none") or "none"
    ).strip().lower()
    plan_port = (plan.get("Port", "none") or "none").strip().lower()

    q2_source_subnet = plan.get("Q2_Src_Subnet")
    q2_destination_subnets = csv_to_list(plan.get("Q2_Dst_Subnets"))

    batfish_session, node_name, snapshot_path, snapshot_name = (
        Initialization_Batfish_session(
            batfish_host,
            snapshot_name,
            node_name,
        )
    )
    node_name = node_name.strip().lower()
    config_path = os.path.join(file_path, f"{hostname}.cfg")

    print("hostname used for Batfish:", hostname)
    print("cfg_path:", config_path)
    print("ACL searched in Batfish:", acl_name)

    attachments, properties_df = find_acl_attachments(
        bf=batfish_session,
        hostname=node_name,
        acl_name=acl_name,
        snapshot_name=snapshot_name,
    )

    try:
        print("Interface properties DF:")
        print(properties_df)

    except Exception:
        print("Could not print props_df")

    acceptable = build_acceptable_attachments(
        router_interfaces=router_interfaces,
        default_route_iface=default_route_iface,
        inside_prefixes=inside_prefixes,
        intent_dir=intent_dir,
        src_ip=source_ip,
        src_subnet=src_subnet,
        dst_ip=destination_ip,
        dst_subnet=dst_subnet,
    )

    print("\n=== Q0 DEBUG ===")
    print("ACL name from plan:", repr(acl_name))
    print("Expected acceptable:", acceptable)
    print("Raw attachments from Batfish:", attachments)

    q0_ok, chosen_interface, chosen_direction, q0_debug = (
        q0_pick_working_attachment(
            attachments,
            acceptable,
        )
    )

    def _prefer_q1_attachment(
        q0_debug: dict,
        fallback_interface: str,
        fallback_direction: str,
    ) -> tuple:
        """
        For Q1 testing, prefer inbound transit ACLs when multiple acceptable
        attachments exist. This avoids testing routed traffic against an outbound
        LAN ACL with a wrong startLocation.
        """
        matches = q0_debug.get("matches") or []

        # 1) Prefer Serial/Transit inbound, e.g. serial0/0 in
        for interface, direction in matches:
            interface_text = str(interface).lower()
            direction_text = str(direction).lower()

            if (
                direction_text == "in"
                and interface_text.startswith("serial")
            ):
                return interface, direction

        # 2) Then prefer any inbound match
        for interface, direction in matches:
            if str(direction).lower() == "in":
                return interface, direction

        # 3) Otherwise keep original choice
        return fallback_interface, fallback_direction

    print("Q0 debug details:", q0_debug)

    results = {
        "status": "ran",
        "plan": plan,
        "Q0": {
            "ok_expected_vs_snapshot": q0_ok,
            "expected": {
                "Intf_Name": (final_interface or "").strip(),
                "Direction": (final_direction or "").strip().lower(),
            },
            "planned": {
                "Intf_Name": (
                    plan.get("Intf_Name") or final_interface or ""
                ).strip(),
                "Direction": (
                    plan.get("Direction") or final_direction or ""
                ).strip().lower(),
            },
            "expected_best": {
                "Intf_Name": (final_interface or "").strip(),
                "Direction": (final_direction or "").strip().lower(),
            },
            "acceptable": q0_debug.get("acceptable"),
            "actual_list": q0_debug.get("actual"),
            "matches": q0_debug.get("matches"),
            "found_attachments": attachments,
            "interface_properties": properties_df,
            "issue": (
                "ok"
                if q0_ok
                else (
                    "acl_not_attached"
                    if not attachments
                    else "no_acceptable_attachment_found"
                )
            ),
        },
        "Q1": {},
        "Q2": {},
        "Q3": {},
        "errors": [],
    }

    if not q0_ok:
        suggest_interface, suggest_direction = (
            acceptable[0]
            if acceptable
            else (expected_interface, expected_direction)
        )

        results["failed_verifier"] = "Q0"
        results["reason"] = "No acceptable ACL attachment found."
        results["final"] = {
            "status": "needs_finetune",
            "stage": "Q0",
            "summary": "Needs finetune",
            "reasons": ["No acceptable ACL attachment found."],
            "suggest_fix": {
                "Intf_Name": suggest_interface,
                "Direction": suggest_direction,
            },
        }

        return results

    interface_name, direction = _prefer_q1_attachment(
        q0_debug,
        chosen_interface,
        chosen_direction,
    )

    context_variables["Intf_Name"] = interface_name
    context_variables["direction"] = direction

    results["Q0"]["chosen_for_q1"] = {
        "Intf_Name": interface_name,
        "Direction": direction,
    }

    q1_positive_df = check_Rule_access_at_iface(
        bf=batfish_session,
        src_ip=q1_positive_source,
        dst_ip=q1_positive_destination,
        application=None if plan_application == "none" else plan_application,
        hostname=node_name,
        intf_name=interface_name,
        direction=direction,
        snapshot_name=snapshot_name,
    )

    expected_rule_line = context_variables.get("Rule")

    if isinstance(expected_rule_line, (list, tuple)):
        expected_rule_line = (
            expected_rule_line[0]
            if expected_rule_line
            else None
        )

    positive_ok, positive_details = q1_validate_result(
        q1_positive_df,
        expected_action=expected_action,
        expected_rule_text=expected_rule_line,
        require_explicit_match=False,
    )

    results["Q1"]["positive"] = {
        "df": q1_positive_df,
        "ok": positive_ok,
        "details": positive_details,
    }

    q2_all_checks = []
    authorized_source_prefix = (
        f"{q1_positive_source}/32"
        if restriction_mode == "only_host"
        else (q2_source_subnet or f"{q1_positive_source}/32")
    )

    q2_all_checks.extend(
        run_q2_violation_check(
            bf=batfish_session,
            node_name=node_name,
            intf_name=interface_name,
            direction=direction,
            snapshot_name=snapshot_name,
            src_prefix=authorized_source_prefix,
            dst_prefixes=q2_destination_subnets,
            action_to_search=opposite_action,
            application=None if plan_application == "none" else plan_application,
            port=None if plan_port == "none" else plan_port,
            label="Q2A(Expected-behavior violations)",
            verbose=verbose,
        )
    )

    results["Q2"]["violation_checks"] = q2_all_checks

    q3_df = check_Reachibility(batfish_session, node_name)
    results["Q3"]["df"] = q3_df

    final_status, summary, reasons, failed_stage = decide_from_batfish_results(
        results
    )

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
    status: str,
    final_status: str,
    stage=None,
    summary=None,
    reasons=None,
    reason=None,
    failed_verifier=None,
    **extra,
) -> dict:
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

    output = {
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
        output["reason"] = reason

    # attach any other payload such as plan, Q0, Q1, Q2, Q3, errors...
    output.update(extra)

    return output


def _save_candidate_to_original(
    context_variables: dict,
    verbose: bool = True,
) -> str:
    """
    Copy <File_name>_2.cfg -> <File_name>.cfg
    and rewrite the hostname inside the config from <File_name>_2 to <File_name>.
    """
    file_name = context_variables.get("File_name")
    file_path = context_variables.get("file_path")

    if not file_name or not file_path:
        raise ValueError("Missing File_name or file_path in context_variables")

    candidate_hostname = f"{file_name}_2"
    original_hostname = file_name

    candidate_config_path = os.path.join(
        file_path,
        f"{candidate_hostname}.cfg",
    )
    original_config_path = os.path.join(
        file_path,
        f"{original_hostname}.cfg",
    )

    if not os.path.exists(candidate_config_path):
        raise FileNotFoundError(
            f"Candidate config not found: {candidate_config_path}"
        )

    with open(candidate_config_path, "r", encoding="utf-8") as source_file:
        candidate_content = source_file.read()

    # Rewrite hostname line only
    candidate_content = re.sub(
        rf"(?mi)^hostname\s+{re.escape(candidate_hostname)}\s*$",
        f"hostname {original_hostname}",
        candidate_content,
        count=1,
    )

    with open(original_config_path, "w", encoding="utf-8") as destination_file:
        destination_file.write(candidate_content)

    if verbose:
        print(
            f"Saved candidate config: "
            f"{candidate_config_path} -> {original_config_path}"
        )
        print(
            f"Rewrote hostname: "
            f"{candidate_hostname} -> {original_hostname}"
        )

    return original_config_path


def _result(status: str, reason=None, stage=None, **kwargs) -> dict:
    output = {
        "status": status,
        **kwargs,
    }

    if reason is not None:
        output["reason"] = reason

    # Only Q0-Q3 are actual verifier failures
    output["failed_verifier"] = (
        stage
        if stage in {"Q0", "Q1", "Q2", "Q3"}
        else None
    )

    output["final"] = {
        "status": status,
        "stage": stage,
        "reason": reason,
    }

    return output


def _attach_failed_verifier(payload: dict, stage=None) -> dict:
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


def _result_with_stage(status: str, reason=None, stage=None, **kwargs) -> dict:
    output = {
        "status": status,
        **kwargs,
    }

    if reason is not None:
        output["reason"] = reason

    output["failed_verifier"] = (
        stage
        if stage in {"Q0", "Q1", "Q2", "Q3"}
        else None
    )

    final = output.get("final")

    if isinstance(final, dict):
        final.setdefault("stage", stage)

    elif stage is not None or reason is not None:
        output["final"] = {
            "status": status,
            "stage": stage,
            "reason": reason,
        }

    return output


# Helper : normalize config for repeat detection
def normalize_cli_text(text: str) -> str:
    if not text:
        return ""

    lines = []

    for line in text.splitlines():
        normalized_line = line.strip().lower()

        if normalized_line:
            lines.append(normalized_line)

    return "\n".join(lines)


# a fallback infer helper
def _infer_failed_verifier_from_result(run_result: dict):
    if not isinstance(run_result, dict):
        return None

    failed_verifier = run_result.get("failed_verifier")

    if failed_verifier in {"Q0", "Q1", "Q2", "Q3"}:
        return failed_verifier

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

        for check in checks:
            if check.get("violations_empty") is False:
                return "Q2"

    q3 = run_result.get("Q3", {})
    q3_dataframe = q3.get("df")

    if q3_dataframe is not None:
        try:
            if not q3_dataframe.empty:
                return "Q3"

        except Exception:
            pass

    return None


def normalize_batfish_result_schema(run_result: dict) -> dict:
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

    final_status = final.get(
        "status",
        status
        if status in {"ok", "needs_more_data", "failed"}
        else "failed",
    )
    stage = final.get("stage")
    failed_verifier = run_result.get("failed_verifier")

    if failed_verifier not in {"Q0", "Q1", "Q2", "Q3"}:
        failed_verifier = (
            stage
            if stage in {"Q0", "Q1", "Q2", "Q3"}
            else None
        )

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
    
def Batfish_validate_until_ok(
    client,
    context_variables: dict,
    batfish_host: str,
    snapshot_name: str = "configs",
    max_iters: int = 5,
    verbose: bool = True,
) -> dict:
    """
    Run -> (if issue) finetune -> apply to file -> rebuild snapshot -> re-run
    until OK or max iterations (max_iters) reached.
    """
    history = []

    for iteration in range(1, max_iters + 1):
        if verbose:
            print(
                f"\n================ ITERATION "
                f"{iteration}/{max_iters} ================"
            )

        run_result = Batfish_validate_once(
            client=client,
            context_variables=context_variables,
            batfish_host=batfish_host,
            snapshot_name=snapshot_name,
            verbose=verbose,
        ) or {
            "status": "failed",
            "reason": "Batfish_validate_once returned None",
            "final": {
                "status": "failed",
                "stage": "unknown",
            },
        }

        run_result = normalize_batfish_result_schema(run_result)
        run_result["failed_verifier"] = _infer_failed_verifier_from_result(
            run_result
        )

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
            return {
                "status": "ok",
                "history": history,
                "last": run_result,
            }

        if final_status == "needs_more_data":
            return {
                "status": "needs_more_data",
                "history": history,
                "last": run_result,
                "reason": run_result.get("reason") or final.get("reason"),
                "failed_verifier": None,
            }

        stage = (
            final.get("stage")
            or _infer_stage_from_results(run_result)
            or "unknown"
        ).strip()

        if verbose:
            print("Finetune required. stage =", stage)

        acl_name = run_result.get("plan", {}).get("ACL_Name")

        try:
            corrected_snippet = None
            file_name = context_variables.get("File_name")
            file_path = context_variables.get("file_path")

            if not file_name or not file_path:
                return {
                    "status": "needs_more_data",
                    "history": history,
                    "last": run_result,
                    "reason": "Missing File_name or file_path",
                    "failed_verifier": None,
                }

            hostname = f"{file_name}_2"
            config_path = os.path.join(file_path, f"{hostname}.cfg")

            if stage == "Q0":
                print("Q0 stage issue")
                suggest = final.get("suggest_fix") or {}

                expected_interface = _norm_intf(
                    suggest.get("Intf_Name")
                    or run_result.get("Q0", {})
                    .get("expected_best", {})
                    .get("Intf_Name")
                    or context_variables.get("Intf_Name")
                )
                expected_direction = _norm_dir(
                    suggest.get("Direction")
                    or run_result.get("Q0", {})
                    .get("expected_best", {})
                    .get("Direction")
                    or context_variables.get("direction")
                )

                print("Q0 fix inputs:", acl_name, expected_interface, expected_direction)

                if not expected_interface or not expected_direction or not acl_name:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": (
                            "Q0 needs attachment fix but missing "
                            f"expected_intf={expected_interface}, "
                            f"expected_dir={expected_direction}, "
                            f"acl_name={acl_name}"
                        ),
                    }

                with open(config_path, "r") as file:
                    current_config = file.read()

                new_config = set_acl_attachment_raw(
                    cfg_text=current_config,
                    acl_name=acl_name,
                    intf_name=expected_interface,
                    direction=expected_direction,
                )

                if new_config == current_config:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": (
                            "Q0 fix produced no config change for "
                            f"acl_name={acl_name}, "
                            f"intf={expected_interface}, "
                            f"dir={expected_direction}"
                        ),
                    }

                with open(config_path, "w") as file:
                    file.write(new_config)

                parse_config_to_json(os.path.join(file_path, hostname))
                context_variables["configuration_response"] = new_config

                if verbose:
                    print(
                        f"Applied Q0 attachment fix: "
                        f"{acl_name} -> {expected_interface} {expected_direction}"
                    )

                continue

            elif stage in {"Q1", "Q2"}:
                print("Q1/Q2 stage issue")

                final = run_result.get("final", {}) or {}
                reasons = final.get("reasons", []) or []
                reason_text = " | ".join(str(reason) for reason in reasons)

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
                    print(
                        "Treating this as a planner/test-location issue, "
                        "not an ACL rewrite issue."
                    )

                    q0 = run_result.get("Q0", {}) or {}
                    q0_ok = q0.get("ok_expected_vs_snapshot") is True
                    q0_matches = q0.get("matches") or []

                    if q0_ok and q0_matches:
                        # Prefer serial/transit inbound for Q1 testing.
                        preferred = None

                        for interface, direction in q0_matches:
                            interface_text = str(interface).lower()
                            direction_text = str(direction).lower()

                            if (
                                direction_text == "in"
                                and interface_text.startswith("serial")
                            ):
                                preferred = (interface, direction)
                                break

                        if preferred is None:
                            for interface, direction in q0_matches:
                                if str(direction).lower() == "in":
                                    preferred = (interface, direction)
                                    break

                        if preferred is not None:
                            preferred_interface, preferred_direction = preferred

                            old_interface = context_variables.get("Intf_Name")
                            old_direction = context_variables.get("direction")

                            context_variables["Intf_Name"] = preferred_interface
                            context_variables["direction"] = preferred_direction

                            print(
                                "Retrying Batfish with Q1-preferred attachment: "
                                f"{preferred_interface} {preferred_direction} "
                                f"(was {old_interface} {old_direction})"
                            )

                            # Do NOT modify config. Just retry validation with better Q1 anchor.
                            continue

                    # If no better Q1 anchor exists, stop cleanly.
                    return {
                        "status": "needs_more_data",
                        "history": history,
                        "last": run_result,
                        "reason": (
                            "Q1 testFilters returned EMPTY. This is likely a "
                            "test-planning or startLocation issue, not an "
                            "ACL-generation issue. "
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
                            "Q2 policy-space validation failed. Not rewriting "
                            "config inside Batfish loop to avoid corrupting the ACL. "
                            f"Reason: {reason_text}"
                        ),
                    }

                # Fallback for non-empty Q1 failure.
                return {
                    "status": "needs_finetune",
                    "history": history,
                    "last": run_result,
                    "reason": (
                        "Q1 validation failed, but it was not an EMPTY "
                        "testFilters planner issue. "
                        f"Reason: {reason_text}"
                    ),
                }

            elif stage == "Q3":
                print("Q3 stage issue")

                with open(config_path, "r") as file:
                    topology_file = file.read()

                suggest_fix = final.get("suggest_fix") or {}
                expected_interface = (
                    suggest_fix.get("Intf_Name")
                    or run_result.get("plan", {}).get("Intf_Name")
                    or run_result.get("Q0", {})
                    .get("expected_best", {})
                    .get("Intf_Name")
                    or context_variables.get("Intf_Name")
                )

                if not expected_interface or not acl_name:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": (
                            f"Q3 missing expected_intf={expected_interface} "
                            f"or acl_name={acl_name}"
                        ),
                    }

                old_acl_text = extract_acl_block(topology_file, acl_name)
                interface_text = extract_interface_stanza(
                    topology_file,
                    expected_interface,
                )

                if not old_acl_text:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": (
                            f"Could not extract ACL block "
                            f"{acl_name!r} from config file."
                        ),
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

                fix_context = dict(context_variables)
                fix_context.update(
                    {
                        "mode": "fix_order",
                        "L_Name": acl_name,
                        "interface_text": interface_text,
                        "acl_text": old_acl_text,
                        "q3_df_rows": q3_rows,
                        "List_Found": True,
                    }
                )

                corrected_snippet = ACL_generator_caller(fix_context)

                if not corrected_snippet:
                    return {
                        "status": "failed",
                        "history": history,
                        "last": run_result,
                        "reason": (
                            "ACL_generator_caller returned empty output "
                            "for stage Q3"
                        ),
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
                        "reason": (
                            "LLM fix_order changed ACL lines "
                            "(not reorder-only). Rejecting."
                        ),
                        "old_acl": old_acl_text,
                        "new_acl": new_acl_text,
                    }

                new_config = replace_acl_block(
                    topology_file,
                    acl_name,
                    corrected_snippet,
                )

                with open(config_path, "w") as file:
                    file.write(new_config)

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

        except Exception as error:
            print(" Finetune/apply crashed:", repr(error))
            traceback.print_exc()

            return {
                "status": "failed",
                "history": history,
                "last": run_result,
                "error": repr(error),
            }

    print("\n=== FULL run_result ===")
    print(run_result)

    return {
        "status": "max_iters_reached",
        "history": history,
        "last": history[-1] if history else None,
    }