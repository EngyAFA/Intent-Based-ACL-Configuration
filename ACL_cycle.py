"""
Controller for the intended cycle:
LLM -> Batfish -> GNS3 validation -> repeat if GNS3 fails.
"""
from __future__ import annotations


import os

os.environ["OPENAI_API_KEY"] =  "YOUR_OPENAI_API_KEY_HERE" # Swarm looks for this


from dataclasses import asdict
from typing import Any, Dict, List

from Batfish.Batfish import Batfish_validate_until_ok, _save_candidate_to_original
from GNS3.Validate import ACLRuleIntent, validate_acl_in_gns3
from Helpers.Parse import parse_config_to_json

from Agents.multiAgent import run_ACL_workflow, build_deploy_commands_q0_aware
# from Agents.multiAgentDS import run_ACL_workflow, build_deploy_commands_q0_aware


def _final_status_is_ok(result: Dict[str, Any]) -> bool:
    if not isinstance(result, dict):
        return False
    if result.get("status") == "ok":
        return True
    final = result.get("final")
    return isinstance(final, dict) and final.get("status") == "ok"


def _gns3_report_to_feedback(report) -> Dict[str, Any]:
    failed_tests = [asdict(r) for r in report.results if not r.pass_result]
    return {
        "status": report.status,
        "router_name": report.router_name,
        "acl_name": report.acl_name,
        "config_apply_ok": report.config_apply_ok,
        "config_verify_ok": report.config_verify_ok,
        "precheck_ok": report.precheck_ok,
        "tests_total": report.tests_total,
        "tests_passed": report.tests_passed,
        "tests_failed": report.tests_failed,
        "intent_classification": report.intent_classification,
        "errors": report.errors,
        "failed_tests": failed_tests,
    }


def _build_gns3_intent(context_variables: Dict[str, Any]) -> ACLRuleIntent:
    return ACLRuleIntent(
        intent_text=context_variables.get("new_intent"),
        action=context_variables.get("action"),
        protocol=context_variables.get("protocol"),
        src_ip=context_variables.get("src_ip"),
        dst_ip=context_variables.get("dst_ip"),
        src_subnet=context_variables.get("src_Subnet") or context_variables.get("src_subnet"),
        dst_subnet=context_variables.get("dst_Subnet") or context_variables.get("dst_subnet"),
        port=context_variables.get("port"),
        application=context_variables.get("app"),
        acl_name=context_variables.get("ACLname") or context_variables.get("L_Name"),
        router_name=context_variables.get("File_name") or context_variables.get("hostname"),
        interface=context_variables.get("Intf_Name"),
        direction=context_variables.get("direction"),
        expected_ace_hint=context_variables.get("Rules"),
    )


def _promote_candidate_and_refresh(context_variables: Dict[str, Any], verbose: bool = True) -> None:
    _save_candidate_to_original(context_variables, verbose=verbose)
    parse_config_to_json(
        os.path.join(context_variables["file_path"], context_variables["File_name"])
    )


def _cleanup_candidate_files(context_variables: Dict[str, Any], verbose: bool = True) -> None:
    file_path = context_variables.get("file_path")
    file_name = context_variables.get("File_name")
    if not file_path or not file_name:
        return

    candidate_base = os.path.join(file_path, f"{file_name}_2")
    for ext in (".cfg", ".json"):
        p = candidate_base + ext
        if os.path.exists(p):
            try:
                os.remove(p)
                if verbose:
                    print(f"Removed temporary file: {p}")
            except OSError:
                pass

def _batfish_is_technical_failure(result: Dict[str, Any]) -> bool:
    """
    Return True when Batfish failed due to runtime/tooling issues rather than
    ACL/policy issues.
    """
    if not isinstance(result, dict):
        return True

    status = str(result.get("status", "")).lower()
    reason = str(result.get("reason", "")).lower()

    final = result.get("final", {}) if isinstance(result.get("final"), dict) else {}
    final_status = str(final.get("status", "")).lower()
    reasons = " | ".join(str(x) for x in final.get("reasons", [])).lower()

    text = " | ".join([status, reason, final_status, reasons])

    technical_markers = [
        "exception",
        "traceback",
        "connection refused",
        "timed out",
        "timeout",
        "snapshot",
        "failed to initialize",
        "could not connect",
        "begin job",
        "parse environment",
        "deserializing",
        "workstatuscode",
        "technical",
        "runtime",
    ]

    # If Batfish says needs_more_data because the planner is missing inputs,
    # treat that as non-repairable by LLM loop here.
    if status == "needs_more_data" or final_status == "needs_more_data":
        return True

    return any(marker in text for marker in technical_markers)


def _gns3_is_technical_failure(gns3_feedback: Dict[str, Any]) -> bool:
    """
    Return True when GNS3 failed because the lab/router/console is unreachable
    or verification could not actually run.
    """
    if not isinstance(gns3_feedback, dict):
        return True

    errors = " | ".join(str(e) for e in gns3_feedback.get("errors", []))
    status = str(gns3_feedback.get("status", "")).lower()

    text = " | ".join([
        status,
        str(gns3_feedback.get("config_apply_ok")),
        str(gns3_feedback.get("config_verify_ok")),
        str(gns3_feedback.get("precheck_ok")),
        errors.lower(),
    ])

    technical_markers = [
        "router output unavailable",
        "precheck failed: no output",
        "no output",
        "timed out",
        "timeout",
        "not found in console list",
        "telnet",
        "router_send_commands error",
        "pc_access error",
        "invalid pc_name",
        "config apply failed",
    ]

    # If nothing really ran, this is technical.
    if (
        gns3_feedback.get("precheck_ok") is False
        and gns3_feedback.get("config_verify_ok") is False
        and gns3_feedback.get("tests_total", 0) == 0
    ):
        return True

    return any(marker in text for marker in technical_markers)
    
def run_llm_batfish_gns3_cycle(
    context_variables: Dict[str, Any],
    *,
    batfish_host: str,
    devices: List[dict],
    max_gns3_repairs: int = 3,
    max_batfish_iters: int = 5,
    include_save: bool = True,
    cleanup_candidate_on_success: bool = False,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Intended flow:
      1) Initial LLM generation
      2) Batfish inner repair loop
      3) If Batfish succeeds -> GNS3 validation
      4) If GNS3 fails -> send GNS3 feedback to LLM and regenerate candidate
      5) Go back to Batfish
      6) Only after GNS3 success -> promote candidate to original config

    Important:
      - Batfish failure is handled inside Batfish_validate_until_ok()
      - GNS3 failure goes back to the LLM, not directly back to Batfish
      - Candidate config is promoted only after GNS3 success
    """
    
    history: List[Dict[str, Any]] = []

    if verbose:
        print("\n======== INITIAL LLM GENERATION ========")

    gen_result = run_ACL_workflow(context_variables)
    history.append({"stage": "llm_generate_initial", "result": gen_result})

    if gen_result.get("conflict_detected"):
        return {
            "status": "conflict_detected",
            "history": history,
            "last": gen_result,
        }

    if gen_result.get("already_exists"):
        return {
            "status": "already_exists",
            "history": history,
            "last": gen_result,
        }

    context_variables.update(gen_result)

    for repair_i in range(1, max_gns3_repairs + 1):
        if verbose:
            print(f"\n======== GNS3 REPAIR ROUND {repair_i}/{max_gns3_repairs} ========")

        bf_result = Batfish_validate_until_ok(
            client=None,
            context_variables=context_variables,
            batfish_host=batfish_host,
            snapshot_name=context_variables.get("snapshot_name", "configs"),
            max_iters=max_batfish_iters,
            verbose=verbose,
        )
        history.append({
            "stage": "batfish",
            "round": repair_i,
            "result": bf_result,
        })

        if not _final_status_is_ok(bf_result):
            if _batfish_is_technical_failure(bf_result):
                return {
                    "status": "batfish_technical_failure",
                    "history": history,
                    "last": bf_result,
                    "reason": "Batfish stopped due to a technical/runtime issue, not an ACL issue.",
                }

            return {
                "status": "batfish_not_ok",
                "history": history,
                "last": bf_result,
            }

        commands = build_deploy_commands_q0_aware(
            acl_snippet=context_variables.get("acl_snippet") or context_variables.get("configuration_response"),
            intf_name=context_variables.get("Intf_Name"),
            direction=context_variables.get("direction"),
            acl_name=context_variables.get("ACLname") or context_variables.get("L_Name"),
            config_text=context_variables.get("config_text", ""),
            include_save=include_save,
        )

        gns3_intent = _build_gns3_intent(context_variables)

        gns3_report = validate_acl_in_gns3(
            intent=gns3_intent,
            acl_commands=commands,
            consol=devices,
            sub_net=context_variables.get("Sub_Net", []),
            include_negative_tests=True,
        )

        gns3_feedback = _gns3_report_to_feedback(gns3_report)

        history.append({
            "stage": "gns3",
            "round": repair_i,
            "commands": commands,
            "report": gns3_feedback,
        })

        if gns3_report.status == "ok":
            _promote_candidate_and_refresh(context_variables, verbose=verbose)

            if cleanup_candidate_on_success:
                _cleanup_candidate_files(context_variables, verbose=verbose)

            return {
                "status": "ok",
                "history": history,
                "gns3_report": gns3_feedback,
                "promoted_config": True,
                "final_router_cfg": os.path.join(
                    context_variables["file_path"],
                    f"{context_variables['File_name']}.cfg",
                ),
            }

        # NEW: stop immediately on technical/runtime GNS3 failures
        if _gns3_is_technical_failure(gns3_feedback):
            return {
                "status": "gns3_technical_failure",
                "history": history,
                "gns3_report": gns3_feedback,
                "reason": "GNS3 verification could not run correctly due to a technical/runtime issue, not an ACL issue.",
            }

        if repair_i == max_gns3_repairs:
            return {
                "status": "gns3_not_ok",
                "history": history,
                "gns3_report": gns3_feedback,
                "reason": "GNS3 validation failed after maximum repair rounds.",
            }

        if verbose:
            print("GNS3 failed due to policy/config behavior. Sending GNS3 feedback to LLM for repair, then re-running Batfish.")

        context_variables["gns3_evidence"] = gns3_feedback
        context_variables["mode"] = "repair_from_gns3"

        gen_result = run_ACL_workflow(context_variables)
        history.append({
            "stage": "llm_repair_from_gns3",
            "round": repair_i,
            "result": gen_result,
        })

        if gen_result.get("conflict_detected"):
            return {
                "status": "conflict_detected",
                "history": history,
                "last": gen_result,
            }

        context_variables.update(gen_result)

    return {
        "status": "gns3_not_ok",
        "history": history,
        "reason": "Unexpected controller exit.",
    }