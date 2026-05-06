# noinspection PyUnresolvedReferences
from pybatfish.datamodel.answer import TableAnswer
from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints  
from pybatfish.util import get_html
from tabulate import tabulate 

from Batfish.preprocess import * 
from Helpers.Formats import normalize_action
# normalize_action, action_test, analyze_ip, choose_ip_in_subnet, choose_any_ip, choose_ip_outside_subnet, choose_ip_from_subnet, protocol_test

def _norm_bf_action(a):
    return (a or "").strip().lower()

def col(df,name):
    for c in df.columns:
        if c.lower() == name.lower():
            return c
    return None

def _canon_spaces(s):
    if s is None:
        return ""
    if isinstance(s, (list, tuple, set)):
        s = " ".join(str(x) for x in s if x)
    else:
        s = str(s)
    return re.sub(r"\s+", " ", s.strip().lower())

################################# Discover where the ACL is actually attached #################################
################# Instead of trusting Intf_Name and direction from the agent, ask Batfish:  ###################
##################### “On which interface(s) is ACL acl_in attached inbound/outbound?” ########################
############# So: attachment check is required if you care about direction/interface correctness. #############
###############################################################################################################
def find_acl_attachments(bf, hostname, acl_name, snapshot_name=None):
    acl_norm = (acl_name or "").strip().lower()
    hostname = (hostname or "").strip().lower()

    q = bf.q.interfaceProperties(
        nodes=hostname,
        properties="Incoming_Filter_Name,Outgoing_Filter_Name",
    )
    df = q.answer(snapshot=snapshot_name).frame()

    # fallback: query all nodes if hostname did not match
    if df.empty:
        q = bf.q.interfaceProperties(
            properties="Incoming_Filter_Name,Outgoing_Filter_Name",
        )
        df = q.answer(snapshot=snapshot_name).frame()

    c_intf = col(df, "Interface") or col(df, "Interfaces")
    c_in = col(df, "Incoming_Filter_Name")
    c_out = col(df, "Outgoing_Filter_Name")
    c_node = col(df, "Node")

    attachments = []

    for _, r in df.iterrows():
        node = str(r.get(c_node, "")).strip().lower() if c_node else ""
        if hostname and node and node != hostname:
            continue

        iface = r.get(c_intf)
        inc = str(r.get(c_in, "") or "").strip().lower()
        out = str(r.get(c_out, "") or "").strip().lower()

        if inc == acl_norm:
            attachments.append({"interface": iface, "direction": "in"})
        if out == acl_norm:
            attachments.append({"interface": iface, "direction": "out"})

    return attachments, df

##################### Q0: Verify the ACL is attached on (interface, direction) #####################
def assert_acl_attached(bf, hostname, intf_name, direction, expected_acl, snapshot_name=None):
    dir_norm = (direction or "").strip().lower()
    if dir_norm not in ("in", "out"):
        raise ValueError(f"direction must be in/out, got {direction!r}")

    expected_norm = (expected_acl or "").strip().lower()

    q = bf.q.interfaceProperties(
        nodes      = hostname,
        interfaces = intf_name,
        properties = "Incoming_Filter_Name,Outgoing_Filter_Name",
    )
    df = q.answer(snapshot=snapshot_name).frame()

    incoming = outgoing = None
    if not df.empty:
        row = df.iloc[0]
        incoming = row.get("Incoming_Filter_Name", None)
        outgoing = row.get("Outgoing_Filter_Name", None)

    actual = incoming if dir_norm == "in" else outgoing
    ok = ((actual or "").strip().lower() == expected_norm)

    # show only columns that exist
    wanted = ["Node", "Hostname", "Interface", "Incoming_Filter_Name", "Outgoing_Filter_Name"]
    cols = [c for c in wanted if c in df.columns]
    attach_df = df[cols] if (not df.empty and cols) else df
    
    print("interfaceProperties columns:", df.columns.tolist())
    print(df.head())
    
    return ok, attach_df, actual

######################################### (Q1) Step 1: TestFilters #############################################
# ########## Testing how filters treat a flow to see if a specific flow from a single device is blocked/permitted
# The testFilters question shows what filters do with a particular flow and why. 
# It takes as input the details of the flow and a set of filters to test. 
# The answer provides a detailed view of how the flow is treated by each filter in the set (permitted / denied).
#################################################################################################################

def check_Rule_access_at_iface(
    bf,
    src_ip,
    dst_ip,
    application,
    hostname,
    intf_name,
    direction,
    snapshot_name=None,
):
    """
    Q1 point check.

    For inbound ACLs:
      startLocation = @enter(host[intf])

    For outbound ACLs:
      do not force @enter(host[intf]), because that is the egress interface.
    """
    dir_norm = direction.strip().lower()
    if dir_norm not in ("in", "out"):
        raise ValueError(f"direction must be 'in' or 'out', got: {direction}")

    filter_ref = f"@{dir_norm}({hostname}[{intf_name}])"

    headers = HeaderConstraints(
        srcIps=src_ip,
        dstIps=dst_ip,
        applications=[application] if application else None,
    )

    if dir_norm == "in":
        q = bf.q.testFilters(
            headers=headers,
            startLocation=f"@enter({hostname}[{intf_name}])",
            filters=filter_ref,
        )
    else:
        q = bf.q.testFilters(
            headers=headers,
            filters=filter_ref,
            nodes=hostname,
        )

    ans = q.answer(snapshot=snapshot_name) if snapshot_name else q.answer()
    return ans.frame()

# --- Swarm tool wrapper ---
def check_Rule_access_tool(
    scr_suggested,
    dst_suggested,
    application,
    L_name,
    hostname,
    SNAPSHOT_NAME,
    context_variables=None,
):
    # get bf from context_variables
    bf = context_variables["bf"]
    return check_Rule_access(bf, scr_suggested, dst_suggested, application, L_name, hostname, SNAPSHOT_NAME)
    

######################## (Q2) Step 2: SearchFilters (Check for violations)####################################
# ########## to verify if all traffic from the subnet is being blocked/permitted,
# Given a space of flows, specified using header fields such as source and destination addresses and ports, 
# and a matching condition (e.g., permit, deny) as input, this question finds flows that satisfy the condition.
# If it reports no flows, then it is guaranteed that no flow within the space satisfies the condition.
# An empty result means the policy is correctly implemented. 
# Any flow returned by the query demonstrates that the policy is not correctly implemented.
###################################################################################################
    #####################################################################################
    #### Check if the intended traffic is already permitted in the current snapshot #####
    #####################################################################################

# 1- we search for the rule existence in the subnet as a whole.

def check_subnet_access_at_iface(
    bf, src_prefix, dst_prefix, application, port, action_to_search, hostname, intf_name, direction, snapshot_name=None,
):
    """
    - searchFilters returns flows in the specified space that match action_to_search
    - for violation-hunting:
        action_to_search = opposite action (deny if expected permit, etc.)
      PASS is EMPTY.
    """
    dir_norm = direction.strip().lower()
    if dir_norm not in ("in", "out"):
        raise ValueError(f"direction must be 'in' or 'out', got: {direction}")
    
    # filter_ref = f"@{dir_norm}({intf_name})"
    filter_ref = f"@{dir_norm}({hostname}[{intf_name}])"
    # IMPORTANT: startLocation must match direction
    # if dir_norm == "in":
    #     start_loc = f"@enter({hostname}[{intf_name}])"
    # else:
    #     start_loc = f"@exit({hostname}[{intf_name}])"
    start_loc = f"@enter({hostname}[{intf_name}])"
        
    
    headers = HeaderConstraints(
        srcIps=src_prefix,
        dstIps=dst_prefix,
        applications=[application] if application else None,
        # If you want to constrain ports without "application":
        # dstPorts=port if port else None,
        # ipProtocols=["tcp"] etc. if needed
    )

    q = bf.q.searchFilters(
        headers=headers,
        startLocation=start_loc,
        filters=filter_ref,
        action=action_to_search,   # IMPORTANT: this is what you SEARCH for (violations or confirms)
        # nodes=hostname,            # optional 
    )

    ans = q.answer(snapshot=snapshot_name) if snapshot_name else q.answer()
    return ans.frame()

def run_q2_violation_check(
    bf,
    node_name,
    intf_name,
    direction,
    snapshot_name,
    src_prefix,
    dst_prefixes,
    action_to_search,
    application,
    port,
    label,
    verbose=False,
):
    checks = []
    for dst_net in dst_prefixes:
        # df_v = check_subnet_access_positive(
        #     bf=bf,
        #     file_path=context_variables.get("config_file_path", ""),
        #     src_Subnet=src_prefix,          # can be /32 or subnet CIDR
        #     dst_Subnet=dst_net,             # should be CIDR
        #     application=app if app != "none" else None,
        #     port=port if port != "none" else None,
        #     action=action_to_search,        # IMPORTANT: this is the action we SEARCH for (violations)
        #     L_name=L_Name,
        #     hostname=node_name,
        # )
        df_v = check_subnet_access_at_iface(
            bf=bf,
            src_prefix=src_prefix,       # can be /32 or /24
            dst_prefix=dst_net,          # /24
            application=None if application == "none" else application,
            port=None if port == "none" else port,
            action_to_search=action_to_search,
            hostname=node_name,
            intf_name=intf_name,
            direction=direction,
            snapshot_name=snapshot_name,
        )
        ok = df_v.empty
        checks.append({
            "check": label,
            "src": src_prefix,
            "dst": dst_net,
            "searched_action": action_to_search,
            "violations_empty": ok,
            "df": df_v,
        })

        if verbose:
            print(f"\n{label} | src={src_prefix} dst={dst_net} | searching violations action={action_to_search}")
            if ok:
                print("PASS: EMPTY (no violations).")
            else:
                print("FAIL: Violations found:")
                print(tabulate(df_v, headers="keys", tablefmt="grid"))
    return checks
    
def check_subnet_access_positive(bf, file_path, src_Subnet, dst_Subnet , application, port, action, L_name, hostname):
    # Q2 Positive: search for flows that behave as expected (expected_action)
    #     in the given src/dst subnet space.
    
    #     Returns a DataFrame of matching flows.
    #     Non-empty => at least one flow behaves as expected.
    #     Empty     => no flows behave as expected.   
    
    expected_action = normalize_action(action)

    search_filter = HeaderConstraints(
    srcIps = src_Subnet, 
    dstIps = dst_Subnet, 
    applications=[application] if application else None,
        # you can optionally add protocol/port constraints here if not encoded in application
        # dstPorts=port or ipProtocols=["tcp"] etc.
    ) 

    answer = bf.q.searchFilters(headers = search_filter,
                            action = action, # we search for expected behavior
                            nodes = hostname,
                            filters = L_name).answer() 
    out = answer.frame()
    # print("return")
    return out
    
def check_subnet_access_positive_tool(
    file_path,
    src_Subnet,
    dst_Subnet,
    application,
    port,
    action,
    L_name,
    hostname,
    context_variables=None,
):
    bf = context_variables["bf"]
    return check_subnet_access_positive(bf, file_path, src_Subnet, dst_Subnet , application, port, action, L_name, hostname)


#  2- we search for the other addresses in the subnet to see if they are not aligned with the action (not_action)

def check_subnet_access_negative(bf, file_path, src_Subnet, dst_Subnet , application, port, action, L_name, hostname):
       # Q2 Negative: search for flows that behave in the UNWANTED way
       #  (opposite of expected_action) in the given src/dst subnet space.
    
       #  Returns a DataFrame of violating flows.
       #  Non-empty => violations exist.
       #  Empty     => no violations.

    expected_action = normalize_action(action)
    not_action = action_test(expected_action)

    search_filter = HeaderConstraints(
    srcIps = src_Subnet, 
    dstIps = dst_Subnet, 
    applications=[application] if application else None,
    ) 

    answer = bf.q.searchFilters(headers = search_filter,
                            action = not_action,   # we search for violations
                            nodes = hostname,
                            filters = L_name).answer() 
    out = answer.frame()
    return out

def check_subnet_access_negative_tool(
    file_path,
    src_Subnet,
    dst_Subnet,
    application,
    port,
    not_action,
    L_name,
    hostname,
    context_variables=None,
):
    bf = context_variables["bf"]
    return check_subnet_access_negative(bf, file_path, src_Subnet, dst_Subnet , application, port, not_action, L_name, hostname)


def run_q2_searchfilters_tests(bf, file_path, src_Subnet, dst_Subnet, application,port, action, L_name, hostname, verbose = True):
    # Run Q2 Positive + Negative automatically for a rule.

    # - Positive: search for flows with expected action (permit/deny).
    # - Negative: search for flows with opposite (unwanted) action.

    # Strong guarantee semantics:
    #   - We EXPECT:
    #       * Positive: at least some flows behave as the rule says.
    #       * Negative: NO flows behave in the opposite way.


    summary = {
        "Q2_positive_status": None,
        "Q2_positive_detail": "",
        "Q2_negative_status": None,
        "Q2_negative_detail": "",
    }

    if not src_Subnet or not dst_Subnet:
        summary["Q2_positive_status"] = "skipped"
        summary["Q2_positive_detail"] = "No src/dst subnet → Q2 Positive skipped."
        summary["Q2_negative_status"] = "skipped"
        summary["Q2_negative_detail"] = "No src/dst subnet → Q2 Negative skipped."
        return summary

    expected_action = normalize_action(action)

    # ----- Q2 POSITIVE -----
    df_pos = check_subnet_access_positive(
        bf,
        file_path,
        src_Subnet,
        dst_Subnet,
        application,
        port,
        expected_action,
        L_name,
        hostname,
    )

    if verbose:
        print("\n=== Q2 Positive: expected action =", expected_action, "===")
        if df_pos.empty:
            print("No flows behave as expected between", src_Subnet, "and", dst_Subnet)
        else:
            print(tabulate(df_pos, headers="keys", tablefmt="grid"))

    if df_pos.empty:
        summary["Q2_positive_status"] = "failed"
        summary["Q2_positive_detail"] = (
            f"No flows with expected action {expected_action} between "
            f"{src_Subnet} and {dst_Subnet}."
        )
    else:
        summary["Q2_positive_status"] = "passed"
        summary["Q2_positive_detail"] = (
            f"Found flows with expected action {expected_action} between "
            f"{src_Subnet} and {dst_Subnet}."
        )

    # ----- Q2 NEGATIVE -----
    df_neg = check_subnet_access_negative(
        bf,
        file_path,
        src_Subnet,
        dst_Subnet,
        application,
        port,
        expected_action,
        L_name,
        hostname,
    )
    not_action = action_test(expected_action)

    if verbose:
        print("\n=== Q2 Negative: searching for UNWANTED action =", not_action, "===")
        if df_neg.empty:
            print("No flows with unwanted action", not_action, "found.")
        else:
            print("Found violating flows with unwanted action", not_action, ":")
            print(tabulate(df_neg, headers="keys", tablefmt="grid"))

    if df_neg.empty:
        summary["Q2_negative_status"] = "passed"
        summary["Q2_negative_detail"] = (
            f"No flows with unwanted action {not_action} between "
            f"{src_Subnet} and {dst_Subnet}."
        )
    else:
        summary["Q2_negative_status"] = "failed"
        summary["Q2_negative_detail"] = (
            f"Found flows with unwanted action {not_action} between "
            f"{src_Subnet} and {dst_Subnet}."
        )

    return summary

###################################### (Q3) Step 3: Filter Line Reachability ######################################
# Analyzing the reachability of filter lines. 
# When debugging or editing filters, it can be useful to confirm that every line is reachable.
########################################################################################################################################

def check_Reachibility (bf, hostname):
    aclAns = bf.q.filterLineReachability(nodes = hostname).answer()
    sorted_aclAns = aclAns.frame().sort_values(by = "Unreachable_Line")     # Sort the DataFrame based on "Unreachable_Line"
    # show(sorted_aclAns)
    return sorted_aclAns
    # Extract and format the information
    # text_output = extract_table_info(sorted_aclAns)
    # print("text_output is " , text_output)     # Print the formatted output
    # return text_output

def check_Reachibility_tool(
    hostname,
    context_variables=None,
):
    bf = context_variables["bf"]
    return check_Reachibility(bf, hostname)



################################################################################################################
# This decision function takes the outputs from Q1 / Q2 / Q3 and returns an overall verdict: 
# fully_correct | partially_correct | not_implemented | conflicting_or_shadowed, plus concise reasons.
# It's designed for your exact pipeline where:

# Q1 uses testFilters(positive + optional negative flow)
# Q2 is used searchFiltersfor violation-hunting (empty = good)
# Q3 uses reachability (empty = good)
################################################################################################################
def decide_from_batfish_results(results: dict):
    """
    Expects results["Q0"], results["Q1"], results["Q2"], results["Q3"] already filled.
    Returns: (final_status, summary_text, reasons_list, failed_stage)
    """
    reasons = []
    final_status = "ok"
    failed_stage = None

    # ---- Q0 placement
    q0 = results.get("Q0", {})
    if q0 and (not q0.get("ok_expected_vs_snapshot", True)):
        final_status = "needs_finetune"
        reasons.append("Q0: ACL attachment in snapshot != expected placement (choose_acl_attachment).")
        if failed_stage is None:
            failed_stage = "Q0"

    # ---- Q1 point checks 
    q1 = results.get("Q1", {})
    pos = q1.get("positive", {})
    if pos:
        if pos.get("ok") is False:
            final_status = "needs_finetune"
            reasons.append(f"Q1: positive flow failed: {pos.get('details', {}).get('reason', 'unknown')}")
            if failed_stage is None:
                failed_stage = "Q1"
    else:
        final_status = "needs_finetune"
        reasons.append("Q1: missing positive test result (not executed or error).")
        if failed_stage is None:
            failed_stage = "Q1"

    neg = q1.get("negative", {})
    if isinstance(neg, dict) and neg.get("ok") is False:
        # negative failing usually means policy too loose/tight
        final_status = "needs_finetune"
        reasons.append(f"Q1: negative flow failed: {neg.get('details', {}).get('reason', 'unknown')}")
        if failed_stage is None:
            failed_stage = "Q1"

    # ---- Q2 violation hunting 
    q2 = results.get("Q2", {})
    viols = q2.get("violation_checks", [])
    if viols:
        failed = [v for v in viols if v.get("violations_empty") is False]
        if failed:
            final_status = "needs_finetune"
            reasons.append(f"Q2: violations found in {len(failed)} check(s).")
            if failed_stage is None:
                failed_stage = "Q2"
    # if Q2 not run, don't fail automatically

    # ---- Q3 unreachable lines (medium)
    q3 = results.get("Q3", {})
    q3df = q3.get("df")
    if q3df is not None:
        try:
            if not q3df.empty:
                # shadowing is usually a finetune issue (ordering, redundant lines)
                final_status = "needs_finetune"
                reasons.append(f"Q3: unreachable/shadowed ACL lines found: {len(q3df)}")
                if failed_stage is None:
                    failed_stage = "Q3"
        except Exception:
            pass

    summary = "OK" if final_status == "ok" else "Needs finetune"
    return final_status, summary, reasons, failed_stage


def decide_acl_health_from_batfish(q1_pos_df,
                                  expected_action_pos,
                                  q1_neg_df = None,
                                  expected_action_neg = None,
                                  q2_violation_results = None,
                                  q3_unreachable_df = None):
    """
    Decide ACL correctness from Batfish outputs.

    Inputs:
      - q1_pos_df: DataFrame returned by testFilters for the positive flow.
      - expected_action_pos: 'permit' / 'deny'
      - q1_neg_df: DataFrame for negative flow (optional).
      - expected_action_neg: expected action for negative flow (optional).
      - q2_violation_results: list of dicts, each like:
            {"dst_subnet": "...", "violations_empty": bool, "df": <DataFrame>}
        where violations_empty==True means PASS for that dst subnet.
        (This matches violation-hunting searchFilters semantics.)
      - q3_unreachable_df: DataFrame returned by reachability check (optional).

    Returns: dict with keys:
      - Validation_Status
      - Summary
      - Q1, Q2, Q3 details
      - Recommended_Action
    """

    verdict = {
        "Validation_Status": None,
        "Summary": "",
        "Q1": {"status": None, "reason": ""},
        "Q2": {"status": None, "reason": ""},
        "Q3": {"status": None, "reason": ""},
        "Recommended_Action": "none",
    }

    exp_pos = _norm_bf_action(expected_action_pos)

    # -------------------------
    # Q1 Positive evaluation
    # -------------------------
    if q1_pos_df is None or getattr(q1_pos_df, "empty", True):
        verdict["Q1"]["status"] = "fail"
        verdict["Q1"]["reason"] = "Q1 positive returned EMPTY (no ACL line matched) → rule likely not implemented."
        q1_pos_ok = False
    else:
        # We accept if ANY row's Action matches expected action (permit/deny)
        actions = [_norm_bf_action(x) for x in list(q1_pos_df.get("Action", []))]
        if exp_pos in actions:
            verdict["Q1"]["status"] = "pass"
            verdict["Q1"]["reason"] = f"Q1 positive matched expected action '{exp_pos}'."
            q1_pos_ok = True
        else:
            verdict["Q1"]["status"] = "fail"
            verdict["Q1"]["reason"] = f"Q1 positive did not match expected action '{exp_pos}'. Found: {actions}"
            q1_pos_ok = False

    # -------------------------
    # Q1 Negative evaluation (optional but strong)
    # -------------------------
    q1_neg_ok = None
    if q1_neg_df is not None and expected_action_neg is not None:
        exp_neg = _norm_bf_action(expected_action_neg)
        if getattr(q1_neg_df, "empty", True):
            verdict["Q1"]["reason"] += " Q1 negative returned EMPTY (no ACL line matched)."
            # Empty negative is ambiguous; mark as partial signal
            q1_neg_ok = None
        else:
            actions = [_norm_bf_action(x) for x in list(q1_neg_df.get("Action", []))]
            if exp_neg in actions:
                verdict["Q1"]["reason"] += f" Q1 negative matched expected action '{exp_neg}'."
                q1_neg_ok = True
            else:
                verdict["Q1"]["reason"] += f" Q1 negative did NOT match expected '{exp_neg}'. Found: {actions}"
                q1_neg_ok = False

    # -------------------------
    # Q2 violation evaluation (searchFilters)
    # violation-hunting semantics:
    #   empty => PASS, non-empty => FAIL
    # -------------------------
    if not q2_violation_results:
        verdict["Q2"]["status"] = "skipped"
        verdict["Q2"]["reason"] = "Q2 not run."
        q2_ok = None
    else:
        failed = [r for r in q2_violation_results if not r.get("violations_empty", False)]
        if not failed:
            verdict["Q2"]["status"] = "pass"
            verdict["Q2"]["reason"] = "Q2 violation hunting: all checks EMPTY (no violations)."
            q2_ok = True
        else:
            verdict["Q2"]["status"] = "fail"
            bad_subnets = [r.get("dst_subnet") for r in failed]
            verdict["Q2"]["reason"] = f"Q2 found violations for dst_subnets: {bad_subnets}"
            q2_ok = False

    # -------------------------
    # Q3 reachability evaluation
    # -------------------------
    if q3_unreachable_df is None:
        verdict["Q3"]["status"] = "skipped"
        verdict["Q3"]["reason"] = "Q3 not run."
        q3_ok = None
    else:
        if getattr(q3_unreachable_df, "empty", True):
            verdict["Q3"]["status"] = "pass"
            verdict["Q3"]["reason"] = "No unreachable/shadowed ACL lines."
            q3_ok = True
        else:
            verdict["Q3"]["status"] = "fail"
            verdict["Q3"]["reason"] = f"Unreachable/shadowed ACL lines found: {len(q3_unreachable_df)}"
            q3_ok = False

    # -------------------------
    # Final decision logic
    # -------------------------
    # 1) If Q1 positive fails badly -> not implemented
    if not q1_pos_ok:
        verdict["Validation_Status"] = "not_implemented"
        verdict["Summary"] = "Positive intent flow does not match expected behavior."
        verdict["Recommended_Action"] = "Check ACL attachment/direction, rule placement, and match conditions (src/dst/app/port)."
        return verdict

    # 2) Q1 positive OK. Now check Q3 shadowing.
    if q3_ok is False:
        verdict["Validation_Status"] = "conflicting_or_shadowed"
        verdict["Summary"] = "Rule behavior works for tested flow, but reachability indicates shadowed/unreachable ACL lines."
        verdict["Recommended_Action"] = "Reorder ACL entries or remove conflicting earlier rules causing shadowing."
        return verdict

    # 3) If Q2 finds violations, it's partially correct (works for sample flow, but space has counterexamples)
    if q2_ok is False:
        verdict["Validation_Status"] = "partially_correct"
        verdict["Summary"] = "Sample flow behaves correctly, but searchFilters found policy violations in the flow space."
        verdict["Recommended_Action"] = "Inspect violating flows in Q2 output; adjust ACL to eliminate unintended permits/denies."
        return verdict

    # 4) If we have a strong negative test and it failed => partially correct
    if q1_neg_ok is False:
        verdict["Validation_Status"] = "partially_correct"
        verdict["Summary"] = "Positive flow correct, but negative flow did not match expected restriction."
        verdict["Recommended_Action"] = "Tighten ACL match conditions (e.g., 'only host', dst scope, port/app constraints)."
        return verdict

    # 5) Otherwise: fully correct (Q1 ok; Q2 ok or skipped; Q3 ok or skipped)
    verdict["Validation_Status"] = "fully_correct"
    verdict["Summary"] = "No evidence of incorrect ACL behavior in Q1/Q2/Q3."
    verdict["Recommended_Action"] = "none"
    return verdict

def q1_validate_result(df, expected_action, expected_rule_text=None, require_explicit_match=False):
    """
    df: batfish testFilters dataframe
    expected_action: 'permit'/'deny'
    expected_rule_text: optional rule line text
    require_explicit_match:
       - if True: require matching ACL line (except when line == 'no-match')
       - if False: action match alone is sufficient
    """
    details = {"ok": False, "reason": "", "matched_row": None}

    if df is None or getattr(df, "empty", True):
        details["reason"] = "EMPTY testFilters result (no matching row)"
        return False, details

    exp_act = normalize_action(expected_action)
    if expected_rule_text is None:
        exp_rules = []
    elif isinstance(expected_rule_text, str):
        exp_rules = [_canon_spaces(expected_rule_text)]
    elif isinstance(expected_rule_text, (list, tuple, set)):
        exp_rules = [_canon_spaces(str(x)) for x in expected_rule_text if x]
    else:
        exp_rules = [_canon_spaces(str(expected_rule_text))]

    for _, row in df.iterrows():
        act = normalize_action(row.get("Action"))
        line = row.get("Line_Content") or ""
        line_c = _canon_spaces(line)

        # First requirement: action must match
        if act != exp_act:
            continue

        # If explicit match required AND rule text provided
        if require_explicit_match and exp_rule:
            # If Batfish says "no-match", accept action match
            if line_c == "no-match":
                details["ok"] = True
                details["matched_row"] = {
                    "Action": row.get("Action"),
                    "Line_Content": row.get("Line_Content"),
                    "Trace": row.get("Trace"),
                }
                details["reason"] = "Action matched (line reported as no-match by Batfish)."
                return True, details

            # Otherwise check rule content match
            if exp_rule not in line_c and line_c not in exp_rule:
                continue

        # If explicit match not required → action match is enough
        details["ok"] = True
        details["matched_row"] = {
            "Action": row.get("Action"),
            "Line_Content": row.get("Line_Content"),
            "Trace": row.get("Trace"),
        }
        details["reason"] = "Matched expected action."
        return True, details

    # nothing matched
    actions = list(df.get("Action", [])) if "Action" in df.columns else []
    lines   = list(df.get("Line_Content", [])) if "Line_Content" in df.columns else []
    details["reason"] = f"No row matched expected action={exp_act}. Found actions={actions}, lines={lines}"
    return False, details