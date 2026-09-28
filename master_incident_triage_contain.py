"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_deduplication' block
    check_deduplication(container=container)

    return

@phantom.playbook_block()
def check_deduplication(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_deduplication() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    container_id = container.get("id")
    artifacts = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress"], scope="all") or []

    src_ip = None
    for row in artifacts:
        if row and row[0]:
            src_ip = row[0]
            break

    # Check if another open container with same label exists
    url = (
        phantom.build_phantom_rest_url("container")
        + '?_filter_status!="closed"'
        + '&page_size=10'
    )
    response = phantom.requests.get(url, verify=False).json()

    is_duplicate = False
    matched_parent_id = None

    for existing_cont in response.get("data", []):
        if existing_cont.get("id") != container_id:
            existing_artifacts = phantom.requests.get(
                phantom.build_phantom_rest_url("container", existing_cont.get("id"), "artifacts"),
                verify=False
            ).json()
            for e_art in existing_artifacts.get("data", []):
                if src_ip and e_art.get("cef", {}).get("sourceAddress") == src_ip:
                    is_duplicate = True
                    matched_parent_id = existing_cont.get("id")
                    break
        if is_duplicate:
            break

    phantom.save_block_result(key="is_duplicate", value=str(is_duplicate))
    phantom.save_block_result(key="matched_parent_id", value="" if matched_parent_id is None else str(matched_parent_id))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="check_deduplication_called", value="True")

    deduplication_result(container=container)

    return


@phantom.playbook_block()
def update_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("update_container() called")

    ################################################################################
    # Duplicate
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def deduplication_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("deduplication_result() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["custom_code:check_deduplication:is_duplicate", "==", True]
        ],
        conditions_dps=[
            ["custom_code:check_deduplication:is_duplicate", "==", True]
        ],
        name="deduplication_result:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_container(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    source_ip_present(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def sub_enrich_and_score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("sub_enrich_and_score() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/sub_enrich_and_score", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/sub_enrich_and_score", container=container, name="sub_enrich_and_score", callback=threat_score_gate)

    return


@phantom.playbook_block()
def threat_score_gate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("threat_score_gate() called")

    severity_value = container.get("severity", None)

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            [severity_value, "==", "high"]
        ],
        conditions_dps=[
            ["container:severity", "==", "high"]
        ],
        name="threat_score_gate:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        host_isolation_prompt(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            [severity_value, "==", "critical"]
        ],
        conditions_dps=[
            ["container:severity", "==", "critical"]
        ],
        name="threat_score_gate:condition_2",
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        return

    return


@phantom.playbook_block()
def host_isolation_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("host_isolation_prompt() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """High-risk threat detected. Approve host isolation?"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Approve host isolation?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="host_isolation_prompt", parameters=parameters, response_types=response_types, callback=host_isolation_decision)

    return


@phantom.playbook_block()
def host_isolation_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("host_isolation_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["host_isolation_prompt:action_result.summary.responses.0", "==", "Yes"]
        ],
        conditions_dps=[
            ["host_isolation_prompt:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="host_isolation_decision:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        firewall_block_prompt(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_approval_rejected_note(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def containment_status_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("containment_status_update() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    join_containment_response_note(container=container)
    containment_response_pin(container=container)

    return


@phantom.playbook_block()
def firewall_block_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("firewall_block_prompt() called")

    # set approver and message variables for phantom.prompt call

    user = phantom.collect2(container=container, datapath=["playbook:launching_user.name"])[0][0]
    role = None
    message = """Approve firewall block for the suspicious source IP?"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Approve firewall block?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="firewall_block_prompt", parameters=parameters, response_types=response_types, callback=firewall_block_decision)

    return


@phantom.playbook_block()
def firewall_block_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("firewall_block_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["firewall_block_prompt:action_result.summary.responses.0", "==", "Yes"]
        ],
        conditions_dps=[
            ["firewall_block_prompt:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="firewall_block_decision:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        containment_status_update(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    join_approval_rejected_note(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def join_approval_rejected_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_approval_rejected_note() called")

    if phantom.completed(action_names=["host_isolation_prompt", "firewall_block_prompt"]):
        # call connected block "approval_rejected_note"
        approval_rejected_note(container=container, handle=handle)

    return


@phantom.playbook_block()
def approval_rejected_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("approval_rejected_note() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(comment="Containment approval was declined by analyst.")

    return


@phantom.playbook_block()
def source_ip_present(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("source_ip_present() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "is not empty", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.sourceAddress", "is not empty", ""]
        ],
        name="source_ip_present:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        sub_enrich_and_score(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def join_containment_response_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_containment_response_note() called")

    if phantom.completed(action_names=["firewall_block_prompt"]):
        # call connected block "containment_response_note"
        containment_response_note(container=container, handle=handle)

    return


@phantom.playbook_block()
def containment_response_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("containment_response_note() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(comment="Containment actions approved: host isolation and firewall block selected. Returning response for assets; no live containment action executed.")

    return


@phantom.playbook_block()
def containment_response_pin(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("containment_response_pin() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(message="Containment actions approved: host isolation and firewall block selected. Returning response for assets; no live containment action executed.", pin_style="blue")

    join_containment_response_note(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return