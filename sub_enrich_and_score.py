"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'destination_address_present' block
    destination_address_present(container=container)
    # call 'safe_default_outputs' block
    safe_default_outputs(container=container)

    return

@phantom.playbook_block()
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ip_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation_1", assets=["talos-intelligence"], callback=calculate_score_v2)

    return


@phantom.playbook_block()
def calculate_score_v2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("calculate_score_v2() called")

    ip_reputation_1_result_data = phantom.collect2(container=container, datapath=["ip_reputation_1:action_result.data.*.Threat_Level","ip_reputation_1:action_result.data.*.Threat_Categories","ip_reputation_1:action_result.status"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress"])

    ip_reputation_1_result_item_0 = [item[0] for item in ip_reputation_1_result_data]
    ip_reputation_1_result_item_1 = [item[1] for item in ip_reputation_1_result_data]
    ip_reputation_1_result_item_2 = [item[2] for item in ip_reputation_1_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    calculate_score_v2__high_risk = None
    calculate_score_v2__risk_score = None
    calculate_score_v2__risk_summary = None
    calculate_score_v2__ioc_used = None
    calculate_score_v2__ioc_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    risk_score_value = 0
    high_risk_value = False
    risk_summary_value = "No reputation data returned."

    destination_values = container_artifact_cef_item_0 if isinstance(container_artifact_cef_item_0, list) else [container_artifact_cef_item_0]
    status_values = ip_reputation_1_result_item_2 if isinstance(ip_reputation_1_result_item_2, list) else [ip_reputation_1_result_item_2]
    level_values = ip_reputation_1_result_item_0 if isinstance(ip_reputation_1_result_item_0, list) else [ip_reputation_1_result_item_0]
    categories_values = ip_reputation_1_result_item_1 if isinstance(ip_reputation_1_result_item_1, list) else [ip_reputation_1_result_item_1]

    ioc_value = ""
    for value in destination_values:
        if value in (None, ""):
            continue
        ioc_value = str(value).strip()
        if ioc_value:
            break

    normalized_categories = []
    for value in categories_values:
        if value in (None, ""):
            continue
        normalized_value = str(value).strip()
        if normalized_value:
            normalized_categories.append(normalized_value)

    for value in level_values:
        if value in (None, ""):
            continue
        normalized_value = str(value).strip().lower()
        if normalized_value.isdigit():
            numeric_value = int(normalized_value)
            if numeric_value > risk_score_value:
                risk_score_value = numeric_value
        else:
            severity_map = {
                "very low": 10,
                "low": 25,
                "medium": 50,
                "high": 75,
                "very high": 90,
                "critical": 95
            }
            mapped_value = severity_map.get(normalized_value)
            if mapped_value is not None and mapped_value > risk_score_value:
                risk_score_value = mapped_value

    high_risk_categories = ["malware", "botnet", "phishing", "c2", "command and control", "spam", "blacklist"]
    for value in normalized_categories:
        normalized_value = value.lower()
        if any(category in normalized_value for category in high_risk_categories):
            high_risk_value = True
            break

    if risk_score_value >= 70:
        high_risk_value = True

    status_failed = any(str(value).strip().lower() == "failed" for value in status_values if value not in (None, ""))
    if status_failed:
        high_risk_value = False
        risk_score_value = 0
        risk_summary_value = "IP reputation lookup failed. Returning normalized safe default score."
    elif normalized_categories or risk_score_value > 0:
        category_text = ", ".join(normalized_categories) if normalized_categories else "none"
        risk_summary_value = "IP reputation evaluated for {0}. Score={1}. Categories={2}.".format(ioc_value or "destination IP", risk_score_value, category_text)
    else:
        risk_summary_value = "IP reputation completed for {0} with no threat indicators returned.".format(ioc_value or "destination IP")

    calculate_score_v2__high_risk = high_risk_value
    calculate_score_v2__risk_score = risk_score_value
    calculate_score_v2__risk_summary = risk_summary_value
    calculate_score_v2__ioc_used = ioc_value
    calculate_score_v2__ioc_type = "ip"
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="calculate_score_v2__inputs:0:ip_reputation_1:action_result.data.*.Threat_Level", value=json.dumps(ip_reputation_1_result_item_0))
    phantom.save_block_result(key="calculate_score_v2__inputs:1:ip_reputation_1:action_result.data.*.Threat_Categories", value=json.dumps(ip_reputation_1_result_item_1))
    phantom.save_block_result(key="calculate_score_v2__inputs:2:ip_reputation_1:action_result.status", value=json.dumps(ip_reputation_1_result_item_2))
    phantom.save_block_result(key="calculate_score_v2__inputs:3:artifact:*.cef.destinationAddress", value=json.dumps(container_artifact_cef_item_0))

    phantom.save_block_result(key="calculate_score_v2:high_risk", value=json.dumps(calculate_score_v2__high_risk))
    phantom.save_block_result(key="calculate_score_v2:risk_score", value=json.dumps(calculate_score_v2__risk_score))
    phantom.save_block_result(key="calculate_score_v2:risk_summary", value=json.dumps(calculate_score_v2__risk_summary))
    phantom.save_block_result(key="calculate_score_v2:ioc_used", value=json.dumps(calculate_score_v2__ioc_used))
    phantom.save_block_result(key="calculate_score_v2:ioc_type", value=json.dumps(calculate_score_v2__ioc_type))

    phantom.save_block_result(key="calculate_score_v2_called", value="True")

    return


@phantom.playbook_block()
def destination_address_present(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("destination_address_present() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "is not empty", ""]
        ],
        conditions_dps=[
            ["artifact:*.cef.destinationAddress", "is not empty", ""]
        ],
        name="destination_address_present:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def safe_default_outputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("safe_default_outputs() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    safe_default_outputs__high_risk = None
    safe_default_outputs__risk_score = None
    safe_default_outputs__risk_summary = None
    safe_default_outputs__ioc_used = None
    safe_default_outputs__ioc_type = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    destination_values = container_artifact_cef_item_0 if isinstance(container_artifact_cef_item_0, list) else [container_artifact_cef_item_0]

    ioc_value = ""
    for value in destination_values:
        if value in (None, ""):
            continue
        ioc_value = str(value).strip()
        if ioc_value:
            break

    safe_default_outputs__high_risk = False
    safe_default_outputs__risk_score = 0
    safe_default_outputs__ioc_used = ioc_value
    safe_default_outputs__ioc_type = "ip"

    if ioc_value:
        safe_default_outputs__risk_summary = "Destination IP present but enrichment was not run. Returning safe default score."
    else:
        safe_default_outputs__risk_summary = "No destination IP present. Returning safe default score."
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="safe_default_outputs__inputs:0:artifact:*.cef.destinationAddress", value=json.dumps(container_artifact_cef_item_0))

    phantom.save_block_result(key="safe_default_outputs:high_risk", value=json.dumps(safe_default_outputs__high_risk))
    phantom.save_block_result(key="safe_default_outputs:risk_score", value=json.dumps(safe_default_outputs__risk_score))
    phantom.save_block_result(key="safe_default_outputs:risk_summary", value=json.dumps(safe_default_outputs__risk_summary))
    phantom.save_block_result(key="safe_default_outputs:ioc_used", value=json.dumps(safe_default_outputs__ioc_used))
    phantom.save_block_result(key="safe_default_outputs:ioc_type", value=json.dumps(safe_default_outputs__ioc_type))

    phantom.save_block_result(key="safe_default_outputs_called", value="True")

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