# scenario1-sumo.py
# author: jd@sumologic.com
# description: This script creates custom Sumo config needed for wiz-sumo-demo scenario 1 "exposed AWS access keys"
#

import os
import subprocess
import sys
import logging
import getpass
import base64
import json
import urllib3

# set up logging
logging.basicConfig(
    stream=sys.stdout,
    format="[%(levelname)-4s, line %(lineno)d] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
    force=True,
)
logger = logging.getLogger(__name__)


def get_quicklab_details():
    """
    Method that determines QuicLab details by reading
    terraform outputs, environment variables, or from user input.
    See quicklab.io for QuickLab setup giude.

    Returns:
        pf (str): The QuickLab prefix, set in aws.auto.tfvars (default: 'quicklab').
        l (str):  The QuickLab Lab ID, generated automatically upon lab instantiation.
        pj (str): The QuickLab project, set in aws.auto.tfvars (default: 'my-project').
    """

    # get QuickLab Prefix
    # env = os.getenv("QUICKLAB_PREFIX")
    output_name = "aws_resource_group"
    result = subprocess.run(
        [f"terraform output -raw {output_name}"],
        check=True,
        shell=True,
        capture_output=True,
        text=True,
    )
    delim_index = result.stdout.index("-")
    tfo = result.stdout[0:delim_index]
    pf = tfo if tfo is not None else input("Enter QuickLab Prefix: ")

    # get QuickLab Lab ID
    # env = os.getenv("QUICKLAB_LAB_ID")
    output_name = "_lab_id"
    result = subprocess.run(
        [f"terraform output -raw {output_name}"],
        check=True,
        shell=True,
        capture_output=True,
        text=True,
    )
    tfo = result.stdout
    l = tfo if tfo is not None else input("Enter QuickLab LabId: ")

    # get QuickLab Project
    # env = os.getenv("QUICKLAB_PROJECT")
    output_name = "_project"
    result = subprocess.run(
        [f"terraform output -raw {output_name}"],
        check=True,
        shell=True,
        capture_output=True,
        text=True,
    )
    tfo = result.stdout
    pj = tfo if tfo is not None else input("Enter QuickLab Project: ")

    return pf, l, pj


def get_sumo_url():
    """
    Method that sets the Sumo Logic API Base URL using the Sumo Logic Deployment Id
    from environment variable or from user input. Deployment Id must be one of:
    "au", "ca", "de", "eu", "fed", "in", "jp", "us1", "us2"

    Returns:
        u (str): a base URL to be used with Sumo Logic API requests.
    """

    env = os.getenv("TF_VAR_sumo_env")
    d = env if env is not None else input("Enter Sumo Logic Deployment: ")

    sumo_deployments = ["au", "ca", "de", "eu", "fed", "in", "jp", "us1", "us2"]

    if d.lower() not in sumo_deployments:
        logger.info(f"Valid Sumo Logic Deployments include: {sumo_deployments}")
        return

    if d.lower() == "us1":
        u = "https://api.sumologic.com/api"
        return u

    u = "https://api." + d.lower() + ".sumologic.com/api"
    return u


def get_secrets():
    """
    Method that reads a Sumo Logic Access ID and Access Key
    from environment variables or from user input.

    Returns:
        i (str): a Sumo Logic Access ID
        k (str): a Sumo Logic Access Key
    """

    env = os.getenv("TF_VAR_sumo_accessid")
    i = env if env is not None else input("Enter Sumo Logic Access Id: ")

    env = os.getenv("TF_VAR_sumo_accesskey")
    k = env if env is not None else getpass.getpass("Enter Sumo Logic Access Key: ")

    return i, k


def req(method: str, endpoint: str, payload):
    """
    Method that issues a request to an API endpoint.

    Args:
        method (str)
        endpoint (str)
        payload (dict)
    Returns:
        resp (object):
    """

    # configure API client
    m = method
    p = json.dumps(payload)  # ? always JSON, or ever UFT-8 .encode("UTF-8") ??
    target = f"{sumo_url}{endpoint}"
    encoded = base64.b64encode(bytes(f"{access_id}:{access_key}", "utf-8")).decode(
        "utf-8"
    )
    h = {"Authorization": "Basic " + encoded, "Content-Type": "application/json"}

    # make API request
    logger.debug(f"Request: {m} {target} {p}")
    http = urllib3.PoolManager()

    try:
        r = http.request(method=m, url=target, headers=h, body=p, fields=None)
        logger.debug(f"Response: {r.status} {r.reason}")
        # | {r._request_url } | headers: {r.headers}
        resp = json.loads(r.data)  # if r.data is not None else ""
        # resp = json.loads(r.data.decode("utf-8")) if r.data else None
        logger.debug(f"Response: {resp}")

        if 200 <= r.status <= 300:
            return resp
        else:
            resp_type = type(r.data)
            logger.debug(f"Response (type): {resp_type}")
            logger.debug(dir(r.data))
            logger.error(f"Response: {r.status} {r.reason}")

            # try to decode bytestring that contains JSON data, then load JSON
            resp = json.loads(r.data.decode("utf-8"))
            logger.debug(f"Response: {resp}")

            raise Exception("Sumo Logic API Request Failed")
    except Exception as e:
        # TODO: test this path more
        code = resp["code"]
        message = resp["message"]
        logger.error(
            f"Exception: {e}. Request Target: {target}, Error Code: {code}, Error Message: {message}"
        )


def create_field_extraction_rule():
    create_these = [
        {
            "name": "csiem-forwarder-wiz",
            "scope": "_sourceCategory=wiz",
            "parseExpression": '"true" as _siemForward | "/Parsers/System/Wiz/Wiz" as _parser',
            "enabled": True,
        }
    ]
    for item in create_these:
        payload = item
        new_resource = req("POST", "/v1/extractionRules", payload)
        if new_resource:
            name = new_resource["name"]
            logger.info(f"created Field Extraction Rule: {name}")
        else:
            logger.warning("no Field Extraction Rule created")


def get_collector_by_name(name: str):
    collector = req("GET", f"/v1/collectors/name/{name}", {})
    collector_id = collector["collector"]["id"]
    return collector_id


def create_http_source():
    # assumes QuickLab has already created a hosted collector
    collector_name = f"{prefix}-{lab_id}"
    collector_id = get_collector_by_name(collector_name)

    create_these = [
        {
            "source": {
                "name": f"{project}",
                "category": "wiz",
                "automaticDateParsing": True,
                "multilineProcessingEnabled": False,
                "useAutolineMatching": False,
                "forceTimeZone": False,
                "filters": [],
                "cutoffTimestamp": 0,
                "encoding": "UTF-8",
                "fields": {},
                "hashAlgorithm": "MD5",
                "messagePerRequest": True,
                "sourceType": "HTTP",
            }
        }
    ]
    for item in create_these:
        payload = item
        new_resource = req("POST", f"/v1/collectors/{collector_id}/sources", payload)
        if new_resource:
            name = new_resource["source"]["name"]
            url = new_resource["source"]["url"]
            logger.info(f"created HTTP source on {collector_name}: {name}")
            # logger.info(f"to send data to {name}, use it's URL: {source_url}")
        else:
            logger.warning(f"no HTTP source created on {collector_name}")

    return name, url


def create_csiem_entity_type():
    create_these = [
        {
            "fields": {
                "name": "Cloud Instance",
                "identifier": "cloudinstance",
                "fields": [
                    "dstDevice_uniqueId",
                    "srcDevice_uniqueId",
                    "device_uniqueId",
                ],
            }
        },
        {
            "fields": {
                "name": "Secret Name",
                "identifier": "secretname",
                "fields": ["targetUser_userId"],
            }
        },
    ]
    for item in create_these:
        payload = item
        new_resource = req("POST", "/sec/v1/custom-entity-types", payload)
        if new_resource:
            name = new_resource["data"]["name"]
            logger.info(f"created CSIEM custom entity type: {name}")
        else:
            logger.warning("no CSIEM custom entity type created")


def create_csiem_custom_insight():
    create_these = [
        {
            "fields": {
                "name": "CSPM - Exposed Secrets on AWS EC2 Instance",
                "description": "you dropped your (access) keys !!",
                "severity": "CRITICAL",
                "ordered": True,
                "enabled": True,
                "tags": ["_mitreAttackTactic:TA0006", "_mitreAttackTechnique:T1552"],
                "dynamicSeverity": [],
                "ruleIds": [],
                "signalNames": ["*cleartext cloud keys"],
            }
        }
    ]
    for item in create_these:
        payload = item
        new_resource = req("POST", "/sec/v1/custom-insights", payload)
        if new_resource:
            name = new_resource["data"]["name"]
            logger.info(f"created CSIEM custom insight: {name}")
        else:
            logger.warning("no CSIEM custom insight created")


def create_csiem_match_rule():
    create_these = [
        {
            "fields": {
                "category": "Credential Access",
                "enabled": "true",
                "entitySelectors": [
                    {"expression": "device_uniqueId", "entityType": "cloudinstance"}
                ],
                "isPrototype": "false",
                "name": "Wiz - Application endpoint on a VM/serverless exposes cleartext cloud keys",
                "summaryExpression": "Threat: {{threat_name}} detected on host: {{device_hostname}}",
                "tags": ["_mitreAttackTactic:TA0006", "_mitreAttackTechnique:T1552"],
                "tuningExpressionIds": [],
                "descriptionExpression": "{{threat_signalSummary}}",
                "expression": "metadata_vendor=\"Wiz\"\nAND threat_name IN ('wc-id-2022', 'wc-id-1135', 'ef843ec6-602f-463a-928b-550bb32d7053')",
                "nameExpression": "{{metadata_vendor}} - {{threat_signalName}}",
                "scoreMapping": {
                    "type": "fieldValue",
                    "default": 5,
                    "field": "normalizedSeverity",
                    "mapping": [],
                },
                "stream": "record",
            }
        }
    ]
    for item in create_these:
        payload = item
        new_resource = req("POST", "/sec/v1/rules/templated", payload)
        if new_resource:
            name = new_resource["data"]["name"]
            logger.info(f"created CSIEM match rule: {name}")
        else:
            logger.warning("no CSIEM match rule created")


def get_csiem_rules(rule_name: str):
    rule = req("GET", f'/sec/v1/rules?q=name:"{rule_name}"&limit=1', {})
    rule_id = rule["data"]["objects"][0]["id"]
    logger.debug(f"rule_id: {rule_id}")
    return rule_id


def disable_csiem_rules():
    rule_name = "Normalized Security Signal"
    rule_id = get_csiem_rules(rule_name)
    payload = {"enabled": False}
    r = req("PUT", f"/sec/v1/rules/{rule_id}/enabled", payload)
    status = r["data"]
    if not r["errors"]:
        logger.info(f"disabled CSIEM rule: {rule_name}")
        logger.debug(f"status: {status}")
    return status


def create_csiem_log_mapping():
    create_these = [
        {
            "fields": {
                "name": "Wiz Catch All (Modified)",
                "fields": [
                    {"name": "description", "value": "control.description"},
                    {"name": "severity", "value": "issue.severity"},
                    {"name": "cloud_region", "value": "resource.region"},
                    {"name": "cloud_provider", "value": "resource.cloudPlatform"},
                    {"name": "accountId", "value": "resource.subscriptionId"},
                    {
                        "name": "threat_ruleType",
                        "value": "direct",
                        "valueType": "constant",
                    },
                    {"name": "threat_signalName", "value": "control.name"},
                    {"name": "threat_signalSummary", "value": "control.description"},
                    {
                        "name": "normalizedSeverity",
                        "value": "issue.severity",
                        "valueType": "lookup",
                        "lookup": [
                            {"key": "CRITICAL", "value": "9"},
                            {"key": "HIGH", "value": "6"},
                            {"key": "MEDIUM", "value": "3"},
                            {"key": "LOW", "value": "1"},
                        ],
                    },
                    {"name": "resource", "value": "resource.name"},
                    {"name": "resourceType", "value": "resource.type"},
                    {"name": "device_hostname", "value": "instanceName"},
                    {
                        "name": "normalizedResource",
                        "value": "resource.type",
                        "valueType": "lookup",
                        "lookup": [{"key": "virtualMachine", "value": "instance"}],
                    },
                    {"name": "threat_name", "value": "control.id"},
                    {"name": "device_uniqueId", "value": "instanceId"},
                    {"name": "cloud_service", "value": "service"},
                    {"name": "targetUser_userId", "value": "accessKeyId"},
                    {"name": "threat_identifier", "value": "control.id"},
                    {"name": "user_username", "value": "userName"},
                    {"name": "http_url", "value": "endpointUrl"},
                ],
                "skippedValues": [",", "-"],
                "structuredInputs": [
                    {
                        "vendor": "Wiz",
                        "product": "Wiz",
                        "eventIdPattern": "_default_",
                        "logFormat": "JSON",
                    }
                ],
                "recordType": "Endpoint",
                "productGuid": "52ac893d-bdf9-4e2c-be83-5f43842a179d",
                "relatesEntities": "true",
                "enabled": "true",
            }
        }
    ]
    for item in create_these:
        payload = item
        new_resource = req("POST", "/sec/v1/log-mappings", payload)
        if new_resource:
            name = new_resource["data"]["name"]
            logger.info(f"created CSIEM log mapping: {name}")
        else:
            logger.warning("no CSIEM log mapping created")


def create_csiem_automation():
    # expects a playbook_id like 65e7a039b087cce1d3a1bfad
    env = os.getenv("SUMO_PLAYBOOK_ID")
    playbook_id = env if env is not None else input("Enter CSIEM Playbook ID: ")
    # The Automation name is automatically set from the playbook's name.
    # Recommendation: use your project name to name your playbook.
    create_these = [
        {
            "fields": {
                "playbookId": playbook_id,
                "cseResourceType": "INSIGHT",
                "executionTypes": ["ON_DEMAND"],
                "enabled": True,
            }
        }
    ]
    for item in create_these:
        payload = item
        new_resource = req("POST", "/sec/v1/automations", payload)
        if new_resource:
            name = new_resource["data"]["name"]
            logger.info(f"created CSIEM automation: {name}")
        else:
            logger.warning("no CSIEM automation created")


def preflight_check():
    pass  # TODO: write this


# main
os.system("clear")
print(
    f"{os.path.basename(__file__)} \n\n"
    "This script creates custom Sumo config needed for wiz-sumo-demo scenario 1: 'exposed AWS access keys'. \n"
)
# preflight_check()
prefix, lab_id, project = get_quicklab_details()
print(f"QuickLab: Prefix={prefix}, LabId={lab_id}, Project={project}")
sumo_url = get_sumo_url()
access_id, access_key = get_secrets()
print(
    f"Sumo Logic: AccessId=***{access_id[-3::]} AccessKey=***{access_key[-3::]} \n\n"
    "=========================="
)


## LAP
print("\nCreating content for Log Analytics Platform...")
source_name, source_url = create_http_source()
create_field_extraction_rule()
# create local config for sana parser


## Automation Service
# print("\nCreating content for Automation Service...")
# app central integrations (EC2, IAM) #! must be created manually
# integration resource (EC2, IAM) #! must be created manually
# create and publish playbook #! must be created manually
# test integration action (requires list actions for integration) #! must be created manually


## CSIEM
print("\nCreating content for CSIEM...")
create_csiem_entity_type()
# disable_csiem_log_mapping() # "Wiz Catch All" # can't do via API
create_csiem_log_mapping()
disable_csiem_rules()  # "Normalized Security Signal"
create_csiem_match_rule()
create_csiem_custom_insight()
create_csiem_automation()


print(
    "\n\n"
    "========================== \n"
    "NOTES: \n"
    f"1. To send Wiz Issue JSON to Sumo HTTP Source {source_name}, use it's URL: {source_url} \n\n"
    "2. The following items should have been done manually prior to running this script: \n"
    "  * create local config for sana parser \n"
    "  * install App Central integrations for EC2 and IAM \n"
    "  * configure integration resources for the EC2 and IAM integrations using your QuickLab's AWS region \n"
    "  * configure playbook nodes to reference the correct integration resources \n"
)
