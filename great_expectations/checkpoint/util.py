from __future__ import annotations

import json
import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dataclasses import dataclass
from hashlib import md5
from datetime import timezone
import time
from decimal import Decimal
import urllib.parse
from typing import Optional, Dict, Any

import requests

from great_expectations.compatibility import aws

logger = logging.getLogger(__name__)


def send_slack_notification(
    payload: dict,
    slack_webhook: str | None = None,
    slack_channel: str | None = None,
    slack_token: str | None = None,
) -> str | None:
    session = requests.Session()
    url = slack_webhook
    headers = None

    # Slack doc about overwritting the channel when using the legacy Incoming Webhooks
    # https://api.slack.com/legacy/custom-integrations/messaging/webhooks
    # ** Since it is legacy, it could be deprecated or removed in the future **
    if slack_channel:
        payload["channel"] = slack_channel

    if not slack_webhook:
        url = "https://slack.com/api/chat.postMessage"
        headers = {"Authorization": f"Bearer {slack_token}"}

    if not url:
        raise ValueError("No Slack webhook URL provided.")  # noqa: TRY003

    try:
        response = session.post(url=url, headers=headers, json=payload)
        response.raise_for_status()
    except requests.ConnectionError:
        logger.warning(f"Failed to connect to Slack webhook after {10} retries.")
        return None
    except requests.HTTPError:
        logger.warning(
            "Request to Slack webhook " f"returned error {response.status_code}: {response.text}"  # type: ignore[possibly-undefined] # ok for httperror
        )
        return None

    return "Slack notification succeeded."


# noinspection SpellCheckingInspection
def send_opsgenie_alert(query: str, message: str, settings: dict) -> bool:
    """Creates an alert in Opsgenie."""
    if settings["region"] is not None:
        url = (
            f"https://api.{settings['region']}.opsgenie.com/v2/alerts"  # accommodate for Europeans
        )
    else:
        url = "https://api.opsgenie.com/v2/alerts"

    headers = {"Authorization": f"GenieKey {settings['api_key']}"}
    payload = {
        "message": message,
        "description": query,
        "priority": settings["priority"],  # allow this to be modified in settings
        "tags": settings["tags"],
    }

    session = requests.Session()

    try:
        response = session.post(url, headers=headers, json=payload)
        response.raise_for_status()
    except requests.ConnectionError as e:
        logger.warning(f"Failed to connect to Opsgenie: {e}")
        return False
    except requests.HTTPError as e:
        logger.warning(f"Request to Opsgenie API returned error {response.status_code}: {e}")  # type: ignore[possibly-undefined] # ok for httperror
        return False
    return True


def send_microsoft_teams_notifications(payload: dict, microsoft_teams_webhook: str) -> str | None:
    session = requests.Session()
    try:
        response = session.post(url=microsoft_teams_webhook, json=payload)
        response.raise_for_status()
    except requests.ConnectionError:
        logger.warning("Failed to connect to Microsoft Teams webhook after 10 retries.")
        return None
    except requests.HTTPError as e:
        logger.warning(f"Request to Microsoft Teams API returned error {response.status_code}: {e}")  # type: ignore[possibly-undefined] # ok for httperror
        return None

    return "Microsoft Teams notification succeeded."


def send_webhook_notifications(query, webhook, target_platform):
    session = requests.Session()
    try:
        response = session.post(url=webhook, json=query)
    except requests.ConnectionError:
        logger.warning(f"Failed to connect to {target_platform} webhook after 10 retries.")
    except Exception as e:
        logger.error(str(e))  # noqa: TRY400
    else:
        if response.status_code != 200:  # noqa: PLR2004
            logger.warning(
                f"Request to {target_platform} webhook "
                f"returned error {response.status_code}: {response.text}"
            )
        else:
            return f"{target_platform} notification succeeded."


# noinspection SpellCheckingInspection
def send_email(  # noqa: C901, PLR0913
    title,
    html,
    smtp_address,
    smtp_port,
    sender_login,
    sender_password,
    sender_alias,
    receiver_emails_list,
    use_tls,
    use_ssl,
):
    msg = MIMEMultipart()
    msg["From"] = sender_alias
    msg["To"] = ", ".join(receiver_emails_list)
    msg["Subject"] = title
    msg.attach(MIMEText(html, "html"))
    try:
        if use_ssl:
            if use_tls:
                logger.warning("Please choose between SSL or TLS, will default to SSL")
            context = ssl.create_default_context()
            mailserver = smtplib.SMTP_SSL(smtp_address, smtp_port, context=context)
        elif use_tls:
            mailserver = smtplib.SMTP(smtp_address, smtp_port)
            context = ssl.create_default_context()
            mailserver.starttls(context=context)
        else:
            logger.warning("Not using TLS or SSL to send an email is not secure")
            mailserver = smtplib.SMTP(smtp_address, smtp_port)
        if sender_login is not None and sender_password is not None:
            mailserver.login(sender_login, sender_password)
        elif not (sender_login is None and sender_password is None):
            logger.error(
                "Please specify both sender_login and sender_password or specify both as None"
            )
        mailserver.sendmail(sender_alias, receiver_emails_list, msg.as_string())
        mailserver.quit()
    except smtplib.SMTPConnectError:
        logger.error(f"Failed to connect to the SMTP server at address: {smtp_address}")  # noqa: TRY400
    except smtplib.SMTPAuthenticationError:
        logger.error(f"Failed to authenticate to the SMTP server at address: {smtp_address}")  # noqa: TRY400
    except Exception as e:
        logger.error(str(e))  # noqa: TRY400
    else:
        return "success"


def send_sns_notification(
    sns_topic_arn: str, sns_subject: str, validation_results: str, **kwargs
) -> str:
    """
    Send JSON results to an SNS topic with a schema of:


    :param sns_topic_arn:  The SNS Arn to publish messages to
    :param sns_subject: : The SNS Message Subject - defaults to expectation_suite_identifier.name
    :param validation_results:  The results of the validation ran
    :param kwargs:  Keyword arguments to pass to the boto3 Session
    :return:  Message ID that was published or error message

    """
    if not aws.boto3:
        logger.warning("boto3 is not installed")
        return "boto3 is not installed"

    message_dict = {
        "TopicArn": sns_topic_arn,
        "Subject": sns_subject,
        "Message": json.dumps(validation_results),
        "MessageAttributes": {
            "String": {"DataType": "String.Array", "StringValue": "ValidationResults"},
        },
        "MessageStructure": "json",
    }
    session = aws.boto3.Session(**kwargs)
    sns = session.client("sns")
    try:
        response = sns.publish(**message_dict)
    except sns.exceptions.InvalidParameterException:
        error_msg = f"Received invalid for message: {validation_results}"
        logger.error(error_msg)  # noqa: TRY400
        return error_msg
    else:
        return f"Successfully posted results to {response['MessageId']} with Subject {sns_subject}"

def send_datahub_notification(
        server_url: str, access_token: str, validation_results, urn: str, **kwargs
) -> str:
    """
    Send JSON results to a DataHub server with a schema of:

    :param server_url:  The DataHub server URL to publish messages to
    :param access_token:  The access token to authenticate with
    :param validation_results:  The results of the validation ran
    :param urn:  The urn of the asset that was validated
    :param kwargs:  Keyword arguments to pass to the requests.post method

    :return:  Message ID that was published or error message

    """
    if len(list(validation_results.keys())) > 0:
        validation_result_obj = validation_results.get(list(validation_results.keys())[0])
    else:
        return "No validation results found"

    mcp_format = f""


    suite_name = validation_result_obj["suite_name"]
    run_id = validation_result_obj.meta.get("run_id")
    data_platform_instance = 'urn:li:dataPlatform:great-expectations'
    active_batch_definition = validation_result_obj.meta.get("active_batch_definition")

    for result in validation_result_obj.results:
        expectation_config = result["expectation_config"]
        expectation_type = expectation_config["type"]
        success = bool(result["success"])

        kwargs = {
            k: v for k, v in expectation_config["kwargs"].items() if k != "batch_id"
        }

        result = result["result"]
        assertion_dataset = urn
        if "column" in kwargs:
            assertion_field = create_datahub_assertion_field_urn(urn, kwargs["column"])
        else:
            assertion_field = None

        assertion_urn = create_datahub_assertion_urn(
            datahub_guid(
                {
                    "platform": "great-expectations",
                    "nativeType": expectation_type,
                    "nativeParameters": kwargs,
                    "dataset": urn,
                    "fields": [assertion_field],
                }
            )
        )

        fields = [assertion_field] if assertion_field else []

        assertionInfo = get_assertion_info(
            expectation_type,
            kwargs,
            assertion_dataset,
            fields,
            suite_name
        )

        run_time = run_id.run_time.astimezone(timezone.utc)

        nativeResults = {
            k: convert_to_string(v)
            for k, v in result.items()
            if (
                    k
                    in [
                        "observed_value",
                        "partial_unexpected_list",
                        "partial_unexpected_counts",
                        "details",
                    ]
                    and v
            )
        }

        assertionResult = {
            "timestampMillis": int(round(time.time() * 1000)),
            "assertionUrn": assertion_urn,
            "asserteeUrn": urn,
            "runId": run_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "result": {
                "type": "SUCCESS" if success else "FAILURE",
                "rowCount": 0 if result.get("element_count") is None else result.get("element_count"),
                "missingCount": 0 if result.get("missing_count") is None else int(result.get("missing_count")),
                "unexpectedCount": 0 if result.get("unexpected_count") is None else int(result.get("unexpected_count")),
                "nativeResults": nativeResults,
            },
            "batchSpec": {
                "customProperties": {
                    "data_asset_name": active_batch_definition["data_asset_name"],
                    "datasource_name": active_batch_definition["datasource_name"],
                }
            },
            "status": "COMPLETE",
            "runtimeContext": {}
        }

        assertion_results = [assertionResult]

        assertion_with_results = [{
            "assertionUrn": assertion_urn,
            "assertionInfo": assertionInfo,
            "assertionPlatform": data_platform_instance,
            "assertionResults": assertion_results
        }]

        for assertion in assertion_with_results:
            assertion_info_data = {
                "entityUrn": assertion["assertionUrn"],
                "aspectName": "assertionInfo",
                "entityType": "assertion",
                "changeType": "UPSERT",
                "aspect": {
                    "contentType": "application/json",
                    "value": json.dumps(assertion["assertionInfo"]),
                }
            }
            emit_mcp(server_url, access_token, assertion_info_data)

            assertion_data = {
                "entityUrn": assertion["assertionUrn"],
                "entityType": "assertion",
                "aspectName": "dataPlatformInstance",
                "changeType": "UPSERT",
                "aspect": {
                    "contentType": "application/json",
                    "value": json.dumps({"platform": assertion["assertionPlatform"]}),
                }
            }
            emit_mcp(server_url, access_token, assertion_data)
            #
            for assertion_result in assertion["assertionResults"]:

                assertion_result_data = {
                    "entityUrn": assertion_result["assertionUrn"],
                    "aspectName": "assertionRunEvent",
                    "entityType": "assertion",
                    "changeType": "UPSERT",
                    "aspect": {
                        "contentType": "application/json",
                        "value": json.dumps(assertion_result),
                    }
                }
                emit_mcp(server_url, access_token, assertion_result_data)


def get_assertion_info(expectation_type, kwargs, dataset, fields, expectation_suite_name):
    def get_min_max(kwargs, type="UNKNOWN"):
        return {
            "minValue": {
                "value": convert_to_string(kwargs.get("min_value")),
                "type": type,
            },
            "maxValue": {
                "value": convert_to_string(kwargs.get("max_value")),
                "type": type,
            },
        }

    known_expectations: Dict[str, DataHubStdAssertion] = {
        # column aggregate expectations
        "expect_column_min_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="MIN",
            parameters=get_min_max(kwargs),
        ),
        "expect_column_max_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="MAX",
            parameters=get_min_max(kwargs),
        ),
        "expect_column_median_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="MEDIAN",
            parameters=get_min_max(kwargs),
        ),
        "expect_column_stdev_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="STDDEV",
            parameters=get_min_max(kwargs, "NUMBER"),
        ),
        "expect_column_mean_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="MEAN",
            parameters=get_min_max(kwargs, "NUMBER"),
        ),
        "expect_column_unique_value_count_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="UNIQUE_COUNT",
            parameters=get_min_max(kwargs, "NUMBER"),
        ),
        "expect_column_proportion_of_unique_values_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="UNIQUE_PROPOTION",
            parameters=get_min_max(kwargs, "NUMBER"),
        ),
        "expect_column_sum_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="SUM",
            parameters=get_min_max(kwargs, "NUMBER"),
        ),
        "expect_column_quantile_values_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="_NATIVE_",
        ),
        # column map expectations
        "expect_column_values_to_not_be_null": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="NOT_NULL",
            aggregation="IDENTITY",
        ),
        "expect_column_values_to_be_in_set": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="IN",
            aggregation="IDENTITY",
            parameters={
                "value": {
                    "value": convert_to_string(kwargs.get("value_set")),
                    "type": "SET"
                }
            }
        ),
        "expect_column_values_to_be_between": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="BETWEEN",
            aggregation="IDENTITY",
            parameters=get_min_max(kwargs),
        ),
        "expect_column_values_to_match_regex": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="REGEX_MATCH",
            aggregation="IDENTITY",
            parameters={
                "value": {
                    "value": kwargs.get("regex"),
                    "type": "STRING"
                }
            }
        ),
        "expect_column_values_to_match_regex_list": DataHubStdAssertion(
            scope="DATASET_COLUMN",
            operator="REGEX_MATCH",
            aggregation="IDENTITY",
            parameters={
                "value": {
                    "value": convert_to_string(kwargs.get("regex_list")),
                    "type": "LIST"
                }
            }
        ),
        "expect_table_columns_to_match_ordered_list": DataHubStdAssertion(
            scope="DATASET_SCHEMA",
            operator="EQUAL_TO",
            aggregation="COLUMNS",
            parameters={
                "value": {
                    "value": convert_to_string(kwargs.get("column_list")),
                    "type": "LIST"
                }
            }
        ),
        "expect_table_columns_to_match_set": DataHubStdAssertion(
            scope="DATASET_SCHEMA",
            operator="EQUAL_TO",
            aggregation="COLUMNS",
            parameters={
                "value": {
                    "value": convert_to_string(kwargs.get("column_set")),
                    "type": "SET"
                }
            }
        ),
        "expect_table_column_count_to_be_between": DataHubStdAssertion(
            scope="DATASET_SCHEMA",
            operator="BETWEEN",
            aggregation="COLUMN_COUNT",
            parameters=get_min_max(kwargs, "NUMBER"),
        ),
        "expect_table_column_count_to_equal": DataHubStdAssertion(
            scope="DATASET_SCHEMA",
            operator="EQUAL_TO",
            aggregation="COLUMN_COUNT",
            parameters={
                "value": {
                    "value": convert_to_string(kwargs.get("value")),
                    "type": "NUMBER"
                }
            }
        ),
        "expect_column_to_exist": DataHubStdAssertion(
            scope="DATASET_SCHEMA",
            operator="_NATIVE_",
            aggregation="_NATIVE_",
        ),
        "expect_table_row_count_to_equal": DataHubStdAssertion(
            scope="DATASET_ROWS",
            operator="EQUAL_TO",
            aggregation="ROW_COUNT",
            parameters={
                "value": {
                    "value": convert_to_string(kwargs.get("value")),
                    "type": "NUMBER"
                }
            }
        ),
        "expect_table_row_count_to_be_between": DataHubStdAssertion(
            scope="DATASET_ROWS",
            operator="BETWEEN",
            aggregation="ROW_COUNT",
            parameters=get_min_max(kwargs, "NUMBER"),
        ),
    }

    data_assertion_info = {
        "dataset": dataset,
        "fields": fields,
        "operator": "_NATIVE_",
        "aggregation": "_NATIVE_",
        "nativeType": expectation_type,
        "nativeParameters": {k: convert_to_string(v) for k, v in kwargs.items()},
        "scope": "DATASET_ROWS"
    }

    if expectation_type in known_expectations.keys():
        assertion = known_expectations[expectation_type]
        data_assertion_info["scope"] = assertion.scope
        data_assertion_info["aggregation"] = assertion.aggregation
        data_assertion_info["operator"] = assertion.operator

    else:
        if "column" in kwargs and expectation_type.startswith(
                "expect_column_value"
        ):
            data_assertion_info.scope = "DATASET_COLUMN"
            data_assertion_info.aggregation = "IDENTITY"
        elif "column" in kwargs:
            data_assertion_info.scope = "DATASET_COLUMN"
            data_assertion_info.aggregation = "_NATIVE_"

    return {
        "type": "DATASET",
        "datasetAssertion": data_assertion_info,
        "customProperties": {"expectation_suite_name": expectation_suite_name}
    }

def create_datahub_assertion_field_urn(dataset_urn: str, field_path: str) -> str:
    return f"urn:li:schemaField:({dataset_urn},{str_encoder(field_path)})"


def create_datahub_assertion_urn(assertion_id: str) -> str:
    return f"urn:li:assertion:{assertion_id}"


def datahub_guid(obj: dict) -> str:
    obj_str = json.dumps(
        obj
    ).encode("utf-8")
    return md5(obj_str).hexdigest()


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)
        return super(DecimalEncoder, self).default(o)


def convert_to_string(var: Any) -> str:
    try:
        tmp = (
            str(var)
            if isinstance(var, (str, int, float))
            else json.dumps(var, cls=DecimalEncoder)
        )
    except TypeError as e:
        logger.debug(e)
        tmp = str(var)
    return tmp


def str_encoder(urn: str) -> str:
    return urllib.parse.quote(urn)


def emit_mcp(gms_url: str, access_token: str, data):
    url = f"{gms_url}/aspects?action=ingestProposal"

    payload = json.dumps({"proposal": data})
    header = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    response = requests.post(url=url, headers=header, data=payload)
    if response.status_code != 200:
        print(f"Failed to emit MCP event. status_code: {response.status_code}, message: {response.reason}, payload: {payload}")


@dataclass
class DataHubStdAssertion:
    scope: str
    operator: str
    aggregation: str
    parameters: Optional[object] = None