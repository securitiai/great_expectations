from __future__ import annotations
from typing import ClassVar, Tuple, Union, List, TYPE_CHECKING, Optional

from typing_extensions import override

from great_expectations.expectations.expectation import QueryExpectation
from great_expectations.util import convert_to_json_serializable

if TYPE_CHECKING:
    from great_expectations.core import ExpectationValidationResult
    from great_expectations.execution_engine import ExecutionEngine



class ExpectValueToMatchCustomQueryOutput(QueryExpectation):
    """
    Expect the result of a custom SQL query to match a specified value.

    expect_value_to_match_custom_query_output is a flexible expectation that can help you test the output of a
    custom SQL query. It can be used to test whether the output of a query matches a specific value, or to test
    whether the output of a query meets other expectations.

    expect_value_to_match_custom_query_output is a *column aggregate expectation*.

    Args:
        input_structure = {
            urn: string,
            pass_fail_column: string
        }

    Keyword Args:
        query (str): The SQL query to run. This query should return a single value.
        result_format (str): The format of the result of the query. Currently, only "SUMMARY" is supported.
        include_config (bool): If True, the query and the expected value will be included in the returned
            expectation_config. Default is False.
        catch_exceptions (bool): If True, exceptions raised while executing the query will be caught and
            included in the result object. Default is False.

    Other Parameters:
        row_condition
        condition_parser

    Returns:
        An ExpectationSuiteValidationResult

    Notes:
        * The query should be written in SQL.
        * The query should be written to return columns that are sent in the arguments. If any column is missing from
          result set, 'Fail' status will be returned
        * The query should be written to return a single row. If the query returns multiple rows, only the first
          row will be used.
        * The values returned under the pass_fail columns should be 'Pass' or 'Fail'. If anything else is received, the
          result will be recorded as 'Fail'
        * The result_format parameter is not currently used, but will be used in a future version of this
          expectation.
        * The include_config parameter is not currently used, but will be used in a future version of this
          expectation.
        * The catch_exceptions parameter is not currently used, but will be used in a future version of this
          expectation.

    Examples:
    """

    query: str
    values: List

    metric_dependencies:  ClassVar[Tuple[str, ...]] = ("query.table",)
    success_keys: ClassVar[Tuple[str, ...]] = ("query", "values")

    domain_keys: ClassVar[Tuple[str, ...]] = (
        "batch_id",
        "row_condition",
        "condition_parser",
    )

    @override
    def _validate(
        self,
        metrics: dict,
        runtime_configuration: dict = None,
        execution_engine: Optional[ExecutionEngine] = None,
    ) -> Union[ExpectationValidationResult, dict]:
        configuration = self.configuration
        metrics = convert_to_json_serializable(data=metrics)
        if len(metrics.get("query.table")) > 0:
            query_result = metrics.get("query.table")[0]
        else:
            return{
                "success": False,
                "result" : {"observed_value": {}}
            }

        values = configuration["kwargs"].get("values")

        success = True

        for val in values:
            if val['pass_fail_column'] not in list(query_result.keys()):
                success = False
                break
            result = query_result[val['pass_fail_column']]
            if result != 'Pass':
                success = False
                break

        return {
            "success": success,
            "result": {"observed_value": query_result},
        }