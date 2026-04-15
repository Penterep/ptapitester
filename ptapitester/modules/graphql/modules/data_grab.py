"""
GraphQL data dumper

This module implements a data dumper for GraphQL

Contains:
- Dumper to perform the dumping
- run() function as an entry point for running the test
"""
from http import HTTPStatus
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import JSONDecodeError
from requests import Response
import json
import re


__TESTLABEL__ = "GraphQL data dumper"


class Dumper:
    """Class for executing the dumper"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient,
                 supported_methods: set, common_tests: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.supported_methods = supported_methods
        self.common_tests = common_tests

        self.helpers.print_header(__TESTLABEL__)


    def _build_nested_query(self, fields: list, build: str) -> str:
        """
        This method builds a nested query from a list of fields. For example a list of fields ["pastes", "owner"] would
        build a query pastes { owner { %s }}

        Parameters
        ----------
        fields: list
            Fields to build the query from.
        build: str
            String to build.

        Returns
        -------
        str
            Built string.
        """
        while fields:
            build = build % (fields.pop(0) + "{ %s }")

        return build


    def _get_type_object(self, t_name: str) -> dict:
        """
        Gets the object with the `t_name` name

        Parameters
        ----------
        t_name: str
            Type name to retrieve.

        Returns
        -------
        dict
            Type with the `t_name` name
        """
        types = self.args.schema.get("__schema", {}).get("types", [])

        for t in types:
            if t.get("name", "") == t_name:
                return t

        return {}


    def _search_type(self, t: dict, t_to_find: str, explored: list) -> list:
        """
        This method checks to see if a type `t` contains a field of type `t_to_find`. It does so recursively in the case
        that the `t` contains a field of the OBJECT type that is not `t_to_find`.

        The method is used when looking to dump data of a certain type that is not returned by a root query.

        Parameters
        ----------
        t: dict
            Type to search
        t_to_find: str
            Type name to locate in `t` fields
        explored: list
            Array of explored types to prevent looping indefinitely

        Returns
        -------
        list
            Array of fields that lead to the `t_to_find` object.
        """
        fields = t.get("fields", [])

        if not fields:
            return explored

        for field in fields:
            base_type = self.helpers.get_base_type(field.get("type", {}))
            if base_type in explored:
                return []

            if t_to_find in base_type and base_type not in explored:
                explored.append(field.get("name"))
                return explored

            elif self.helpers.get_base_kind(field) == "OBJECT":
                explored.append(self._search_type(self._get_type_object(field.get("name")), t_to_find, explored))
                return explored

        return explored

    def _get_query_return_type(self, query: dict) -> str:
        """
        This method gets the return type of a GraphQL query

        Parameters
        ----------
        query: dict

        Returns
        -------
        str
            Name of the return type.
        """
        return self.helpers.get_base_type(query.get("type", {}))

    def _find_missing_arguments(self, text: str) -> str:
        """
        This method extracts arguments from error messages regarding missing arguments

        Parameters
        ----------
        text: str
            Error message string.
        Returns
        -------
        str
            Missing argument
        """
        pattern = r"missing \d+ required positional argument: '([^']+)'"
        match = re.search(pattern, text)

        if match:
            return match.group(1)

        return ""

    def _get_fields(self, type_name: str, found: set) -> str:
        """
        This method return a string of fields that we can query on a given type.

        Parameters
        ----------
        type_name: str
            Name of the type to query
        found: set
            Set of found types to prevent looping

        Returns
        -------
        str
            Comma separated string of fields
        """
        if not found:
            found = set()

        found.add(type_name)
        all_fields = []

        for t in self.args.schema.get("__schema",{}).get("types", []):
            if t.get("name", "") == type_name:

                fields = (t.get("fields", []))
                for field in fields:
                    name = field.get("name")
                    field_type = field.get("type", {})
                    field_type_name = self.helpers.get_base_type(field_type)

                    if field_type_name in found:
                        continue

                    if self.helpers.get_base_kind(field_type) == "OBJECT":
                        all_fields.append(f"{name}"+"{"+self._get_fields(field_type_name, found)+"}")
                    else:
                        all_fields.append(name)

        return ",".join(all_fields)


    def _send_query(self, query: object, query_name: str) -> dict:
        """
        Helper method to send queries, look for missing arguments and handle JSON decoding
        Parameters
        ----------
        query: object
            GraphQL query to send
        query_name: str
            Name of the query

        Returns
        -------
        dict
            Data from the JSON response
        """
        response: Response = self.helpers.send_request(self.supported_methods, query)

        try:
            response_json = response.json()
        except JSONDecodeError as e:
            ptprint(f"Could not get JSON from response: {e}", "ERROR", not self.args.json, indent=4)
            return {}

        if response.status_code != HTTPStatus.OK or "errors" in response_json:
            missing_args = list(filter(None, [self._find_missing_arguments(error.get("message"))
                            for error in response_json.get("errors", [])]))
            if missing_args:
                ptprint(f"Missing argument for query {query_name}: '{','.join(missing_args)}'", "ERROR", not self.args.json,
                indent=4)
                ptprint(f"Query: {query} Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                return {}


            ptprint(f"Error sending query {query_name}", "ERROR", not self.args.json, indent=4)
            ptprint(f"Query: {query} Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return {}

        return response_json.get("data", {})


    def _dump_type(self, graphql_type: str) -> None:
        """
        This method dumps all objects of the `graphql_type` type. It first does so by looking if any of the root queries return
        this type and if not, it looks if any of the other return types contain a field of the `graphql_type`.

        Parameters
        ----------
        graphql_type: str
            Type to dump
        """
        schema = self.args.schema.get("__schema", {})
        query_type = schema.get("queryType", {}).get("name", "")
        for t in schema.get("types", []):
            if t.get("name", "") == query_type:
                for query in t.get("fields", []):
                    o = self._search_type(self._get_type_object(self._get_query_return_type(query)), graphql_type, [])

                    if graphql_type == self._get_query_return_type(query) and query.get("name", ""):
                        selection = "{" + query.get("name") + "{ %s }}" % self._get_fields(graphql_type, None)
                        built_query = {"query": selection}

                        if t_result := self._send_query(built_query, query.get("name")):
                            ptprint(f"Type {graphql_type} result from query {query.get('name')}:\n"
                                    f"{json.dumps(t_result, indent=1)}",
                                    "VULN", not self.args.json, indent=4)

                    elif o:
                        fields = self._get_fields(graphql_type, set())
                        built_query = self._build_nested_query(o, query.get("name")+"{ %s }") % fields
                        payload = {"query": "{ %s }" % built_query}
                        if t_result := self._send_query(payload, query.get("name", "")):
                            ptprint(f"Type {graphql_type} result from query {query.get('name')}:\n"
                                    f"{json.dumps(t_result, indent=1)}",
                                    "VULN", not self.args.json, indent=4)


    def run(self) -> None:
        """
        Executes the GraphQL data dumper
        """
        if not self.args.dump_types:
            ptprint(f"No type provided. Please do so with the -dt argument", "ERROR", not self.args.json,
                    indent=4)
            return

        types = self.args.dump_types.split(",")

        for t in types:
            self._dump_type(t)



def run(args, ptjsonlib, helpers, http_client, supported_methods, common_tests):
    """Entry point for running the Dumper test"""
    Dumper(args, ptjsonlib, helpers, http_client, supported_methods, common_tests).run()
