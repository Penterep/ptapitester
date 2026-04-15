"""
GraphQL introspection test

This module implements a test that checks if a GraphQL instance supports introspection

Contains:
- Introspection class to perform the availability test
- run() function as an entry point for running the test
"""
import json
from http import HTTPStatus
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import JSONDecodeError
import os
from requests import Response

__TESTLABEL__ = "GraphQL introspection test"


class Introspection:
    """Class for executing the GraphQL introspection test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, supported_methods,
                 common_tests: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.supported_methods = supported_methods
        self.common_tests = common_tests

        self.helpers.print_header(__TESTLABEL__)

    def _print_directives(self, intro_output: object) -> None:
        """
        This method prints the directives found in the introspection output in a formatted format.

        Parameters
        ----------
        intro_output: object
            Introspection output.
        """
        directives = intro_output.get("data", {}).get("__schema", {}).get("directives", [])

        if not directives or directives is None:
            ptprint("Could not get directives from introspection output", "OK", not self.args.json, indent=4)
            return

        ptprint("Found directives:", "INFO", not self.args.json, indent=4)

        for directive in directives:
            if directive is None: continue

            args = [f"{arg.get('name', '-')}: {self.helpers.get_field_type_string(arg.get('type', {}))}"
                    for arg in directive.get("args", {})]

            directive_name = directive.get("name", "-")
            ptprint(f"@{directive_name}{self.helpers.get_arg_string(args)}", "INFO", not self.args.json,
                    indent=8)


    def _print_types(self, intro_output: object) -> None:
        """
        This method prints the types found in the introspection output in a formatted format.

        Parameters
        ----------
        intro_output: object
            Introspection output.
        """
        types = intro_output.get("data", {}).get("__schema", {}).get("types", [])

        if not types or types is None:
            ptprint("Could not get types from introspection output", "OK", not self.args.json, indent=4)
            return

        for data_type in types:
            if data_type is None: continue
            fields = data_type.get("fields", []) or data_type.get("inputFields", []) or []

            if not fields:
                ptprint(f"Type {data_type.get('name', '-')} of kind {data_type.get('kind', '-')} with no fields",
                        "INFO", not self.args.json, indent=4)
                continue

            ptprint(f"Type {data_type.get('name', '-')} of kind {data_type.get('kind', '-')} with fields:",
                    "INFO", not self.args.json, indent=4)

            for field in fields:
                if field is None: continue
                field_name = field.get("name", "-")
                field_type = self.helpers.get_field_type_string(field.get("type", {}))
                args = [f"{arg.get('name', '-')}: {self.helpers.get_field_type_string(arg.get('type', {}))}"
                       for arg in field.get("args", {})]

                ptprint(f"{field_name}{self.helpers.get_arg_string(args)}: {field_type}", "INFO",
                        not self.args.json, indent=8)

    def _dump_to_file(self, data: object) -> None:
        """
        This method prints the output of the introspection test to the file provided with the -o/--output-introspection argument

        Parameters
        ----------
        data: object
            JSON result of the introspection test
        """

        filename = f"{self.args.output_introspection}.json" if ".json" not in self.args.output_introspection else self.args.output_introspection

        if os.path.dirname(filename):
            os.makedirs(os.path.dirname(filename), exist_ok=True)

        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
        except IOError as e:
            ptprint(f"Encountered an error when writing the introspection output to file: {e}", "ERROR",
                    not self.args.json, indent=4)


    def _send_query(self, query: dict) -> dict:
        """
        This method is used for sending introspection queries

        Parameters
        ----------
        query: dict
            Introspection query to send

        Returns
        -------
        dict
            JSON introspection data. Empty dictionary if the query failed
        """

        response: Response = self.helpers.send_request(self.supported_methods, query)

        try:
            response_json = response.json()
        except JSONDecodeError as e:
            ptprint(f"Could not get JSON from response: {e}", "ERROR", not self.args.json, indent=4)
            return {}

        if response.status_code != HTTPStatus.OK or "errors" in response_json:
            ptprint(f"Could not send introspection query. Received response code: {response.status_code}", "OK",
                    not self.args.json, indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return {}

        try:
            return response.json()
        except JSONDecodeError as e:
            ptprint(f"Error decoding JSON from response: {e}", "ERROR", not self.args.json, indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return {}

    def _verify_introspection(self) -> bool:
        """
        This method verifies if introspection is supported

        Returns
        -------
        bool
            True if the GraphQL instance supports introspection. False if otherwise or and error occurred.
        """
        query = {"query": "{__schema{queryType{name}}}"}

        if not (response_json := self._send_query(query)):
            return False

        data = response_json.get("data", {})

        if not data:
            ptprint("The target does not support introspection", "OK", not self.args.json, indent=4)
            return False

        if not data.get("__schema", {}).get("queryType", {}).get("name"):
            ptprint("The target does not support introspection", "OK", not self.args.json, indent=4)
            return False

        ptprint("The target supports introspection.", "VULN", not self.args.json,
                indent=4)
        self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-INTROSPECTION")
        return True


    def _schema_introspection(self) -> object:
        """
        This method sends a query to get information on the structure of a GraphQL schema.
        Writes the output to a file if -o argument is specified.

        Returns
        -------
        bool
            True if the introspection was successful. False otherwise or if and error occurs.
        """
        query = "query IntrospectionQuery {                __schema {                queryType { name }                mutationType { name }                subscriptionType { name }                types {                    ...FullType                }                directives {                    name                    description                    locations                    args {                    ...InputValue                    }                }                }            }            fragment FullType on __Type {                kind                name                description                fields(includeDeprecated: true) {                name                description                args {                    ...InputValue                }                type {                    ...TypeRef                }                isDeprecated                deprecationReason                }                inputFields {                ...InputValue                }                interfaces {                ...TypeRef                }                enumValues(includeDeprecated: true) {                name                description                isDeprecated                deprecationReason                }                possibleTypes {                ...TypeRef                }            }            fragment InputValue on __InputValue {                name                description                type { ...TypeRef }                defaultValue            }            fragment TypeRef on __Type {                kind                name                ofType {                kind                name                ofType {                    kind                    name                    ofType {                    kind                    name                    ofType {                        kind                        name                        ofType {                        kind                        name                        ofType {                            kind                            name                            ofType {                            kind                            name                            }                        }                        }                    }                    }                }                }            }"
        data = {"query": query}

        if not (response_json := self._send_query(data)):
            return {}

        ptprint(f"JSON:\n{json.dumps(response_json, indent=2)}", "INFO", self.args.verbose, indent=4,
                colortext=True)

        if self.args.output_introspection:
            self._dump_to_file(response_json)

        return response_json


    def run(self) -> object:
        """Executes the introspection test. Exits early if we cannot verify introspection support"""


        if not self._verify_introspection():
            return {}

        introspection_output = self._schema_introspection()

        self._print_types(introspection_output)
        self._print_directives(introspection_output)

        return introspection_output


def run(args, ptjsonlib, helpers, http_client, supported_methods, common_tests) -> object:
    """Entry point for running the Introspection test"""
    return Introspection(args, ptjsonlib, helpers, http_client, supported_methods, common_tests).run()
