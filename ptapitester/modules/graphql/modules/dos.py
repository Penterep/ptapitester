"""
GraphQL DoS test

This module implements a test that probes a GraphQL endpoint for vulnerabilities that could cause DoS

Contains:
- DoS class to perform the DoS test
- run() function as an entry point for running the test
"""
from http import HTTPStatus
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import JSONDecodeError
from requests.exceptions import ConnectionError


__TESTLABEL__ = "GraphQL DoS test"


class DoS:
    """Class for executing the GraphQL DoS test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient,
                 supported_methods: set, common_tests: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.supported_methods = supported_methods
        self.common_tests = common_tests

        self.helpers.print_header(__TESTLABEL__)

    def _circular_relationships(self) -> None:
        """
        This method checks to see if the GraphQL schema contains any circular relationships
        """
        if self.helpers.cycle_detector.run_detection():
            self.ptjsonlib.add_vulnerability("PTV-DOS-CIRCULAR-RELATIONSHIPS")


    def _circular_fragments(self) -> None:
        """
        This method checks to see if the GraphQL server allows fragments to form circular relationships
        """
        fragment_query = """
        query {
            ...A
        }
        
        fragment A on __Schema {
            types
            ...B
        }
        
        fragment B on __Schema {
            types
            ...A
        }
        """

        query = {"query": fragment_query}
        try:
            response = self.helpers.send_request(self.supported_methods, query)
        except ConnectionError as e:
            ptprint(f"Connection error. This might have been caused by a circular fragment relationship and the server has crashed: {e}",
                    "ERROR", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-DOS-CIRCULAR-FRAGMENTS")
            return

        ptprint(f"The server does not allow circular relationships between fragments", "OK", not self.args.json,
                indent=4)
        ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)

    def _duplicate_fields(self) -> None:
        """
        This method checks if the GraphQL server will accept 500 duplicate fields in a query
        """
        duplicated_field = "__typename \n" * 500
        query = {"query": "query{"+duplicated_field+"}"}

        response = self.helpers.send_request(self.supported_methods, query)

        try:
            response_json = response.json()
            if response.status_code != HTTPStatus.OK or "errors" in response_json:
                ptprint(f"The server does not allow duplicate fields in requests", "OK", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                return
        except JSONDecodeError:
            if response.status_code != HTTPStatus.OK:
                ptprint(f"The server does not allow duplicate fields in requests. Received status code: {response.status_code}",
                        "OK", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                return

        ptprint("The server allows 500 duplicate fields in queries", "VULN", not self.args.json, indent=4)
        ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
        self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-DOS-DUPLICATE-FIELDS")


    def _alias_overload(self) -> None:
        """
        This method checks to see if a GraphQL server will accept a query with 100 different aliases
        """
        aliases = "".join([f"alias{n}:__typename \n" for n in range(1, 101)])
        query = {"query": "query{" + aliases + "}"}

        response = self.helpers.send_request(self.supported_methods, query)

        try:
            response_json = response.json()
            if response.status_code != HTTPStatus.OK or "errors" in response_json:
                ptprint(f"The server does not allow alias overloading", "OK", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                return
        except JSONDecodeError:
            if response.status_code != HTTPStatus.OK:
                ptprint(
                    f"The server does not allow alias overloading. Received status code: {response.status_code}",
                    "OK", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                return

        ptprint("The server allows alias overloading", "VULN", not self.args.json, indent=4)
        ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
        self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-DOS-ALIAS-OVERLOADING")


    def _directive_overload(self) -> None:
        """
        This method checks to see if we can send 50 non-existent directives to a GraphQL server
        """
        directives = f"__typename " + "@abcd"*50
        query = {"query": "query{" + directives + "}"}

        response = self.helpers.send_request(self.supported_methods, query)

        try:
            response_json = response.json()
            if len(response_json.get("errors", [])) == 50:
                ptprint("The server allows directive overloading", "VULN", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-DOS-DIRECTIVE-OVERLOADING")
                return
            else:
                ptprint("The server does not allow directive overloading", "OK", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
        except JSONDecodeError as e:
                ptprint(f"Could not read JSON from response: {e}", "VULN", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                return


    def _batching(self) -> None:
        """
        This method checks to see if we can send an array-based batch of queries to a GraphQL server
        """
        query = {"query": "{__typename}"}
        batch = [query] * 10

        response = self.helpers.send_request(self.supported_methods, batch)

        try:
            response_json = response.json()
            if response.status_code != HTTPStatus.OK or "errors" in response_json:
                ptprint(f"The server does not not accept batch requests", "OK", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                return
        except JSONDecodeError:
            if response.status_code != HTTPStatus.OK:
                ptprint(f"The server doest not accept batch requests. Received status code: {response.status_code}",
                        "OK", not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
                return

        ptprint("The server accepts batch requests", "VULN", not self.args.json, indent=4)
        self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-DOS-BATCHING")


    def run(self) -> None:
        """
        Executes the GraphQL DoS test (only if loud mode is enabled with the -l/--loud argument)

        The test probes the GraphQL server for the following DoS related vulnerabilities:
        1. Circular relationships
        2. Field duplication
        3. Alias overloading
        4. Directive overloading
        6. Array-based query batching
        """
        if not self.args.loud:
            ptprint("Loud mode not enabled. Skipping DoS tests. To enable use the -l argument", "INFO",
                    not self.args.json, indent=4)
            return

        self._circular_relationships()
        self._duplicate_fields()
        self._alias_overload()
        self._directive_overload()
        self._batching()
        self._circular_fragments()


def run(args, ptjsonlib, helpers, http_client, supported_methods, common_tests):
    """Entry point for running the DoS test"""
    DoS(args, ptjsonlib, helpers, http_client, supported_methods, common_tests).run()
