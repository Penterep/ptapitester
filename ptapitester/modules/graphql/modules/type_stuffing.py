"""
GraphQL type stuffing module

This module tries to map the GraphQL types by stuffing words in the __type meta field

Contains:
- TypeStuffing to perform the type stuffing
- run() function as an entry point for running the test
"""
from http import HTTPStatus
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import JSONDecodeError
from requests import Response
import os

__TESTLABEL__ = "GraphQL type stuffing"

class TypeStuffing:
    """Class for executing the GraphQL type stuffing test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient,
                 supported_methods: set, common_tests: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.supported_methods = supported_methods
        self._new_types = set()
        self._found_types = set()
        self._queued_types = set()
        self.common_tests = common_tests

        self.helpers.print_header(__TESTLABEL__)

    def _print_type(self, t: dict) -> None:
        """
        This method prints out information about a GraphQL type, it's fields and their types. If a field is of a type which
        we have not yet probed with the __type query, we add it to a queue of types to query.

        Parameters
        ----------
        t: dict
            GraphQL type
        """
        fields = t.get("fields", []) or t.get("inputFields", []) or []

        if not fields:
            ptprint(f"Type {t.get('name', '-')} of kind {t.get('kind', '-')} with no fields",
                    "INFO", not self.args.json, indent=4)
            return

        ptprint(f"Type {t.get('name', '-')} of kind {t.get('kind', '-')} with fields:",
                "INFO", not self.args.json, indent=4)

        for field in fields:
            if field is None: continue
            field_name = field.get("name", "-")
            base_type = self.helpers.get_base_type(field.get("type", {}))
            base_kind = self.helpers.get_base_kind(field.get("type", {}))
            field_type_s = self.helpers.get_field_type_string(field.get("type", {}))

            if base_type and base_kind == "OBJECT" and base_type not in self._found_types and base_type not in self._queued_types:
                self._new_types.add(base_type)
            
            args = [f"{arg.get('name', '-')}: {self.helpers.get_field_type_string(arg.get('type', {}))}"
                    for arg in field.get("args", [])]

            ptprint(f"{field_name}{self.helpers.get_arg_string(args)}: {field_type_s}", "INFO",
                    not self.args.json, indent=8)
        


    def _create_batch(self, chunk: list, type_query: str) -> list:
        """
        This method creates a batch of __type queries.

        Parameters
        ----------
        chunk: list
            List of words to insert into the __type query.
        type_query: str
            GraphQL __type query

        Returns
        -------
        list
            A list of __type queries
        """
        return [{"query": type_query % word} for word in chunk]


    def _stuff(self, wordlist: list, batching: bool) -> None:
        """
        This method handles the creation of GraphQL __type queries. It first does so by using a wordlist of possible types
        and if a type contains a field of another type which we have not yet probed, we add it to a queue of types to probe.

        Parameters
        ----------
        wordlist: list
            A list of possible types.
        batching: bool
            Send GraphQL queries in batches if True
        """
        if not wordlist:
            ptprint("Cannot use empty wordlist", "ERROR", not self.args.json, indent=4)
            return

        wordlist = [w for w in wordlist if w and w not in self._found_types and w not in self._queued_types]

        if not wordlist:
            return

        type_query = '{__type(name: "%s"){name kind fields{name type{name kind ofType{name kind ofType{name kind ofType{name kind}}}}args{name type{name kind ofType{name kind ofType{name kind}}}}}ofType{name}}}'

        batch_size = 50 if batching else 1

        for w in wordlist:
            self._queued_types.add(w)

        while wordlist:
            if batching:
                chunk = wordlist[:batch_size]
                wordlist = wordlist[batch_size:]
                batch = self._create_batch(chunk, type_query)
                self._check_response(batch, batching)
            else:
                word = wordlist.pop(0)
                self._check_response({"query": type_query % word}, batching)

            unprobed = {t for t in self._new_types if t and t not in self._found_types and t not in self._queued_types}
            if unprobed:
                for u in unprobed:
                    self._queued_types.add(u)
                    wordlist.append(u)

                self._new_types.difference_update(unprobed)

    def _check_response(self, query: object, batching: bool):
        """
        This method sends a __type query (or queries if batching is set to True) and checks to see if the server returns
        information about the probed type.

        Parameters
        ----------
        query: object
            GraphQL __type query or a list of __type queries
        batching: bool
            Send GraphQL queries in batches if True
        """
        response: Response = self.helpers.send_request(self.supported_methods, query)
        try:
            response_json = response.json()
        except JSONDecodeError as e:
            ptprint(f"Could not get JSON from response: {e}", "ERROR", not self.args.json, indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return

        if response.status_code != HTTPStatus.OK or "errors" in response_json:
            ptprint(f"Error sending query. Received status code: {response.status_code}", "ERROR",
                    not self.args.json, indent=4)

            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return


        if batching:
            for batch_part in response_json:
                t = batch_part.get("data", {}).get("__type", {})
                if t:
                    self._found_types.add(t.get("name", ""))
                    self._print_type(t)
        else:
            t = response_json.get("data", {}).get("__type", {})
            if t:
                self._found_types.add(t.get("name", "-"))
                self._print_type(t)


    def _verify_stuffing(self) -> bool:
        """
        This method checks to see if the GraphQL server supports __type queries.

        Returns
        -------
        bool
            True if yes. False otherwise
        """
        query = {"query": '{__type(name: "Query"){name}}'}
        response: Response = self.helpers.send_request(self.supported_methods, query)

        try:
            response_json = response.json()
        except JSONDecodeError as e:
            ptprint(f"Error getting JSON from response: {e}", "ERROR", not self.args.json, indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4,
                    colortext=True)
            return False

        if response.status_code != HTTPStatus.OK or "errors" in response_json:
            ptprint("The host does not support the __type metafield", "OK", not self.args.json, indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4,
                    colortext=True)
            return False

        ptprint("The host supports the __type metafield", "VULN", not self.args.json, indent=4)
        self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-TYPE-STUFFING")

        return True


    def _verify_batching(self) -> bool:
        """
        This method checks to see if the GraphQL server supports sending batch requests.

        Returns
        bool
            True if the server supports batching, False otherwise
        """
        query = {"query": "query {__typename}"}
        batch = [query] * 10

        response: Response = self.helpers.send_request(self.supported_methods, batch)

        try:
            response_json = response.json()
        except JSONDecodeError as e:
            ptprint(f"Error getting JSON from batch response: {e}", "ERROR", not self.args.json, indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4,
                    colortext=True)
            return False

        if response.status_code != HTTPStatus.OK or "errors" in response_json:
            ptprint("The host does not support batching. Sending queries one by one", "OK", not self.args.json, indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4,
                    colortext=True)
            return False

        return True


    def run(self) -> None:
        """
        Executes the type stuffing test

        The method first verifies if the GraphQL server schema is already mapped and if yes, we only verify if it supports
        __type queries. In the case that the schema is not mapped, we verify if the server supports __type queries and then
        execute type stuffing using the wordlist provided.
        """
        if self.args.schema:
            self._verify_stuffing()
            ptprint(f"GraphQL schema already mapped. Skipping type stuffing", "VULN", not self.args.json,
                    indent=4)
            return

        if not self.args.wordlist_types:
            ptprint(f"You need to provide a wordlist for the type stuffing module. Please do so with the -wt argument",
                    "ERROR", not self.args.json, indent=4)
            return

        if not self._verify_stuffing():
            return

        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, self.args.wordlist_types)

        with open(wordlist_path, "r") as wordlist:
            self._stuff([word for word in wordlist.read().split('\n')], self._verify_batching())


def run(args, ptjsonlib, helpers, http_client, supported_methods, common_tests):
    """Entry point for running the TypeStuffing test"""
    TypeStuffing(args, ptjsonlib, helpers, http_client, supported_methods, common_tests).run()
