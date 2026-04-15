"""
GraphQL method change test

This module implements a test that checks if we can change the HTTP POST method to a GET method

Contains:
- MethodTest to perform the availability test
- run() function as an entry point for running the test
"""
from http import HTTPStatus
from requests import Response
from argparse import Namespace
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from ptlibs.ptprinthelper import ptprint
import urllib.parse

__TESTLABEL__ = "GraphQL method change test"


class MethodTest:
    """Class for executing the GraphQL method change test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, supported_methods: set,
                 common_tests: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.supported_methods = supported_methods
        self.common_tests = common_tests

        self.helpers.print_header(__TESTLABEL__)


    def _check_response(self, response: Response) -> bool:
        """
        This method checks if the HTTP response code was HTTP 200 OK
        Args:
            response: received HTTP response

        Returns: True if the received response was HTTP 200 OK. False otherwise
        """
        if response.status_code == HTTPStatus.OK:
            ptprint(f"Received response: {response.text}", "ADDITIONS", self.args.verbose, indent=8, colortext=True)
            ptprint("Successfully exchanged POST method for GET", "VULN", not self.args.json, indent=8)
            return True

        ptprint("Could not exchange POST method for GET", "OK", not self.args.json, indent=8)
        ptprint(f"Received response: {response.text}", "ADDITIONS", self.args.verbose, indent=8, colortext=True)
        return False

    def _basic_query(self) -> None:
        """
        This method checks to see if we can exchange the POST method for a GET method in a basic query
        """
        query = {"query": "query{__typename}"}
        encoded = urllib.parse.urlencode(query)

        ptprint(f"Attempting to exchange POST for GET in query at {self.args.url}", "INFO",
                not self.args.json, indent=4)

        response: Response = self.http_client.send_request(method="GET", url=self.args.url + '?' + encoded,
                                                           allow_redirects=False,
                                                           headers={"User-Agent": "Penterep Tools"}, merge_headers=False)

        self._check_response(response)


    def _mutation(self) -> None:
        """
        This method checks to see if we can exchange the POST method for a GET method in a mutation
        """
        query = { "query": "mutation{__typename}"}
        encoded = urllib.parse.urlencode(query)

        ptprint(f"Attempting to exchange POST for GET in a mutation at {self.args.url}", "INFO",
                not self.args.json, indent=4)

        response: Response = self.http_client.send_request(method="GET", url=self.args.url + '?' + encoded,
                                                           allow_redirects=False,
                                                           headers={"User-Agent": "Penterep Tools"}, merge_headers=False)

        self._check_response(response)


    def run(self) -> None:
        """
        Executes the GraphQL method change test

        Tries to swap the POST method for a GET method in a:
            1. Query
            2. Mutation
        """
        self._basic_query()
        self._mutation()


def run(args, ptjsonlib, helpers, http_client, supported_methods, common_tests):
    """Entry point for running the MethodTest test"""
    MethodTest(args, ptjsonlib, helpers, http_client, supported_methods, common_tests).run()
