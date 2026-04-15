"""
GraphQL availability test

This module implements a test that checks if the provided URL is hosting GraphQL or not

Contains:
- IsGraphQL to perform the availability test
- run() function as an entry point for running the test
"""
import threading
from http import HTTPStatus
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import JSONDecodeError
from requests import Response
import requests


__TESTLABEL__ = "GraphQL supported methods test"

class IsGraphQL:
    """Class for executing the GraphQL availability test"""
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, supported_methods: set) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.supported_methods = supported_methods
        self.stop_event = threading.Event()
        self.found_url = ""

        self.helpers.print_header(__TESTLABEL__)


    def _check_JSON(self, response: Response) -> bool:
        """
        This method checks if the JSON response is equal to the expected response of a basic GraphQL query {"query": "query{__typename}"}.

        Parameters
        ----------
        response
            HTTP response of the host
        Returns
        -------
        bool
            True if the received response matches the expected. False otherwise
        """
        expected = [{"data": {"__typename": "Query"}}, {"data":{"__typename":"RootQueryType"}}, {"data":{"__typename":"RootQuery"}}]

        try:
            json_response = response.json()
        except JSONDecodeError as e:
            ptprint(f"Error decoding JSON from response: {e}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return False

        return json_response in expected


    def _check_response_GET(self, url: str) -> bool:
        """
        This method test the presence of GraphQL on a given endpoint with the HTTP method GET.
        
        Parameters
        ----------
        url: str
            URL of the host
            
        Returns
        -------
        bool
            True if the method detects GraphQL on the endpoint with the GET HTTP method. False otherwise
        """

        final_url = url+"?query=query%7B__typename%7D"

        headers = self.args.headers.copy()
        if "content-type" in headers.keys():
            headers.pop("content-type")
        elif "Content-Type" in headers.keys():
            headers.pop("Content-Type")

        ptprint(f"Trying endpoint {url} with method GET", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
        response = self.http_client.send_request(url=final_url, method="GET", allow_redirects=True, headers=headers, merge_headers=False)

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            ptprint(f"The host has authentication enabled for method GET at {url}", "OK", not self.args.json,
                    indent=4)
            return False

        if response.status_code != HTTPStatus.OK:
            ptprint(f"Could not GET {final_url}. Received status code: {response.status_code}", "ADDITIONS", self.args.verbose,
                    indent=4, colortext=True)
            return False

        return self._check_JSON(response)


    def _check_response_POST(self, url: str) -> bool:
        """
        This method test the presence of GraphQL on a given endpoint with the HTTP method POST.
        
        Parameters
        ----------
        url: str
            URL of the host
            
        Returns
        -------
        bool
            True if the method detects GraphQL on the endpoint with the POST HTTP method. False otherwise
        """
        payload = {"query": "query{__typename}"}

        ptprint(f"Trying {url} with method POST {self.args.headers}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
        response = self.http_client.send_request(method="POST", url=url, json=payload, allow_redirects=True,
                                                 headers=self.args.headers)

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            ptprint(f"The host has authentication enabled for method POST at {url}", "OK", not self.args.json, indent=4)
            return False

        if response.status_code != HTTPStatus.OK:
            ptprint(f"Could not POST {url}. Received status code: {response.status_code}", "ADDITIONS",
                    self.args.verbose,
                    indent=4, colortext=True)
            ptprint(f"Full response: {response.text}", "ADDITIONS")
            return False

        return self._check_JSON(response)


    def _check_response(self, url: str) -> None:
        """
        This method tests to see if the provided endpoint hosts GraphQL or not.
        It first tries to detect GraphQL with the HTTP GET method and then with the HTTP POST method.
        If any of the HTTP methods is successful, the HTTP method is added to a set of supported HTTP methods.


        Parameters
        ----------
        url: str
            URL to probe for the presence of GraphQL

        Returns
        -------
        str
            URL of GraphQL API endpoint
        """


        try:
            if self._check_response_GET(url):
                self.supported_methods.add("GET")
            if self._check_response_POST(url):
                self.supported_methods.add("POST")
        except requests.exceptions.RequestException as error_msg:
            ptprint(f"Error trying to connect with HTTPS: {error_msg}.", "ADDITIONS",
                    self.args.verbose, indent=4, colortext=True)
            self.ptjsonlib.end_error(f"Error retrieving initial responses:", details=error_msg,
                                     condition=self.args.json)



    def run(self) -> None:
        """
        Executes the GraphQL availability test

        Sends the following query to test if GraphQL is present on the provided URL: {'query': 'query{__typename}'}.
        If GraphQL is not detected on the provided URL, we try to bruteforce common GraphQL endpoints with a wordlist.
        Ends with an error if GraphQL is not detected.
        """

        self._check_response(self.args.url)
        ptprint(f"Supported methods: {", ".join(self.supported_methods)}", "VULN", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, supported_methods):
    """Entry point for running the IsGraphQL test"""
    IsGraphQL(args, ptjsonlib, helpers, http_client, supported_methods ).run()
