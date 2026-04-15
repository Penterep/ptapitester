"""
GraphiQL test

This module implements a test that checks if the given GraphQL instance provides the GraphiQL graphical interface

Contains:
- GraphiQL class to perform the test
- run() function as an entry point for running the test
"""
import concurrent
import threading
from http import HTTPStatus
from ptlibs.ptprinthelper import ptprint
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from urllib.parse import urlparse
from requests import Response
import sys
from pathlib import Path
import os

__TESTLABEL__ = "GraphiQL test"




class GraphiQL:
    """Class for executing the GraphiQL availability test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, supported_methods: set,
                 common_tests: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.supported_methods = supported_methods
        self.stop_event = threading.Event()
        self.found_url = ""
        self.common_tests = common_tests

        self.helpers.print_header(__TESTLABEL__)


    def _worker(self, test_url: str):
        """
        Worker function for the thread pool.

        Parameters
        ----------
        test_url: str
            URL to probe for GraphQL
        """
        if self.stop_event.is_set():
            return None

        if self._check_response(test_url):
            self.found_url = test_url
            self.stop_event.set()
            return test_url

        return None


    def _brute_force(self, url: str) -> str:
        """
        This method probes suspected GraphiQL endpoints from a wordlist specified with the -w/--wordlist argument (default data/wordlists/endpoints.txt).
        If the response contains the string 'graphiql', we return the endpoint

        :return: URL of the verified GraphiQL endpoint. Empty string if none is found
        """

        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, f"../data/wordlists/endpoints.txt")

        with open(self.args.wordlist or wordlist_path, "r") as wordlist:
            endpoints = [url+new_url for new_url in wordlist.read().split('\n')]

        max_workers = 30

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(self._worker, url): url for url in endpoints}

            for future in concurrent.futures.as_completed(future_to_url):
                if self.stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

        return self.found_url

    def _check_response(self, url: str) -> str:
        headers = self.args.headers.copy()
        headers.update({"Accept": "text/html"})
        if "content-type" in headers.keys():
            headers.pop("content-type")
        elif "Content-Type" in headers.keys():
            headers.pop("Content-Type")

        response: Response = self.http_client.send_request(method="GET", url=url,
                                                           allow_redirects=False, headers=headers, merge_headers=False)

        ptprint(f"Received response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)

        if response.status_code != HTTPStatus.OK:
            ptprint(f"Could not get {url}. Received status code: {response.status_code}", "ADDITIONS",
                    self.args.verbose, indent=4, colortext=True)
            return ""

        elif "graphiql" in response.text.lower():
            return url

        return ""

    def run(self) -> None:
        """
        Executes the GraphiQL test

        Sends an HTTP GET request to the GraphQL URL with the 'Accept' header set to 'text/html'. If the response contains
        the string 'graphiql' we print that we've detected GraphiQL. In the opposite case we run a dictionary attack to try
        to locate a valid GraphiQL endpoint.
        """

        headers = self.args.headers.copy()
        headers.update({"Accept": "text/html"})
        if "content-type" in headers.keys():
            headers.pop("content-type")
        elif "Content-Type" in headers.keys():
            headers.pop("Content-Type")

        response: Response = self.http_client.send_request(method="GET",url=self.args.url, allow_redirects=False,
                                                           headers=headers, merge_headers=False)

        if "graphiql" in response.text.lower():
            ptprint(f"{self.args.url} provides GraphiQL", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-GRAPHIQL")
        elif graphiql_url := self._brute_force(self.args.url):
            ptprint(f"{graphiql_url} provides GraphiQL", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-GRAPHIQL")
        else:
            parsed = urlparse(self.args.url)
            url = parsed.scheme + "://" + parsed.netloc

            if graphiql_url := self._brute_force(url):
                ptprint(f"{graphiql_url} provides GraphiQL", "VULN", not self.args.json, indent=4)
                self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-GRAPHIQL")

            else:
                ptprint(f"Could not find GraphiQL or other graphical interfaces", "OK", not self.args.json, indent=4)




def run(args, ptjsonlib, helpers, http_client, supported_methods, common_tests):
    """Entry point for running the GraphiQL test"""
    GraphiQL(args, ptjsonlib, helpers, http_client, supported_methods, common_tests).run()
