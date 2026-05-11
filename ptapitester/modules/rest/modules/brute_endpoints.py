"""
REST API endpoint discovery

This module tries to discover REST API endpoints using a dictionary attack

Contains:
- Brute class to discover endpoints
- run() function as an entry point for running the test
"""
import os
import re

from ptlibs import ptprint
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from requests import Response
from http import HTTPStatus
from ptthreads.ptthreads import ptthreads

__TESTLABEL__ = "REST API endpoint discovery"


class Brute:
    """Class for executing the endpoint discovery test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, common_tests: object,
                 endpoints: set[str]) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.endpoints = endpoints

        self.helpers.print_header(__TESTLABEL__)


    def _check_nonexistent_endpoint(self, path: str, endpoint) -> bool:
        new_path = path.removesuffix(endpoint) + "/id0n0tex1st_yaho000o"

        response: Response = self.http_client.send_request(url=self.args.url+new_path, method="GET", headers=self.args.headers,
                                                           allow_redirects=self.args.redirects)

        if response == HTTPStatus.NOT_FOUND:
            return False

        return True


    def _check_REST(self, response: Response) -> bool:
        json_pattern = re.compile(r"^\s*application/json\s*(?:;|$)", re.IGNORECASE)
        xml_pattern = re.compile(r"^\s*(?:application|text)/xml\s*(?:;|$)", re.IGNORECASE)

        if (not json_pattern.search(response.headers.get("content-type", "")) and
                not xml_pattern.search(response.headers.get("content-type", ""))):
            return False

        return True

    def _try_endpoint(self, endpoint: str) -> str:
        response: Response = self.http_client.send_request(url=self.args.url+endpoint, method="GET", headers=self.args.headers,
                                                           allow_redirects=self.args.redirects)

        if (response.status_code != HTTPStatus.NOT_FOUND
                and not 500 <= response.status_code < 599):

            if response.status_code == HTTPStatus.UNAUTHORIZED and self._check_nonexistent_endpoint(self.args.url+endpoint, endpoint):
                return ""


            if self._check_REST(response):
                return endpoint

        return ""


    def run(self) -> None:
        """
        Here you define your module code
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, f"../data/wordlists/wordlist_short.txt")

        with open(wordlist_path, "r") as wordlist:
            endpoints = [endpoint for endpoint in wordlist.read().split('\n')]

        if self.args.url[-1] == '/':
            self.args.url = self.args.url[:-1]

        threads: ptthreads = ptthreads()
        self.endpoints.update(threads.threads(endpoints, self._try_endpoint, self.args.threads))

        self.endpoints.remove("")

        for endpoint in self.endpoints:
            ptprint(f"Discovered API endpoint: {self.args.url+endpoint}", "INFO", not self.args.json,
                    indent=4)





def run(args, ptjsonlib, helpers, http_client, common_tests, endpoints):
    """Entry point for running the sample test"""
    Brute(args, ptjsonlib, helpers, http_client, common_tests, endpoints).run()
