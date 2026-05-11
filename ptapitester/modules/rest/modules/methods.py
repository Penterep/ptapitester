"""
REST API methods test

This module tries to discover what methods an API endpoint supports

Contains:
- Methods class to run the test
- run() function as an entry point for running the test
"""

from ptlibs import ptprint
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from requests import Response
from http import HTTPStatus

__TESTLABEL__ = "REST API method discovery"



class Methods:
    """Class for executing the method discovery test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, common_tests: object,
                 endpoints: set[str]) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.endpoints = endpoints

        self.helpers.print_header(__TESTLABEL__)


    def _try_get(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="GET", allow_redirects=self.args.redirects,
                                                     headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method GET", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method GET. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED

    def _try_post(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="POST",
                                                               allow_redirects=self.args.redirects,
                                                               headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method POST", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method POST. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED

    def _try_head(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="HEAD",
                                                               allow_redirects=self.args.redirects,
                                                               headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method HEAD", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method HEAD. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED

    def _try_put(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="PUT",
                                                               allow_redirects=self.args.redirects,
                                                               headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method PUT", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method PUT. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED

    def _try_delete(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="DELETE",
                                                               allow_redirects=self.args.redirects,
                                                               headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method DELETE", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method DELETE. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED

    def _try_connect(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="CONNECT",
                                                               allow_redirects=self.args.redirects,
                                                               headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method CONNECT", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method CONNECT. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED

    def _try_options(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="OPTIONS",
                                                               allow_redirects=self.args.redirects,
                                                               headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method OPTIONS", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method OPTIONS. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED

    def _try_trace(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="TRACE",
                                                               allow_redirects=self.args.redirects,
                                                               headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method TRACE", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method TRACE. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED

    def _try_patch(self) -> bool:
        try:
            response: Response = self.http_client.send_request(url=self.args.url, method="PATCH",
                                                               allow_redirects=self.args.redirects,
                                                               headers=self.args.headers)

        except Exception as e:
            ptprint(f"Connection error occurred for method PATCH", "ERROR", not self.args.json,
                    indent=4)
            return False

        ptprint(f"Trying method PATCH. Received status code: {response.status_code}", "ADDITIONS",
                self.args.verbose, indent=4, colortext=True)

        return response.status_code != HTTPStatus.METHOD_NOT_ALLOWED


    def run(self) -> None:
        """
        The test tries to send a request with the GET, POST, PUT, PATCH, DELETE, CONNECT, TRACE, HEAD and OPTIONS HTTP methods.
        """

        methods = {
            "GET": self._try_get(),
            "POST": self._try_post(),
            "PUT": self._try_put(),
            "PATCH": self._try_patch(),
            "DELETE": self._try_delete(),
            "CONNECT": self._try_connect(),
            "TRACE": self._try_trace(),
            "HEAD": self._try_head(),
            "OPTIONS": self._try_options()
        }

        ptprint(f"Allowed methods: {', '.join([method for method, allowed in methods.items() if allowed])}", "INFO",
                not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests, endpoints):
    """Entry point for running the Methods test"""
    Methods(args, ptjsonlib, helpers, http_client, common_tests, endpoints).run()
