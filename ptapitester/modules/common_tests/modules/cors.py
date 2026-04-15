"""
API CORS security test

Contains:
- Cors class to perform the test
- run() function as an entry point for running the test
"""
from requests.models import Response
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "API CORS security test"


class Cors:
    """
    Class for testing the CORS security of an API endpoint
    """
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, base_indent) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.base_indent = base_indent

        self.helpers.print_header(__TESTLABEL__, self.base_indent)


    def _check_acac(self, response: Response) -> None:
        """
        This method checks whether the API endpoint returns the Access-Control-Allow-Credentials header and whether it is
        true.
        """
        if not response.headers.get("Access-Control-Allow-Credentials", ""):
            ptprint("The host does not return the Access-Control-Allow-Credentials header", "OK",
                    not self.args.json, indent=self.base_indent+8)
            return

        if response.headers.get("Access-Control-Allow-Credentials", "") == "true":
            ptprint("Access-Control-Allow-Credentials is set to true", "VULN",
                    not self.args.json, indent=self.base_indent+8)
        else:
            ptprint("Access-Control-Allow-Credentials is set to false", "OK",
                    not self.args.json, indent=self.base_indent+8)


    def _check_reflection(self, response: Response, fake_origin: str) -> None:
        """
        This method checks if the API endpoint reflects the Origin header that we provide it
        """
        if response.headers.get("Access-Control-Allow-Origin", "") == fake_origin:
            ptprint("The host is reflecting origin", "VULN", not self.args.json, indent=self.base_indent+4)
            self._check_acac(response)
        else:
            ptprint("The host is not reflecting origin", "OK", not self.args.json, indent=self.base_indent+4)


    def _check_wildcard(self, response: Response) -> None:
        """
        This method checks if the API endpoint allows any origin by having the Access-Control-Allow-Origin header set to '*'
        """
        if response.headers.get("Access-Control-Allow-Origin", "") == '*':
            ptprint("The host allows the * wildcard as origin", "VULN", not self.args.json, indent=self.base_indent+4)
            self._check_acac(response)
        else:
            ptprint("The host does no allow the * wildcard as origin", "OK", not self.args.json,
                    indent=self.base_indent+4)


    def _check_null(self):
        """This method checks if the API endpoint accepts a null origin."""
        headers = self.args.headers.copy()
        headers.update({"Origin": "null"})

        response: Response = self.helpers.send_request(self.args.base_request, headers)

        if response.headers.get("Access-Control-Allow-Origin", "") == "null":
            ptprint("The host allows a null origin", "VULN", not self.args.json, indent=self.base_indent+4)
            self._check_acac(response)
        else:
            ptprint("The host does not allow a null origin", "OK", not self.args.json, indent=self.base_indent+4)


    def run(self) -> None:
        """
        Executes the CORS security test.

        1. Checks if the API endpoint reflects an arbitrary URL
        2. Checks if the API endpoint accepts any origin (* wildcard)
        3. Checks if the API endpoint accepts a null origin.

        In each step checks if the API endpoint returns an Access-Control-Allow-Credentials header and whether it is set to true.
        """
        headers = self.args.headers.copy()
        fake_origin = "very-much-a-fake-website.com"
        headers.update({"Origin": fake_origin})

        base_request: Response = self.helpers.send_request(self.args.base_request, headers)

        if not base_request.headers.get("Access-Control-Allow-Origin", ""):
            ptprint("The host does not return the Access-Control-Allow-Origin header", "OK", not self.args.json,
                    indent=self.base_indent+4)
            return

        self._check_reflection(base_request, fake_origin)
        self._check_wildcard(base_request)
        self._check_null()


def run(args, ptjsonlib, helpers, http_client, base_indent):
    """Entry point for running the CORS security test"""
    Cors(args, ptjsonlib, helpers, http_client, base_indent).run()
