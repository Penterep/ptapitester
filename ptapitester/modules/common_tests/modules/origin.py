"""
API Origin header security test

Contains:
- Origin class to perform the test
- run() function as an entry point for running the test
"""
from http import HTTPStatus

from requests.models import Response
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "API Origin header security test"


class Origin:
    """
    Class for testing the Origin header security of aN API endpoint
    """
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, base_indent) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.base_indent = base_indent

        self.helpers.print_header(__TESTLABEL__, self.base_indent)


    def run(self) -> None:
        """
        Executes the Origin header security test.

        Send an HTTP request with a spoofed Origin header and checks if the host denies it or not.
        """
        headers = self.args.headers.copy()
        fake_origin = "very-much-a-fake-website.com"
        headers.update({"Origin": fake_origin})

        response: Response = self.helpers.send_request(self.args.base_request, headers)

        if response.status_code == HTTPStatus.OK:
            ptprint("The host accepts an invalid Origin header", "VULN", not self.args.json, indent=self.base_indent+4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=self.base_indent+4)
            self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-FAKE-ORIGIN")
            return

        ptprint("The host does not accept a fake Origin header", "OK", not self.args.json, indent=self.base_indent+4)
        ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=self.base_indent+4)


def run(args, ptjsonlib, helpers, http_client, base_indent):
    """Entry point for running the Origin security test"""
    Origin(args, ptjsonlib, helpers, http_client, base_indent).run()
