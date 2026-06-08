"""
API Content-Disposition header security test

Contains:
- ContentDisposition class to perform the test
- run() function as an entry point for running the test
"""

from requests.models import Response
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint


__TESTLABEL__ = "API Content-Disposition header security test"


class ContentDisposition:
    """
    Class for testing the Content-Disposition header security of an API endpoint
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
        Executes the Content-Disposition header security test.

        Send an HTTP request with a spoofed Content-Disposition header and checks if the host denies it or not.
        """
        response: Response = self.helpers.send_request(self.args.base_request, self.args.headers)

        for header, value in response.headers.items():
            if header.lower() == "content-disposition":
                ptprint(f"The server returns a Content-Disposition header: {value}", "INFO", not self.args.json,
                        indent=self.base_indent+4)
                return

        ptprint(f"The server does not return a Content-Disposition header", "INFO", not self.args.json,
                indent=self.base_indent + 4)

def run(args, ptjsonlib, helpers, http_client, base_indent):
    """Entry point for running the Content-Disposition security test"""
    ContentDisposition(args, ptjsonlib, helpers, http_client, base_indent).run()
