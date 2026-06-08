"""
API Content-Type header security test

Contains:
- Content-Type class to perform the test
- run() function as an entry point for running the test
"""
import random
from http import HTTPStatus

from requests.models import Response
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from string import ascii_lowercase

__TESTLABEL__ = "API Content-Type header security test"


class ContentType:
    """
    Class for testing the Content-Type header security of an API endpoint
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
        Executes the Content-Type header security test.

        Send an HTTP request with a spoofed Content-Type header and checks if the host denies it or not.
        """
        headers = self.args.headers.copy()
        headers.update({"Content-Type": f"aNonExistentContentType-{''.join(random.choices(ascii_lowercase, k=4))}"})
        response: Response = self.helpers.send_request(self.args.base_request, headers)

        if response.status_code in [HTTPStatus.UNSUPPORTED_MEDIA_TYPE, HTTPStatus.BAD_REQUEST]:
            ptprint(f"The server rejects a non-existent media type", "OK", not self.args.json, indent=self.base_indent+4)
            return

        ptprint(f"The server does not reject and incorrect media type", "VULN", not self.args.json,
                indent=self.base_indent+4)
        self.ptjsonlib.add_vulnerability("PTV-API-SPOOFED-MEDIA-TYPE", description="The API accepts an incorrect media type")

def run(args, ptjsonlib, helpers, http_client, base_indent):
    """Entry point for running the Content-Type security test"""
    ContentType(args, ptjsonlib, helpers, http_client, base_indent).run()
