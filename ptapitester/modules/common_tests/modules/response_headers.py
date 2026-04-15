"""
API Origin header security test

Contains:
- Origin class to perform the test
- run() function as an entry point for running the test
"""
from requests.models import Response
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint


__TESTLABEL__ = "API headers security test"


class Origin:
    """
    Class for testing the Origin header security of a API endpoint
    """
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, base_indent) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.base_indent = base_indent

        self.helpers.print_header(__TESTLABEL__, self.base_indent)

    def _cache_control(self, response: Response) -> None:
        """
        This method checks the HTTP response headers from the server to see if they return a Cache-Control header.
        If they do, the method checks if they are set to no-cache, no-store or must-revalidate.

        Args:
            response:
                Server HTTP response
        """
        cc_headers = response.headers.get("cache-control", "").lower()

        if not cc_headers:
            ptprint("The host does not implement a cache-control policy", "VULN", not self.args.json,
                    indent=self.base_indent+4)
            self.ptjsonlib.add_vulnerability("PTV-PTAPITESTER-CACHE-CONTROL")
            return

        ptprint(f"Cache-Control headers: {cc_headers}", "ADDITIONS", self.args.verbose, indent=self.base_indent+4,
                colortext=True)
        cc_headers = set(cc_headers.split(", "))

        if not any(cc_headers.intersection({"no-cache", "no-store", "must-revalidate"})):
            ptprint("The host enforces an insecure cache-control policy", "VULN", not self.args.json,
                    indent=self.base_indent+4)
            self.ptjsonlib.add_vulnerability("PTV-PTAPITESTER-CACHE-CONTROL")
        else:
            ptprint("The host enforces a secure cache-control policy", "OK", not self.args.json,
                    indent=self.base_indent+4)


    def run(self) -> None:
        """
        Executes the Origin header security test.

        Send an HTTP request with a spoofed Origin header and checks if the host denies it or not.
        """
        response: Response = self.helpers.send_request(self.args.base_request, self.args.headers)

        self._cache_control(response)

def run(args, ptjsonlib, helpers, http_client, base_indent):
    """Entry point for running the Origin security test"""
    Origin(args, ptjsonlib, helpers, http_client, base_indent).run()
