"""
API CORS security test

Contains:
- Https class to perform the test
- run() function as an entry point for running the test
"""
from requests.models import Response
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import SSLError

__TESTLABEL__ = "API HTTPS security test"


class Https:
    """
    Class for testing the CORS security of a API endpoint
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
        """
        ptprint(f"Not yet implemented", "INFO", not self.args.json, indent=4)





def run(args, ptjsonlib, helpers, http_client, base_indent):
    """Entry point for running the CORS security test"""
    Https(args, ptjsonlib, helpers, http_client, base_indent).run()
