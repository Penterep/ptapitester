"""
Sample module

This module is a sample for demonstrational purposes

Contains:
- Sample class to demonstrate
- run() function as an entry point for running the test
"""
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace


__TESTLABEL__ = "Sample SOAP API test"


class DoS:
    """Class for executing the sample test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, common_tests: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests

        self.helpers.print_header(__TESTLABEL__)


    def run(self) -> None:
        """
        Here you define your module code
        """
        # You can use your helper functions:
        self.helpers.sample_helper()

        # You can execute common API tests from the ptapitester.common_tests module:
        self.common_tests.run()

        # You can add vulnerabilities:
        self.ptjsonlib.add_vulnerability("PTV-SOAP-SAMPLE-VULN")



def run(args, ptjsonlib, helpers, http_client, common_tests):
    """Entry point for running the sample test"""
    DoS(args, ptjsonlib, helpers, http_client, common_tests).run()
