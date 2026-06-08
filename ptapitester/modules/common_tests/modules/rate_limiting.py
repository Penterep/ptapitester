"""
API rate limit test

This module implements a test that checks if an API implements rate limiting

Contains:
- RateLimitTest class to perform the availability test
- run() function as an entry point for running the test
"""
from http import HTTPStatus

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import JSONDecodeError
from requests import Response

__TESTLABEL__ = "API rate limit test"


class RateLimitTest:
    """Class for executing the API rate limit test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient,
                 base_indent: int) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.base_indet = base_indent

        self.helpers.print_header(__TESTLABEL__)


    def _flood(self) -> None:
        """
        This method floods the target with 1000 requests to see if we get blocked or not. Prints out if we succeeded in getting blocked.
        """
        max_requests = 1000

        for request_idx in range(1, max_requests+1):
            response: Response = self.helpers.send_request(self.args.base_request, self.args.headers)

            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                ptprint(f"BLOCKED! HTTP 429 Too Many Request received on request no. {request_idx}", "NOTVULN",
                        not self.args.json, indent=4)
                return

            elif response.status_code == HTTPStatus.OK:
                try:
                    json_response = response.json()

                    if "errors" in json_response:
                        ptprint(f"Possible block. Got API error: {json_response}", "NOTVULN", not self.args.json,
                                indent=4)
                        return
                except JSONDecodeError as e:
                    ptprint(f"Could not decode JSON from response. {e}", "ERROR",
                            not self.args.json, indent=4)
                    ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)


        ptprint("The host does not seem to be implementing rate-limiting measures.", "VULN", not self.args.json,
                indent=4)


    def _test_ratelimit_headers(self, response: Response) -> bool:
        """
        This method goes through the HTTP response and looks for header with the word 'ratelimit' and 'rate-limit' in it.

        Parameters
        ----------
        response:
            HTTP response to check for rate limit headers

        Returns
        -------
        bool
            True if we have found rate limit headers. False otherwise.
        """
        found = False

        for header in response.headers.keys():
            if "ratelimit" in header.lower() or "rate-limit" in header.lower():
                ptprint(f"Found a rate-limit header - {header}: {response.headers.get(header)}", "OK",
                        not self.args.json, indent=4)
                found = True

        return found


    def run(self) -> None:
        """
        Executes the rate limit test.

        First looks for rate-limit headers and if none are found we flood the host with API requests (if loud mode is enabled with the -l/--loud argument).
        """
        response: Response = self.helpers.send_request(self.args.base_request, self.args.headers)

        if not self._test_ratelimit_headers(response):
            ptprint("The target does not implement rate-limiting headers", "VULN", not self.args.json, indent=4)

        if self.args.loud:
            self._flood()


def run(args, ptjsonlib, helpers, http_client, base_indent):
    """Entry point for running the RateLimit test"""
    RateLimitTest(args, ptjsonlib, helpers, http_client, base_indent).run()
