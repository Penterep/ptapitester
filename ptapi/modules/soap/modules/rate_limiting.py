"""
SOAP Rate Limiting test

Tests whether the server implements rate limiting
by sending rapid successive requests.
"""
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Rate Limiting test"


class RateLimiting:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        probe_data = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>rate_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        codes = []
        for _ in range(30):
            r = self.helpers.send_soap_request(data=probe_data)
            if r is None:
                continue
            codes.append(r.status_code)
            if r.status_code == 429:
                ptprint("Rate limiting is active (HTTP 429 received).", "OK",
                        not self.args.json, indent=4)
                return

        if codes:
            unique_codes = list(set(codes))
            ptprint(f"No rate limiting detected after {len(codes)} requests.",
                    "VULN", not self.args.json, indent=4, colortext=True)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-NO-RATE-LIMIT", node_key=self.helpers.node_key,
                data={"evidence": f"Sent {len(codes)} requests. HTTP codes: {unique_codes}"})
        else:
            ptprint("Rate limit test inconclusive (server unreachable).", "INFO",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    RateLimiting(args, ptjsonlib, helpers, http_client, common_tests).run()
