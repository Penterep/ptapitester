"""
SOAP WS-Security Replay Protection test

Checks whether SOAP responses contain WS-Security elements
(Timestamp, Nonce) that protect against replay attacks.
"""
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Replay Protection test"


class ReplayProtection:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        soap_request = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>replay_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        r = self.helpers.send_soap_request(data=soap_request)
        if r is None:
            ptprint("Could not complete replay protection test.", "INFO",
                    not self.args.json, indent=4)
            return

        body_lower = r.text.lower()
        ws_security_indicators = ["wsse:security", "wsu:timestamp", "wsse:nonce",
                                   "timestamp", "nonce", "ws-security"]

        found = [ind for ind in ws_security_indicators if ind in body_lower]
        if found:
            ptprint("WS-Security elements detected.", "OK",
                    not self.args.json, indent=4)
        else:
            ptprint("Replay protection inconclusive.", "INFO",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ReplayProtection(args, ptjsonlib, helpers, http_client, common_tests).run()
