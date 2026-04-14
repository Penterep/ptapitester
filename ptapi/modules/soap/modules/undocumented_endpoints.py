"""
SOAP Undocumented Endpoints test

Dictionary attack to discover SOAP endpoints not declared in WSDL.
Uses dual-baseline tolerance to eliminate false positives from catch-all servers.
"""
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Undocumented Endpoints discovery"


class UndocumentedEndpoints:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        wordlist = self.helpers.load_wordlist("soap_endpoints.txt")
        if not wordlist:
            ptprint("No endpoint wordlist found. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        known = {self.helpers.endpoint_url.rstrip('/').lower(),
                 self.helpers.base_url.rstrip('/').lower()}

        soap_body = ('<?xml version="1.0"?><soap:Envelope xmlns:soap='
                     '"http://schemas.xmlsoap.org/soap/envelope/">'
                     '<soap:Body><test>probe</test></soap:Body></soap:Envelope>')

        # Dual-baseline
        b1_r = self.helpers.send_soap_request(
            url=self.helpers.base_url + "/nonexistent_path_8374629", data=soap_body)
        b2_r = self.helpers.send_soap_request(
            url=self.helpers.base_url + "/anotherfake_472910xy", data=soap_body)

        if b1_r is None or b2_r is None:
            ptprint("Could not establish baseline. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        baseline_status = b1_r.status_code
        tolerance = abs(len(b1_r.text) - len(b2_r.text)) + 30

        found_endpoints = []

        for path in wordlist:
            path = path.strip()
            if not path or not path.startswith('/'):
                continue

            test_url = self.helpers.base_url + path
            if test_url.rstrip('/').lower() in known:
                continue

            r = self.helpers.send_soap_request(url=test_url, data=soap_body)
            if r is None:
                continue
            if r.status_code in (404, 405):
                continue
            if r.status_code == baseline_status and abs(len(r.text) - len(b1_r.text)) <= tolerance:
                continue

            ct = r.headers.get("Content-Type", "").lower()
            if "html" in ct and "xml" not in ct:
                continue

            found_endpoints.append(path)
            ptprint(f"  Undocumented endpoint found: {path} (HTTP {r.status_code})",
                    "VULN", not self.args.json, indent=4, colortext=True)

        if found_endpoints:
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-UNDOCUMENTED-ENDPOINTS", node_key=self.helpers.node_key,
                data={"evidence": f"Dictionary attack found {len(found_endpoints)} "
                                  f"endpoint(s) not in WSDL: {', '.join(found_endpoints)}"})
        else:
            ptprint("No undocumented endpoints found.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    UndocumentedEndpoints(args, ptjsonlib, helpers, http_client, common_tests).run()
