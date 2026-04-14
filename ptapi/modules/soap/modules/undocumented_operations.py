"""
SOAP Undocumented Operations test

Dictionary attack to discover SOAP operations not declared in WSDL.
Uses dual-baseline tolerance to eliminate false positives.
"""
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Undocumented Operations discovery"


class UndocumentedOperations:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        wordlist = self.helpers.load_wordlist("soap_operations.txt")
        if not wordlist:
            ptprint("No operations wordlist found. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        known_lower = {op.lower() for op in self.helpers.known_operations}

        # Dual-baseline
        baseline_op = "nonexistentOp839274"
        baseline2_op = "anotherFakeOp472910"

        b1_soap = (
            f'<?xml version="1.0"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><{baseline_op} xmlns="http://tempuri.org/"/></soap:Body>'
            f'</soap:Envelope>'
        )
        b2_soap = (
            f'<?xml version="1.0"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><{baseline2_op} xmlns="http://tempuri.org/"/></soap:Body>'
            f'</soap:Envelope>'
        )

        b1_r = self.helpers.send_soap_request(
            data=b1_soap, headers={"Content-Type": "text/xml; charset=utf-8",
                                    "SOAPAction": f'"urn:test:{baseline_op}"'})
        b2_r = self.helpers.send_soap_request(
            data=b2_soap, headers={"Content-Type": "text/xml; charset=utf-8",
                                    "SOAPAction": f'"urn:test:{baseline2_op}"'})

        if b1_r is None or b2_r is None:
            ptprint("Could not establish baseline. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        baseline_status = b1_r.status_code
        tolerance = abs(len(b1_r.text) - len(b2_r.text)) + 20

        found_operations = []

        for op_name in wordlist:
            op_name = op_name.strip()
            if not op_name or op_name.lower() in known_lower:
                continue

            soap_request = (
                f'<?xml version="1.0"?>'
                f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                f'<soap:Body><{op_name} xmlns="http://tempuri.org/"/></soap:Body>'
                f'</soap:Envelope>'
            )

            r = self.helpers.send_soap_request(
                data=soap_request,
                headers={"Content-Type": "text/xml; charset=utf-8",
                          "SOAPAction": f'"urn:test:{op_name}"'})
            if r is None:
                continue

            is_different = False

            if r.status_code != baseline_status:
                is_different = True
            elif abs(len(r.text) - len(b1_r.text)) > tolerance:
                is_different = True

            if is_different:
                found_operations.append(op_name)
                ptprint(f"  Undocumented operation found: {op_name} (HTTP {r.status_code})",
                        "VULN", not self.args.json, indent=4, colortext=True)

        if found_operations:
            wsdl_info = (f"WSDL declares: {', '.join(self.helpers.known_operations)}"
                         if self.helpers.known_operations else "No WSDL available")
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-UNDOCUMENTED-OPERATIONS", node_key=self.helpers.node_key,
                data={"evidence": f"Dictionary attack found {len(found_operations)} "
                                  f"undocumented operation(s): {', '.join(found_operations)}. "
                                  f"{wsdl_info}"})
        else:
            ptprint("No undocumented operations found.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    UndocumentedOperations(args, ptjsonlib, helpers, http_client, common_tests).run()
