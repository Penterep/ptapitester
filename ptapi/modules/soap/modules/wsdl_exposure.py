"""
SOAP WSDL Exposure test

Tests whether WSDL document is publicly accessible and extracts
API structure (operations, namespace).
"""
import re
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP WSDL exposure test"


class WSDLExposure:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        if not self.helpers.wsdl_content:
            wsdl_paths = [
                self.helpers.endpoint_url.rstrip('/') + "?wsdl",
                self.helpers.base_url + "/?wsdl",
                self.helpers.base_url + "/",
            ]
            for path in wsdl_paths:
                r = self.helpers.send_get_request(path)
                if r and r.status_code == 200:
                    ct = r.headers.get("Content-Type", "").lower()
                    body_lower = r.text.lower()
                    if ("xml" in ct or body_lower.lstrip().startswith("<?xml")):
                        if "definitions" in body_lower:
                            self.helpers.wsdl_content = r.text
                            self.helpers.wsdl_url = path
                            break

        if self.helpers.wsdl_content:
            namespace = re.search(r'targetNamespace="([^"]+)"', self.helpers.wsdl_content)
            ns_text = namespace.group(1) if namespace else "unknown"
            operations = self.helpers.extract_operations_from_wsdl()
            op_count = len(operations)

            evidence = f"WSDL accessible at {self.helpers.wsdl_url}. Namespace: {ns_text}"
            if operations:
                evidence += f". Operations exposed ({op_count}): {', '.join(operations[:10])}"

            self.ptjsonlib.add_vulnerability("PTV-SOAP-WSDL-EXPOSED",
                                              node_key=self.helpers.node_key,
                                              data={"evidence": evidence})
            ptprint(f"WSDL exposure confirmed ({op_count} operations).", "VULN",
                    not self.args.json, indent=4)
            for op in operations:
                ptprint(f"  WSDL operation: {op}", "PARSED", not self.args.json, indent=4)
        else:
            ptprint("No WSDL exposure detected.", "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    WSDLExposure(args, ptjsonlib, helpers, http_client, common_tests).run()
