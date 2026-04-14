"""
SOAP Undocumented Parameters discovery

Dictionary attack to discover hidden parameters in SOAP operations.
For each known operation, sends requests with additional XML elements
and compares responses with baseline.
"""
import requests
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP Undocumented Parameters discovery"


class UndocumentedParameters:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _send_raw(self, data):
        try:
            return requests.post(
                self.helpers.endpoint_url,
                data=data.encode('utf-8'),
                headers={"Content-Type": "text/xml; charset=utf-8"},
                timeout=getattr(self.args, 'timeout', 10),
                verify=False
            )
        except Exception:
            return None

    def run(self):
        # Common hidden parameter names
        param_names = [
            "admin", "isAdmin", "role", "debug", "verbose", "include_deleted",
            "includeDeleted", "internal", "secret", "token", "api_key", "apiKey",
            "password", "auth", "format", "raw", "showAll", "includeHidden",
            "bypass", "override", "elevated", "privileged", "sudo", "root",
        ]

        # Get operations to test — from WSDL + any discovered undocumented ones
        operations = list(self.helpers.known_operations)

        # Also load undocumented operations from wordlist results if available
        undoc_ops = self.helpers.load_wordlist("soap_operations.txt")
        # We only test known + discovered operations, not the full wordlist

        if not operations:
            ptprint("No operations known. Skipping parameter discovery.", "INFO",
                    not self.args.json, indent=4)
            return

        all_findings = []

        for operation in operations:
            # Baseline 1: normal operation call
            b1_soap = (
                f'<?xml version="1.0"?>'
                f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                f'<soap:Body><{operation}><message>param_test</message></{operation}></soap:Body>'
                f'</soap:Envelope>'
            )

            # Baseline 2: operation with nonexistent parameter
            b2_soap = (
                f'<?xml version="1.0"?>'
                f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                f'<soap:Body><{operation}><message>param_test</message>'
                f'<nonexistentParam839274>test</nonexistentParam839274>'
                f'</{operation}></soap:Body></soap:Envelope>'
            )

            b1_r = self._send_raw(b1_soap)
            b2_r = self._send_raw(b2_soap)
            if b1_r is None or b2_r is None:
                continue

            tolerance = abs(len(b1_r.text) - len(b2_r.text)) + 30
            baseline_status = b2_r.status_code
            baseline_len = len(b2_r.text)

            found_params = []

            for param_name in param_names:
                test_soap = (
                    f'<?xml version="1.0"?>'
                    f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                    f'<soap:Body><{operation}><message>param_test</message>'
                    f'<{param_name}>true</{param_name}>'
                    f'</{operation}></soap:Body></soap:Envelope>'
                )

                r = self._send_raw(test_soap)
                if r is None:
                    continue

                is_different = False
                if r.status_code != baseline_status:
                    is_different = True
                elif abs(len(r.text) - baseline_len) > tolerance:
                    is_different = True

                if is_different:
                    found_params.append(param_name)

            if found_params:
                ptprint(f"  {operation}: undocumented params: {', '.join(found_params)}",
                        "VULN", not self.args.json, indent=4, colortext=True)
                all_findings.append({"operation": operation, "params": found_params})

        if all_findings:
            evidence_parts = [f"{f['operation']}({', '.join(f['params'])})" for f in all_findings]
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-UNDOCUMENTED-PARAMS", node_key=self.helpers.node_key,
                data={"evidence": f"Undocumented parameters: {'; '.join(evidence_parts)}"})
        else:
            ptprint("No undocumented parameters found.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    UndocumentedParameters(args, ptjsonlib, helpers, http_client, common_tests).run()
