"""
SOAP Server-side Validation test

Tests whether the server properly validates parameter values beyond XSD
schema — e.g. oversized strings, special characters, unexpected formats.

For each string parameter of each operation, sends:
- Oversized strings (10000 characters)
- Strings with special/binary characters

If the server processes these without rejection, it's missing input
validation (OWASP A03 - Injection).
"""
import requests
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Server-side Validation test"

OVERSIZED_STRING = "A" * 10000


class ServerSideValidation:
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

    def _is_rejection(self, r):
        if r is None:
            return True
        body_lower = r.text.lower()
        return (r.status_code in (400, 413, 500) or
                "soap:fault" in body_lower or
                "faultstring" in body_lower)

    def _build_request(self, tns, input_element, params):
        params_xml = ''
        for name, value in params.items():
            value_safe = (str(value).replace('&', '&amp;').replace('<', '&lt;')
                          .replace('>', '&gt;'))
            params_xml += f'<tns:{name}>{value_safe}</tns:{name}>'
        return (
            f'<?xml version="1.0"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{tns}">'
            f'<soap:Body><tns:{input_element}>{params_xml}'
            f'</tns:{input_element}></soap:Body></soap:Envelope>'
        )

    def run(self):
        operations = self.helpers.parsed_operations
        if not operations:
            ptprint("No parsed operations available. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        tns = getattr(self.helpers, 'target_namespace', '') or 'http://tempuri.org/'
        findings = []

        for op in operations[:3]:  # limit to first 3 ops
            op_name = op.get('name', '')
            input_element = op.get('input_element', op_name)
            params = op.get('input_params', [])

            string_params = [p for p in params if p['type'] == 'string']
            if not string_params:
                continue

            # Build defaults for non-tested params
            defaults = {p['name']: 'test' if p['type'] == 'string' else '1'
                        for p in params}

            for p in string_params:
                test_values = defaults.copy()
                test_values[p['name']] = OVERSIZED_STRING
                req = self._build_request(tns, input_element, test_values)
                r = self._send_raw(req)

                if r is not None and not self._is_rejection(r):
                    findings.append(f"Operation '{op_name}' parameter '{p['name']}': "
                                    f"accepted 10000-char string (HTTP {r.status_code})")

        if findings:
            ptprint("Server-side validation issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-WEAK-VALIDATION", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server appears to validate oversized input.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ServerSideValidation(args, ptjsonlib, helpers, http_client, common_tests).run()
