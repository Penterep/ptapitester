"""
SOAP Integer Overflow test

Tests whether numeric parameters (int, long, short, byte) are protected
against integer overflow attacks by sending values outside valid ranges.

For each numeric parameter, sends:
- int32 overflow: 2^31 (2147483648)
- int32 underflow: -(2^31 + 1)
- int64 overflow: 9999999999999999999

If the server accepts these values without error, it may be vulnerable
to overflow issues causing incorrect calculations, bypass of limits,
or memory corruption.
"""
import requests
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Integer Overflow test"

NUMERIC_TYPES = ('int', 'integer', 'long', 'short', 'byte')

OVERFLOW_VALUES = [
    ("2147483648", "int32 +1 (2^31)"),
    ("-2147483649", "int32 -1 (-(2^31+1))"),
    ("9999999999999999999", "int64 overflow"),
]


class IntegerOverflow:
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
        return (r.status_code in (400, 500) or
                "soap:fault" in body_lower or
                "faultstring" in body_lower or
                "overflow" in body_lower or
                "invalid" in body_lower)

    def _build_request(self, tns, input_element, params):
        params_xml = ''
        for name, value in params.items():
            params_xml += f'<tns:{name}>{value}</tns:{name}>'
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

        tested_any = False
        for op in operations[:3]:
            op_name = op.get('name', '')
            input_element = op.get('input_element', op_name)
            params = op.get('input_params', [])

            numeric_params = [p for p in params if p['type'] in NUMERIC_TYPES]
            if not numeric_params:
                continue

            tested_any = True
            defaults = {p['name']: 'test' if p['type'] == 'string' else '1'
                        for p in params}

            for p in numeric_params:
                for overflow_val, label in OVERFLOW_VALUES:
                    test_values = defaults.copy()
                    test_values[p['name']] = overflow_val
                    req = self._build_request(tns, input_element, test_values)
                    r = self._send_raw(req)

                    if r is not None and not self._is_rejection(r):
                        findings.append(f"Operation '{op_name}' parameter '{p['name']}' "
                                        f"({p['type']}): accepted {label} value "
                                        f"'{overflow_val}' (HTTP {r.status_code})")
                        break

        if not tested_any:
            ptprint("No numeric parameters to test. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        if findings:
            ptprint("Integer overflow issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-INTEGER-OVERFLOW", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server rejects integer overflow values.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    IntegerOverflow(args, ptjsonlib, helpers, http_client, common_tests).run()
