"""
SOAP Null/Empty Input test

Tests whether required parameters properly reject empty or null values.

For each required parameter, sends:
- Empty string value: <param></param>
- xsi:nil attribute: <param xsi:nil="true"/>

If server accepts these for required parameters, it may process with
default values, NULL pointer exceptions, or bypass business logic.
"""
import requests
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Null/Empty Input test"


class NullInput:
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
                "faultstring" in body_lower)

    def _build_request(self, tns, input_element, params_xml_content):
        return (
            f'<?xml version="1.0"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            f' xmlns:tns="{tns}">'
            f'<soap:Body><tns:{input_element}>{params_xml_content}'
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

            required_params = [p for p in params if p.get('required', True)]
            if not required_params:
                continue

            tested_any = True

            for p in required_params:
                # Test 1: empty value <param></param>
                params_xml = ''
                for other in params:
                    if other['name'] == p['name']:
                        params_xml += f'<tns:{p["name"]}></tns:{p["name"]}>'
                    else:
                        default = 'test' if other['type'] == 'string' else '1'
                        params_xml += f'<tns:{other["name"]}>{default}</tns:{other["name"]}>'

                req = self._build_request(tns, input_element, params_xml)
                r = self._send_raw(req)
                if r is not None and not self._is_rejection(r):
                    findings.append(f"Operation '{op_name}' required parameter "
                                    f"'{p['name']}': accepted empty value "
                                    f"(HTTP {r.status_code})")
                    continue

                # Test 2: xsi:nil
                params_xml = ''
                for other in params:
                    if other['name'] == p['name']:
                        params_xml += f'<tns:{p["name"]} xsi:nil="true"/>'
                    else:
                        default = 'test' if other['type'] == 'string' else '1'
                        params_xml += f'<tns:{other["name"]}>{default}</tns:{other["name"]}>'

                req = self._build_request(tns, input_element, params_xml)
                r = self._send_raw(req)
                if r is not None and not self._is_rejection(r):
                    findings.append(f"Operation '{op_name}' required parameter "
                                    f"'{p['name']}': accepted xsi:nil='true' "
                                    f"(HTTP {r.status_code})")

        if not tested_any:
            ptprint("No required parameters to test. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        if findings:
            ptprint("Null/empty input issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-NULL-INPUT", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server rejects null/empty input for required parameters.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    NullInput(args, ptjsonlib, helpers, http_client, common_tests).run()
