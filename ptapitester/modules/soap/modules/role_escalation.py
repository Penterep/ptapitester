"""
SOAP Role Escalation test

Tests whether the server accepts unauthorized parameters that could
grant elevated privileges (role escalation, admin bypass, debug mode).

"""
import requests
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Role Escalation test"

ROLE_ESCALATION_PARAMS = [
    ("isAdmin", "true"),
    ("role", "admin"),
    ("admin", "1"),
    ("debug", "true"),
    ("includeDeleted", "true"),
    ("bypassAuth", "true"),
]


class RoleEscalation:
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

        for op in operations[:3]:
            op_name = op.get('name', '')
            input_element = op.get('input_element', op_name)
            params = op.get('input_params', [])

            if not params:
                continue

            defaults = {p['name']: 'test' if p['type'] == 'string' else '1'
                        for p in params}

            # Baseline request
            baseline_req = self._build_request(tns, input_element, defaults)
            baseline_r = self._send_raw(baseline_req)
            if baseline_r is None:
                continue

            baseline_len = len(baseline_r.text)
            baseline_status = baseline_r.status_code

            for extra_name, extra_value in ROLE_ESCALATION_PARAMS:
                # Skip if already a legitimate parameter
                if any(p['name'] == extra_name for p in params):
                    continue

                test_values = defaults.copy()
                test_values[extra_name] = extra_value
                req = self._build_request(tns, input_element, test_values)
                r = self._send_raw(req)

                if r is None:
                    continue

                # Detect whether extra parameter changed server behavior.
                # Compare on same status code (200=200, 404=404 etc.) — if
                # the response size differs significantly, the server
                # processed the extra parameter.
                if (r.status_code == baseline_status and
                        abs(len(r.text) - baseline_len) > 50):
                    findings.append(f"Operation '{op_name}': extra parameter "
                                    f"'{extra_name}={extra_value}' changed response "
                                    f"(baseline {baseline_len}B, with extra {len(r.text)}B)")

        if findings:
            ptprint("Role escalation issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-ROLE-ESCALATION", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server ignores unauthorized extra parameters.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    RoleEscalation(args, ptjsonlib, helpers, http_client, common_tests).run()