"""
SOAP X-Forwarded-For authorization bypass test

Tests X-Forwarded-For, X-Real-IP etc. on all known endpoints.
"""
import requests as req_lib
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP X-Forwarded-For bypass test"


class XForwardedForBypass:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        soap_request = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>xff_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        # Test endpoints: main + any discovered undocumented ones
        endpoints = [self.helpers.endpoint_url]
        known_admin_paths = ["/admin-service", "/admin", "/debug/service", "/internal/service"]
        for path in known_admin_paths:
            endpoints.append(self.helpers.base_url + path)

        bypass_headers_list = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Forwarded-For", "::1"),
        ]

        findings = []

        for url in endpoints:
            # Normal request without XFF
            try:
                r_normal = req_lib.post(url, data=soap_request,
                    headers={"Content-Type": "text/xml"},
                    timeout=getattr(self.args, 'timeout', 10), verify=False)
            except Exception:
                continue

            normal_status = r_normal.status_code

            for header_name, header_value in bypass_headers_list:
                try:
                    r_xff = req_lib.post(url, data=soap_request,
                        headers={"Content-Type": "text/xml", header_name: header_value},
                        timeout=getattr(self.args, 'timeout', 10), verify=False)
                except Exception:
                    continue

                # Auth bypass: 401/403 becomes 200
                if normal_status in (401, 403) and r_xff.status_code == 200:
                    findings.append(f"{header_name}: {header_value} bypassed auth at {url} "
                                    f"(status {normal_status} -> {r_xff.status_code})")

                # XFF value reflected in response body
                if header_value in r_xff.text:
                    findings.append(f"{header_name} value '{header_value}' reflected in response at {url}")

                # Different response size (might indicate different data access)
                if normal_status == r_xff.status_code and abs(len(r_xff.text) - len(r_normal.text)) > 100:
                    findings.append(f"{header_name} causes different response at {url} "
                                    f"(len diff: {abs(len(r_xff.text) - len(r_normal.text))})")

                if findings:
                    break
            if findings:
                break

        if findings:
            ptprint("X-Forwarded-For bypass possible!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-XFF-BYPASS", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server does not appear vulnerable to X-Forwarded-For bypass.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XForwardedForBypass(args, ptjsonlib, helpers, http_client, common_tests).run()
