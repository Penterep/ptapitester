"""XML-RPC X-Forwarded-For authorization bypass test"""
import requests as req_lib
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC X-Forwarded-For bypass test"


class XForwardedForBypass:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        probe = '<?xml version="1.0"?><methodCall><methodName>ping</methodName></methodCall>'

        # Normal request
        try:
            r_normal = req_lib.post(self.helpers.endpoint_url, data=probe,
                headers={"Content-Type": "text/xml"},
                timeout=getattr(self.args, 'timeout', 10), verify=False)
        except Exception:
            ptprint("Could not complete X-Forwarded-For test.", "INFO",
                    not self.args.json, indent=4)
            return

        normal_status = r_normal.status_code

        bypass_headers_list = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Forwarded-For", "::1"),
        ]

        findings = []
        for header_name, header_value in bypass_headers_list:
            try:
                r_xff = req_lib.post(self.helpers.endpoint_url, data=probe,
                    headers={"Content-Type": "text/xml", header_name: header_value},
                    timeout=getattr(self.args, 'timeout', 10), verify=False)
            except Exception:
                continue

            # Auth bypass
            if normal_status in (401, 403) and r_xff.status_code == 200:
                findings.append(f"{header_name}: {header_value} bypassed auth "
                                f"(status {normal_status} -> {r_xff.status_code})")

            # XFF value reflected
            if header_value in r_xff.text:
                findings.append(f"{header_name} value '{header_value}' reflected in response")

            # Response size difference
            if normal_status == r_xff.status_code and abs(len(r_xff.text) - len(r_normal.text)) > 50:
                findings.append(f"{header_name} causes different response "
                                f"(len diff: {abs(len(r_xff.text) - len(r_normal.text))})")

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
