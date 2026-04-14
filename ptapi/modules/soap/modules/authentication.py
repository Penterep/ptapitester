"""
SOAP Authentication test

Tests whether SOAP endpoints and operations are accessible
without authentication. Checks for absence of auth mechanisms
(401/403 responses, WWW-Authenticate headers, WS-Security requirements).
"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP Authentication test"


class AuthenticationTest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        soap_request = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>auth_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        findings = []

        # Test main endpoint
        r = self.helpers.send_soap_request(data=soap_request)
        if r is None:
            ptprint("Could not complete authentication test.", "INFO",
                    not self.args.json, indent=4)
            return

        # Check if endpoint requires auth
        if r.status_code in (401, 403):
            ptprint(f"Endpoint requires authentication (HTTP {r.status_code}).", "OK",
                    not self.args.json, indent=4)

            # Check auth type
            www_auth = r.headers.get("WWW-Authenticate", "")
            if www_auth:
                ptprint(f"  Authentication type: {www_auth}", "INFO",
                        not self.args.json, indent=4)
        else:
            findings.append(f"Main endpoint {self.helpers.endpoint_url} accessible without "
                            f"authentication (HTTP {r.status_code})")

        # Check for auth-related headers in response
        auth_headers = ["WWW-Authenticate", "Authorization", "X-API-Key"]
        has_auth_header = False
        for header in auth_headers:
            if r.headers.get(header):
                has_auth_header = True

        # Check if response contains WS-Security requirements
        body_lower = r.text.lower()
        ws_security = any(ind in body_lower for ind in [
            "wsse:security", "wsu:timestamp", "authentication required",
            "unauthorized", "access denied", "login required"
        ])

        if not has_auth_header and r.status_code not in (401, 403) and not ws_security:
            findings.append("No authentication mechanism detected (no WWW-Authenticate header, "
                            "no WS-Security, no 401/403 response)")

        # Test known sensitive endpoints
        sensitive_paths = ["/admin-service", "/debug/service", "/internal/service"]
        for path in sensitive_paths:
            test_url = self.helpers.base_url + path
            r_sensitive = self.helpers.send_soap_request(url=test_url, data=soap_request)
            if r_sensitive and r_sensitive.status_code == 200:
                findings.append(f"Sensitive endpoint {path} accessible without authentication")

        if findings:
            ptprint("Authentication issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-NO-AUTH", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Authentication mechanisms are in place.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    AuthenticationTest(args, ptjsonlib, helpers, http_client, common_tests).run()
