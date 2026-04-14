"""
XML-RPC Authentication test

Tests whether XML-RPC endpoint and methods are accessible
without authentication.
"""
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Authentication test"


class AuthenticationTest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        findings = []

        # Test endpoint access without auth
        probe = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
        r = self.helpers.send_xmlrpc_raw(data=probe)

        if r is None:
            ptprint("Could not complete authentication test.", "INFO",
                    not self.args.json, indent=4)
            return

        if r.status_code in (401, 403):
            ptprint(f"Endpoint requires authentication (HTTP {r.status_code}).", "OK",
                    not self.args.json, indent=4)
            www_auth = r.headers.get("WWW-Authenticate", "")
            if www_auth:
                ptprint(f"  Authentication type: {www_auth}", "INFO",
                        not self.args.json, indent=4)
            return

        # Introspection is accessible without auth
        if "<methodresponse" in r.text.lower() and "<array>" in r.text.lower():
            findings.append("Introspection (system.listMethods) accessible without authentication")

        # Check for auth-related response indicators
        body_lower = r.text.lower()
        has_auth = any(ind in body_lower for ind in [
            "authentication required", "unauthorized", "access denied",
            "login required", "wsse:security"
        ])
        www_auth = r.headers.get("WWW-Authenticate")

        if not has_auth and not www_auth and r.status_code not in (401, 403):
            findings.append("No authentication mechanism detected on endpoint")

        # Test sensitive methods without auth
        server = self.helpers.get_xmlrpc_proxy()
        sensitive_methods = [m for m in self.helpers.discovered_methods
                            if any(p in m.lower() for p in
                                   ["admin", "delete", "config", "user", "create"])]

        for method in sensitive_methods:
            try:
                result = getattr(server, method)()
                if result is not None:
                    findings.append(f"Sensitive method '{method}' callable without authentication")
                    break
            except xmlrpc.client.Fault:
                pass
            except TypeError:
                # Method requires params — still callable without auth
                findings.append(f"Sensitive method '{method}' reachable without authentication")
                break
            except Exception:
                pass

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
