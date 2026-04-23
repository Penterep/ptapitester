"""
XML-RPC Token Expiration and Session Security test

Tests whether the server properly manages authentication tokens:
- Checks for secure cookie flags (Secure, HttpOnly, SameSite)
- Checks for token expiration
- Checks JWT tokens for proper expiration
"""
import re
import time
import base64
import json
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Token Expiration test"


class TokenExpiration:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _decode_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return None

    def run(self):
        probe = '<?xml version="1.0"?><methodCall><methodName>ping</methodName></methodCall>'
        r = self.helpers.send_xmlrpc_raw(data=probe)
        if r is None:
            ptprint("Could not complete token expiration test.", "INFO",
                    not self.args.json, indent=4)
            return

        findings = []

        # Check Set-Cookie headers
        set_cookies = r.headers.get("Set-Cookie", "")
        if set_cookies:
            cookies = set_cookies if isinstance(set_cookies, list) else [set_cookies]
            for cookie in cookies:
                cookie_lower = cookie.lower()
                if "secure" not in cookie_lower:
                    findings.append(f"Cookie missing Secure flag: {cookie[:60]}...")
                if "httponly" not in cookie_lower:
                    findings.append(f"Cookie missing HttpOnly flag: {cookie[:60]}...")
                if "samesite" not in cookie_lower:
                    findings.append(f"Cookie missing SameSite attribute: {cookie[:60]}...")
                if "expires=" not in cookie_lower and "max-age=" not in cookie_lower:
                    findings.append(f"Session cookie without expiration: {cookie[:60]}...")
                max_age_match = re.search(r'max-age=(\d+)', cookie_lower)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age > 86400 * 30:
                        findings.append(f"Cookie with excessive Max-Age ({max_age // 86400} days)")

        # Check for JWT
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        for location, content in [("response body", r.text),
                                   ("Authorization", r.headers.get("Authorization", ""))]:
            jwt_match = re.search(jwt_pattern, content)
            if jwt_match:
                payload = self._decode_jwt(jwt_match.group(0))
                if payload:
                    if 'exp' not in payload:
                        findings.append(f"JWT in {location} has no expiration claim")
                    else:
                        exp = payload['exp']
                        if exp - time.time() > 86400 * 7:
                            findings.append(f"JWT in {location} expires in {int((exp - time.time()) / 86400)} days (excessive)")

        # No tokens found
        if not set_cookies and not any(re.search(jwt_pattern, loc[1]) for loc in [("body", r.text)]):
            ptprint("No tokens or session cookies detected in response.", "INFO",
                    not self.args.json, indent=4)
            return

        if findings:
            ptprint("Token/session security issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-TOKEN-SECURITY", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Token/session security appears properly configured.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    TokenExpiration(args, ptjsonlib, helpers, http_client, common_tests).run()
