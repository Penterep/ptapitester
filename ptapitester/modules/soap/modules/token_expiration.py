"""
SOAP Token Expiration and Session Security test

Tests whether the server properly manages authentication tokens:
- Checks for secure cookie flags (Secure, HttpOnly, SameSite)
- Checks for token expiration headers
- Checks if JWT tokens have proper expiration
- Checks if session cookies expire properly
"""
import re
import time
import base64
import json
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Token Expiration test"


class TokenExpiration:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _decode_jwt(self, token):
        """Decode JWT payload without verification."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            # Pad base64
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return None

    def run(self):
        soap_request = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>token_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        r = self.helpers.send_soap_request(data=soap_request)
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

                # Check Secure flag
                if "secure" not in cookie_lower:
                    findings.append(f"Cookie missing Secure flag: {cookie[:60]}...")

                # Check HttpOnly flag
                if "httponly" not in cookie_lower:
                    findings.append(f"Cookie missing HttpOnly flag: {cookie[:60]}...")

                # Check SameSite
                if "samesite" not in cookie_lower:
                    findings.append(f"Cookie missing SameSite attribute: {cookie[:60]}...")

                # Check Expires / Max-Age
                has_expiry = "expires=" in cookie_lower or "max-age=" in cookie_lower
                if not has_expiry:
                    findings.append(f"Session cookie without expiration (session-only): {cookie[:60]}...")

                # Check for overly long Max-Age
                max_age_match = re.search(r'max-age=(\d+)', cookie_lower)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age > 86400 * 30:  # More than 30 days
                        findings.append(f"Cookie with excessive Max-Age ({max_age}s = "
                                        f"{max_age // 86400} days): {cookie[:60]}...")

        # Check for JWT in response body or headers
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        jwt_locations = [
            ("response body", r.text),
            ("Authorization header", r.headers.get("Authorization", "")),
            ("X-Auth-Token header", r.headers.get("X-Auth-Token", "")),
        ]

        for location, content in jwt_locations:
            jwt_match = re.search(jwt_pattern, content)
            if jwt_match:
                token = jwt_match.group(0)
                payload = self._decode_jwt(token)
                if payload:
                    ptprint(f"  JWT token found in {location}", "INFO",
                            not self.args.json, indent=4)

                    # Check expiration
                    if 'exp' not in payload:
                        findings.append(f"JWT token in {location} has no expiration (exp) claim")
                    else:
                        exp = payload['exp']
                        now = time.time()
                        if exp < now:
                            findings.append(f"JWT token in {location} is already expired")
                        elif exp - now > 86400 * 7:
                            days = int((exp - now) / 86400)
                            findings.append(f"JWT token in {location} expires in {days} days (excessive)")

                    # Check for sensitive data in payload
                    sensitive_keys = ['password', 'secret', 'key', 'credit_card', 'ssn']
                    for key in sensitive_keys:
                        if key in str(payload).lower():
                            findings.append(f"JWT token contains potentially sensitive data: '{key}'")

        # Check cache headers — tokens should not be cached
        cache_control = r.headers.get("Cache-Control", "").lower()
        pragma = r.headers.get("Pragma", "").lower()

        if set_cookies or any(re.search(jwt_pattern, loc[1]) for loc in jwt_locations):
            if "no-store" not in cache_control and "no-cache" not in cache_control:
                findings.append("Response with tokens/cookies does not set Cache-Control: no-store")

        # No tokens found at all
        if not set_cookies and not any(re.search(jwt_pattern, loc[1]) for loc in jwt_locations):
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
