"""
SOAP Replay Attack test

Tests whether the server accepts identical requests multiple times
without any replay protection mechanism (nonce, timestamp, message ID,
WS-Security Timestamp, etc.).

Sends the same request 3 times with identical headers and body,
and checks if:
- Server accepts all 3 with identical responses (no replay protection)
- Request contains any replay protection elements (WS-Security Timestamp,
  MessageID, Nonce, etc.)
"""
import re
import hashlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Replay Attack test"


class ReplayAttack:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        # Build a request - use a parsed operation if available, otherwise generic
        operations = self.helpers.parsed_operations
        tns = getattr(self.helpers, 'target_namespace', '') or 'urn:examples:helloservice'

        if operations:
            op = operations[0]
            input_element = op.get('input_element', op.get('name', 'echo'))
            params = op.get('input_params', [])

            body_content = f'<tns:{input_element}>'
            for p in params:
                default = 'replay_test' if p['type'] == 'string' else '1'
                body_content += f'<tns:{p["name"]}>{default}</tns:{p["name"]}>'
            body_content += f'</tns:{input_element}>'
        else:
            body_content = '<message>replay_test</message>'

        soap_request = (
            f'<?xml version="1.0"?>'
            f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{tns}">'
            f'<soapenv:Body>{body_content}</soapenv:Body>'
            f'</soapenv:Envelope>'
        )

        findings = []
        responses = []

        # Send the exact same request 3 times
        for i in range(3):
            r = self.helpers.send_soap_request(data=soap_request)
            if r is None:
                ptprint("Could not complete replay test (request failed).", "INFO",
                        not self.args.json, indent=4)
                return
            responses.append(r)

        # Check 1: Do all 3 requests succeed with identical responses?
        status_codes = [r.status_code for r in responses]
        body_hashes = [hashlib.md5(r.text.encode()).hexdigest() for r in responses]

        all_succeeded = all(r.status_code in (200, 404) for r in responses)
        identical_bodies = len(set(body_hashes)) == 1

        if all_succeeded and identical_bodies:
            # All 3 identical requests got identical responses
            # Check if server has any anti-replay mechanism in response
            last_body = responses[-1].text.lower()
            has_nonce = any(ind in last_body for ind in [
                "nonce", "wsu:timestamp", "wsse:usernametoken",
                "x-request-id", "messageid"
            ])

            if not has_nonce:
                findings.append(f"Server accepted 3 identical requests with identical responses "
                                f"(status codes: {status_codes}). No replay protection detected.")

        # Check 2: Are any replay protection HTTP headers present?
        headers = responses[0].headers
        protection_headers = [
            "X-Request-ID", "X-Correlation-ID", "X-Nonce",
            "X-CSRF-Token", "X-Anti-Replay"
        ]
        has_protection_header = any(h in headers for h in protection_headers)

        # Check 3: Does the request/response mention WS-Security or similar?
        ws_security_present = (
            "wsse:" in soap_request.lower() or
            "wsu:timestamp" in responses[0].text.lower() or
            "wsse:usernametoken" in responses[0].text.lower()
        )

        if not has_protection_header and not ws_security_present and all_succeeded:
            findings.append("No WS-Security Timestamp, MessageID, or anti-replay HTTP "
                            "headers detected in requests or responses.")

        if findings:
            ptprint("Replay attack possible — no replay protection!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-NO-REPLAY-PROTECTION", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server appears to implement some form of replay protection.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ReplayAttack(args, ptjsonlib, helpers, http_client, common_tests).run()
