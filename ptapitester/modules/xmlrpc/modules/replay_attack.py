"""
XML-RPC Replay Attack test

Tests whether the server accepts identical XML-RPC requests multiple times
without any replay protection mechanism.

Sends the same request 3 times and checks if:
- All 3 succeed with identical responses (no replay protection)
- Response/request headers contain any anti-replay mechanism
"""
import hashlib
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Replay Attack test"


class ReplayAttack:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        # Pick a safe method to replay — prefer 'ping' or non-system method
        method = 'ping'
        if self.helpers.discovered_methods:
            # Prefer simple/safe methods for replay test
            for candidate in ['ping', 'system.listMethods']:
                if candidate in self.helpers.discovered_methods:
                    method = candidate
                    break
            else:
                # Pick first non-destructive method
                for m in self.helpers.discovered_methods:
                    if not any(d in m.lower() for d in
                               ['delete', 'remove', 'create', 'new', 'add']):
                        method = m
                        break

        probe = (f'<?xml version="1.0"?>'
                 f'<methodCall><methodName>{method}</methodName></methodCall>')

        findings = []
        responses = []

        # Send exact same request 3 times
        for i in range(3):
            r = self.helpers.send_xmlrpc_raw(data=probe)
            if r is None:
                ptprint("Could not complete replay test (request failed).", "INFO",
                        not self.args.json, indent=4)
                return
            responses.append(r)

        # Check 1: All 3 succeed with identical responses?
        status_codes = [r.status_code for r in responses]
        body_hashes = [hashlib.md5(r.text.encode()).hexdigest() for r in responses]

        all_succeeded = all(r.status_code == 200 for r in responses)
        identical_bodies = len(set(body_hashes)) == 1

        if all_succeeded and identical_bodies:
            # Check if response body contains any anti-replay indicator
            body_lower = responses[-1].text.lower()
            has_nonce = any(ind in body_lower for ind in [
                "nonce", "messageid", "timestamp", "sequence"
            ])

            if not has_nonce:
                findings.append(f"Server accepted 3 identical '{method}' requests with "
                                f"identical responses (status: {status_codes}). "
                                f"No replay protection detected.")

        # Check 2: Anti-replay HTTP headers in responses?
        headers = responses[0].headers
        protection_headers = [
            "X-Request-ID", "X-Correlation-ID", "X-Nonce",
            "X-CSRF-Token", "X-Anti-Replay"
        ]
        has_protection_header = any(h in headers for h in protection_headers)

        if not has_protection_header and all_succeeded:
            findings.append("No anti-replay HTTP headers (X-Request-ID, X-Nonce, "
                            "X-CSRF-Token) detected in responses.")

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
