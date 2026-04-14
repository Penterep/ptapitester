"""
SOAP DoS / Operation timeout test

Tests whether SOAP operations take excessively long to respond,
which could indicate DoS vulnerability or resource exhaustion.
"""
import time
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP Operation timeout test"


class OperationTimeout:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        operations = list(self.helpers.known_operations)
        if not operations:
            operations = ["echo"]

        slow_threshold = 5.0  # seconds
        findings = []

        for operation in operations:
            soap_request = (
                f'<?xml version="1.0"?>'
                f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                f'<soap:Body><{operation}><message>timeout_test</message></{operation}></soap:Body>'
                f'</soap:Envelope>'
            )

            # Measure response time
            start = time.time()
            r = self.helpers.send_soap_request(data=soap_request)
            elapsed = time.time() - start

            if r is None:
                if elapsed >= slow_threshold:
                    findings.append(f"Operation '{operation}' caused timeout ({elapsed:.1f}s)")
                continue

            if elapsed >= slow_threshold:
                findings.append(f"Operation '{operation}' slow response: {elapsed:.1f}s "
                                f"(HTTP {r.status_code})")

            ptprint(f"  {operation}: {elapsed:.2f}s (HTTP {r.status_code})", "INFO",
                    not self.args.json, indent=4)

        # Also test with large payload
        large_message = "A" * 100000
        large_soap = (
            f'<?xml version="1.0"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><echo><message>{large_message}</message></echo></soap:Body>'
            f'</soap:Envelope>'
        )

        start = time.time()
        r_large = self.helpers.send_soap_request(data=large_soap)
        elapsed_large = time.time() - start

        if elapsed_large >= slow_threshold:
            findings.append(f"Large payload (100KB) caused slow response: {elapsed_large:.1f}s")

        ptprint(f"  Large payload (100KB): {elapsed_large:.2f}s", "INFO",
                not self.args.json, indent=4)

        if findings:
            ptprint("Potential DoS vulnerability — slow operations detected!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-SLOW-OPERATION", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("All operations respond within acceptable time.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    OperationTimeout(args, ptjsonlib, helpers, http_client, common_tests).run()
