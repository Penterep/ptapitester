"""
XML-RPC Operation timeout test

Tests whether XML-RPC methods take excessively long to respond.
"""
import time
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Operation timeout test"


class OperationTimeout:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        methods_to_test = [m for m in self.helpers.discovered_methods
                           if not m.startswith("system.")]
        if not methods_to_test:
            ptprint("No methods to test. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        slow_threshold = 5.0
        findings = []
        server = self.helpers.get_xmlrpc_proxy()

        for method in methods_to_test:
            start = time.time()
            try:
                getattr(server, method)()
            except Exception:
                pass
            elapsed = time.time() - start

            if elapsed >= slow_threshold:
                findings.append(f"Method '{method}' slow response: {elapsed:.1f}s")

            ptprint(f"  {method}: {elapsed:.2f}s", "INFO",
                    not self.args.json, indent=4)

        # Large payload test
        large_data = "A" * 100000
        probe = (f'<?xml version="1.0"?><methodCall><methodName>ping</methodName>'
                 f'<params><param><value><string>{large_data}</string></value></param></params>'
                 f'</methodCall>')
        start = time.time()
        r = self.helpers.send_xmlrpc_raw(data=probe)
        elapsed_large = time.time() - start

        if elapsed_large >= slow_threshold:
            findings.append(f"Large payload (100KB) caused slow response: {elapsed_large:.1f}s")

        ptprint(f"  Large payload (100KB): {elapsed_large:.2f}s", "INFO",
                not self.args.json, indent=4)

        if findings:
            ptprint("Potential DoS vulnerability — slow operations!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-SLOW-OPERATION", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("All methods respond within acceptable time.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    OperationTimeout(args, ptjsonlib, helpers, http_client, common_tests).run()
