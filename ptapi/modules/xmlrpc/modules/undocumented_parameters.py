"""XML-RPC Undocumented Parameters discovery via dictionary attack"""
import requests
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Undocumented Parameters discovery"

class UndocumentedParameters:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _send_raw(self, data):
        """Send raw XML directly for reliable struct handling."""
        try:
            return requests.post(
                self.helpers.endpoint_url,
                data=data.encode('utf-8'),
                headers={"Content-Type": "text/xml; charset=utf-8"},
                timeout=getattr(self.args, 'timeout', 10),
                verify=False
            )
        except Exception:
            return None

    def run(self):
        param_names = self.helpers.load_wordlist("xmlrpc_params.txt")
        if not param_names:
            ptprint("No params wordlist found. Skipping.", "INFO", not self.args.json, indent=4)
            return

        # Test both documented and undocumented methods
        methods_to_test = [m for m in self.helpers.discovered_methods if not m.startswith("system.")]
        if hasattr(self.helpers, 'undocumented_methods') and self.helpers.undocumented_methods:
            for m in self.helpers.undocumented_methods:
                if m not in methods_to_test and not m.startswith("system."):
                    methods_to_test.append(m)

        if not methods_to_test:
            ptprint("No methods to test. Skipping.", "INFO", not self.args.json, indent=4)
            return

        all_findings = []
        for method in methods_to_test:
            # Baseline 1: no params
            b1_payload = (f"<?xml version='1.0'?><methodCall><methodName>{method}</methodName>"
                         f"<params></params></methodCall>")

            # Baseline 2: struct with nonexistent param
            b2_payload = (f"<?xml version='1.0'?><methodCall><methodName>{method}</methodName>"
                         f"<params><param><value><struct>"
                         f"<member><name>nonexistentParam839274</name>"
                         f"<value><string>test</string></value></member>"
                         f"</struct></value></param></params></methodCall>")

            b1_r = self._send_raw(b1_payload)
            b2_r = self._send_raw(b2_payload)
            if b1_r is None or b2_r is None:
                continue

            tolerance = abs(len(b1_r.text) - len(b2_r.text)) + 30
            baseline_status = b2_r.status_code
            baseline_len = len(b2_r.text)

            found_params = []
            for param_name in param_names:
                test_payload = (f"<?xml version='1.0'?><methodCall><methodName>{method}</methodName>"
                               f"<params><param><value><struct>"
                               f"<member><name>{param_name}</name>"
                               f"<value><string>test</string></value></member>"
                               f"</struct></value></param></params></methodCall>")

                r = self._send_raw(test_payload)
                if r is None:
                    continue

                is_different = False
                if r.status_code != baseline_status:
                    is_different = True
                elif abs(len(r.text) - baseline_len) > tolerance:
                    is_different = True
                if "<params>" in r.text.lower() and "<params>" not in b2_r.text.lower():
                    is_different = True

                if is_different:
                    found_params.append(param_name)

            if found_params:
                ptprint(f"  {method}: undocumented params: {', '.join(found_params)}",
                        "VULN", not self.args.json, indent=4, colortext=True)
                all_findings.append({"method": method, "params": found_params})

        if all_findings:
            evidence_parts = [f"{f['method']}({', '.join(f['params'])})" for f in all_findings]
            self.ptjsonlib.add_vulnerability(
                "PTV-RPC-UNDOCUMENTED-PARAMS", node_key=self.helpers.node_key,
                data={"evidence": f"Undocumented parameters: {'; '.join(evidence_parts)}"})
        else:
            ptprint("No undocumented parameters found.", "OK", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    UndocumentedParameters(args, ptjsonlib, helpers, http_client, common_tests).run()
