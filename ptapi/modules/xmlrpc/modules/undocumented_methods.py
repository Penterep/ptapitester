"""XML-RPC Undocumented Methods discovery via dictionary attack"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Undocumented Methods discovery"

class UndocumentedMethods:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        wordlist = self.helpers.load_wordlist("xmlrpc_methods.txt")
        if not wordlist:
            ptprint("No methods wordlist found. Skipping.", "INFO", not self.args.json, indent=4)
            return

        known = set(self.helpers.discovered_methods)

        # Baseline
        baseline_payload = '<?xml version="1.0"?><methodCall><methodName>nonexistent.method.839274</methodName></methodCall>'
        try:
            baseline_r = self.helpers.send_xmlrpc_raw(data=baseline_payload)
            if baseline_r is None:
                return
            baseline_status = baseline_r.status_code
            baseline_body = baseline_r.text.lower()
            baseline_len = len(baseline_r.text)
            baseline_has_fault = "faultstring" in baseline_body
        except Exception:
            return

        found_methods = []
        for method_name in wordlist:
            if not method_name or method_name in known:
                continue

            payload = f'<?xml version="1.0"?><methodCall><methodName>{method_name}</methodName></methodCall>'
            r = self.helpers.send_xmlrpc_raw(data=payload)
            if r is None:
                continue

            body_lower = r.text.lower()
            is_different = False

            if baseline_has_fault and "faultstring" not in body_lower:
                is_different = True
            if baseline_has_fault and "faultstring" in body_lower and abs(len(r.text) - baseline_len) > 100:
                is_different = True
            if "<params>" in body_lower and "<value>" in body_lower:
                is_different = True
            if r.status_code != baseline_status:
                is_different = True

            if is_different:
                found_methods.append(method_name)
                ptprint(f"  Undocumented method found: {method_name} (HTTP {r.status_code})",
                        "VULN", not self.args.json, indent=4, colortext=True)

        if found_methods:
            self.helpers.undocumented_methods = found_methods
            self.ptjsonlib.add_vulnerability(
                "PTV-RPC-UNDOCUMENTED-METHODS", node_key=self.helpers.node_key,
                data={"evidence": f"Dictionary attack found {len(found_methods)} undocumented method(s): {', '.join(found_methods)}"})
        else:
            ptprint("No undocumented methods found.", "OK", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    UndocumentedMethods(args, ptjsonlib, helpers, http_client, common_tests).run()
