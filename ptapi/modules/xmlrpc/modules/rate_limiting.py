"""XML-RPC Rate Limiting test"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Rate Limiting test"

class RateLimiting:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        probe = '<?xml version="1.0"?><methodCall><methodName>ping</methodName></methodCall>'
        codes = []
        for _ in range(25):
            r = self.helpers.send_xmlrpc_raw(data=probe)
            if r is None:
                continue
            codes.append(r.status_code)
            if r.status_code == 429:
                ptprint("Rate limiting is active (HTTP 429 received).", "OK",
                        not self.args.json, indent=4)
                return

        if codes:
            ptprint(f"No rate limiting after {len(codes)} requests.", "VULN",
                    not self.args.json, indent=4, colortext=True)
            self.ptjsonlib.add_vulnerability("PTV-GEN-NO-RATE-LIMIT", node_key=self.helpers.node_key,
                data={"evidence": f"Sent {len(codes)} requests. HTTP codes: {list(set(codes))}"})

def run(args, ptjsonlib, helpers, http_client, common_tests):
    RateLimiting(args, ptjsonlib, helpers, http_client, common_tests).run()
