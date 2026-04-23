"""XML-RPC system.multicall amplification test"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Multicall Amplification test"

class MulticallAmplification:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        if "system.multicall" not in self.helpers.discovered_methods:
            ptprint("system.multicall not available.", "OK",
                    not self.args.json, indent=4)
            return

        calls = [{"methodName": "ping", "params": []} for _ in range(21)]
        multicall_payload = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
        for c in calls:
            multicall_payload += (f'<value><struct>'
                                 f'<member><name>methodName</name><value><string>{c["methodName"]}</string></value></member>'
                                 f'<member><name>params</name><value><array><data></data></array></value></member>'
                                 f'</struct></value>')
        multicall_payload += '</data></array></value></param></params></methodCall>'

        r = self.helpers.send_xmlrpc_raw(data=multicall_payload)
        if r is not None and "<array>" in r.text.lower():
            count = r.text.lower().count("<value>")
            if count >= 10:
                ptprint(f"system.multicall amplification possible ({count} responses)!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-RPC-MULTICALL-ABUSE", node_key=self.helpers.node_key,
                    data={"evidence": f"system.multicall executed {len(calls)} calls in single request."})
                return

        ptprint("system.multicall not exploitable.", "OK", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    MulticallAmplification(args, ptjsonlib, helpers, http_client, common_tests).run()
