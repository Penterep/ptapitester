"""
SOAP XML Bomb (Billion Laughs) test

Tests whether the server is vulnerable to entity expansion DoS attacks.
"""
import time
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP XML Bomb resistance test"


class XMLBomb:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        bomb_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz ['
            '<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
            ']>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>&lol3;</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        start = time.time()
        r = self.helpers.send_soap_request(data=bomb_payload)
        elapsed = time.time() - start

        if r is None:
            ptprint("XML Bomb test inconclusive (connection error).", "INFO",
                    not self.args.json, indent=4)
            return

        body_lower = r.text.lower()

        if "lollollol" in body_lower or body_lower.count("lol") >= 50:
            ptprint(f"XML Bomb processed — entity expanded (100x 'lol')!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            self.ptjsonlib.add_vulnerability(
                "PTV-XML-BOMB", node_key=self.helpers.node_key,
                data={"evidence": f"Server expanded nested entities (100x 'lol' in response). "
                                  f"Response time: {elapsed:.1f}s. Vulnerable to Billion Laughs DoS."})
        elif "entity" in body_lower and ("denied" in body_lower or "forbidden" in body_lower or "error" in body_lower):
            ptprint("Server correctly rejected entity expansion.", "OK",
                    not self.args.json, indent=4)
        else:
            ptprint("Server appears resistant to XML Bomb.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XMLBomb(args, ptjsonlib, helpers, http_client, common_tests).run()
