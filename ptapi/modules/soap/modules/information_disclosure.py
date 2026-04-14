"""
SOAP Information Disclosure test

Tests for verbose error messages, internal path leaks,
and technology disclosure via HTTP headers.
"""
import re
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Information Disclosure test"


class InformationDisclosure:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        test_inputs = [
            ("Invalid XML", "<not_valid_xml!!!"),
            ("Malformed SOAP", '<?xml version="1.0"?><soapenv:Envelope><BROKEN'),
            ("Non-existent operation",
             '<?xml version="1.0"?>'
             '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
             '<soapenv:Body><nonexistentOperation>test</nonexistentOperation></soapenv:Body>'
             '</soapenv:Envelope>'),
        ]

        verbose_patterns = [
            "traceback", "exception", "stack trace", "error at line",
            "parse error", "syntax error", "lxml", "xmlsyntaxerror",
            "system.web.services", "javax.xml", "soapfault",
        ]

        path_patterns = [
            r'/[a-z_/]+\.py\b', r'/var/www/', r'/home/\w+/',
            r'/app/', r'/opt/', r'/srv/', r'/usr/',
            r'[A-Z]:\\\\', r'[A-Z]:\\[Uu]ser',
        ]

        tech_headers = ["server", "x-powered-by", "x-aspnet-version",
                        "x-generator", "x-runtime"]

        for trigger_name, trigger_data in test_inputs:
            r = self.helpers.send_soap_request(data=trigger_data)
            if r is None:
                continue

            body_lower = r.text.lower()

            # Verbose Errors
            matched = [p for p in verbose_patterns if p in body_lower]
            if matched:
                snippet = r.text[:200].strip().replace('\n', ' ')
                ptprint(f"Information disclosure: PTV-SOAP-VERBOSE-ERRORS", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-SOAP-VERBOSE-ERRORS", node_key=self.helpers.node_key,
                    data={"evidence": f"Trigger: {trigger_name}. Patterns: {matched}. "
                                      f"Snippet: {snippet}"})
                break

        # Path Leak
        for trigger_name, trigger_data in test_inputs:
            r = self.helpers.send_soap_request(data=trigger_data)
            if r is None:
                continue

            for pattern in path_patterns:
                match = re.search(pattern, r.text, re.IGNORECASE)
                if match:
                    ptprint(f"Information disclosure: PTV-GEN-PATH-LEAK", "VULN",
                            not self.args.json, indent=4, colortext=True)
                    self.ptjsonlib.add_vulnerability(
                        "PTV-GEN-PATH-LEAK", node_key=self.helpers.node_key,
                        data={"evidence": f"Internal path leaked: {match.group(0)}"})
                    break
            else:
                continue
            break

        # Tech Disclosure via headers
        r = self.helpers.send_soap_request(
            data='<?xml version="1.0"?>'
                 '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                 '<soapenv:Body><message>tech_check</message></soapenv:Body>'
                 '</soapenv:Envelope>')
        if r:
            for header_name in tech_headers:
                value = r.headers.get(header_name)
                if value:
                    ptprint(f"Information disclosure: PTV-SOAP-TECH-DISCLOSURE", "VULN",
                            not self.args.json, indent=4, colortext=True)
                    self.ptjsonlib.add_vulnerability(
                        "PTV-SOAP-TECH-DISCLOSURE", node_key=self.helpers.node_key,
                        data={"evidence": f"Header '{header_name}: {value}'"})
                    break


def run(args, ptjsonlib, helpers, http_client, common_tests):
    InformationDisclosure(args, ptjsonlib, helpers, http_client, common_tests).run()
