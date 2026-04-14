"""XML-RPC Information Disclosure test — verbose errors, path leak, tech disclosure"""
import re
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Information Disclosure test"

class InformationDisclosure:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        test_inputs = [
            ("Invalid XML", "<invalid_xml/>"),
            ("Malformed method call", '<?xml version="1.0"?><methodCall><BROKEN'),
            ("Non-existent method", '<?xml version="1.0"?><methodCall><methodName>nonexistent.method.12345</methodName></methodCall>'),
        ]

        verbose_patterns = ["traceback", "exception", "stack trace", "error at line",
                           "parse error", "lxml", "xmlsyntaxerror"]
        path_patterns = [r'/[a-z_/]+\.py\b', r'/var/www/', r'/home/\w+/', r'/app/', r'/opt/']
        tech_headers = ["server", "x-powered-by", "x-aspnet-version"]

        found_tech = False
        found_verbose = False
        found_path = False

        for trigger_name, trigger_data in test_inputs:
            r = self.helpers.send_xmlrpc_raw(data=trigger_data)
            if r is None:
                continue
            body_lower = r.text.lower()

            # Tech Disclosure — report only once
            if not found_tech:
                for header_name in tech_headers:
                    value = r.headers.get(header_name)
                    if value:
                        ptprint("Information disclosure: PTV-RPC-TECH-DISCLOSURE", "VULN",
                                not self.args.json, indent=4, colortext=True)
                        self.ptjsonlib.add_vulnerability(
                            "PTV-RPC-TECH-DISCLOSURE", node_key=self.helpers.node_key,
                            data={"evidence": f"Header '{header_name}: {value}'"})
                        found_tech = True
                        break

            # Verbose Errors — report only once
            if not found_verbose:
                matched = [p for p in verbose_patterns if p in body_lower]
                if matched:
                    snippet = r.text[:200].strip().replace('\n', ' ')
                    ptprint("Information disclosure: PTV-RPC-VERBOSE-ERRORS", "VULN",
                            not self.args.json, indent=4, colortext=True)
                    self.ptjsonlib.add_vulnerability(
                        "PTV-RPC-VERBOSE-ERRORS", node_key=self.helpers.node_key,
                        data={"evidence": f"Trigger: {trigger_name}. Patterns: {matched}. Snippet: {snippet}"})
                    found_verbose = True

            # Path Leak — report only once
            if not found_path:
                for pattern in path_patterns:
                    match = re.search(pattern, r.text, re.IGNORECASE)
                    if match:
                        ptprint("Information disclosure: PTV-GEN-PATH-LEAK", "VULN",
                                not self.args.json, indent=4, colortext=True)
                        self.ptjsonlib.add_vulnerability(
                            "PTV-GEN-PATH-LEAK", node_key=self.helpers.node_key,
                            data={"evidence": f"Trigger: {trigger_name}. Path: {match.group(0)}"})
                        found_path = True
                        break

            # Early exit if all found
            if found_tech and found_verbose and found_path:
                return

        if not found_tech and not found_verbose and not found_path:
            ptprint("No information disclosure detected.", "OK", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    InformationDisclosure(args, ptjsonlib, helpers, http_client, common_tests).run()
