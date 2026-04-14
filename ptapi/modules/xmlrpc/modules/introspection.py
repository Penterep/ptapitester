"""
XML-RPC Introspection test

Tests whether introspection is enabled (system.listMethods,
system.methodSignature, system.methodHelp) and extracts API schema.
"""
import xmlrpc.client
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Introspection test"


class Introspection:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        try:
            server = self.helpers.get_xmlrpc_proxy()
            self.helpers.discovered_methods = server.system.listMethods()

            for method in self.helpers.discovered_methods:
                method_info = {"signature": "N/A", "help": "N/A"}
                try:
                    method_info["signature"] = server.system.methodSignature(method)
                except Exception:
                    pass
                try:
                    method_info["help"] = server.system.methodHelp(method)
                except Exception:
                    pass
                self.helpers.metadata[method] = method_info

            if self.helpers.discovered_methods:
                ptprint(f"Introspection enabled — extracted {len(self.helpers.discovered_methods)} method(s).",
                        "VULN", not self.args.json, indent=4, colortext=True)
                for method in self.helpers.discovered_methods:
                    ptprint(f"  Method: {method}", "PARSED",
                            not self.args.json, indent=4)

                # Report as vulnerability
                evidence = f"Exposed {len(self.helpers.discovered_methods)} methods: "
                evidence += ", ".join(self.helpers.discovered_methods[:15])
                if len(self.helpers.discovered_methods) > 15:
                    evidence += f"... (+{len(self.helpers.discovered_methods) - 15} more)"
                self.ptjsonlib.add_vulnerability(
                    "PTV-RPC-INTROSPECTION-ENABLED",
                    node_key=self.helpers.node_key,
                    data={"evidence": evidence})

                # Update node properties with API schema
                self.ptjsonlib.add_properties(
                    properties={"apiSchema": self.helpers.metadata},
                    node_key=self.helpers.node_key
                )
            else:
                ptprint("Introspection returned no methods.", "INFO",
                        not self.args.json, indent=4)

        except xmlrpc.client.Fault as e:
            ptprint(f"Introspection rejected (Fault: {e.faultString}).",
                    "OK", not self.args.json, indent=4)
        except Exception as e:
            ptprint(f"Introspection failed: {type(e).__name__}",
                    "INFO", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    Introspection(args, ptjsonlib, helpers, http_client, common_tests).run()
