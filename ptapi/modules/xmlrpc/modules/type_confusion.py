"""XML-RPC Type Confusion test — sends unexpected parameter types"""
import xmlrpc.client
import requests
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Type Confusion test"

class TypeConfusion:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        methods_to_test = [m for m in self.helpers.discovered_methods
                           if not m.startswith("system.") and m != "ping"]
        if not methods_to_test:
            ptprint("No suitable methods for type confusion. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        error_indicators = ["traceback", "exception", "typeerror", "valueerror",
                           "attributeerror", "has no attribute", "unexpected type",
                           "invalid literal", "object is not", "object has no",
                           "not supported", "unsupported operand", "cannot",
                           "takes exactly", "argument", "positional"]

        server = self.helpers.get_xmlrpc_proxy()

        # Test via xmlrpc.client — sends properly typed XML-RPC values
        type_tests = [
            ("boolean True", [True]),
            ("boolean False", [False]),
            ("integer", [99999]),
            ("list", [[1, 2, 3]]),
            ("dict/struct", [{"x": 1}]),
            ("double", [99.99]),
        ]

        for method in methods_to_test:
            for type_name, args_list in type_tests:
                try:
                    result = getattr(server, method)(*args_list)
                    # If method accepts the wrong type without error, that's also interesting
                    # but not a vulnerability — we only flag verbose errors
                except xmlrpc.client.Fault as e:
                    fault_lower = e.faultString.lower()
                    matched = [ind for ind in error_indicators if ind in fault_lower]
                    if matched:
                        snippet = e.faultString[:200].strip().replace('\n', ' ')
                        ptprint(f"Type confusion error: {method} with {type_name}!", "VULN",
                                not self.args.json, indent=4, colortext=True)
                        self.ptjsonlib.add_vulnerability(
                            "PTV-GEN-TYPE-CONFUSION-VERBOSE", node_key=self.helpers.node_key,
                            data={"evidence": f"Method: {method}, Type: {type_name}. "
                                              f"Fault: {snippet}"})
                        return
                except Exception:
                    pass

        ptprint("Server handled type confusion securely.", "OK",
                not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    TypeConfusion(args, ptjsonlib, helpers, http_client, common_tests).run()