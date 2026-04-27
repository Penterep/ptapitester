"""
XML-RPC Server-side Validation test

Tests whether the server validates string parameters by sending oversized
values. Works without system.methodSignature by probing each method
with different argument counts until one succeeds, then replaces a string
argument with oversized value.
"""
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Server-side Validation test"

OVERSIZED_STRING = "A" * 10000


class ServerSideValidation:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _find_valid_arg_count(self, server, method_name):
        """Try 0-4 string arguments. Return first count that doesn't fail
        with a parameter-count error."""
        for count in range(0, 5):
            try:
                args = ['test'] * count
                getattr(server, method_name)(*args)
                return count
            except xmlrpc.client.Fault as e:
                msg = e.faultString.lower()
                if any(k in msg for k in ['argument', 'param', 'takes', 'required',
                                           'missing', 'positional', 'not found']):
                    continue
                return count
            except Exception:
                continue
        return None

    def run(self):
        if not self.helpers.discovered_methods:
            ptprint("No discovered methods. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        server = self.helpers.get_xmlrpc_proxy()
        findings = []

        methods = [m for m in self.helpers.discovered_methods
                   if not m.startswith('system.')][:5]

        for method_name in methods:
            arg_count = self._find_valid_arg_count(server, method_name)
            if arg_count is None or arg_count == 0:
                continue

            args = [OVERSIZED_STRING] + ['test'] * (arg_count - 1)

            try:
                getattr(server, method_name)(*args)
                findings.append(f"Method '{method_name}': accepted 10000-char string "
                                f"as first argument without error")
            except xmlrpc.client.Fault:
                pass
            except Exception:
                pass

        if findings:
            ptprint("Server-side validation issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-RPC-WEAK-VALIDATION", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server validates oversized input.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ServerSideValidation(args, ptjsonlib, helpers, http_client, common_tests).run()