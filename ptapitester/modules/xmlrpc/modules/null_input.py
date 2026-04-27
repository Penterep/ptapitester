"""
XML-RPC Null/Empty Input test

Tests whether the server accepts empty string values for parameters.
Works without methodSignature by finding working argument count,
then replacing first argument with empty string.
"""
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Null/Empty Input test"


class NullInput:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _find_valid_arg_count(self, server, method_name):
        for count in range(1, 5):
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
            if arg_count is None:
                continue

            # Empty string as first argument
            args = [''] + ['test'] * (arg_count - 1)

            try:
                getattr(server, method_name)(*args)
                findings.append(f"Method '{method_name}': accepted empty string "
                                f"as first argument without error")
            except xmlrpc.client.Fault:
                pass
            except Exception:
                pass

        if findings:
            ptprint("Null/empty input issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-RPC-NULL-INPUT", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server rejects null/empty input.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    NullInput(args, ptjsonlib, helpers, http_client, common_tests).run()