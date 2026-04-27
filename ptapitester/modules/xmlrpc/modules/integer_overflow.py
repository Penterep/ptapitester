"""
XML-RPC Integer Overflow test

Tests integer overflow by attempting to call methods with very large
integer values. Works without methodSignature by trying to find a
working argument count, then substituting int overflow values.
"""
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Integer Overflow test"

OVERFLOW_VALUES = [
    (2**31, "int32 overflow (2^31)"),
    (-(2**31 + 1), "int32 underflow"),
]


class IntegerOverflow:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _find_working_args(self, server, method_name):
        """Try integer arguments from 1-4 and return the first count that
        doesn't fail with a parameter count error."""
        for count in range(1, 5):
            try:
                args = [1] * count
                getattr(server, method_name)(*args)
                return count
            except xmlrpc.client.Fault as e:
                msg = e.faultString.lower()
                if any(k in msg for k in ['argument', 'param', 'takes', 'required',
                                           'missing', 'positional', 'not found']):
                    continue
                # Fault not about argument count — method was called
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
            arg_count = self._find_working_args(server, method_name)
            if arg_count is None:
                continue

            for overflow_val, label in OVERFLOW_VALUES:
                args = [overflow_val] + [1] * (arg_count - 1)
                try:
                    getattr(server, method_name)(*args)
                    findings.append(f"Method '{method_name}': accepted {label} "
                                    f"value {overflow_val} as first argument")
                    break
                except (xmlrpc.client.Fault, OverflowError):
                    pass
                except Exception:
                    pass

        if findings:
            ptprint("Integer overflow issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-RPC-INTEGER-OVERFLOW", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server rejects integer overflow values.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    IntegerOverflow(args, ptjsonlib, helpers, http_client, common_tests).run()