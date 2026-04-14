"""XML-RPC SSRF via pingback.ping test"""
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC SSRF Pingback test"

class SSRFPingback:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        if "pingback.ping" not in self.helpers.discovered_methods:
            ptprint("pingback.ping not available. Skipping.", "OK",
                    not self.args.json, indent=4)
            return

        ptprint("pingback.ping detected — testing SSRF...", "INFO",
                not self.args.json, indent=4)

        # Use ServerProxy for proper XML-RPC communication
        server = self.helpers.get_xmlrpc_proxy()

        ssrf_indicators = [
            "pingback", "registered", "http", "source responded",
            "connect", "refused", "connection", "timeout", "error",
        ]

        try:
            result = server.pingback.ping("http://127.0.0.1:22", "http://example.com")
            result_str = str(result).lower()

            # Server successfully made the connection attempt
            if any(ind in result_str for ind in ssrf_indicators):
                ptprint("SSRF via pingback.ping — server attempted internal connection!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-RPC-SSRF-PINGBACK", node_key=self.helpers.node_key,
                    data={"evidence": f"pingback.ping to http://127.0.0.1:22 triggered connection attempt. "
                                      f"Server can be used as SSRF proxy."})
                return

        except xmlrpc.client.Fault as e:
            fault_lower = str(e.faultString).lower()
            # Fault with connection-related message = server tried to connect
            if any(ind in fault_lower for ind in ["connect", "refused", "timeout",
                                                   "error", "could not", "errno"]):
                ptprint("SSRF via pingback.ping — server attempted internal connection!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-RPC-SSRF-PINGBACK", node_key=self.helpers.node_key,
                    data={"evidence": f"pingback.ping to http://127.0.0.1:22 triggered connection attempt. "
                                      f"Fault: {e.faultString[:200]}"})
                return

        except Exception as e:
            # Any network-related exception = server tried to connect
            error_str = str(e).lower()
            if any(ind in error_str for ind in ["connect", "timeout", "refused"]):
                ptprint("SSRF via pingback.ping — server attempted internal connection!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-RPC-SSRF-PINGBACK", node_key=self.helpers.node_key,
                    data={"evidence": f"pingback.ping to http://127.0.0.1:22 caused error: {str(e)[:200]}"})
                return

        ptprint("No SSRF indicators detected.", "OK", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    SSRFPingback(args, ptjsonlib, helpers, http_client, common_tests).run()
