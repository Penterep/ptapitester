"""XML-RPC Content-Type header test"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "XML-RPC Content-Type validation test"


class ContentTypeValidation:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        probe = '<?xml version="1.0"?><methodCall><methodName>ping</methodName></methodCall>'
        r = self.helpers.send_xmlrpc_raw(data=probe)
        if r is None:
            ptprint("Could not complete Content-Type test.", "INFO",
                    not self.args.json, indent=4)
            return

        ct = r.headers.get("Content-Type", "")
        issues = []

        if not ct:
            issues.append("Content-Type header is missing entirely")
        else:
            ct_lower = ct.lower()

            valid_types = ["text/xml", "application/xml"]
            if not any(vt in ct_lower for vt in valid_types):
                issues.append(f"Unexpected Content-Type: {ct}. Expected text/xml")

            if "charset" not in ct_lower:
                issues.append("Content-Type does not specify charset. "
                              "Should include charset=utf-8 to prevent encoding attacks")

        if issues:
            evidence = "; ".join(issues) + f". Actual header: '{ct}'"
            ptprint("Content-Type issues found.", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for issue in issues:
                ptprint(f"  {issue}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-CONTENT-TYPE-MISCONFIGURED", node_key=self.helpers.node_key,
                data={"evidence": evidence})
        else:
            ptprint(f"Content-Type is properly configured: {ct}", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ContentTypeValidation(args, ptjsonlib, helpers, http_client, common_tests).run()
