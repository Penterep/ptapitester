"""
SOAP Content-Type header test

Checks whether SOAP responses contain a properly configured
Content-Type header with correct MIME type and charset.
"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP Content-Type validation test"


class ContentTypeValidation:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        soap_request = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>content_type_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        r = self.helpers.send_soap_request(data=soap_request)
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

            # SOAP should return text/xml or application/soap+xml
            valid_types = ["text/xml", "application/soap+xml", "application/xml"]
            has_valid_type = any(vt in ct_lower for vt in valid_types)
            if not has_valid_type:
                issues.append(f"Unexpected Content-Type: {ct}. "
                              f"Expected text/xml or application/soap+xml")

            # Check charset
            if "charset" not in ct_lower:
                issues.append("Content-Type does not specify charset. "
                              "Should include charset=utf-8 to prevent encoding attacks")

        if issues:
            evidence = "; ".join(issues) + f". Actual header: '{ct}'"
            ptprint(f"Content-Type issues found.", "VULN",
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
