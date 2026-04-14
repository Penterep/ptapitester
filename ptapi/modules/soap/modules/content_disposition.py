"""
SOAP Content-Disposition header test

Checks whether SOAP responses contain a properly configured
Content-Disposition header to prevent MIME-based attacks.
"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP Content-Disposition header test"


class ContentDisposition:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        soap_request = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>disposition_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        r = self.helpers.send_soap_request(data=soap_request)
        if r is None:
            ptprint("Could not complete Content-Disposition test.", "INFO",
                    not self.args.json, indent=4)
            return

        cd = r.headers.get("Content-Disposition")
        if cd:
            ptprint(f"Content-Disposition header present: {cd}", "OK",
                    not self.args.json, indent=4)
        else:
            ptprint("Content-Disposition header is missing.", "VULN",
                    not self.args.json, indent=4, colortext=True)
            self.ptjsonlib.add_vulnerability(
                "PTV-GEN-MISSING-CONTENT-DISPOSITION", node_key=self.helpers.node_key,
                data={"evidence": "Response does not include Content-Disposition header. "
                                  "This may allow MIME-type sniffing or content injection."})


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ContentDisposition(args, ptjsonlib, helpers, http_client, common_tests).run()
