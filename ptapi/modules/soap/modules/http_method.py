"""
SOAP HTTP method test

Tests whether SOAP endpoint accepts GET instead of POST.
SOAP standard requires POST — accepting GET may expose to CSRF.
"""
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP HTTP method test"


class HTTPMethodTest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        soap_indicators = ["envelope", "fault", "soap:", "soapenv:", "wsdl:",
                           "faultcode", "faultstring"]

        # Test 1: Plain GET to the endpoint
        r_plain = self.helpers.send_get_request(self.helpers.endpoint_url)
        if r_plain and r_plain.status_code != 405:
            plain_lower = r_plain.text.lower()
            if any(ind in plain_lower for ind in soap_indicators):
                ptprint("Server accepts GET requests (returns SOAP response)!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-SOAP-GET-ALLOWED", node_key=self.helpers.node_key,
                    data={"evidence": f"Plain GET to {self.helpers.endpoint_url} returned "
                                      f"SOAP content (HTTP {r_plain.status_code}). "
                                      f"SOAP should only accept POST."})
                return

        # Test 2: GET with xml query parameter
        from urllib.parse import quote
        soap_body = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>get_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )
        get_url = self.helpers.endpoint_url + "?xml=" + quote(soap_body)
        r_get = self.helpers.send_get_request(get_url)

        if r_get and r_get.status_code != 405:
            get_lower = r_get.text.lower()
            if any(ind in get_lower for ind in soap_indicators) or "get_test" in get_lower:
                ptprint("Server processes SOAP via GET with query parameter!", "VULN",
                        not self.args.json, indent=4, colortext=True)
                self.ptjsonlib.add_vulnerability(
                    "PTV-SOAP-GET-ALLOWED", node_key=self.helpers.node_key,
                    data={"evidence": f"GET with ?xml= to {self.helpers.endpoint_url} returned "
                                      f"SOAP response (HTTP {r_get.status_code})."})
                return

        if (r_plain and r_plain.status_code == 405) or (r_get and r_get.status_code == 405):
            ptprint("Server correctly rejects GET requests (405 Method Not Allowed).", "OK",
                    not self.args.json, indent=4)
        else:
            ptprint("Server does not process SOAP via GET.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    HTTPMethodTest(args, ptjsonlib, helpers, http_client, common_tests).run()
