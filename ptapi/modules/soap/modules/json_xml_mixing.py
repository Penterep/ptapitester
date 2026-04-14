"""
SOAP JSON/XML mixing test

Tests whether the server accepts JSON instead of XML.
"""
import json
import requests
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP JSON/XML mixing test"


class JSONXMLMixing:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        # Normal SOAP XML baseline
        soap_xml = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>json_mixing_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        r_xml = self.helpers.send_soap_request(data=soap_xml)
        if r_xml is None:
            ptprint("Could not complete JSON/XML mixing test.", "INFO",
                    not self.args.json, indent=4)
            return

        # Send JSON with application/json Content-Type using direct requests
        json_payloads = [
            {"message": "json_mixing_test"},
            {"method": "echo", "params": {"message": "json_mixing_test"}},
            {"method": "echo", "message": "json_mixing_test"},
            {"Envelope": {"Body": {"message": "json_mixing_test"}}},
        ]

        for payload in json_payloads:
            try:
                r_json = requests.post(
                    self.helpers.endpoint_url,
                    data=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                    timeout=getattr(self.args, 'timeout', 10),
                    verify=False
                )
            except Exception:
                continue

            if r_json is None:
                continue

            body_lower = r_json.text.lower()

            # Check for meaningful processing (not just generic XML parse error)
            xml_error_indicators = ["xml parse error", "start tag expected",
                                     "xmlsyntaxerror", "not well-formed"]
            is_xml_error = any(ind in body_lower for ind in xml_error_indicators)

            if not is_xml_error and r_json.status_code in (200, 404, 500):
                # Server processed the JSON — check if response differs from XML error
                if ("json_mixing_test" in body_lower or
                    "user not found" in body_lower or
                    "unknown operation" in body_lower or
                    r_json.status_code == 200):

                    ptprint("JSON/XML mixing possible — server processes JSON requests!", "VULN",
                            not self.args.json, indent=4, colortext=True)
                    snippet = r_json.text[:150].strip().replace('\n', ' ')
                    self.ptjsonlib.add_vulnerability(
                        "PTV-SOAP-JSON-XML-MIXING", node_key=self.helpers.node_key,
                        data={"evidence": f"Server accepted JSON with Content-Type: application/json. "
                                          f"Response (HTTP {r_json.status_code}): {snippet}"})
                    return

        ptprint("Server does not accept JSON instead of XML.", "OK",
                not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    JSONXMLMixing(args, ptjsonlib, helpers, http_client, common_tests).run()
