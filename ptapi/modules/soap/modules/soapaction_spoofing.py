"""
SOAP SOAPAction Spoofing test

Tests whether the server validates SOAPAction header against
the actual operation in the XML body.
"""
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP SOAPAction Spoofing test"


class SOAPActionSpoofing:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def run(self):
        normal_soap = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        r_normal = self.helpers.send_soap_request(
            data=normal_soap,
            headers={"Content-Type": "text/xml", "SOAPAction": '"urn:test:echo"'})

        r_spoofed = self.helpers.send_soap_request(
            data=normal_soap,
            headers={"Content-Type": "text/xml", "SOAPAction": '"urn:SPOOFED:nonexistent"'})

        if r_normal is None or r_spoofed is None:
            ptprint("Could not complete SOAPAction test.", "INFO",
                    not self.args.json, indent=4)
            return

        if r_normal.status_code == r_spoofed.status_code:
            ptprint("SOAPAction Spoofing possible (header ignored)!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-ACTION-SPOOFING", node_key=self.helpers.node_key,
                data={"evidence": f"Normal status: {r_normal.status_code}, "
                                  f"Spoofed status: {r_spoofed.status_code}. "
                                  f"Server does not validate SOAPAction header."})
        else:
            ptprint("SOAPAction is properly validated.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    SOAPActionSpoofing(args, ptjsonlib, helpers, http_client, common_tests).run()
