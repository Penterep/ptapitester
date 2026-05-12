"""
SOAP HTTP method test

"""
from urllib.parse import quote
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP HTTP method test"


SOAP_INDICATORS = [
    "envelope", "fault", "soap:", "soapenv:", "wsdl:",
    "faultcode", "faultstring", "<wsdl",
]

PARSER_PROOF_INDICATORS = [

    "soap:fault", "soapenv:fault", "<fault>", "faultcode", "faultstring",

    "xml parse error", "not well-formed", "xml syntax error",
    "xmlsyntaxerror", "premature end", "unclosed token",

    "namespace", "undeclared prefix", "doctype", "external entity",
  
    "soap processing", "operation not found", "unknown operation",
    "schema validation", "xsd validation",
]


class HTTPMethodTest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _looks_like_soap(self, text):
        if not text:
            return False
        text_lower = text.lower()
        return any(ind in text_lower for ind in SOAP_INDICATORS)

    def _looks_like_parser_processing(self, text):
        """
        Return True if the response shows evidence that an XML parser
        processed the payload (SOAP Fault, parse error, namespace error...).
        Mere reflection of the parameter is NOT proof of parsing.
        """
        if not text:
            return False
        text_lower = text.lower()
        return any(ind in text_lower for ind in PARSER_PROOF_INDICATORS)

    def _test_plain_get(self):
        """
        Send a plain GET to the endpoint. If the endpoint returns SOAP/WSDL,
        report this as INFO — exposing WSDL via GET is legitimate, and SOAP 1.2
        permits a GET binding for safe operations.
        """
        r = self.helpers.send_get_request(self.helpers.endpoint_url)
        if r is None:
            return False

        if r.status_code == 405:
            return False

        if self._looks_like_soap(r.text):
            ptprint("Endpoint responds to plain GET with SOAP/WSDL content "
                    "(informational, not a vulnerability).", "INFO",
                    not self.args.json, indent=4)
            return True

        return False

    def _test_xml_in_query(self):
        probes = [
            ('<?xml version="1.0"?>'
             '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
             '<soapenv:Body><message>baseline</message></soapenv:Body>'
             '</soapenv:Envelope>'),

            ('<?xml version="1.0"?>'
             '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
             '<soapenv:Body><message>malformed_unclosed'
             '</soapenv:Envelope>'),

            ('<?xml version="1.0"?>'
             '<undeclared:Envelope>'
             '<undeclared:Body><message>ns_test</message></undeclared:Body>'
             '</undeclared:Envelope>'),

            ('<?xml version="1.0"?>'
             '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
             '<soapenv:Body><123invalid>bad</123invalid></soapenv:Body>'
             '</soapenv:Envelope>'),
        ]

        for idx, payload in enumerate(probes, 1):
            url = self.helpers.endpoint_url + "?xml=" + quote(payload)
            r = self.helpers.send_get_request(url)

            if r is None or r.status_code == 405:
                continue

            if self._looks_like_parser_processing(r.text):
                snippet = r.text[:200].strip().replace('\n', ' ')
                evidence = (
                    f"Severity: LOW. "
                    f"GET request to {self.helpers.endpoint_url}?xml=<...> "
                    f"with probe #{idx} (parser-trigger payload) caused XML parser "
                    f"processing on the server side (HTTP {r.status_code}). "
                    f"Response excerpt: {snippet}. "
                    f"This means the SOAP endpoint accepts and parses XML "
                    f"envelopes from GET parameters, which broadens the CSRF "
                    f"attack surface — operations may be triggered by simply "
                    f"opening a URL or loading an HTML <img> element."
                )

                ptprint("XML parser processes GET ?xml= parameter "
                        "(LOW severity).", "VULN",
                        not self.args.json, indent=4, colortext=True)
                ptprint(f"  Probe #{idx} triggered parser; response snippet: "
                        f"{snippet[:80]}...", "VULN",
                        not self.args.json, indent=4)

                self.ptjsonlib.add_vulnerability(
                    "PTV-SOAP-GET-MISCONFIGURED",
                    node_key=self.helpers.node_key,
                    data={"evidence": evidence})
                return True

        return False

    def run(self):

        plain_get_exposes_soap = self._test_plain_get()

        xml_parsed = self._test_xml_in_query()

        if not plain_get_exposes_soap and not xml_parsed:
            ptprint("Endpoint correctly restricts SOAP processing to POST.",
                    "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    HTTPMethodTest(args, ptjsonlib, helpers, http_client, common_tests).run()