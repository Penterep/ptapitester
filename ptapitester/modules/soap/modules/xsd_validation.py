"""
SOAP XSD Schema Validation test

Tests whether the server validates incoming requests against XSD schema
before processing. Sends three types of invalid requests and checks if
the server rejects them or processes them without validation:
1. Wrong data type (string where int is expected)
2. Extra unknown element
3. Missing required parameter
"""
import requests
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP XSD Schema Validation test"


class XSDValidation:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _send_raw(self, data):
        try:
            return requests.post(
                self.helpers.endpoint_url,
                data=data.encode('utf-8'),
                headers={"Content-Type": "text/xml; charset=utf-8"},
                timeout=getattr(self.args, 'timeout', 10),
                verify=False
            )
        except Exception:
            return None

    def _is_soap_fault(self, response):
        body_lower = response.text.lower()
        return ("soap:fault" in body_lower or "soapenv:fault" in body_lower or
                "faultcode" in body_lower or "faultstring" in body_lower)

    def _is_schema_error(self, response):
        body_lower = response.text.lower()
        schema_indicators = ["schema", "validation", "invalid", "xsd",
                             "unexpected element", "not allowed"]
        return any(ind in body_lower for ind in schema_indicators)

    def _is_rejection(self, response):
        """Check if server rejected the request (fault, schema error, or 500)."""
        return (response.status_code == 500 or
                self._is_soap_fault(response) or
                self._is_schema_error(response))

    def run(self):
        operations = self.helpers.parsed_operations
        if not operations:
            ptprint("No parsed operations available. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        tns = getattr(self.helpers, 'target_namespace', '') or 'http://tempuri.org/'
        findings = []

        for op in operations:
            op_name = op.get('name', '')
            input_element = op.get('input_element', op_name)
            params = op.get('input_params', [])

            if not params:
                continue

            # Test 1: Wrong data type — string where int is expected
            int_params = [p for p in params if p['type'] in
                          ('int', 'integer', 'long', 'short', 'decimal', 'float', 'double')]
            if int_params:
                param = int_params[0]
                wrong_type_soap = (
                    f'<?xml version="1.0"?>'
                    f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
                    f' xmlns:tns="{tns}">'
                    f'<soap:Body><tns:{input_element}>'
                    f'<tns:{param["name"]}>NOT_A_NUMBER_XSD_TEST</tns:{param["name"]}>'
                    f'</tns:{input_element}></soap:Body></soap:Envelope>'
                )
                r = self._send_raw(wrong_type_soap)
                if r is not None and not self._is_rejection(r):
                    findings.append(f"Operation '{op_name}': accepted string for "
                                    f"{param['type']} parameter '{param['name']}' (HTTP {r.status_code})")

            # Test 2: Extra unknown element
            extra_soap = (
                f'<?xml version="1.0"?>'
                f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
                f' xmlns:tns="{tns}">'
                f'<soap:Body><tns:{input_element}>'
            )
            for p in params:
                default = 'test_value' if p['type'] == 'string' else '1'
                extra_soap += f'<tns:{p["name"]}>{default}</tns:{p["name"]}>'
            extra_soap += (
                f'<tns:__xsd_test_unknown_element>injected</tns:__xsd_test_unknown_element>'
                f'</tns:{input_element}></soap:Body></soap:Envelope>'
            )

            r = self._send_raw(extra_soap)
            if r is not None and not self._is_rejection(r):
                findings.append(f"Operation '{op_name}': accepted unknown element "
                                f"(HTTP {r.status_code})")

            # Test 3: Missing required parameter
            missing_soap = (
                f'<?xml version="1.0"?>'
                f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
                f' xmlns:tns="{tns}">'
                f'<soap:Body><tns:{input_element}>'
                f'</tns:{input_element}></soap:Body></soap:Envelope>'
            )

            r = self._send_raw(missing_soap)
            if r is not None and not self._is_rejection(r):
                findings.append(f"Operation '{op_name}': accepted missing required "
                                f"parameter (HTTP {r.status_code})")

            # Test only first operation with parameters
            break

        if findings:
            ptprint("XSD validation issues found!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-NO-XSD-VALIDATION", node_key=self.helpers.node_key,
                data={"evidence": "; ".join(findings)})
        else:
            ptprint("Server appears to validate requests against XSD schema.", "OK",
                    not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XSDValidation(args, ptjsonlib, helpers, http_client, common_tests).run()