"""
SOAP trusted proxy header authorization bypass test

"""

import html
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP trusted proxy header bypass test"


AUTH_DENIED_HTTP_STATUS = {401, 403, 407}

AUTH_DENIED_INDICATORS = [
    "access denied","accessdenied","unauthorized","unauthorised","forbidden","permission denied",
    "not authorized","not authorised","authentication required","auth required","login required",
    "invalid credentials","token required","missing token","jwt required",
]

SOAP_FAULT_INDICATORS = [
    "soap:fault","soapenv:fault","<fault>","faultcode","faultstring",
]

TRUSTED_IP_HEADER_TESTS = [
    ("X-Forwarded-For", "127.0.0.1"),("X-Forwarded-For", "::1"),("X-Forwarded-For", "localhost"),("X-Forwarded-For", "10.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1, 10.0.0.1"),("X-Real-IP", "127.0.0.1"),("X-Client-IP", "127.0.0.1"),("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),("X-Remote-Addr", "127.0.0.1"),("X-Original-Forwarded-For", "127.0.0.1"),("Forwarded", "for=127.0.0.1"),
    ("Forwarded", "for=\"127.0.0.1\""),
]


class XForwardedForBypass:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)


    def _has_any(self, text, indicators):
        if not text:
            return False
        low = text.lower()
        return any(ind in low for ind in indicators)

    def _is_soap_fault(self, response):
        if response is None:
            return False
        return self._has_any(response.text or "", SOAP_FAULT_INDICATORS)

    def _is_auth_denied(self, response):
        if response is None:
            return False
    
        if response.status_code in AUTH_DENIED_HTTP_STATUS:
            return True
    
        body = response.text or ""

        if 200 <= response.status_code < 300 and self._is_soap_fault(response):
        
            m = re.search(
                r"<(?:\w+:)?faultcode\b[^>]*>(.*?)</(?:\w+:)?faultcode>",
                body, re.DOTALL | re.IGNORECASE)
            if m:
                faultcode = m.group(1).lower()
                auth_fault_tokens = ["failedauthentication", "invalidsecurity",
                                    "unauthorized", "accessdenied", "auth"]
            if not any(tok in faultcode for tok in auth_fault_tokens):
                return False  # business fault — not auth denial
    
        if self._has_any(body, AUTH_DENIED_INDICATORS):
            return True
    
        return False

    def _extract_body_elements(self, response_text):
       
        if not response_text:
            return set()

        m = re.search(
            r"<(?:\w+:)?Body[^>]*>(.*?)</(?:\w+:)?Body>",
            response_text,
            re.DOTALL | re.IGNORECASE,
        )
        if not m:
            return set()

        body_content = m.group(1)
        names = set()

        for tag in re.findall(r"<(?:\w+:)?([A-Za-z_][\w\-.]*)", body_content):
            names.add(tag.lower())

        return names

    def _looks_like_operation_success(self, response, op_name):
        
        if response is None:
            return False

        if not (200 <= response.status_code < 300):
            return False

        if self._is_soap_fault(response):
            return False

        if self._is_auth_denied(response):
            return False

        body_elements = self._extract_body_elements(response.text or "")
        op_lower = (op_name or "").lower()

        expected_names = {
            op_lower,
            f"{op_lower}response",
            f"{op_lower}result",
            f"{op_lower}output",
        }

        if body_elements & expected_names:
            return True

        generic_success_elements = {
            "return",
            "result",
            "response",
            "success",
            "data",
            "value",
        }

        if body_elements & generic_success_elements:
            return True

        body = (response.text or "").lower()
        if "<envelope" in body or ":envelope" in body:
            return True

        return False

    def _default_value(self, param_type):
        if not param_type:
            return "test"

        t = param_type.lower()

        if t in ("string", "str", "xsd:string"):
            return "test"
        if t in ("int", "integer", "long", "short", "xsd:int", "xsd:integer"):
            return "1"
        if t in ("decimal", "float", "double", "xsd:decimal", "xsd:float", "xsd:double"):
            return "1.0"
        if t in ("boolean", "bool", "xsd:boolean"):
            return "true"

        return "test"

    def _build_request(self, op):
        """
        Build a valid SOAP body for a parsed WSDL operation.
        """
        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element", op.get("name", ""))
        params = op.get("input_params", []) or []

        params_xml = ""

        for p in params:
            p_name = p.get("name", "")
            p_type = p.get("type", "string")

            if not p_name:
                continue

            value = self._default_value(p_type)
            params_xml += f"<tns:{p_name}>{html.escape(str(value))}</tns:{p_name}>"

        return (
            '<?xml version="1.0"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{html.escape(tns)}">'
            f"<soap:Body><tns:{input_element}>{params_xml}</tns:{input_element}></soap:Body>"
            "</soap:Envelope>"
        )

    def _soap_action_for(self, op):
        action = op.get("soap_action") or op.get("soapAction") or ""
        if action:
            return f'"{action}"'
        return f'"urn:{op.get("name", "operation")}"'

    def _send(self, url, body, op, extra_headers=None):
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": self._soap_action_for(op),
        }

        if extra_headers:
            headers.update(extra_headers)

        try:
            return self.http_client.send_request(
                url=url,
                method="POST",
                data=body,
                headers=headers,
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _get_endpoints(self):
        endpoints = set()

        if getattr(self.helpers, "endpoint_url", None):
            endpoints.add(self.helpers.endpoint_url)

        for attr in ("discovered_endpoints", "endpoint_urls", "service_endpoints"):
            values = getattr(self.helpers, attr, None)
            if isinstance(values, (list, tuple, set)):
                for v in values:
                    if isinstance(v, str) and v.startswith(("http://", "https://")):
                        endpoints.add(v)

        return sorted(endpoints)


    def _test_operation_on_endpoint(self, endpoint, op):
        op_name = op.get("name", "")
        body = self._build_request(op)

        info_notes = []

        baseline = self._send(endpoint, body, op)

        if baseline is None:
            return None, [f"Could not obtain baseline response for operation '{op_name}' at {endpoint}."]

        baseline_denied = self._is_auth_denied(baseline)
        baseline_success = self._looks_like_operation_success(baseline, op_name)

        if baseline_success and not baseline_denied:
            return None, [
                f"Operation '{op_name}' at {endpoint} is already accessible without spoofed "
                f"IP headers; authorization bypass cannot be evaluated for this operation."
            ]

        if not baseline_denied:
            return None, [
                f"Operation '{op_name}' at {endpoint} did not produce a clear authorization "
                f"denial in the baseline response; skipping bypass decision to avoid false positives."
            ]

        for header_name, header_value in TRUSTED_IP_HEADER_TESTS:
            spoofed = self._send(
                endpoint,
                body,
                op,
                extra_headers={header_name: header_value},
            )

            if spoofed is None:
                continue

            spoofed_success = self._looks_like_operation_success(spoofed, op_name)
            spoofed_denied = self._is_auth_denied(spoofed)

            if spoofed_success and not spoofed_denied:
                finding = (
                    f"Possible trusted-proxy header authorization bypass detected. "
                    f"Endpoint '{endpoint}', operation '{op_name}' was denied without spoofed "
                    f"headers but appeared successful when sending "
                    f"{header_name}: {header_value}. "
                    f"Baseline HTTP {baseline.status_code}; spoofed HTTP {spoofed.status_code}. "
                    f"This suggests the backend may trust client-supplied IP forwarding headers."
                )
                return finding, info_notes

            if header_value in (spoofed.text or ""):
                info_notes.append(
                    f"{header_name}: {header_value} was reflected in the response for "
                    f"operation '{op_name}' at {endpoint}; this is informational only "
                    f"and not treated as authorization bypass."
                )

        return None, info_notes
    
    def _print_info_summary(self, info_notes):
        if not info_notes:
            return

        not_denied = 0
        already_accessible = 0
        auth_denied = 0
        other = 0

        for note in info_notes:
            low = note.lower()

            if "did not produce a clear authorization denial" in low:
                not_denied += 1
            elif "already accessible without spoofed ip headers" in low:
                already_accessible += 1
            elif "baseline classified as auth_denied" in low:
                auth_denied += 1
            else:
                other += 1

        if not_denied:
            ptprint(
                f"  (info) Skipped decisions: {not_denied} baseline response(s) "
                f"were not clear authorization denials.",
                "INFO",
                not self.args.json,
                indent=4,
            )

        if already_accessible:
            ptprint(
                f"  (info) Already accessible operations: {already_accessible}; "
                f"authorization bypass could not be evaluated for them.",
                "INFO",
                not self.args.json,
                indent=4,
            )

        if auth_denied:
            ptprint(
                f"  (info) Auth-denied baseline observations: {auth_denied}.",
                "INFO",
                not self.args.json,
                indent=4,
            )

        if other:
            ptprint(
                f"  (info) Other observations: {other}.",
                "INFO",
                not self.args.json,
                indent=4,
            )

    def run(self):
        endpoints = self._get_endpoints()

        if not endpoints:
            ptprint("No SOAP endpoints available. Skipping XFF bypass test.",
                    "INFO", not self.args.json, indent=4)
            return

        operations = getattr(self.helpers, "parsed_operations", []) or []
        valid_ops = [op for op in operations if op.get("name")]

        if not valid_ops:
            ptprint("No parsed WSDL operations available. Skipping XFF bypass test "
                    "to avoid testing invalid generic SOAP bodies.",
                    "INFO", not self.args.json, indent=4)
            return

        findings = []
        info_notes = []

        for endpoint in endpoints:
            if getattr(self.args, "verbose", False):
                ptprint(f"Testing endpoint: {endpoint}", "INFO",
                        not self.args.json, indent=4)

            for op in valid_ops:
                finding, notes = self._test_operation_on_endpoint(endpoint, op)

                if notes:
                    info_notes.extend(notes)

                if finding:
                    findings.append(finding)
                    break

        if findings:
            ptprint("Possible trusted-proxy header authorization bypass detected.",
                    "VULN", not self.args.json, indent=4, colortext=True)

            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)

            evidence = (
                "Possible trusted-proxy header authorization bypass detected on SOAP API. "
                "A baseline request was denied, while an otherwise identical request with "
                "a spoofed client-IP forwarding header appeared successful. "
                "Findings: "
                + " || ".join(findings)
            )

            if info_notes:
                evidence += " Additional observations: " + " ".join(info_notes[:10])

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-TRUSTED-PROXY-HEADER-BYPASS",
                node_key=self.helpers.node_key,
                data={"evidence": evidence},
            )
            return

        ptprint("No trusted-proxy header authorization bypass detected.",
                "OK", not self.args.json, indent=4)

        
def run(args, ptjsonlib, helpers, http_client, common_tests):
    XForwardedForBypass(args, ptjsonlib, helpers, http_client, common_tests).run()