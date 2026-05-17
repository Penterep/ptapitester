"""
SOAP Authentication assessment test
"""
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Authentication assessment"

AUTH_FAULT_TOKENS = [
    "failedauthentication", "invalidsecurity", "securitytokenunavailable",
    "messageexpired", "mustunderstand", "accessdenied", "unauthorized",
    "authenticationfailed", "invalidcredentials", "notauthorized",
    "authentication required", "policy", "wsse:invalidsecuritytoken",
    "wsse:failedauthentication", "wsse:invalidsecurity",
    "security token", "wsp:policy",
]

WS_SECURITY_MARKERS = [
    "wsse:security", "wsse:usernametoken", "wsse:binarysecuritytoken",
    "wsse:password", "wsu:timestamp",
    "ws-security", "wssecurity",
    "wsp:policy", "wsp:policyreference", "wsp:exactlyone", "wsp:all",
    "sp:transportbinding", "sp:asymmetricbinding", "sp:symmetricbinding",
    "sp:signedparts", "sp:encryptedparts", "sp:usernametoken",
    "saml", "samlp", "saml:assertion",
    "http://schemas.xmlsoap.org/ws/2002/12/secext",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss",
    "http://www.w3.org/ns/ws-policy",
    "http://schemas.xmlsoap.org/ws/2004/09/policy",
]

SOAP_FAULT_RE = re.compile(
    r"<(?:\w+:)?fault\b[^>]*>(.*?)</(?:\w+:)?fault>",
    re.DOTALL | re.IGNORECASE,
)
FAULTCODE_RE = re.compile(
    r"<(?:\w+:)?faultcode\b[^>]*>(.*?)</(?:\w+:)?faultcode>",
    re.DOTALL | re.IGNORECASE,
)
FAULTSTRING_RE = re.compile(
    r"<(?:\w+:)?faultstring\b[^>]*>(.*?)</(?:\w+:)?faultstring>",
    re.DOTALL | re.IGNORECASE,
)


class AuthenticationTest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _default_value(self, param_type):
        if param_type == 'string':
            return 'test'
        if param_type in ('int', 'integer', 'long', 'short'):
            return '1'
        if param_type in ('decimal', 'float', 'double'):
            return '1.0'
        if param_type == 'boolean':
            return 'true'
        return 'test'

    def _build_request(self, op):
        """Build a valid SOAP envelope for an operation."""
        tns = getattr(self.helpers, 'target_namespace', '') or 'http://tempuri.org/'
        input_element = op.get('input_element', op.get('name', ''))
        params = op.get('input_params', [])

        params_xml = ''
        for p in params:
            p_name = p.get('name', '')
            p_type = p.get('type', 'string')
            if not p_name:
                continue
            val = self._default_value(p_type)
            params_xml += f'<tns:{p_name}>{val}</tns:{p_name}>'

        return (
            f'<?xml version="1.0"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{tns}">'
            f'<soap:Body><tns:{input_element}>{params_xml}'
            f'</tns:{input_element}></soap:Body></soap:Envelope>'
        )

    def _generic_request(self):
        return (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>auth_assessment</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

    def _extract_soap_fault(self, body_text):
        if not body_text:
            return None, None
        m = SOAP_FAULT_RE.search(body_text)
        if not m:
            return None, None
        fault_body = m.group(1)
        code_m = FAULTCODE_RE.search(fault_body)
        string_m = FAULTSTRING_RE.search(fault_body)
        code = (code_m.group(1).strip() if code_m else "")
        msg = (string_m.group(1).strip() if string_m else "")
        return code, msg

    def _fault_is_auth_related(self, faultcode, faultstring):
        combined = f"{faultcode} {faultstring}".lower()
        for tok in AUTH_FAULT_TOKENS:
            if tok in combined:
                return tok
        return None

    def _detect_ws_security_markers(self, text):
        if not text:
            return []
        low = text.lower()
        found = []
        for marker in WS_SECURITY_MARKERS:
            if marker.lower() in low:
                found.append(marker)
        return found

    def _http_auth_challenge(self, response):
        if response is None:
            return None
        val = response.headers.get("WWW-Authenticate", "").strip()
        return val if val else None

    def _classify_response(self, response):
        signals = []
        if response is None:
            return "uncertain", ["no response from server"]

        if response.status_code in (401, 403, 407):
            signals.append(
                f"HTTP {response.status_code} response (transport-level "
                f"authentication enforcement)")
            challenge = self._http_auth_challenge(response)
            if challenge:
                signals.append(f"WWW-Authenticate: {challenge}")
            return "auth_enforced", signals

        challenge = self._http_auth_challenge(response)
        if challenge:
            signals.append(f"WWW-Authenticate header: {challenge}")
            return "auth_enforced", signals

        code, msg = self._extract_soap_fault(response.text or "")
        if code or msg:
            auth_tok = self._fault_is_auth_related(code, msg)
            if auth_tok:
                signals.append(
                    f"SOAP Fault indicates authentication enforcement "
                    f"(faultcode={code!r}, faultstring~={msg[:80]!r}, "
                    f"matched token: {auth_tok!r})")
                return "auth_enforced", signals
            signals.append(
                f"SOAP Fault returned but does not appear auth-related "
                f"(faultcode={code!r}, faultstring~={msg[:80]!r})")
            return "uncertain", signals

        if 200 <= response.status_code < 300:
            signals.append(
                f"HTTP {response.status_code} response with no SOAP Fault "
                f"and no authentication challenge")
            return "public_or_anonymous", signals

        if 300 <= response.status_code < 400:
            signals.append(
                f"HTTP {response.status_code} redirect — possible "
                f"gateway/proxy-handled authentication")
            return "uncertain", signals
        signals.append(f"HTTP {response.status_code} response — unclear")
        return "uncertain", signals

    def _fetch_wsdl_text(self):
        """Try to obtain the raw WSDL text so we can scan it for
        WS-Security / WS-Policy markers. Returns string or None.

        Uses helpers.send_soap_request to a typical ?wsdl URL or the
        base URL — implementations vary, so this is best-effort."""
        candidates = []
        endpoint = getattr(self.helpers, 'endpoint_url', '') or ''
        base = getattr(self.helpers, 'base_url', '') or endpoint
        for c in (endpoint + "?wsdl", base + "?wsdl", base, endpoint):
            if c and c not in candidates:
                candidates.append(c)

        for url in candidates:
            try:
                r = self.http_client.send_request(
                    url=url, method="GET",
                    headers={"Accept": "text/xml,application/xml,*/*"},
                    merge_headers=False, allow_redirects=True,
                )
                if r is not None and r.status_code == 200 and r.text:
                    low = r.text.lower()
                    if "wsdl:definitions" in low or "<definitions" in low \
                            or "wsdl/" in low:
                        return r.text
            except Exception:
                continue
        return None

    def run(self):
        operations = getattr(self.helpers, 'parsed_operations', []) or []
        valid_ops = [op for op in operations if op.get('name')]

        wsdl_text = self._fetch_wsdl_text()
        wsdl_ws_markers = self._detect_ws_security_markers(wsdl_text or "")

        per_op_results = []
        response_ws_markers_union = set()

        if valid_ops:
            for op in valid_ops:
                op_name = op['name']
                r = self.helpers.send_soap_request(data=self._build_request(op))
                if r is None:
                    per_op_results.append((op_name, "uncertain",
                                            ["no response from server"]))
                    continue
                markers = self._detect_ws_security_markers(r.text or "")
                response_ws_markers_union.update(markers)
                classification, signals = self._classify_response(r)
                if markers:
                    signals.append(
                        f"WS-Security markers observed in response: "
                        f"{', '.join(markers[:5])}")
                per_op_results.append((op_name, classification, signals))
        else:
            r = self.helpers.send_soap_request(data=self._generic_request())
            if r is None:
                ptprint("Could not complete authentication assessment "
                        "(no response from server).", "INFO",
                        not self.args.json, indent=4)
                return
            markers = self._detect_ws_security_markers(r.text or "")
            response_ws_markers_union.update(markers)
            classification, signals = self._classify_response(r)
            if markers:
                signals.append(
                    f"WS-Security markers observed in response: "
                    f"{', '.join(markers[:5])}")
            per_op_results.append(("", classification, signals))

        public_ops = [op for op, cls, _ in per_op_results
                      if cls == "public_or_anonymous"]
        enforced_ops = [op for op, cls, _ in per_op_results
                        if cls == "auth_enforced"]
        uncertain_ops = [op for op, cls, _ in per_op_results
                         if cls == "uncertain"]

        has_ws_security_markers = bool(wsdl_ws_markers or response_ws_markers_union)

        findings = []
        info_notes = []

        summary_parts = []
        if public_ops:
            summary_parts.append(f"{len(public_ops)} public ({', '.join(public_ops)})")
        if enforced_ops:
            summary_parts.append(f"{len(enforced_ops)} enforced ({', '.join(enforced_ops)})")
        if uncertain_ops:
            summary_parts.append(f"{len(uncertain_ops)} uncertain ({', '.join(uncertain_ops)})")

        if summary_parts:
            ptprint(
                f"  Tested {len(per_op_results)} operation(s): "
                f"{'; '.join(summary_parts)}.",
                "INFO",
                not self.args.json,
                indent=4,
            )

        if wsdl_ws_markers:
            info_notes.append(
                f"WS-Security / WS-Policy markers found in WSDL: "
                f"{', '.join(wsdl_ws_markers[:5])}"
                + ("..." if len(wsdl_ws_markers) > 5 else ""))
        if response_ws_markers_union and not wsdl_ws_markers:
            info_notes.append(
                f"WS-Security markers observed in responses: "
                f"{', '.join(list(response_ws_markers_union)[:5])}")

        if enforced_ops and public_ops:
            findings.append(
                f"Inconsistent auth enforcement: {len(public_ops)} public op(s) "
                f"vs {len(enforced_ops)} enforced. "
                f"Verify if public operations are intentionally anonymous."
            )

        elif public_ops and not enforced_ops and not has_ws_security_markers:
            findings.append(
                f"No authentication enforcement observed across "
                f"{len(public_ops)} operation(s). No WWW-Authenticate, no 401/403, "
                f"no auth-related SOAP Faults, no WS-Security/WS-Policy markers."
            )

        elif public_ops and not enforced_ops and has_ws_security_markers:
            info_notes.append(
                "Operations responded without auth challenge, but WS-Security "
                "markers present — auth may be enforced at message level."
            )

        elif enforced_ops and not public_ops:
            info_notes.append(
                f"All probed operations responded with authentication "
                f"enforcement signals.")

        if findings:
            ptprint("Authentication assessment: potential authentication "
                    "enforcement issue.", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
            if info_notes and not (wsdl_ws_markers or response_ws_markers_union):
                for n in info_notes:
                    ptprint(f"  (info) {n}", "INFO",
                            not self.args.json, indent=4)

            evidence = (
                f"Authentication assessment on SOAP endpoint "
                f"{getattr(self.helpers, 'endpoint_url', '')}. "
                + " || ".join(findings)
            )
            if info_notes:
                evidence += " Additional observations: " + " ".join(info_notes)

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-AUTHENTICATION",
                node_key=self.helpers.node_key,
                data={"evidence": evidence})
            return

        if info_notes:
            ptprint("Authentication assessment completed (informational).",
                    "OK", not self.args.json, indent=4)
            for n in info_notes:
                ptprint(f"  {n}", "INFO", not self.args.json, indent=4)
        else:
            ptprint("Authentication assessment completed (no findings).",
                    "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    AuthenticationTest(args, ptjsonlib, helpers, http_client, common_tests).run()