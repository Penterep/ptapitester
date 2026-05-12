"""
SOAP JSON/XML mixing test
"""
import json
import requests
from ptlibs.ptprinthelper import ptprint
__TESTLABEL__ = "SOAP JSON/XML mixing test"

XML_ERROR_INDICATORS = [
    "xml parse error", "not well-formed", "xml syntax error",
    "xmlsyntaxerror", "premature end", "unclosed token",
    "start tag expected", "invalid xml",
]

SOAP_FAULT_INDICATORS = [
    "soap:fault", "soapenv:fault", "<fault>", "faultcode", "faultstring",
]

SOAP_RESPONSE_INDICATORS = [
    "<soap:envelope", "<soapenv:envelope", "<env:envelope",
    ":envelope xmlns",
]

JSON_PARSER_ERROR_INDICATORS = [
    "json parse error", "json.decoder", "jsondecodeerror",
    "invalid json", "malformed json", "unexpected token",
    "expecting value", "expecting property name",
]


class JSONXMLMixing:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.helpers.print_header(__TESTLABEL__)

    def _has_indicators(self, text, indicators):
        if not text:
            return False
        text_lower = text.lower()
        return any(ind in text_lower for ind in indicators)

    def _send_json(self, raw_body):
        """Send a raw body with Content-Type: application/json."""
        try:
            return requests.post(
                self.helpers.endpoint_url,
                data=raw_body.encode('utf-8') if isinstance(raw_body, str)
                     else raw_body,
                headers={"Content-Type": "application/json"},
                timeout=getattr(self.args, 'timeout', 10),
                verify=False
            )
        except Exception:
            return None

    def _build_payloads(self):
        
        payloads = []

        operations = getattr(self.helpers, 'parsed_operations', []) or []
        for op in operations:
            op_name = op.get('name', '')
            if not op_name:
                continue
            params = {}
            marker = f"jxm_{op_name}_marker"
            for p in op.get('input_params', []):
                p_name = p.get('name', '')
                p_type = p.get('type', 'string')
                if not p_name:
                    continue
                if p_type == 'string':
                    params[p_name] = marker
                elif p_type in ('int', 'integer', 'long', 'short'):
                    params[p_name] = 7 
                elif p_type in ('decimal', 'float', 'double'):
                    params[p_name] = 7.5
                elif p_type == 'boolean':
                    params[p_name] = True
                else:
                    params[p_name] = marker

            payloads.append(({"method": op_name, "params": params}, marker))
            payloads.append(({"method": op_name, **params}, marker))

        payloads.extend([
            ({"message": "jxm_generic_marker"}, "jxm_generic_marker"),
            ({"method": "echo", "message": "jxm_generic_marker"},
             "jxm_generic_marker"),
            ({"Envelope": {"Body": {"message": "jxm_generic_marker"}}},
             "jxm_generic_marker"),
        ])
        return payloads

    def _check_negative_signals(self, response):
        """Return True if the response shows a NEGATIVE signal — server
        did not accept JSON."""
        if response.status_code in (406, 415):
            return True
        if self._has_indicators(response.text, XML_ERROR_INDICATORS):
            return True
        if self._has_indicators(response.text, SOAP_FAULT_INDICATORS):
            return True
        return False

    def _check_positive_signals(self, response, marker):
        """
        Evaluate positive signals on a JSON response. Returns a list of
        trigger descriptions (empty if no strong signal found).
        """
        triggers = []
        body_lower = (response.text or "").lower()
        ct = response.headers.get("Content-Type", "").lower()

        if self._has_indicators(response.text, SOAP_RESPONSE_INDICATORS):
            triggers.append("server responded with SOAP envelope to JSON request "
                            "(JSON triggered SOAP-level processing)")

        if "json" in ct:
            triggers.append(f"server returned Content-Type: {ct}")

        if marker and marker.lower() in body_lower:
            triggers.append(f"response contains marker '{marker}' from JSON "
                            f"payload (server processed JSON-supplied data)")

        return triggers

    def _probe_malformed_json(self):
        """
        Send malformed JSON and check whether the response contains a
        JSON parser error (proves a JSON parser ran on the body).
        """
        malformed_probes = [
            '{"method": "echo", "params": {',     # truncated
            '{"method": "echo" "missing_comma"}',  # syntax error
            '{key_without_quotes: "value"}',       # invalid key
        ]
        for body in malformed_probes:
            r = self._send_json(body)
            if r is None:
                continue
            if self._has_indicators(r.text, JSON_PARSER_ERROR_INDICATORS):
                snippet = r.text[:150].strip().replace('\n', ' ')
                return (
                    f"malformed JSON triggered a JSON parser error "
                    f"(HTTP {r.status_code}, response: {snippet})",
                    body, r,
                )
        return None

    def run(self):
        soap_xml = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>baseline</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )
        r_xml = self.helpers.send_soap_request(data=soap_xml)
        if r_xml is None:
            ptprint("Could not complete JSON/XML mixing test (no XML baseline).",
                    "INFO", not self.args.json, indent=4)
            return
        json_payloads = self._build_payloads()

        for payload, marker in json_payloads:
            r_json = self._send_json(json.dumps(payload))
            if r_json is None:
                continue

            if self._check_negative_signals(r_json):
                continue

            triggers = self._check_positive_signals(r_json, marker)
            if not triggers:
                continue

            payload_preview = json.dumps(payload)[:80]
            snippet = r_json.text[:150].strip().replace('\n', ' ')
            ct = r_json.headers.get("Content-Type", "(missing)")

            evidence = (
                f"Server accepted JSON body with Content-Type: "
                f"application/json on a SOAP endpoint. "
                f"Triggers: {' | '.join(triggers)}. "
                f"Sent payload: {payload_preview}. "
                f"Response (HTTP {r_json.status_code}, "
                f"Content-Type: {ct}): {snippet}. "
                f"SOAP only supports XML; accepting JSON broadens the "
                f"attack surface with a second parser."
            )

            ptprint("JSON/XML mixing possible — server processes JSON "
                    "requests!", "VULN",
                    not self.args.json, indent=4, colortext=True)
            for t in triggers:
                ptprint(f"  Trigger: {t}", "VULN",
                        not self.args.json, indent=4)
            ptprint(f"  Payload sent: {payload_preview}", "VULN",
                    not self.args.json, indent=4)
            ptprint(f"  Response snippet: {snippet}", "VULN",
                    not self.args.json, indent=4)

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-JSON-XML-MIXING",
                node_key=self.helpers.node_key,
                data={"evidence": evidence})
            return
        
        probe_result = self._probe_malformed_json()
        if probe_result is not None:
            trigger_desc, sent_body, response = probe_result
            evidence = (
                f"JSON parser execution detected on a SOAP endpoint. "
                f"Trigger: {trigger_desc}. "
                f"Sent (malformed) body: {sent_body[:80]}. "
                f"This indicates the server runs a JSON parser on incoming "
                f"requests with Content-Type: application/json, even though "
                f"SOAP only supports XML."
            )

            ptprint("JSON/XML mixing possible — server runs JSON parser!",
                    "VULN", not self.args.json, indent=4, colortext=True)
            ptprint(f"  Trigger: {trigger_desc}", "VULN",
                    not self.args.json, indent=4)
            ptprint(f"  Malformed payload: {sent_body[:80]}", "VULN",
                    not self.args.json, indent=4)

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-JSON-XML-MIXING",
                node_key=self.helpers.node_key,
                data={"evidence": evidence})
            return

        ptprint("Server does not accept JSON instead of XML.", "OK",
                not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    JSONXMLMixing(args, ptjsonlib, helpers, http_client, common_tests).run()