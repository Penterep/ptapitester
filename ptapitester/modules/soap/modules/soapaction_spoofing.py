"""
SOAP operation dispatch consistency test (formerly: SOAPAction Spoofing)

"""
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP SOAPAction spoofing / dispatch consistency test"

SOAP_FAULT_INDICATORS = [
    "soap:fault", "soapenv:fault", "<fault>", "faultcode", "faultstring",
]


class SOAPActionSpoofing:
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
        """Build a VALID SOAP envelope for the given operation, with
        type-appropriate default values for each parameter."""
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

    def _soap_action_for(self, op):
        """Return the SOAPAction string declared for this operation,
        falling back to a synthesised value if not present in the WSDL."""
        action = op.get('soap_action') or op.get('soapAction') or ''
        if action:
            return f'"{action}"'
        # Fallback: synthesise a plausible action value
        return f'"urn:{op.get("name", "operation")}"'

    def _send(self, body, headers):
        try:
            return self.http_client.send_request(
                url=self.helpers.endpoint_url, method="POST",
                data=body, headers=headers,
                merge_headers=False, allow_redirects=True
            )
        except Exception:
            return None

    def _extract_body_elements(self, response_text):
        """Extract element local-names that appear inside soap:Body.
        Returns a set of lowercased element names — used to figure out
        which operation the server actually executed."""
        if not response_text:
            return set()
        m = re.search(
            r"<(?:\w+:)?Body[^>]*>(.*?)</(?:\w+:)?Body>",
            response_text, re.DOTALL | re.IGNORECASE,
        )
        if not m:
            return set()
        body_content = m.group(1)
        names = set()
        for tag in re.findall(r"<(?:\w+:)?([A-Za-z_][\w\-]*)", body_content):
            names.add(tag.lower())
        return names

    def _has_fault(self, response_text):
        if not response_text:
            return False
        low = response_text.lower()
        return any(ind in low for ind in SOAP_FAULT_INDICATORS)

    def _looks_like_operation_output(self, op_name, body_elements):
        """Return True if body_elements suggest the response came from
        operation `op_name` (e.g. 'addResponse', 'getUserResponse', or
        'addResult')."""
        if not op_name:
            return False
        op_lower = op_name.lower()
        for el in body_elements:
            if op_lower in el:
                return True
        return False

    def run(self):
        operations = getattr(self.helpers, 'parsed_operations', []) or []
        valid_ops = [op for op in operations if op.get('name')]

        if len(valid_ops) < 2:
            ptprint("Fewer than 2 operations available in WSDL — cannot "
                    "perform cross-operation mismatch test. Skipping.",
                    "INFO", not self.args.json, indent=4)
            return

        op_a, op_b = valid_ops[0], valid_ops[1]
        body_a = self._build_request(op_a)
        action_a = self._soap_action_for(op_a)
        action_b = self._soap_action_for(op_b)

        r_baseline = self._send(body_a, {
            "Content-Type": "text/xml",
            "SOAPAction": action_a,
        })

        r_mismatch = self._send(body_a, {
            "Content-Type": "text/xml",
            "SOAPAction": action_b,
        })

        r_nonexistent = self._send(body_a, {
            "Content-Type": "text/xml",
            "SOAPAction": '"urn:NonexistentOperation"',
        })

        r_empty = self._send(body_a, {
            "Content-Type": "text/xml",
            "SOAPAction": '""',
        })

        r_missing = self._send(body_a, {"Content-Type": "text/xml"})

        # Bail if baseline failed
        if r_baseline is None or r_mismatch is None:
            ptprint("Could not complete dispatch consistency test "
                    "(baseline or mismatch request failed).", "INFO",
                    not self.args.json, indent=4)
            return

        baseline_elements = self._extract_body_elements(r_baseline.text)
        baseline_fault = self._has_fault(r_baseline.text)
        baseline_returns_a = self._looks_like_operation_output(
            op_a['name'], baseline_elements)

        mismatch_elements = self._extract_body_elements(r_mismatch.text)
        mismatch_fault = self._has_fault(r_mismatch.text)
        mismatch_returns_a = self._looks_like_operation_output(
            op_a['name'], mismatch_elements)
        mismatch_returns_b = self._looks_like_operation_output(
            op_b['name'], mismatch_elements)

        findings = []   
        info_notes = []  

        if mismatch_returns_b and not mismatch_returns_a:
            findings.append(
                f"Operation confusion: body declared operation "
                f"'{op_a['name']}' but server returned output of operation "
                f"'{op_b['name']}' when SOAPAction header was set to "
                f"{action_b}. The server dispatches by SOAPAction, ignoring "
                f"the XML Body operation — this can be abused if access "
                f"control is enforced on the Body element only.")

        elif baseline_fault != mismatch_fault:
            if mismatch_fault and not baseline_fault:
                low = (r_mismatch.text or "").lower()
                if "soapaction" not in low:
                    findings.append(
                        f"Dispatch inconsistency: changing SOAPAction header "
                        f"to {action_b} caused the server to return a SOAP "
                        f"Fault on an otherwise valid request, but the Fault "
                        f"does not reference SOAPAction. Server may dispatch "
                        f"inconsistently based on header content.")
                else:
                    info_notes.append(
                        "Server validates SOAPAction header — mismatched "
                        "SOAPAction produces a SOAP Fault referencing "
                        "SOAPAction. This is the recommended behaviour.")

        if (baseline_returns_a and mismatch_returns_a and
                not mismatch_returns_b and not mismatch_fault):
            info_notes.append(
                f"SOAPAction header is ignored — server dispatched operation "
                f"'{op_a['name']}' (declared in Body) regardless of "
                f"SOAPAction value. This is a legitimate dispatch strategy.")

        for name, r in [("nonexistent", r_nonexistent),
                        ("empty", r_empty),
                        ("missing", r_missing)]:
            if r is None:
                continue
            els = self._extract_body_elements(r.text)
            fault = self._has_fault(r.text)
            returns_a = self._looks_like_operation_output(op_a['name'], els)
            if returns_a and not fault:
                info_notes.append(
                    f"Server still executed '{op_a['name']}' with "
                    f"{name} SOAPAction.")

        if findings:
            ptprint("Operation dispatch inconsistency detected.", "VULN",
                    not self.args.json, indent=4, colortext=True)
            evidence_parts = []
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
                evidence_parts.append(f)

            evidence = (
                f"Operations probed: '{op_a['name']}' (body) crossed with "
                f"'{op_b['name']}' (SOAPAction). "
                + " || ".join(evidence_parts)
            )
            if info_notes:
                evidence += " Additional observations: " + " ".join(info_notes)

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-DISPATCH-INCONSISTENCY",
                node_key=self.helpers.node_key,
                data={"evidence": evidence})
            return

        if info_notes:
            ptprint("Operation dispatch appears consistent. Informational "
                    "observations:", "OK",
                    not self.args.json, indent=4)
            for n in info_notes:
                ptprint(f"  {n}", "INFO", not self.args.json, indent=4)
        else:
            ptprint("Operation dispatch appears consistent across SOAPAction "
                    "variants.", "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    SOAPActionSpoofing(args, ptjsonlib, helpers, http_client, common_tests).run()