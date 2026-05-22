"""
SOAP XSD Schema Validation / Schema Enforcement test
"""

import html
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP XSD Schema Validation test"


SCHEMA_REJECTION_INDICATORS = [
    "schema validation", "xmlschema", "xml schema", "xsd", "cvc-",
    "facet-valid", "not a valid value", "is not a valid value",
    "unexpected element", "element is not expected",
    "this element is not expected", "not allowed", "minoccurs", "maxoccurs",
    "missing required", "required element", "required parameter",
    "cannot be converted", "failed to validate", "validation failed",
]

CLEAN_INPUT_REJECTION_INDICATORS = [
    "invalid integer", "invalid int", "invalid number", "invalid decimal",
    "invalid float", "invalid double", "invalid value", "could not convert",
    "cannot convert", "type mismatch", "bad request",
]

SOAP_FAULT_INDICATORS = [
    "soap:fault", "soapenv:fault", "<fault>", "faultcode", "faultstring",
]

AUTH_DENIED_INDICATORS = [
    "access denied", "unauthorized", "unauthorised", "forbidden",
    "authentication failed", "authentication required", "failedauthentication",
    "invalidsecuritytoken", "wsse:",
]

BACKEND_ERROR_INDICATORS = [
    "traceback", "stack trace", "exception", "valueerror", "typeerror",
    "sqlalchemy", "database error", "internal server error",
]

DANGEROUS_OPERATION_WORDS = [
    "delete", "remove", "update", "edit", "create", "new",
    "insert", "write", "set", "change",
]

URL_LIKE_PARAM_NAMES = {
    "url", "uri", "endpoint", "endpointurl", "callback", "callbackurl",
    "webhook", "location", "target", "resource", "feed",
    "image", "imageurl", "avatar", "schema", "wsdl", "service",
    "link", "redirect", "fetch", "source", "href", "src",
}

MAX_OPERATIONS_TO_TEST = 10


class XSDValidation:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _send_raw(self, data, op=None):
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
        }

        action = self._soap_action_for(op) if op else None
        if action:
            headers["SOAPAction"] = action

        try:
            return self.http_client.send_request(
                url=self.helpers.endpoint_url,
                method="POST",
                data=data,
                headers=headers,
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _soap_action_for(self, op):
        if not op:
            return None

        action = op.get("soap_action") or op.get("soapAction") or ""
        if action:
            return f'"{action}"'

        name = op.get("name", "")
        return f'"urn:{name}"' if name else None

    def _has_any(self, text, indicators):
        if not text:
            return False

        low = text.lower()
        return any(ind in low for ind in indicators)

    def _is_soap_fault(self, response):
        if response is None:
            return False

        return self._has_any(response.text or "", SOAP_FAULT_INDICATORS)

    def _is_schema_rejection(self, response):
        if response is None:
            return False

        body = response.text or ""

        if self._has_any(body, SCHEMA_REJECTION_INDICATORS):
            return True

        if response.status_code in (400, 422) and self._is_soap_fault(response):
            return True

        return False

    def _is_clean_input_rejection(self, response):
        if response is None:
            return False

        body = response.text or ""

        if self._has_any(body, CLEAN_INPUT_REJECTION_INDICATORS):
            return True

        if response.status_code in (400, 422) and not self._is_backend_error(response):
            return True

        return False

    def _is_auth_denied(self, response):
        if response is None:
            return False

        if response.status_code in (401, 403, 407):
            return True

        return self._has_any(response.text or "", AUTH_DENIED_INDICATORS)

    def _is_backend_error(self, response):
        if response is None:
            return False

        if response.status_code >= 500:
            return True

        return self._has_any(response.text or "", BACKEND_ERROR_INDICATORS)

    def _normalise_type(self, param_type):
        if not param_type:
            return "string"

        t = str(param_type).lower().strip()
        if ":" in t:
            t = t.split(":", 1)[-1]

        return t

    def _default_value(self, param_type):
        t = self._normalise_type(param_type)

        if t in ("string", "normalizedstring", "token"):
            return "test"

        if t in (
            "int", "integer", "long", "short", "byte",
            "nonnegativeinteger", "positiveinteger",
        ):
            return "1"

        if t in ("decimal", "float", "double"):
            return "1.0"

        if t in ("boolean", "bool"):
            return "true"

        if t == "date":
            return "2050-01-01"

        if t == "datetime":
            return "2050-01-01T00:00:00Z"

        return "test"

    def _is_numeric_type(self, param_type):
        t = self._normalise_type(param_type)

        return t in (
            "int", "integer", "long", "short", "byte",
            "nonnegativeinteger", "positiveinteger",
            "decimal", "float", "double",
        )

    def _is_required_param(self, param):
        min_occurs = (
            param.get("minOccurs")
            or param.get("min_occurs")
            or param.get("min")
        )

        nillable = param.get("nillable")

        if str(min_occurs) == "0":
            return False

        if str(nillable).lower() == "true":
            return False

        return True

    def _is_dangerous_operation(self, op_name):
        low = (op_name or "").lower()
        return any(word in low for word in DANGEROUS_OPERATION_WORDS)

    def _is_url_like_param(self, param_name):
        if not param_name:
            return False

        low = param_name.lower()

        if low in URL_LIKE_PARAM_NAMES:
            return True

        return any(word in low for word in URL_LIKE_PARAM_NAMES)

    def _has_url_like_param(self, op):
        params = op.get("input_params", []) or []
        return any(self._is_url_like_param(p.get("name", "")) for p in params)

    def _build_request(self, op, overrides=None, omit_params=None, extra_elements=None):
        overrides = overrides or {}
        omit_params = set(omit_params or [])
        extra_elements = extra_elements or []

        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element", op.get("name", ""))
        params = op.get("input_params", []) or []

        params_xml = ""

        for p in params:
            p_name = p.get("name", "")
            p_type = p.get("type", "string")

            if not p_name or p_name in omit_params:
                continue

            value = overrides.get(p_name, self._default_value(p_type))

            params_xml += (
                f"<tns:{p_name}>"
                f"{html.escape(str(value), quote=False)}"
                f"</tns:{p_name}>"
            )

        for name, value in extra_elements:
            params_xml += (
                f"<tns:{name}>"
                f"{html.escape(str(value), quote=False)}"
                f"</tns:{name}>"
            )

        return (
            '<?xml version="1.0"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{html.escape(tns, quote=True)}">'
            "<soap:Body>"
            f"<tns:{input_element}>"
            f"{params_xml}"
            f"</tns:{input_element}>"
            "</soap:Body>"
            "</soap:Envelope>"
        )

    def _extract_body_elements(self, response_text):
        if not response_text:
            return set()

        match = re.search(
            r"<(?:\w+:)?Body[^>]*>(.*?)</(?:\w+:)?Body>",
            response_text,
            re.DOTALL | re.IGNORECASE,
        )

        if not match:
            return set()

        body_content = match.group(1)
        names = set()

        for tag in re.findall(r"<(?:\w+:)?([A-Za-z_][\w\-.]*)", body_content):
            names.add(tag.lower())

        return names

    def _looks_like_operation_response(self, response, op_name):
        if response is None:
            return False

        if self._is_soap_fault(response):
            return False

        body = response.text or ""
        elements = self._extract_body_elements(body)
        op_lower = (op_name or "").lower()

        expected = {
            op_lower,
            f"{op_lower}response",
            f"{op_lower}result",
            f"{op_lower}output",
        }

        if elements & expected:
            return True

        generic_result_elements = {
            "return", "result", "response", "data", "value",
        }

        if elements & generic_result_elements:
            return True

        return False

    def _classify_response(self, response, op_name):
        if response is None:
            return "NO_RESPONSE"

        if self._is_auth_denied(response):
            return "AUTH_DENIED"

        if self._is_schema_rejection(response):
            return "SCHEMA_REJECTION"

        if self._is_clean_input_rejection(response):
            return "CLEAN_INPUT_REJECTION"

        if self._is_backend_error(response):
            return "BACKEND_ERROR"

        if self._looks_like_operation_response(response, op_name):
            return "OPERATION_REACHED"

        if 200 <= response.status_code < 300 and not self._is_soap_fault(response):
            return "OPERATION_REACHED"

        return "AMBIGUOUS"

    def _response_excerpt(self, response, limit=160):
        if response is None:
            return ""

        return (response.text or "")[:limit].strip().replace("\n", " ")

    def _make_mutations(self, op):
        mutations = []
        params = op.get("input_params", []) or []

        numeric_params = [
            p for p in params
            if p.get("name") and self._is_numeric_type(p.get("type", ""))
        ]

        if numeric_params:
            p = numeric_params[0]
            mutations.append({
                "name": "wrong data type",
                "description": (
                    f"string value sent for numeric parameter "
                    f"'{p['name']}' of type '{p.get('type', 'unknown')}'"
                ),
                "request": self._build_request(
                    op,
                    overrides={p["name"]: "NOT_A_NUMBER_XSD_TEST"},
                ),
            })

        mutations.append({
            "name": "extra unknown element",
            "description": "undocumented element '__xsd_test_unknown_element' added",
            "request": self._build_request(
                op,
                extra_elements=[("__xsd_test_unknown_element", "injected")],
            ),
        })

        required_params = [
            p for p in params
            if p.get("name") and self._is_required_param(p)
        ]

        if required_params:
            p = required_params[0]
            mutations.append({
                "name": "missing parameter",
                "description": f"documented parameter '{p['name']}' omitted from request",
                "request": self._build_request(
                    op,
                    omit_params={p["name"]},
                ),
            })

        return mutations

    def _test_operation(self, op):
        op_name = op.get("name", "")
        params = op.get("input_params", []) or []

        if not op_name or not params:
            return []

        if self._is_dangerous_operation(op_name):
            return []

        if self._has_url_like_param(op):
            return []

        baseline_request = self._build_request(op)
        baseline_response = self._send_raw(baseline_request, op=op)
        baseline_class = self._classify_response(baseline_response, op_name)

        if baseline_class != "OPERATION_REACHED":
            return []

        findings = []

        for mutation in self._make_mutations(op):
            response = self._send_raw(mutation["request"], op=op)

            if response is None:
                continue

            cls = self._classify_response(response, op_name)

            if cls == "BACKEND_ERROR":
                findings.append({
                    "operation": op_name,
                    "mutation": mutation["name"],
                    "classification": cls,
                    "description": mutation["description"],
                    "http_status": response.status_code,
                    "response_excerpt": self._response_excerpt(response),
                    "message": (
                        "Schema-invalid request caused backend/server error "
                        "instead of clean rejection."
                    ),
                })

            elif cls == "OPERATION_REACHED":
                findings.append({
                    "operation": op_name,
                    "mutation": mutation["name"],
                    "classification": cls,
                    "description": mutation["description"],
                    "http_status": response.status_code,
                    "message": (
                        "Schema-invalid request reached operation/business logic "
                        "instead of being rejected before handling."
                    ),
                })

        return findings

    def _group_findings(self, findings):
        grouped = {}

        for finding in findings:
            op = finding.get("operation", "unknown")
            mutation = finding.get("mutation", "unknown mutation")
            grouped.setdefault(op, []).append(mutation)

        return grouped

    def run(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []

        if not operations:
            ptprint("No parsed operations available for XSD validation test.",
                    "OK", not self.args.json, indent=4)
            return

        candidates = [
            op for op in operations
            if op.get("name") and op.get("input_params")
        ]

        if not candidates:
            ptprint("No operations with parameters available for XSD validation test.",
                    "OK", not self.args.json, indent=4)
            return

        findings = []
        tested = 0

        for op in candidates:
            if tested >= MAX_OPERATIONS_TO_TEST:
                break

            op_findings = self._test_operation(op)

            if op_findings:
                findings.extend(op_findings)

            tested += 1

        if findings:
            ptprint("SOAP schema enforcement issues found.",
                    "VULN", not self.args.json, indent=4, colortext=True)

            grouped = self._group_findings(findings)

            for op_name, mutations in grouped.items():
                unique_mutations = []
                for mutation in mutations:
                    if mutation not in unique_mutations:
                        unique_mutations.append(mutation)

                ptprint(
                    f"  {op_name}: {', '.join(unique_mutations)}.",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-SCHEMA-ENFORCEMENT",
                node_key=self.helpers.node_key,
                data={
                    "summary": "SOAP schema enforcement issues were observed.",
                    "description": (
                        "Schema-invalid SOAP requests reached operation/business "
                        "logic or caused backend/server errors instead of being "
                        "rejected cleanly before handling."
                    ),
                    "confidence": "black-box heuristic",
                    "testedOperations": tested,
                    "findingCount": len(findings),
                    "findings": findings,
                    "evidence": " || ".join(
                        f"{f['operation']}:{f['mutation']}:{f['classification']}"
                        for f in findings
                    ),
                },
            )
            return

        ptprint("No SOAP schema enforcement issues detected.",
                "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XSDValidation(args, ptjsonlib, helpers, http_client, common_tests).run()