"""
SOAP Server-side Validation test
"""

import html
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Server-side Validation test"


MAX_OPERATIONS_TO_TEST = 10
MAX_PARAMS_PER_OPERATION = 4

OVERSIZED_STRING_LENGTH = 10000
BOUNDARY_STRING_LENGTH = 1024

DANGEROUS_OPERATION_WORDS = [
    "delete","remove","update","edit","create","insert","write",
    "set","change","submit","payment","pay","transfer","new",
]

URL_LIKE_PARAM_NAMES = {
    "url","uri","endpoint","endpointurl","callback","callbackurl","webhook",
    "location","target","resource","feed","image","imageurl","avatar","schema",
    "wsdl","service","link","redirect","fetch","source","href","src",
}

AUTH_DENIED_HTTP_STATUS = {401, 403, 407}

AUTH_DENIED_INDICATORS = [
    "access denied","unauthorized","unauthorised","forbidden","authentication failed",
    "authentication required","failedauthentication","invalidsecuritytoken","wsse:",
]

SOAP_FAULT_INDICATORS = [
    "soap:fault","soapenv:fault","<fault>","faultcode","faultstring",
]

VALIDATION_REJECTION_INDICATORS = [
    "validation failed","invalid input","invalid value","invalid format","value too long",
    "too long","maximum length","max length","length exceeded","payload too large",
    "request entity too large","content too large","not allowed","disallowed",
    "control character","invalid character","bad request","invalid parameter",
    "parameter validation","input validation",
]

SCHEMA_REJECTION_INDICATORS = [
    "schema validation","xmlschema","xml schema","xsd","cvc-","facet-valid","unexpected element",
    "element is not expected","minoccurs","maxoccurs","missing required","required element",
]

BACKEND_ERROR_INDICATORS = [
    "traceback","stack trace","exception","valueerror","typeerror","sqlalchemy",
    "database error","internal server error","nullpointerexception","indexerror",
]

SQL_ERROR_INDICATORS = [
    "sql syntax","sqlite","mysql","postgresql","ora-","sqlalchemy",
    "unterminated quoted string","syntax error near","odbc",
]


class ServerSideValidation:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _normalise_type(self, param_type):
        if not param_type:
            return "string"

        t = str(param_type).lower().strip()
        if ":" in t:
            t = t.split(":", 1)[-1]

        return t

    def _has_any(self, text, indicators):
        if not text:
            return False

        low = text.lower()
        return any(ind in low for ind in indicators)

    def _matched_indicators(self, text, indicators):
        if not text:
            return []

        low = text.lower()
        return [ind for ind in indicators if ind in low]

    def _response_excerpt(self, response, limit=180):
        if response is None:
            return ""

        text = response.text or ""
        text = re.sub(r"\s+", " ", text).strip()
        text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)

        if len(text) > limit:
            text = text[:limit] + "..."

        return text

    def _is_soap_fault(self, response):
        if response is None:
            return False

        return self._has_any(response.text or "", SOAP_FAULT_INDICATORS)

    def _is_auth_denied(self, response):
        if response is None:
            return False

        if response.status_code in AUTH_DENIED_HTTP_STATUS:
            return True

        return self._has_any(response.text or "", AUTH_DENIED_INDICATORS)

    def _is_schema_rejection(self, response):
        if response is None:
            return False

        return self._has_any(response.text or "", SCHEMA_REJECTION_INDICATORS)

    def _is_validation_rejection(self, response):
        if response is None:
            return False

        if response.status_code in (400, 413, 422):
            return True

        return self._has_any(response.text or "", VALIDATION_REJECTION_INDICATORS)

    def _is_backend_error(self, response):
        if response is None:
            return False

        if response.status_code >= 500:
            return True

        return self._has_any(response.text or "", BACKEND_ERROR_INDICATORS)

    def _has_sql_error(self, response):
        if response is None:
            return False

        return self._has_any(response.text or "", SQL_ERROR_INDICATORS)

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

        if self._is_auth_denied(response):
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
            "return","result","response","success","data","value",
        }

        if elements & generic_result_elements:
            return True

        return 200 <= response.status_code < 300

    def _classify_response(self, response, op_name):
        if response is None:
            return "NO_RESPONSE"

        if self._is_auth_denied(response):
            return "AUTH_DENIED"

        if self._is_schema_rejection(response):
            return "SCHEMA_REJECTION"

        if self._is_validation_rejection(response):
            return "VALIDATION_REJECTION"

        if self._is_backend_error(response):
            return "BACKEND_ERROR"

        if self._looks_like_operation_response(response, op_name):
            return "OPERATION_REACHED"

        if response.status_code in (404, 409):
            return "BUSINESS_RESPONSE"

        return "AMBIGUOUS"

    def _default_value(self, param_type, param_name=""):
        ptype = self._normalise_type(param_type)
        pname = (param_name or "").lower()

        if "email" in pname:
            return "user@example.test"
        if "name" in pname:
            return "test"
        if pname == "id" or pname.endswith("id") or pname.endswith("_id"):
            return "1"
        if "format" in pname:
            return "safe"
        if "nonce" in pname:
            return "validation-test-nonce"
        if "account" in pname:
            return "test-account"

        if ptype in ("string", "normalizedstring", "token"):
            return "test"

        if ptype in (
            "int","integer","long","short","byte","nonnegativeinteger","positiveinteger",
        ):
            return "1"

        if ptype in ("decimal", "float", "double"):
            return "1.0"

        if ptype in ("boolean", "bool"):
            return "true"

        if ptype == "date":
            return "2050-01-01"

        if ptype == "datetime":
            return "2050-01-01T00:00:00Z"

        return "test"

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

    def _is_string_param(self, param):
        return self._normalise_type(param.get("type", "")) in (
            "string","normalizedstring","token",
        )

    def _candidate_operations(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []
        candidates = []

        for op in operations:
            if not op.get("name"):
                continue

            if not op.get("input_params"):
                continue

            if self._is_dangerous_operation(op.get("name", "")):
                continue

            if self._has_url_like_param(op):
                continue

            string_params = [
                p for p in op.get("input_params", [])
                if p.get("name") and self._is_string_param(p)
            ]

            if not string_params:
                continue

            candidates.append(op)

        return candidates[:MAX_OPERATIONS_TO_TEST]

    def _soap_action_for(self, op):
        action = op.get("soap_action") or op.get("soapAction") or ""

        if action:
            return f'"{action}"'

        name = op.get("name", "")
        return f'"urn:{name}"' if name else ""

    def _build_request(self, op, overrides=None):
        overrides = overrides or {}

        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element", op.get("name", ""))
        params = op.get("input_params", []) or []

        params_xml = ""
        for param in params:
            name = param.get("name", "")
            ptype = param.get("type", "string")

            if not name:
                continue

            value = overrides.get(name, self._default_value(ptype, name))
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

    def _send(self, body, op):
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
        }

        soap_action = self._soap_action_for(op)
        if soap_action:
            headers["SOAPAction"] = soap_action

        try:
            return self.http_client.send_request(
                url=self.helpers.endpoint_url,
                method="POST",
                data=body,
                headers=headers,
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _payloads_for_param(self, param):
        pname = param.get("name", "")
        payloads = [
            {
                "name": "oversized_string",
                "category": "length",
                "value": "A" * OVERSIZED_STRING_LENGTH,
                "description": f"{OVERSIZED_STRING_LENGTH}-character string",
            },
            {
                "name": "boundary_length_string",
                "category": "length",
                "value": "B" * BOUNDARY_STRING_LENGTH,
                "description": f"{BOUNDARY_STRING_LENGTH}-character string",
            },
            {
                "name": "control_characters",
                "category": "character_policy",
                "value": "valid_text\u0001\u0002\u0008end",
                "description": "XML-escaped control-character payload",
            },
            {
                "name": "metacharacter_string",
                "category": "character_policy",
                "value": "'\"<>${}[]{};--",
                "description": "special metacharacter string",
            },
        ]

        low = pname.lower()

        if "email" in low:
            payloads.append({
                "name": "invalid_email_format",
                "category": "format",
                "value": "not-an-email-address",
                "description": "invalid email-like value",
            })

        if "format" in low:
            payloads.append({
                "name": "unexpected_format_value",
                "category": "format",
                "value": "__unexpected_format_value__",
                "description": "unexpected format selector value",
            })

        if "id" in low:
            payloads.append({
                "name": "invalid_identifier_format",
                "category": "format",
                "value": "not-a-valid-id",
                "description": "invalid identifier-like value",
            })

        return payloads

    def _is_finding_classification(self, classification):
        return classification in (
            "OPERATION_REACHED","BUSINESS_RESPONSE","BACKEND_ERROR",
        )

    def _finding_type_for_classification(self, classification):
        if classification == "BACKEND_ERROR":
            return "backend_error_on_invalid_input"

        return "invalid_input_accepted"

    def _test_param_payload(self, op, param, payload, baseline_class):
        op_name = op.get("name", "")
        param_name = param.get("name", "")

        request_body = self._build_request(
            op,
            overrides={param_name: payload["value"]},
        )
        response = self._send(request_body, op)
        classification = self._classify_response(response, op_name)

        if not self._is_finding_classification(classification):
            return None

        finding = {
            "operation": op_name,
            "parameter": param_name,
            "payload": payload["name"],
            "category": payload["category"],
            "classification": classification,
            "baselineClassification": baseline_class,
            "type": self._finding_type_for_classification(classification),
            "httpStatus": getattr(response, "status_code", None),
            "description": payload["description"],
        }

        if classification == "BACKEND_ERROR":
            finding["responseExcerpt"] = self._response_excerpt(response)
            sql_matches = self._matched_indicators(response.text or "", SQL_ERROR_INDICATORS) if response else []
            if sql_matches:
                finding["matchedBackendIndicators"] = sorted(set(sql_matches))

        return finding

    def _test_operation(self, op):
        op_name = op.get("name", "")
        baseline_response = self._send(self._build_request(op), op)
        baseline_class = self._classify_response(baseline_response, op_name)

        if baseline_class not in ("OPERATION_REACHED", "BUSINESS_RESPONSE"):
            return []

        findings = []
        string_params = [
            p for p in op.get("input_params", []) or []
            if p.get("name") and self._is_string_param(p)
        ]

        for param in string_params[:MAX_PARAMS_PER_OPERATION]:
            for payload in self._payloads_for_param(param):
                finding = self._test_param_payload(op, param, payload, baseline_class)
                if finding:
                    findings.append(finding)

        return findings

    def _dedupe_findings(self, findings):
        seen = set()
        out = []

        for finding in findings:
            key = (
                finding.get("operation"),
                finding.get("parameter"),
                finding.get("payload"),
                finding.get("type"),
            )

            if key in seen:
                continue

            seen.add(key)
            out.append(finding)

        return out

    def _group_findings(self, findings):
        grouped = {}

        for finding in findings:
            op_name = finding.get("operation", "unknown")
            param_name = finding.get("parameter", "unknown")
            key = (op_name, param_name)

            grouped.setdefault(key, {
                "operation": op_name,
                "parameter": param_name,
                "issues": [],
                "payloads": [],
                "categories": [],
                "classifications": [],
            })

            grouped[key]["issues"].append(finding.get("type", "unknown"))
            grouped[key]["payloads"].append(finding.get("payload", "unknown"))
            grouped[key]["categories"].append(finding.get("category", "unknown"))
            grouped[key]["classifications"].append(finding.get("classification", "unknown"))

        result = []
        for item in grouped.values():
            result.append({
                "operation": item["operation"],
                "parameter": item["parameter"],
                "issues": sorted(set(item["issues"])),
                "payloads": sorted(set(item["payloads"])),
                "categories": sorted(set(item["categories"])),
                "classifications": sorted(set(item["classifications"])),
            })

        return sorted(result, key=lambda x: (x["operation"], x["parameter"]))

    def _print_console_summary(self, grouped_findings):
        ptprint(
            "Server-side validation issues found.",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        for item in grouped_findings:
            payloads = ", ".join(item["payloads"])
            issues = ", ".join(item["issues"])
            ptprint(
                f"  {item['operation']}.{item['parameter']}: {payloads} ({issues}).",
                "VULN",
                not self.args.json,
                indent=4,
            )

    def run(self):
        operations = self._candidate_operations()

        if not operations:
            ptprint(
                "No suitable SOAP string parameters available for server-side validation test.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        findings = []

        for op in operations:
            findings.extend(self._test_operation(op))

        findings = self._dedupe_findings(findings)

        if not findings:
            ptprint(
                "No server-side validation weaknesses detected in tested SOAP parameters.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        grouped_findings = self._group_findings(findings)
        self._print_console_summary(grouped_findings)

        issue_types = sorted(set(f.get("type", "unknown") for f in findings))
        payloads = sorted(set(f.get("payload", "unknown") for f in findings))
        categories = sorted(set(f.get("category", "unknown") for f in findings))

        self.ptjsonlib.add_vulnerability(
            "PTV-SOAP-WEAK-SERVER-SIDE-VALIDATION",
            node_key=self.helpers.node_key,
            data={
                "summary": "SOAP server-side input validation weaknesses were observed.",
                "description": (
                    "The SOAP endpoint accepted semantically suspicious or oversized "
                    "schema-valid input values, or produced backend errors when such "
                    "values were submitted. This test focuses on application-level "
                    "validation beyond XSD/schema enforcement."
                ),
                "confidence": "black-box heuristic",
                "testedOperationCount": len(operations),
                "findingCount": len(findings),
                "affectedParameters": grouped_findings,
                "issueTypes": issue_types,
                "payloads": payloads,
                "categories": categories,
                "note": (
                    "This test intentionally avoids schema-invalid request structures."
                ),
            },
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ServerSideValidation(args, ptjsonlib, helpers, http_client, common_tests).run()
