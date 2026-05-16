"""
XML-RPC Server-side Validation test

Checks whether XML-RPC methods enforce application-level input validation
beyond XML-RPC type/signature compatibility. The test sends valid XML-RPC
requests with semantically suspicious, oversized, or control-character string
values.
"""

import re
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Server-side Validation test"


MAX_METHODS_TO_TEST = 10
MAX_PARAMS_PER_METHOD = 4
MAX_FALLBACK_ARG_COUNT = 4

OVERSIZED_STRING_LENGTH = 10000
BOUNDARY_STRING_LENGTH = 1024

DANGEROUS_METHOD_WORDS = [
    "delete",
    "remove",
    "update",
    "edit",
    "create",
    "new",
    "insert",
    "write",
    "set",
    "change",
    "submit",
    "payment",
    "pay",
    "transfer",
    "execute",
    "exec",
    "admin",
]

URL_LIKE_PARAM_NAMES = {
    "url",
    "uri",
    "endpoint",
    "endpointurl",
    "callback",
    "callbackurl",
    "webhook",
    "location",
    "target",
    "resource",
    "feed",
    "image",
    "imageurl",
    "avatar",
    "schema",
    "wsdl",
    "service",
    "link",
    "redirect",
    "fetch",
    "source",
    "href",
    "src",
}

AUTH_DENIED_HTTP_STATUS = {401, 403, 407}

AUTH_DENIED_INDICATORS = [
    "access denied",
    "unauthorized",
    "unauthorised",
    "forbidden",
    "authentication failed",
    "authentication required",
    "invalid credentials",
    "token required",
    "missing token",
    "jwt required",
]

VALIDATION_REJECTION_INDICATORS = [
    "validation failed",
    "invalid input",
    "invalid value",
    "invalid format",
    "value too long",
    "too long",
    "maximum length",
    "max length",
    "length exceeded",
    "payload too large",
    "request entity too large",
    "content too large",
    "not allowed",
    "disallowed",
    "control character",
    "invalid character",
    "bad request",
    "invalid parameter",
    "parameter validation",
    "input validation",
]

SIGNATURE_OR_TYPE_REJECTION_INDICATORS = [
    "argument",
    "arguments",
    "parameter",
    "parameters",
    "param",
    "takes",
    "required",
    "missing",
    "positional",
    "expected",
    "typeerror",
    "wrong type",
    "invalid type",
    "cannot marshal",
    "method not found",
    "is not supported",
    "not supported",
]

BACKEND_ERROR_INDICATORS = [
    "traceback",
    "stack trace",
    "exception",
    "valueerror",
    "typeerror",
    "attributeerror",
    "sqlalchemy",
    "database error",
    "internal server error",
    "nullpointerexception",
    "indexerror",
]

SQL_ERROR_INDICATORS = [
    "sql syntax",
    "sqlite",
    "mysql",
    "postgresql",
    "ora-",
    "odbc",
    "sqlalchemy",
    "unterminated quoted string",
    "syntax error near",
]

BUSINESS_RESPONSE_INDICATORS = [
    "not found",
    "user not found",
    "bad credentials",
    "processed",
    "ok",
    "status",
    "result",
]

SYSTEM_METHOD_PREFIXES = (
    "system.",
    "demo.",
)


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

        aliases = {
            "str": "string",
            "text": "string",
            "unicode": "string",
            "i4": "int",
            "i8": "int",
            "integer": "int",
            "boolean": "bool",
        }

        return aliases.get(t, t)

    def _has_any(self, text, indicators):
        if not text:
            return False

        low = str(text).lower()
        return any(ind in low for ind in indicators)

    def _matched_indicators(self, text, indicators):
        if not text:
            return []

        low = str(text).lower()
        return [ind for ind in indicators if ind in low]

    def _response_excerpt(self, text, limit=180):
        if not text:
            return ""

        norm = re.sub(r"\s+", " ", str(text)).strip()
        norm = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", norm)

        if len(norm) > limit:
            norm = norm[:limit] + "..."

        return norm

    def _is_dangerous_method(self, method_name):
        low = (method_name or "").lower()
        return any(word in low for word in DANGEROUS_METHOD_WORDS)

    def _is_url_like_param(self, param_name):
        if not param_name:
            return False

        low = param_name.lower()

        if low in URL_LIKE_PARAM_NAMES:
            return True

        return any(word in low for word in URL_LIKE_PARAM_NAMES)

    def _has_url_like_param(self, method):
        return any(
            self._is_url_like_param(param.get("name", ""))
            for param in method.get("params", []) or []
        )

    def _is_system_method(self, method_name):
        low = (method_name or "").lower()
        return low.startswith(SYSTEM_METHOD_PREFIXES)

    def _is_string_param(self, param):
        return self._normalise_type(param.get("type", "")) in (
            "string",
            "normalizedstring",
            "token",
        )

    def _default_value(self, param_type, param_name=""):
        ptype = self._normalise_type(param_type)
        pname = (param_name or "").lower()

        if "email" in pname:
            return "user@example.test"
        if pname == "username" or pname == "name" or pname == "user" or pname.endswith("name"):
            return "test"
        if pname == "id" or pname.endswith("id") or pname.endswith("_id"):
            return "1"
        if "format" in pname:
            return "safe"
        if "nonce" in pname:
            return "validation-test-nonce"
        if "account" in pname:
            return "test-account"
        if "password" in pname or "pass" in pname:
            return "test"

        if ptype in ("string", "normalizedstring", "token"):
            return "test"
        if ptype in ("int", "integer", "long", "short", "byte"):
            return 1
        if ptype in ("decimal", "float", "double"):
            return 1.0
        if ptype in ("bool", "boolean"):
            return True
        if ptype in ("array", "list"):
            return []
        if ptype in ("struct", "dict"):
            return {}
        if ptype in ("date", "datetime", "datetime.iso8601"):
            return "2050-01-01T00:00:00"

        return "test"

    def _send_raw(self, method_name, params):
        body = xmlrpc.client.dumps(
            tuple(params),
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

        headers = {
            "Content-Type": "text/xml; charset=utf-8",
        }

        try:
            return self.http_client.send_request(
                url=self.helpers.endpoint_url,
                method="POST",
                data=body,
                headers=headers,
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception as e:
            return {
                "client_exception": f"{type(e).__name__}: {e}",
            }

    def _parse_xmlrpc_response(self, response):
        if response is None:
            return {
                "kind": "NO_RESPONSE",
                "text": "",
                "faultCode": None,
                "faultString": "",
                "result": None,
                "status": None,
            }

        if isinstance(response, dict) and response.get("client_exception"):
            return {
                "kind": "CLIENT_EXCEPTION",
                "text": response["client_exception"],
                "faultCode": None,
                "faultString": "",
                "result": None,
                "status": None,
            }

        text = response.text or ""
        status = getattr(response, "status_code", None)

        try:
            values, _method = xmlrpc.client.loads(text)
            result = values[0] if values else None
            return {
                "kind": "SUCCESS",
                "text": text,
                "faultCode": None,
                "faultString": "",
                "result": result,
                "status": status,
            }
        except xmlrpc.client.Fault as fault:
            return {
                "kind": "FAULT",
                "text": fault.faultString or text,
                "faultCode": fault.faultCode,
                "faultString": fault.faultString or "",
                "result": None,
                "status": status,
            }
        except Exception:
            return {
                "kind": "RAW_RESPONSE",
                "text": text,
                "faultCode": None,
                "faultString": "",
                "result": None,
                "status": status,
            }

    def _classify_response(self, response, method_name):
        parsed = self._parse_xmlrpc_response(response)
        text = parsed.get("text", "") or ""
        fault_string = parsed.get("faultString", "") or ""
        status = parsed.get("status")
        kind = parsed.get("kind")

        if kind in ("NO_RESPONSE", "CLIENT_EXCEPTION"):
            return "NO_RESPONSE", parsed

        if status in AUTH_DENIED_HTTP_STATUS or self._has_any(text, AUTH_DENIED_INDICATORS):
            return "AUTH_DENIED", parsed

        if kind == "FAULT" and self._has_any(fault_string, SIGNATURE_OR_TYPE_REJECTION_INDICATORS):
            return "SIGNATURE_OR_TYPE_REJECTION", parsed

        if status in (400, 413, 422) or self._has_any(text, VALIDATION_REJECTION_INDICATORS):
            return "VALIDATION_REJECTION", parsed

        if status and status >= 500:
            return "BACKEND_ERROR", parsed

        if self._has_any(text, BACKEND_ERROR_INDICATORS):
            return "BACKEND_ERROR", parsed

        if kind == "SUCCESS":
            return "METHOD_REACHED", parsed

        if kind == "FAULT":
            if self._has_any(fault_string, BUSINESS_RESPONSE_INDICATORS):
                return "BUSINESS_RESPONSE", parsed
            return "AMBIGUOUS_FAULT", parsed

        if kind == "RAW_RESPONSE" and status and 200 <= status < 300:
            return "METHOD_REACHED", parsed

        return "AMBIGUOUS", parsed

    def _extract_params_from_method_dict(self, method):
        params = method.get("params") or method.get("parameters") or []
        out = []

        if not isinstance(params, list):
            return out

        for index, param in enumerate(params, 1):
            if not isinstance(param, dict):
                continue

            name = param.get("name") or f"param{index}"
            ptype = param.get("type") or "string"
            out.append({
                "name": name,
                "type": self._normalise_type(ptype),
                "source": param.get("typeSource") or param.get("source") or "metadata",
            })

        return out

    def _parse_method_help_params(self, method_name, help_text):
        if not help_text or not isinstance(help_text, str):
            return []

        start = help_text.find("(")
        end = help_text.find(")", start + 1)

        if start == -1 or end == -1 or end <= start:
            return []

        inside = help_text[start + 1:end].strip()
        if not inside:
            return []

        params = []
        for index, part in enumerate(inside.split(","), 1):
            tokens = part.strip().split()
            if not tokens:
                continue

            if len(tokens) >= 2:
                ptype = tokens[0]
                name = tokens[-1]
            else:
                ptype = "string"
                name = tokens[0]

            clean_name = "".join(
                ch for ch in name
                if ch.isalnum() or ch in "_.-"
            ) or f"param{index}"

            params.append({
                "name": clean_name,
                "type": self._normalise_type(ptype),
                "source": "methodHelp",
            })

        return params

    def _direct_introspection_methods(self):
        list_response = self._send_raw("system.listMethods", [])
        list_parsed = self._parse_xmlrpc_response(list_response)

        if list_parsed.get("kind") != "SUCCESS":
            return []

        method_names = list_parsed.get("result") or []
        if not isinstance(method_names, (list, tuple)):
            return []

        methods = []
        seen = set()

        for method_name in method_names:
            if not isinstance(method_name, str) or method_name in seen:
                continue

            seen.add(method_name)

            signature_params = []
            sig_response = self._send_raw("system.methodSignature", [method_name])
            sig_parsed = self._parse_xmlrpc_response(sig_response)
            sig_result = sig_parsed.get("result") if sig_parsed.get("kind") == "SUCCESS" else None

            if isinstance(sig_result, list) and sig_result:
                first_signature = sig_result[0]
                if isinstance(first_signature, list) and len(first_signature) > 1:
                    for index, param_type in enumerate(first_signature[1:], 1):
                        signature_params.append({
                            "name": f"param{index}",
                            "type": self._normalise_type(param_type),
                            "source": "methodSignature",
                        })

            help_response = self._send_raw("system.methodHelp", [method_name])
            help_parsed = self._parse_xmlrpc_response(help_response)
            help_result = help_parsed.get("result") if help_parsed.get("kind") == "SUCCESS" else ""
            help_params = self._parse_method_help_params(method_name, help_result)

            if signature_params and help_params and len(signature_params) == len(help_params):
                params = []
                for sig_param, help_param in zip(signature_params, help_params):
                    params.append({
                        "name": help_param.get("name") or sig_param.get("name"),
                        "type": sig_param.get("type") or help_param.get("type") or "string",
                        "source": "methodSignature+methodHelp",
                    })
            elif signature_params:
                params = signature_params
            else:
                params = help_params

            methods.append({
                "name": method_name,
                "params": params,
                "source": "direct_introspection",
            })

        return methods

    def _metadata_methods_from_helpers(self):
        candidates = []

        for attr in (
            "resolved_methods",
            "method_metadata",
            "parsed_methods",
            "discovered_method_details",
            "introspection_methods",
            "xmlrpc_methods",
        ):
            value = getattr(self.helpers, attr, None)
            if isinstance(value, list):
                candidates.extend(value)

        methods = []
        seen = set()

        for item in candidates:
            if not isinstance(item, dict):
                continue

            name = item.get("name") or item.get("method") or item.get("methodName")
            if not name or name in seen:
                continue

            params = self._extract_params_from_method_dict(item)
            if not params:
                continue

            methods.append({
                "name": name,
                "params": params,
                "source": item.get("source") or "metadata",
            })
            seen.add(name)

        return methods

    def _fallback_methods_from_discovery(self):
        methods = []
        discovered = getattr(self.helpers, "discovered_methods", []) or []

        for name in discovered:
            if not name:
                continue

            methods.append({
                "name": name,
                "params": [],
                "source": "discovered_methods",
            })

        return methods

    def _infer_arg_count_and_params(self, method_name):
        for count in range(0, MAX_FALLBACK_ARG_COUNT + 1):
            params = ["test"] * count
            response = self._send_raw(method_name, params)
            classification, _parsed = self._classify_response(response, method_name)

            if classification == "SIGNATURE_OR_TYPE_REJECTION":
                continue

            if classification in (
                "METHOD_REACHED",
                "BUSINESS_RESPONSE",
                "VALIDATION_REJECTION",
                "BACKEND_ERROR",
                "AMBIGUOUS_FAULT",
                "AMBIGUOUS",
            ):
                return [
                    {
                        "name": f"param{i + 1}",
                        "type": "string",
                        "source": "fallback_arg_count_probe",
                    }
                    for i in range(count)
                ]

        return []

    def _candidate_methods(self):
        methods = self._metadata_methods_from_helpers()

        if not methods:
            methods = self._direct_introspection_methods()

        if not methods:
            methods = self._fallback_methods_from_discovery()

        candidates = []
        seen = set()

        for method in methods:
            name = method.get("name", "")

            if not name or name in seen:
                continue

            seen.add(name)

            if self._is_system_method(name):
                continue

            if self._is_dangerous_method(name):
                continue

            params = method.get("params") or []

            if not params:
                params = self._infer_arg_count_and_params(name)

            if not params:
                continue

            normalized_method = {
                "name": name,
                "params": params,
                "source": method.get("source", "unknown"),
            }

            if self._has_url_like_param(normalized_method):
                continue

            string_params = [p for p in params if self._is_string_param(p)]
            if not string_params:
                continue

            candidates.append(normalized_method)

        return candidates[:MAX_METHODS_TO_TEST]

    def _build_params(self, method, overrides=None):
        overrides = overrides or {}
        values = []

        for param in method.get("params", []) or []:
            name = param.get("name", "")
            ptype = param.get("type", "string")

            if name in overrides:
                values.append(overrides[name])
            else:
                values.append(self._default_value(ptype, name))

        return values

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
                "description": "XML-RPC string containing control-character code points",
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

        if "user" in low or "name" in low:
            payloads.append({
                "name": "invalid_name_metacharacters",
                "category": "format",
                "value": "admin' OR '1'='1",
                "description": "username/name value containing SQL-like metacharacters",
            })

        return payloads

    def _is_finding_classification(self, classification):
        return classification in (
            "METHOD_REACHED",
            "BUSINESS_RESPONSE",
            "BACKEND_ERROR",
        )

    def _finding_type_for_classification(self, classification):
        if classification == "BACKEND_ERROR":
            return "backend_error_on_invalid_input"

        return "invalid_input_accepted"

    def _test_param_payload(self, method, param, payload, baseline_class):
        method_name = method.get("name", "")
        param_name = param.get("name", "")
        values = self._build_params(method, overrides={param_name: payload["value"]})
        response = self._send_raw(method_name, values)
        classification, parsed = self._classify_response(response, method_name)

        if not self._is_finding_classification(classification):
            return None

        finding = {
            "method": method_name,
            "parameter": param_name,
            "payload": payload["name"],
            "category": payload["category"],
            "classification": classification,
            "baselineClassification": baseline_class,
            "type": self._finding_type_for_classification(classification),
            "httpStatus": parsed.get("status"),
            "description": payload["description"],
        }

        if classification == "BACKEND_ERROR":
            finding["responseExcerpt"] = self._response_excerpt(parsed.get("text"))
            sql_matches = self._matched_indicators(parsed.get("text", ""), SQL_ERROR_INDICATORS)
            if sql_matches:
                finding["matchedBackendIndicators"] = sorted(set(sql_matches))

        return finding

    def _test_method(self, method):
        method_name = method.get("name", "")
        baseline_values = self._build_params(method)
        baseline_response = self._send_raw(method_name, baseline_values)
        baseline_class, _parsed = self._classify_response(baseline_response, method_name)

        if baseline_class not in ("METHOD_REACHED", "BUSINESS_RESPONSE"):
            return []

        findings = []
        string_params = [
            p for p in method.get("params", []) or []
            if p.get("name") and self._is_string_param(p)
        ]

        for param in string_params[:MAX_PARAMS_PER_METHOD]:
            for payload in self._payloads_for_param(param):
                finding = self._test_param_payload(method, param, payload, baseline_class)
                if finding:
                    findings.append(finding)
        return findings

    def _dedupe_findings(self, findings):
        seen = set()
        out = []

        for finding in findings:
            key = (
                finding.get("method"),
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
            method = finding.get("method", "unknown")
            parameter = finding.get("parameter", "unknown")
            key = (method, parameter)

            grouped.setdefault(key, {
                "method": method,
                "parameter": parameter,
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
                "method": item["method"],
                "parameter": item["parameter"],
                "issues": sorted(set(item["issues"])),
                "payloads": sorted(set(item["payloads"])),
                "categories": sorted(set(item["categories"])),
                "classifications": sorted(set(item["classifications"])),
            })

        return sorted(result, key=lambda x: (x["method"], x["parameter"]))

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
                f"  {item['method']}.{item['parameter']}: {payloads} ({issues}).",
                "VULN",
                not self.args.json,
                indent=4,
            )

    def run(self):
        methods = self._candidate_methods()

        if not methods:
            ptprint(
                "No suitable XML-RPC string parameters available for server-side validation test.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        findings = []

        for method in methods:
            findings.extend(self._test_method(method))

        findings = self._dedupe_findings(findings)

        if not findings:
            ptprint(
                "No server-side validation weaknesses detected in tested XML-RPC parameters.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        grouped_findings = self._group_findings(findings)
        self._print_console_summary(grouped_findings)

        self.ptjsonlib.add_vulnerability(
            "PTV-XMLRPC-WEAK-SERVER-SIDE-VALIDATION",
            node_key=self.helpers.node_key,
            data={
                "summary": "XML-RPC server-side input validation weaknesses were observed.",
                "description": (
                    "The XML-RPC endpoint accepted semantically suspicious or oversized "
                    "type-valid string values, or produced backend errors when such values "
                    "were submitted. This test focuses on application-level validation "
                    "beyond XML-RPC type/signature compatibility."
                ),
                "confidence": "black-box heuristic",
                "testedMethodCount": len(methods),
                "findingCount": len(findings),
                "affectedParameters": grouped_findings,
                "issueTypes": sorted(set(f.get("type", "unknown") for f in findings)),
                "payloads": sorted(set(f.get("payload", "unknown") for f in findings)),
                "categories": sorted(set(f.get("category", "unknown") for f in findings)),
                "note": (
                    "This test avoids system methods, dangerous state-changing methods, "
                    "and URL-like parameters. Type/signature rejection is not treated as "
                    "a finding."
                ),
            },
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ServerSideValidation(args, ptjsonlib, helpers, http_client, common_tests).run()
