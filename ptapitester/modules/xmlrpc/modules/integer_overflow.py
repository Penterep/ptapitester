"""
XML-RPC Integer Overflow / Integer Range Enforcement test
"""

import html
import json
import re
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Integer Overflow test"

MAX_METHODS_TO_TEST = 12
MAX_INTEGER_PARAMS_PER_METHOD = 6

XMLRPC_INT_MIN = -(2 ** 31)
XMLRPC_INT_MAX = (2 ** 31) - 1

OVERFLOW_TEST_VALUES = [
    {
        "case": "int32_plus_one",
        "value": 2 ** 31,
        "label": "int32 +1",
    },
    {
        "case": "int32_minus_one",
        "value": -(2 ** 31) - 1,
        "label": "int32 -1",
    },
]

DANGEROUS_METHOD_WORDS = [
    "delete","remove","update","edit","create","new","insert","write","set",
    "change","submit","payment","pay","transfer","execute","exec","admin",
]

SYSTEM_METHOD_PREFIXES = ("system.", "demo.")

INTEGER_TYPES = {
    "int","i4","integer","long","short","byte",
}

REJECTION_INDICATORS = [
    "overflow","out of range","outside range","too large","too small","invalid integer",
    "invalid int","invalid value","bad request","cannot convert","could not convert",
    "type mismatch","not a valid","32-bit","int32",
]

SIGNATURE_OR_TYPE_ERROR_INDICATORS = [
    "wrong number of arguments","too many arguments","not enough arguments","missing required argument",
    "missing required parameter","takes exactly","takes positional","required positional",
    "unexpected argument","unexpected parameter","wrong type","invalid type","method not found",
    "method is not supported","not supported",
]

AUTH_DENIED_INDICATORS = [
    "access denied","unauthorized","unauthorised","forbidden",
    "authentication required","token required","missing token",
]

BACKEND_ERROR_INDICATORS = [
    "traceback","stack trace","exception","valueerror","typeerror",
    "attributeerror","internal server error","database error",
]


class IntegerOverflow:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _normalise_type(self, value):
        if not value:
            return "string"

        value = str(value).strip().lower()
        if ":" in value:
            value = value.split(":", 1)[-1]

        aliases = {
            "str": "string",
            "text": "string",
            "unicode": "string",
            "i8": "long",
            "boolean": "bool",
            "dict": "struct",
            "map": "struct",
        }

        return aliases.get(value, value)

    def _has_any(self, text, indicators):
        if not text:
            return False

        low = str(text).lower()
        return any(ind in low for ind in indicators)

    def _safe_excerpt(self, text, limit=180):
        if not text:
            return ""

        value = re.sub(r"\s+", " ", str(text)).strip()
        value = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value)

        if len(value) > limit:
            value = value[:limit] + "..."

        return value

    def _is_system_method(self, method_name):
        low = (method_name or "").lower()
        return low.startswith(SYSTEM_METHOD_PREFIXES)

    def _method_words(self, method_name):
        low = (method_name or "").lower()
        return [word for word in re.split(r"[^a-z0-9]+|(?<=[a-z])(?=[A-Z])", low) if word]

    def _is_dangerous_method(self, method_name):
        low = (method_name or "").lower()
        words = set(self._method_words(method_name))

        if any(word in words for word in DANGEROUS_METHOD_WORDS):
            return True

        dangerous_prefixes = (
            "delete", "remove", "update", "create", "insert", "submit",
            "payment", "transfer", "execute", "admin.",
        )
        return low.startswith(dangerous_prefixes)

    def _default_value(self, param_type="string", param_name=""):
        ptype = self._normalise_type(param_type)
        pname = (param_name or "").lower()

        if ptype in INTEGER_TYPES:
            return 1
        if ptype in ("decimal", "float", "double"):
            return 1.0
        if ptype == "bool":
            return True
        if ptype in ("array", "list"):
            return []
        if ptype == "struct":
            return {}
        if ptype in ("date", "datetime", "datetime.iso8601"):
            return "2050-01-01T00:00:00"

        if pname == "id" or pname.endswith("id") or pname.endswith("_id"):
            return "1"
        if "email" in pname:
            return "user@example.test"
        if "nonce" in pname:
            return "integer-overflow-test-nonce"
        if "account" in pname:
            return "test-account"

        return "test"

    def _xml_value(self, param_type, value, force_raw_int=False):
        ptype = self._normalise_type(param_type)

        if force_raw_int:
            return f"<value><int>{value}</int></value>"

        if ptype in INTEGER_TYPES:
            return f"<value><int>{int(value)}</int></value>"

        if ptype in ("decimal", "float", "double"):
            return f"<value><double>{float(value)}</double></value>"

        if ptype == "bool":
            return f"<value><boolean>{1 if value else 0}</boolean></value>"

        if ptype in ("array", "list"):
            return "<value><array><data></data></array></value>"

        if ptype == "struct":
            return "<value><struct></struct></value>"

        return f"<value><string>{html.escape(str(value), quote=False)}</string></value>"

    def _build_request(self, method_name, params, overflow_index=None, overflow_value=None):
        params_xml = []

        for index, param in enumerate(params):
            ptype = param.get("type", "string")
            value = param.get("value", self._default_value(ptype, param.get("name", "")))

            if overflow_index is not None and index == overflow_index:
                value_xml = self._xml_value(ptype, overflow_value, force_raw_int=True)
            else:
                value_xml = self._xml_value(ptype, value)

            params_xml.append(f"<param>{value_xml}</param>")

        return (
            "<?xml version='1.0'?>"
            "<methodCall>"
            f"<methodName>{html.escape(method_name, quote=False)}</methodName>"
            f"<params>{''.join(params_xml)}</params>"
            "</methodCall>"
        )

    def _send_request(self, method_name, params, overflow_index=None, overflow_value=None):
        data = self._build_request(method_name, params, overflow_index, overflow_value)

        try:
            return self.http_client.send_request(
                url=self.helpers.endpoint_url,
                method="POST",
                data=data,
                headers={"Content-Type": "text/xml; charset=utf-8"},
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _send_safe_call(self, method_name, values):
        data = xmlrpc.client.dumps(
            tuple(values),
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

        try:
            return self.http_client.send_request(
                url=self.helpers.endpoint_url,
                method="POST",
                data=data,
                headers={"Content-Type": "text/xml; charset=utf-8"},
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _parse_xmlrpc_response(self, response):
        if response is None:
            return {
                "kind": "NO_RESPONSE",
                "status": None,
                "result": None,
                "text": "",
                "faultCode": None,
                "faultString": "",
            }

        text = response.text or ""
        status = getattr(response, "status_code", None)

        try:
            values, _method = xmlrpc.client.loads(text)
            result = values[0] if values else None
            return {
                "kind": "SUCCESS",
                "status": status,
                "result": result,
                "text": text,
                "faultCode": None,
                "faultString": "",
            }
        except xmlrpc.client.Fault as fault:
            return {
                "kind": "FAULT",
                "status": status,
                "result": None,
                "text": fault.faultString or text,
                "faultCode": fault.faultCode,
                "faultString": fault.faultString or "",
            }
        except Exception:
            return {
                "kind": "RAW_RESPONSE",
                "status": status,
                "result": None,
                "text": text,
                "faultCode": None,
                "faultString": "",
            }

    def _classify_response(self, parsed):
        text = parsed.get("text", "") or ""
        status = parsed.get("status")
        kind = parsed.get("kind")

        if kind == "NO_RESPONSE":
            return "NO_RESPONSE"

        if status in (401, 403, 407) or self._has_any(text, AUTH_DENIED_INDICATORS):
            return "AUTH_DENIED"

        if kind == "SUCCESS":
            return "OPERATION_REACHED"
    
        if kind == "FAULT":
            fault_text = parsed.get("faultString") or text

            if self._has_any(fault_text, REJECTION_INDICATORS):
                return "INTEGER_REJECTED"

            if self._has_any(fault_text, SIGNATURE_OR_TYPE_ERROR_INDICATORS):
                return "SIGNATURE_OR_TYPE_ERROR"

            if self._has_any(fault_text, BACKEND_ERROR_INDICATORS):
                return "BACKEND_ERROR"

            return "AMBIGUOUS"

        if status and status >= 500:
            return "BACKEND_ERROR"

        if self._has_any(text, BACKEND_ERROR_INDICATORS):
            return "BACKEND_ERROR"

        if kind == "RAW_RESPONSE" and status and 200 <= status < 300:
            return "OPERATION_REACHED"

        return "AMBIGUOUS"

    def _canonical_result(self, result):
        try:
            return json.dumps(result, sort_keys=True, default=str, ensure_ascii=False)
        except Exception:
            return repr(result)

    def _result_contains_value(self, result, value):
        target = str(value)
        return target in self._canonical_result(result)

    def _extract_numeric_values(self, value):
        values = []

        if isinstance(value, bool):
            return values

        if isinstance(value, int):
            values.append(value)

        elif isinstance(value, float):
            if value.is_integer():
                values.append(int(value))

        elif isinstance(value, dict):
            for child in value.values():
                values.extend(self._extract_numeric_values(child))

        elif isinstance(value, (list, tuple)):
            for child in value:
                values.extend(self._extract_numeric_values(child))

        return values

    def _has_out_of_range_numeric_result(self, result, baseline_result=None):
        baseline_numbers = set()
        if baseline_result is not None:
            baseline_numbers = set(self._extract_numeric_values(baseline_result))

        for number in self._extract_numeric_values(result):
            if number < XMLRPC_INT_MIN or number > XMLRPC_INT_MAX:
                if number not in baseline_numbers:
                    return True
        return False

    def _acceptance_evidence(self, baseline_result, mutated_result, overflow_value):
        evidence = []

        if self._result_contains_value(mutated_result, overflow_value):
            evidence.append("response_contains_test_value")

        if self._has_out_of_range_numeric_result(mutated_result, baseline_result):
            evidence.append("response_contains_out_of_range_integer")

        if self._canonical_result(baseline_result) != self._canonical_result(mutated_result):
            evidence.append("response_changed_from_baseline")

        return sorted(set(evidence))

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
                ptype = tokens[0]
                name = f"param{index}"

            clean_name = "".join(ch for ch in name if ch.isalnum() or ch in "_.-") or f"param{index}"
            params.append({
                "name": clean_name,
                "type": self._normalise_type(ptype),
                "source": "methodHelp",
            })

        return params

    def _direct_introspection_methods(self):
        response = self._send_safe_call("system.listMethods", [])
        parsed = self._parse_xmlrpc_response(response)

        if parsed["kind"] != "SUCCESS" or not isinstance(parsed["result"], (list, tuple)):
            return []

        methods = []
        seen = set()

        for method_name in parsed["result"]:
            if not isinstance(method_name, str) or method_name in seen:
                continue

            seen.add(method_name)
            signature_params = []

            sig_response = self._send_safe_call("system.methodSignature", [method_name])
            sig_parsed = self._parse_xmlrpc_response(sig_response)

            if sig_parsed["kind"] == "SUCCESS" and isinstance(sig_parsed["result"], list):
                signatures = sig_parsed["result"]
                if signatures and isinstance(signatures[0], list) and len(signatures[0]) > 1:
                    for index, ptype in enumerate(signatures[0][1:], 1):
                        signature_params.append({
                            "name": f"param{index}",
                            "type": self._normalise_type(ptype),
                            "source": "methodSignature",
                        })

            help_response = self._send_safe_call("system.methodHelp", [method_name])
            help_parsed = self._parse_xmlrpc_response(help_response)
            help_params = []

            if help_parsed["kind"] == "SUCCESS":
                help_params = self._parse_method_help_params(method_name, help_parsed["result"])

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

    def _helper_methods(self):
        methods = []
        seen = set()

        for attr in (
            "resolved_methods",
            "method_metadata",
            "parsed_methods",
            "discovered_method_details",
            "introspection_methods",
            "xmlrpc_methods",
        ):
            value = getattr(self.helpers, attr, None)
            if not isinstance(value, list):
                continue

            for item in value:
                if not isinstance(item, dict):
                    continue

                name = item.get("name") or item.get("method") or item.get("methodName")
                if not name or name in seen:
                    continue

                raw_params = item.get("params") or item.get("parameters") or []
                params = []
                if isinstance(raw_params, list):
                    for index, param in enumerate(raw_params, 1):
                        if isinstance(param, dict):
                            params.append({
                                "name": param.get("name") or f"param{index}",
                                "type": self._normalise_type(param.get("type") or "string"),
                                "source": param.get("source") or "helper_metadata",
                            })

                methods.append({
                    "name": name,
                    "params": params,
                    "source": "helper_metadata",
                })
                seen.add(name)

        return methods

    def _candidate_methods(self):
        helper_methods = self._helper_methods()
        introspection_methods = self._direct_introspection_methods()

        merged = {}

        for method in helper_methods + introspection_methods:
            name = method.get("name", "")
            if not name:
                continue

            existing = merged.get(name)
            current_params = method.get("params") or []

            if existing is None:
                merged[name] = method
                continue

            existing_params = existing.get("params") or []

            if current_params and not existing_params:
                merged[name] = method
            elif current_params and existing_params:
                current_has_int = any(
                    self._normalise_type(param.get("type")) in INTEGER_TYPES
                    for param in current_params
                )
                existing_has_int = any(
                    self._normalise_type(param.get("type")) in INTEGER_TYPES
                    for param in existing_params
                )

                if current_has_int and not existing_has_int:
                    merged[name] = method

        candidates = []

        for method in merged.values():
            name = method.get("name", "")
            if not name:
                continue

            if self._is_system_method(name) or self._is_dangerous_method(name):
                continue

            params = method.get("params") or []
            integer_params = [
                index for index, param in enumerate(params)
                if self._normalise_type(param.get("type")) in INTEGER_TYPES
            ]

            if not integer_params:
                continue

            candidates.append({
                "name": name,
                "params": params,
                "integerParamIndexes": integer_params[:MAX_INTEGER_PARAMS_PER_METHOD],
                "source": method.get("source", "unknown"),
            })

        return candidates[:MAX_METHODS_TO_TEST]

    def _prepare_params(self, method):
        params = []

        for param in method.get("params", []) or []:
            ptype = param.get("type", "string")
            pname = param.get("name", "")
            params.append({
                "name": pname,
                "type": ptype,
                "value": self._default_value(ptype, pname),
            })

        return params

    def _test_integer_param(self, method, param_index):
        method_name = method["name"]
        params = self._prepare_params(method)

        if param_index >= len(params):
            return []

        param = params[param_index]
        param_name = param.get("name") or f"param{param_index + 1}"

        baseline_response = self._send_request(method_name, params)
        baseline_parsed = self._parse_xmlrpc_response(baseline_response)
        baseline_class = self._classify_response(baseline_parsed)

        if baseline_class != "OPERATION_REACHED":
            return []

        findings = []

        for test in OVERFLOW_TEST_VALUES:
            overflow_value = test["value"]
            mutated_response = self._send_request(
                method_name,
                params,
                overflow_index=param_index,
                overflow_value=overflow_value,
            )
            mutated_parsed = self._parse_xmlrpc_response(mutated_response)
            mutated_class = self._classify_response(mutated_parsed)

            if mutated_class in (
                "INTEGER_REJECTED",
                "SIGNATURE_OR_TYPE_ERROR",
                "AUTH_DENIED",
                "NO_RESPONSE",
            ):
                continue

            if mutated_class != "OPERATION_REACHED":
                continue

            evidence = self._acceptance_evidence(
                baseline_parsed.get("result"),
                mutated_parsed.get("result"),
                overflow_value,
            )

            if not evidence:
                continue

            findings.append({
                "method": method_name,
                "parameter": param_name,
                "parameterIndex": param_index,
                "declaredType": self._normalise_type(param.get("type")),
                "case": test["case"],
                "label": test["label"],
                "value": overflow_value,
                "httpStatus": mutated_parsed.get("status"),
                "classification": mutated_class,
                "evidenceTypes": evidence,
                "evidenceExcerpt": self._safe_excerpt(mutated_parsed.get("text"), 180),
            })

        return findings

    def _dedupe_findings(self, findings):
        seen = set()
        out = []

        for finding in findings:
            key = (
                finding["method"],
                finding["parameter"],
                finding["case"],
                finding["value"],
            )

            if key in seen:
                continue

            seen.add(key)
            out.append(finding)

        return out

    def _group_findings(self, findings):
        grouped = {}

        for finding in findings:
            key = (finding["method"], finding["parameter"])
            grouped.setdefault(key, {
                "method": finding["method"],
                "parameter": finding["parameter"],
                "declaredType": finding["declaredType"],
                "cases": [],
            })
            grouped[key]["cases"].append({
                "case": finding["case"],
                "label": finding["label"],
                "value": finding["value"],
                "httpStatus": finding["httpStatus"],
                "evidenceTypes": finding["evidenceTypes"],
                "evidenceExcerpt": finding["evidenceExcerpt"],
            })

        return sorted(grouped.values(), key=lambda item: (item["method"], item["parameter"]))

    def _print_findings(self, affected):
        ptprint(
            "XML-RPC integer range enforcement issues found.",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        for item in affected:
            cases = ", ".join(
                f"{case['label']} ({case['value']})"
                for case in item["cases"]
            )
            ptprint(
                f"  {item['method']}.{item['parameter']}: accepted {cases}.",
                "VULN",
                not self.args.json,
                indent=4,
            )

    def run(self):
        methods = self._candidate_methods()

        if not methods:
            ptprint(
                "No XML-RPC methods with integer parameters available for overflow testing.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        findings = []
        tested_integer_params = 0

        for method in methods:
            for param_index in method["integerParamIndexes"]:
                tested_integer_params += 1
                findings.extend(self._test_integer_param(method, param_index))

        findings = self._dedupe_findings(findings)

        if not findings:
            ptprint(
                "Server rejects tested out-of-range XML-RPC integer values.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        affected = self._group_findings(findings)
        self._print_findings(affected)

        self.ptjsonlib.add_vulnerability(
            "PTV-XMLRPC-INTEGER-OVERFLOW",
            node_key=self.helpers.node_key,
            data={
                "summary": "XML-RPC integer range enforcement issues were observed.",
                "description": (
                    "The XML-RPC endpoint accepted out-of-range values inside <int> "
                    "parameters for methods that declare integer arguments. The payloads "
                    "were sent as raw XML-RPC requests to avoid client-side serializer "
                    "range checks."
                ),
                "confidence": "black-box evidence",
                "testedMethodCount": len(methods),
                "testedIntegerParameterCount": tested_integer_params,
                "findingCount": len(findings),
                "xmlrpcIntRange": {
                    "min": XMLRPC_INT_MIN,
                    "max": XMLRPC_INT_MAX,
                },
                "affectedMethods": affected,
                "issueTypes": ["out_of_range_xmlrpc_int_accepted"],
            },
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    IntegerOverflow(args, ptjsonlib, helpers, http_client, common_tests).run()
