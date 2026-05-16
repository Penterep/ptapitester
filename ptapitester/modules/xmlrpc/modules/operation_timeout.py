"""
XML-RPC Operation timeout test
"""

import re
import time
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Operation timeout test"


MAX_METHODS_TO_TEST = 10
MAX_FALLBACK_ARG_COUNT = 4
SLOW_THRESHOLD_SECONDS = 5.0
RELATIVE_SLOW_FACTOR = 5.0
LARGE_PAYLOAD_SIZE = 100000

DANGEROUS_METHOD_WORDS = [
    "delete","remove","update","edit","create","new","insert","write","set",
    "change","submit","payment","pay","transfer","execute","exec","admin",
]

URL_LIKE_PARAM_NAMES = {
    "url","uri","endpoint","endpointurl","callback","callbackurl","webhook",
    "location","target","resource","feed","image","imageurl","avatar","schema",
    "wsdl","service","link","redirect","fetch","source","href","src",
}

SIGNATURE_OR_TYPE_REJECTION_INDICATORS = [
    "argument","arguments","parameter","parameters","param","takes","required","missing","positional",
    "expected","wrong type","invalid type","cannot marshal","method not found","is not supported","not supported",
]

AUTH_DENIED_INDICATORS = [
    "access denied","unauthorized","unauthorised","authentication failed","authentication required",
    "invalid credentials","token required","missing token","jwt required","forbidden",
]

BACKEND_ERROR_INDICATORS = [
    "traceback","stack trace","exception","valueerror","typeerror",
    "sqlalchemy","database error","internal server error","attributeerror",
]

BUSINESS_RESPONSE_INDICATORS = [
    "not found","user not found","bad credentials",
    "processed","ok","status","result",
]

AUTH_DENIED_HTTP_STATUS = {401, 403, 407}
SYSTEM_METHOD_PREFIXES = ("system.", "demo.")


class OperationTimeout:
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

        value = str(param_type).lower().strip()
        if ":" in value:
            value = value.split(":", 1)[-1]

        aliases = {
            "str": "string",
            "text": "string",
            "unicode": "string",
            "i4": "int",
            "i8": "int",
            "integer": "int",
            "boolean": "bool",
        }

        return aliases.get(value, value)

    def _has_any(self, text, indicators):
        if not text:
            return False

        low = str(text).lower()
        return any(ind in low for ind in indicators)

    def _normalise_excerpt(self, text, limit=180):
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

    def _is_string_param(self, param):
        return self._normalise_type(param.get("type", "")) in (
            "string",
            "normalizedstring",
            "token",
        )

    def _default_value(self, param_type="string", param_name=""):
        ptype = self._normalise_type(param_type)
        pname = (param_name or "").lower()

        if "email" in pname:
            return "user@example.test"
        if "user" in pname or "name" in pname:
            return "test"
        if "id" in pname:
            return "1"
        if "format" in pname:
            return "safe"
        if "nonce" in pname:
            return "timeout-test-nonce"
        if "account" in pname:
            return "test-account"
        if "password" in pname or "pass" in pname:
            return "test"

        if ptype in ("string", "normalizedstring", "token"):
            return "test"
        if ptype in ("int", "long", "short", "byte"):
            return 1
        if ptype in ("decimal", "float", "double"):
            return 1.0
        if ptype in ("bool",):
            return True
        if ptype in ("array", "list"):
            return []
        if ptype in ("struct", "dict"):
            return {}
        if ptype in ("date", "datetime", "datetime.iso8601"):
            return "2050-01-01T00:00:00"

        return "test"

    def _build_xmlrpc_request(self, method_name, params=None):
        params = params or []
        return xmlrpc.client.dumps(
            tuple(params),
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

    def _send_raw(self, method_name, params=None):
        body = self._build_xmlrpc_request(method_name, params or [])
        start = time.monotonic()

        try:
            response = self.http_client.send_request(
                url=self.helpers.endpoint_url,
                method="POST",
                data=body,
                headers={"Content-Type": "text/xml; charset=utf-8"},
                merge_headers=False,
                allow_redirects=True,
            )
            elapsed = time.monotonic() - start
            return response, elapsed, None
        except Exception as exc:
            elapsed = time.monotonic() - start
            return None, elapsed, f"{type(exc).__name__}: {exc}"

    def _parse_xmlrpc_response(self, response, client_error=None):
        if client_error:
            return {
                "kind": "CLIENT_ERROR",
                "text": client_error,
                "faultCode": None,
                "faultString": "",
                "status": None,
            }

        if response is None:
            return {
                "kind": "NO_RESPONSE",
                "text": "",
                "faultCode": None,
                "faultString": "",
                "status": None,
            }

        text = response.text or ""
        status = getattr(response, "status_code", None)

        try:
            xmlrpc.client.loads(text)
            return {
                "kind": "SUCCESS",
                "text": text,
                "faultCode": None,
                "faultString": "",
                "status": status,
            }
        except xmlrpc.client.Fault as fault:
            return {
                "kind": "FAULT",
                "text": fault.faultString or text,
                "faultCode": fault.faultCode,
                "faultString": fault.faultString or "",
                "status": status,
            }
        except Exception:
            return {
                "kind": "RAW_RESPONSE",
                "text": text,
                "faultCode": None,
                "faultString": "",
                "status": status,
            }

    def _classify_response(self, response, client_error=None):
        parsed = self._parse_xmlrpc_response(response, client_error)
        text = parsed.get("text", "") or ""
        fault_string = parsed.get("faultString", "") or ""
        status = parsed.get("status")
        kind = parsed.get("kind")

        if kind in ("NO_RESPONSE", "CLIENT_ERROR"):
            return "NO_RESPONSE", parsed

        if status in AUTH_DENIED_HTTP_STATUS or self._has_any(text, AUTH_DENIED_INDICATORS):
            return "AUTH_DENIED", parsed

        if kind == "FAULT" and self._has_any(fault_string, SIGNATURE_OR_TYPE_REJECTION_INDICATORS):
            return "SIGNATURE_OR_TYPE_REJECTION", parsed

        if status and status >= 500:
            return "BACKEND_ERROR", parsed

        if self._has_any(text, BACKEND_ERROR_INDICATORS):
            return "BACKEND_ERROR", parsed

        if kind == "SUCCESS":
            return "METHOD_REACHED", parsed

        if kind == "FAULT" and self._has_any(fault_string, BUSINESS_RESPONSE_INDICATORS):
            return "BUSINESS_RESPONSE", parsed

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

            out.append({
                "name": param.get("name") or f"param{index}",
                "type": self._normalise_type(param.get("type") or "string"),
                "source": param.get("typeSource") or param.get("source") or "metadata",
            })

        return out

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
            methods.append({
                "name": name,
                "params": params,
                "source": item.get("source") or "helper_metadata",
            })
            seen.add(name)

        return methods

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
        response, _elapsed, error = self._send_raw("system.listMethods", [])
        classification, parsed = self._classify_response(response, error)

        if classification != "METHOD_REACHED":
            return []

        try:
            values, _method = xmlrpc.client.loads(response.text or "")
            method_names = values[0] if values else []
        except Exception:
            return []

        if not isinstance(method_names, (list, tuple)):
            return []

        methods = []
        seen = set()

        for method_name in method_names:
            if not isinstance(method_name, str) or method_name in seen:
                continue

            seen.add(method_name)
            signature_params = []

            sig_response, _sig_elapsed, sig_error = self._send_raw(
                "system.methodSignature",
                [method_name],
            )
            sig_classification, _sig_parsed = self._classify_response(sig_response, sig_error)

            if sig_classification == "METHOD_REACHED":
                try:
                    sig_values, _sig_method = xmlrpc.client.loads(sig_response.text or "")
                    sig_result = sig_values[0] if sig_values else None
                except Exception:
                    sig_result = None

                if isinstance(sig_result, list) and sig_result:
                    first_signature = sig_result[0]
                    if isinstance(first_signature, list) and len(first_signature) > 1:
                        for index, param_type in enumerate(first_signature[1:], 1):
                            signature_params.append({
                                "name": f"param{index}",
                                "type": self._normalise_type(param_type),
                                "source": "methodSignature",
                            })

            help_params = []
            help_response, _help_elapsed, help_error = self._send_raw(
                "system.methodHelp",
                [method_name],
            )
            help_classification, _help_parsed = self._classify_response(help_response, help_error)

            if help_classification == "METHOD_REACHED":
                try:
                    help_values, _help_method = xmlrpc.client.loads(help_response.text or "")
                    help_result = help_values[0] if help_values else ""
                except Exception:
                    help_result = ""
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

    def _fallback_methods_from_discovery(self):
        methods = []
        discovered = getattr(self.helpers, "discovered_methods", []) or []

        for name in discovered:
            if not isinstance(name, str) or not name:
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
            response, _elapsed, error = self._send_raw(method_name, params)
            classification, _parsed = self._classify_response(response, error)

            if classification == "SIGNATURE_OR_TYPE_REJECTION":
                continue

            if classification in (
                "METHOD_REACHED",
                "BUSINESS_RESPONSE",
                "BACKEND_ERROR",
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

            normalized_method = {
                "name": name,
                "params": params,
                "source": method.get("source", "unknown"),
            }

            if self._has_url_like_param(normalized_method):
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

    def _safe_string_param(self, method):
        for param in method.get("params", []) or []:
            if self._is_string_param(param) and not self._is_url_like_param(param.get("name", "")):
                return param
        return None

    def _baseline_latency(self):
        candidates = ["ping", "demo.ping"]
        timings = []

        for method_name in candidates:
            response, elapsed, error = self._send_raw(method_name, [])
            classification, _parsed = self._classify_response(response, error)
            if classification in ("METHOD_REACHED", "BUSINESS_RESPONSE"):
                timings.append(elapsed)

        if not timings:
            return None

        return min(timings)

    def _slow_reason(self, elapsed, baseline_latency):
        if elapsed >= SLOW_THRESHOLD_SECONDS:
            return "absolute_threshold_exceeded"

        if baseline_latency and baseline_latency > 0:
            if elapsed >= baseline_latency * RELATIVE_SLOW_FACTOR and elapsed >= 1.0:
                return "relative_threshold_exceeded"

        return None

    def _test_normal_method_call(self, method, baseline_latency):
        method_name = method.get("name", "")
        params = self._build_params(method)
        response, elapsed, error = self._send_raw(method_name, params)
        classification, parsed = self._classify_response(response, error)

        if classification in ("SIGNATURE_OR_TYPE_REJECTION", "AUTH_DENIED", "NO_RESPONSE"):
            return None

        reason = self._slow_reason(elapsed, baseline_latency)
        if not reason:
            return None

        return {
            "method": method_name,
            "probe": "normal_call",
            "elapsedSeconds": round(elapsed, 3),
            "thresholdSeconds": SLOW_THRESHOLD_SECONDS,
            "relativeFactor": RELATIVE_SLOW_FACTOR,
            "baselineSeconds": round(baseline_latency, 3) if baseline_latency else None,
            "classification": classification,
            "reason": reason,
            "httpStatus": parsed.get("status"),
        }

    def _test_large_payload_call(self, method, baseline_latency):
        method_name = method.get("name", "")
        param = self._safe_string_param(method)

        if not param:
            return None

        params = self._build_params(
            method,
            overrides={param.get("name"): "A" * LARGE_PAYLOAD_SIZE},
        )
        response, elapsed, error = self._send_raw(method_name, params)
        classification, parsed = self._classify_response(response, error)

        if classification in ("SIGNATURE_OR_TYPE_REJECTION", "AUTH_DENIED", "NO_RESPONSE"):
            return None

        reason = self._slow_reason(elapsed, baseline_latency)
        if not reason:
            return None

        return {
            "method": method_name,
            "parameter": param.get("name"),
            "probe": "large_string_payload",
            "payloadBytesApprox": LARGE_PAYLOAD_SIZE,
            "elapsedSeconds": round(elapsed, 3),
            "thresholdSeconds": SLOW_THRESHOLD_SECONDS,
            "relativeFactor": RELATIVE_SLOW_FACTOR,
            "baselineSeconds": round(baseline_latency, 3) if baseline_latency else None,
            "classification": classification,
            "reason": reason,
            "httpStatus": parsed.get("status"),
        }

    def _dedupe_findings(self, findings):
        seen = set()
        out = []

        for finding in findings:
            key = (
                finding.get("method"),
                finding.get("parameter"),
                finding.get("probe"),
                finding.get("reason"),
            )
            if key in seen:
                continue

            seen.add(key)
            out.append(finding)

        return out

    def _print_findings(self, findings):
        ptprint(
            "Slow XML-RPC operation behavior observed.",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        for finding in findings:
            if finding.get("probe") == "large_string_payload":
                target = f"{finding['method']}.{finding.get('parameter', 'param')}"
                detail = f"large payload, {finding['elapsedSeconds']}s"
            else:
                target = finding["method"]
                detail = f"normal call, {finding['elapsedSeconds']}s"

            ptprint(
                f"  {target}: {detail} ({finding['reason']}).",
                "VULN",
                not self.args.json,
                indent=4,
            )

    def run(self):
        methods = self._candidate_methods()

        if not methods:
            ptprint(
                "No suitable XML-RPC methods available for timeout testing.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        baseline_latency = self._baseline_latency()
        findings = []

        for method in methods:
            normal_finding = self._test_normal_method_call(method, baseline_latency)
            if normal_finding:
                findings.append(normal_finding)

            large_finding = self._test_large_payload_call(method, baseline_latency)
            if large_finding:
                findings.append(large_finding)

        findings = self._dedupe_findings(findings)

        if not findings:
            ptprint(
                "No slow XML-RPC operation behavior observed with tested requests.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        self._print_findings(findings)

        self.ptjsonlib.add_vulnerability(
            "PTV-XMLRPC-SLOW-OPERATION",
            node_key=self.helpers.node_key,
            data={
                "summary": "Slow XML-RPC operation behavior was observed.",
                "description": (
                    "One or more low-risk XML-RPC method calls responded slowly under "
                    "normal or bounded large-payload probes. This may indicate resource "
                    "exhaustion risk or inefficient server-side processing."
                ),
                "confidence": "black-box heuristic",
                "testedMethodCount": len(methods),
                "findingCount": len(findings),
                "thresholdSeconds": SLOW_THRESHOLD_SECONDS,
                "relativeSlowFactor": RELATIVE_SLOW_FACTOR,
                "baselineSeconds": round(baseline_latency, 3) if baseline_latency else None,
                "findings": findings,
                "methods": sorted(set(f["method"] for f in findings)),
                "probes": sorted(set(f["probe"] for f in findings)),
            },
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    OperationTimeout(args, ptjsonlib, helpers, http_client, common_tests).run()
