"""
XML-RPC X-Forwarded-For authorization bypass test
"""

import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC X-Forwarded-For bypass test"


AUTH_DENIED_HTTP_STATUS = {401, 403, 407}

AUTH_DENIED_INDICATORS = [
    "authentication required","auth required","unauthorized","unauthorised","permission denied","login required",
    "not logged in","invalid credentials","invalid token","token required","missing token","api key required",
    "cookie required","session expired","session required","401 unauthorized","403 forbidden","access denied",
    "requires trusted internal ip","trusted internal ip",
]

INVALID_PARAMS_INDICATORS = [
    "invalid params","invalid parameter","missing parameter","missing argument","wrong number of parameters","wrong number of arguments",
    "takes exactly","takes at least","expected","required positional","argument","parameter",
]

METHOD_NOT_FOUND_INDICATORS = [
    "method not found","unknown method","no such method","method does not exist","procedure not found",
]

SENSITIVE_METHOD_KEYWORDS = [
    "admin","config","debug","secret","token","password","credential","user",
    "users","profile","account","role","permission","protected","private","data",
]

DESTRUCTIVE_METHOD_KEYWORDS = [
    "delete","remove","create","new","insert","update","edit",
    "set","change","write","reset","disable","enable",
]

SPOOFED_IP_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),("X-Forwarded-For", "::1"),("X-Forwarded-For", "localhost"),("X-Forwarded-For", "10.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1, 10.0.0.1"),("X-Real-IP", "127.0.0.1"),("X-Client-IP", "127.0.0.1"),("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),("X-Remote-Addr", "127.0.0.1"),("X-Original-Forwarded-For", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1"),("Forwarded", 'for="127.0.0.1"'),
]

MAX_METHODS_TO_TEST = 20
MAX_PARAM_SETS_PER_METHOD = 5


class XForwardedForBypass:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _endpoint_url(self):
        return getattr(self.helpers, "endpoint_url", None) or getattr(self.args, "url", None)

    def _has_any(self, text, indicators):
        if not text:
            return False
        low = text.lower()
        return any(ind in low for ind in indicators)

    def _build_call(self, method_name, params=None):
        params = tuple(params or ())
        return xmlrpc.client.dumps(
            params,
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

    def _send_raw_call(self, method_name, params=None, extra_headers=None):
        url = self._endpoint_url()
        if not url:
            return None

        headers = {
            "Content-Type": "text/xml",
        }

        if extra_headers:
            headers.update(extra_headers)

        body = self._build_call(method_name, params)

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

    def _parse_xmlrpc_response(self, response):
        if response is None:
            return {
                "type": "NO_RESPONSE",
                "params": [],
                "faultCode": None,
                "faultString": "",
            }

        raw = response.text or ""

        try:
            params, _method = xmlrpc.client.loads(raw)
            return {
                "type": "SUCCESS",
                "params": list(params),
                "faultCode": None,
                "faultString": "",
            }
        except xmlrpc.client.Fault as fault:
            return {
                "type": "FAULT",
                "params": [],
                "faultCode": fault.faultCode,
                "faultString": fault.faultString or "",
            }
        except Exception as e:
            return {
                "type": "PARSE_ERROR",
                "params": [],
                "faultCode": None,
                "faultString": str(e),
            }

    def _classify_response(self, response):

        parsed = self._parse_xmlrpc_response(response)

        if response is None:
            return "NO_RESPONSE", parsed

        raw = response.text or ""

        if response.status_code in AUTH_DENIED_HTTP_STATUS:
            return "AUTH_DENIED", parsed

        if self._has_any(raw, AUTH_DENIED_INDICATORS):
            return "AUTH_DENIED", parsed

        if parsed["type"] == "SUCCESS":
            return "SUCCESS", parsed

        if parsed["type"] == "FAULT":
            fault_text = parsed.get("faultString", "") or ""

            if parsed.get("faultCode") in AUTH_DENIED_HTTP_STATUS:
                return "AUTH_DENIED", parsed

            if self._has_any(fault_text, AUTH_DENIED_INDICATORS):
                return "AUTH_DENIED", parsed

            if self._has_any(fault_text, METHOD_NOT_FOUND_INDICATORS):
                return "METHOD_NOT_FOUND", parsed

            if self._has_any(fault_text, INVALID_PARAMS_INDICATORS):
                return "INVALID_PARAMS", parsed

            return "XMLRPC_FAULT", parsed

        if response.status_code >= 500:
            return "SERVER_ERROR", parsed

        if parsed["type"] == "PARSE_ERROR":
            return "PARSE_ERROR", parsed

        return "AMBIGUOUS", parsed

    def _response_excerpt(self, response, limit=180):
        if response is None:
            return ""
        return (response.text or "")[:limit].strip().replace("\n", " ")

    def _is_sensitive_method(self, method_name):
        low = (method_name or "").lower()
        return any(k in low for k in SENSITIVE_METHOD_KEYWORDS)

    def _is_destructive_method(self, method_name):
        low = (method_name or "").lower()
        return any(k in low for k in DESTRUCTIVE_METHOD_KEYWORDS)

    def _extract_param_types_from_signature(self, sig):

        if not sig:
            return None

        if isinstance(sig, list) and sig and isinstance(sig[0], (list, tuple)):
            first = list(sig[0])
            if len(first) >= 1:
                return first[1:]

        return None

    def _get_param_types_for_method(self, method_name):
        
        metadata = getattr(self.helpers, "metadata", {}) or {}

        if isinstance(metadata, dict):
            info = metadata.get(method_name)

            if isinstance(info, dict):
                param_types = info.get("param_types")
                if isinstance(param_types, list):
                    return param_types

                signature = info.get("signature")
                parsed = self._extract_param_types_from_signature(signature)
                if parsed is not None:
                    return parsed

        possible_attrs = [
            "method_signatures",
            "discovered_signatures",
            "method_signature_map",
            "signatures",
        ]

        for attr in possible_attrs:
            sigs = getattr(self.helpers, attr, None)
            if isinstance(sigs, dict) and method_name in sigs:
                sig = sigs[method_name]

                parsed = self._extract_param_types_from_signature(sig)
                if parsed is not None:
                    return parsed

                if isinstance(sig, list):
                    return sig

        return None

    def _default_value_for_type(self, typ):
        if not typ:
            return "test"

        t = str(typ).lower()

        if ":" in t:
            t = t.split(":", 1)[-1]

        if t in ("string", "str"):
            return "test"

        if t in ("int", "i4", "i8", "integer", "long", "short"):
            return 1

        if t in ("double", "float", "decimal"):
            return 1.0

        if t in ("boolean", "bool"):
            return True

        if t in ("array", "list"):
            return []

        if t in ("struct", "dict"):
            return {}

        if t == "base64":
            return xmlrpc.client.Binary(b"test")

        if t in ("datetime", "datetime.iso8601", "date"):
            return xmlrpc.client.DateTime("20260101T00:00:00")

        return "test"

    def _param_sets_for_method(self, method_name):
        
        param_sets = [[]]

        param_types = self._get_param_types_for_method(method_name)
        if param_types is not None:
            typed = [self._default_value_for_type(t) for t in param_types]
            if typed not in param_sets:
                param_sets.append(typed)

        low = method_name.lower()

        if any(k in low for k in ("get", "read", "find", "lookup", "list", "show")):
            for candidate in (
                ["test"],
                [1],
                [{"id": 1}],
                [{"username": "test"}],
            ):
                if candidate not in param_sets:
                    param_sets.append(candidate)

        return param_sets[:MAX_PARAM_SETS_PER_METHOD]

    def _get_candidate_methods(self):
        
        methods = set()

        for m in getattr(self.helpers, "discovered_methods", []) or []:
            if isinstance(m, str):
                methods.add(m)

        metadata = getattr(self.helpers, "metadata", {}) or {}
        if isinstance(metadata, dict):
            for m in metadata.keys():
                if isinstance(m, str):
                    methods.add(m)

        candidates = []

        for method in sorted(methods):
            if method.startswith("system."):
                continue

            if not self._is_sensitive_method(method):
                continue

            if self._is_destructive_method(method):
                continue

            candidates.append(method)

        return candidates

    def _test_method(self, method):
        findings = []
        observations = []

        param_sets = self._param_sets_for_method(method)

        baseline_case = None

        for params in param_sets:
            baseline = self._send_raw_call(method, params)
            baseline_class, baseline_parsed = self._classify_response(baseline)

            if baseline_class == "AUTH_DENIED":
                baseline_case = {
                    "params": params,
                    "response": baseline,
                    "classification": baseline_class,
                    "httpStatus": baseline.status_code if baseline is not None else None,
                }
                break

            if baseline_class == "SUCCESS":
                observations.append({
                    "method": method,
                    "paramsUsed": params,
                    "classification": "BASELINE_ALREADY_SUCCESS",
                    "httpStatus": baseline.status_code if baseline is not None else None,
                })
                return findings, observations

        if baseline_case is None:
            observations.append({
                "method": method,
                "classification": "NO_AUTH_DENIED_BASELINE",
                "paramSetsAttempted": len(param_sets),
            })
            return findings, observations

        baseline_params = baseline_case["params"]

        for header_name, header_value in SPOOFED_IP_HEADERS:
            spoofed = self._send_raw_call(
                method,
                baseline_params,
                extra_headers={header_name: header_value},
            )

            spoofed_class, spoofed_parsed = self._classify_response(spoofed)
            spoofed_status = spoofed.status_code if spoofed is not None else None

            if spoofed_class == "SUCCESS":
                findings.append({
                    "type": "TRUSTED_PROXY_HEADER_AUTH_BYPASS",
                    "method": method,
                    "paramsUsed": baseline_params,
                    "header": header_name,
                    "headerValue": header_value,
                    "baselineClassification": baseline_case["classification"],
                    "baselineHttpStatus": baseline_case["httpStatus"],
                    "spoofedClassification": spoofed_class,
                    "spoofedHttpStatus": spoofed_status,
                    "message": (
                        "Method was denied without spoofed IP headers but "
                        "returned a successful response when a trusted-proxy "
                        "client IP header was supplied."
                    ),
                })
                return findings, observations

            all_response_text = ""
            if spoofed is not None:
                all_response_text = (spoofed.text or "") + str(dict(spoofed.headers))

            if header_value in all_response_text:
                observations.append({
                    "method": method,
                    "classification": "HEADER_REFLECTION",
                    "header": header_name,
                    "headerValue": header_value,
                    "spoofedHttpStatus": spoofed_status,
                })

        return findings, observations


    def run(self):
        candidates = self._get_candidate_methods()

        if not candidates:
            ptprint(
                "No suitable sensitive XML-RPC methods available for XFF bypass test.",
                "INFO",
                not self.args.json,
                indent=4,
            )
            return

        findings = []
        observations = []
        tested_methods = 0

        for method in candidates:
            if tested_methods >= MAX_METHODS_TO_TEST:
                break

            method_findings, method_observations = self._test_method(method)

            findings.extend(method_findings)
            observations.extend(method_observations)
            tested_methods += 1

        if findings:
            ptprint("XML-RPC trusted proxy header authorization bypass detected.",
                    "VULN", not self.args.json, indent=4, colortext=True)

            for finding in findings:
                ptprint(
                    f"  Method '{finding['method']}' was denied without spoofed "
                    f"headers but succeeded with "
                    f"{finding['header']}: {finding['headerValue']}.",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-TRUSTED-PROXY-HEADER-BYPASS",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC trusted proxy header authorization bypass was observed.",
                    "description": (
                        "A sensitive-looking XML-RPC method was denied in the "
                        "baseline request but returned a successful response "
                        "when a spoofed client-IP forwarding header was supplied."
                    ),
                    "confidence": "black-box heuristic",
                    "testedMethods": tested_methods,
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                    "note": (
                        "Header reflection and response size differences are not "
                        "treated as vulnerabilities. A finding requires an "
                        "AUTH_DENIED -> SUCCESS transition."
                    ),
                },
            )
            return

        ptprint("No XML-RPC trusted proxy header authorization bypass detected.",
                "OK", not self.args.json, indent=4)

        self.ptjsonlib.add_properties(
            properties={
                "xmlrpcXForwardedForBypassTest": {
                    "status": "no_bypass_detected",
                    "testedMethods": tested_methods,
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "No AUTH_DENIED -> SUCCESS transition was observed "
                        "for tested methods and spoofed IP headers."
                    ),
                }
            },
            node_key=self.helpers.node_key,
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XForwardedForBypass(args, ptjsonlib, helpers, http_client, common_tests).run()