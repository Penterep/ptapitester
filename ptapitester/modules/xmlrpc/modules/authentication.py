"""
XML-RPC Authentication test
"""

import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Authentication test"


AUTH_DENIED_HTTP_STATUS = {401, 403, 407}

AUTH_DENIED_INDICATORS = [
    "authentication required","auth required","unauthorized","unauthorised","access denied","permission denied",
    "forbidden","login required","not logged in","invalid credentials","invalid token","token required",
    "missing token","jwt required","api key required","cookie required",
]

INVALID_PARAMS_INDICATORS = [
    "invalid params","invalid parameter","missing parameter","missing argument","wrong number of parameters",
    "wrong number of arguments","takes exactly","takes at least","expected","required positional","argument","parameter",
]

METHOD_NOT_FOUND_INDICATORS = [
    "method not found","unknown method","no such method","method does not exist","procedure not found",
]

SENSITIVE_METHOD_KEYWORDS = [
    "admin","config","debug","secret","token","password","credential","user","users","profile",
    "account","role","permission","protected","private","data",
]

DESTRUCTIVE_METHOD_KEYWORDS = [
    "delete","remove","create","new","insert","update","edit","set","change","write","reset","disable","enable",
]

SENSITIVE_RESPONSE_INDICATORS = [
    "password","password_hash","secret","token","jwt","api_key","apikey","credential","role","admin",
    "debug","config","database","private",
]

MAX_METHODS_TO_TEST = 20


class AuthenticationTest:
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

    def _send_unauthenticated_call(self, method_name, params=None):
        url = self._endpoint_url()
        if not url:
            return None

        body = self._build_call(method_name, params)

        try:
            return self.http_client.send_request(
                url=url,
                method="POST",
                data=body,
                headers={
                    "Content-Type": "text/xml",
                },
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
                "raw": "",
            }

        raw = response.text or ""

        try:
            params, _method = xmlrpc.client.loads(raw)
            return {
                "type": "SUCCESS",
                "params": list(params),
                "faultCode": None,
                "faultString": "",
                "raw": raw,
            }
        except xmlrpc.client.Fault as fault:
            return {
                "type": "FAULT",
                "params": [],
                "faultCode": fault.faultCode,
                "faultString": fault.faultString or "",
                "raw": raw,
            }
        except Exception:
            return {
                "type": "PARSE_ERROR",
                "params": [],
                "faultCode": None,
                "faultString": "",
                "raw": raw,
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

    def _response_contains_sensitive_data(self, response):
        if response is None:
            return False
        return self._has_any(response.text or "", SENSITIVE_RESPONSE_INDICATORS)

    def _is_sensitive_method(self, method_name):
        low = (method_name or "").lower()
        return any(k in low for k in SENSITIVE_METHOD_KEYWORDS)

    def _is_destructive_method(self, method_name):
        low = (method_name or "").lower()
        return any(k in low for k in DESTRUCTIVE_METHOD_KEYWORDS)

    def _get_known_methods_without_introspection(self):
        methods = set()

        for m in getattr(self.helpers, "discovered_methods", []) or []:
            if isinstance(m, str):
                methods.add(m)

        metadata = getattr(self.helpers, "metadata", {}) or {}
        if isinstance(metadata, dict):
            for m in metadata.keys():
                if isinstance(m, str):
                    methods.add(m)

        return sorted(methods)

    def _get_signature_for_method(self, method_name):
        metadata = getattr(self.helpers, "metadata", {}) or {}

        if isinstance(metadata, dict):
            info = metadata.get(method_name)
            if isinstance(info, dict):
                param_types = info.get("param_types")
                if isinstance(param_types, list):
                    return param_types

                signature = info.get("signature")
                if isinstance(signature, list):
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
                if isinstance(sig, list):
                    parsed = self._extract_param_types_from_signature(sig)
                    return parsed if parsed is not None else sig

        return None

    def _extract_param_types_from_signature(self, sig):
        if not sig:
            return None

        if isinstance(sig, list) and sig and isinstance(sig[0], (list, tuple)):
            first = list(sig[0])
            if len(first) >= 1:
                return first[1:]

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
        sig = self._get_signature_for_method(method_name)

        final_sets = [[]]

        if sig:
            typed_params = [self._default_value_for_type(t) for t in sig]
            if typed_params not in final_sets:
                final_sets.append(typed_params)

        low = method_name.lower()
        if any(k in low for k in ("get", "read", "find", "lookup", "list", "show")):
            for candidate in [["test"], [1], [{"id": 1}], [{"username": "test"}]]:
                if candidate not in final_sets:
                    final_sets.append(candidate)

        return final_sets[:5]

    def _method_result_summary(self, parsed):
        if not parsed:
            return ""

        if parsed.get("type") == "FAULT":
            return (
                f"faultCode={parsed.get('faultCode')}, "
                f"faultString={parsed.get('faultString')!r}"
            )

        if parsed.get("type") == "SUCCESS":
            params = parsed.get("params", [])
            return f"returned {len(params)} value(s)"

        return parsed.get("type", "")

    def _test_sensitive_methods(self, known_methods):
        findings = []
        observations = []

        sensitive_methods = [
            m for m in known_methods
            if not m.startswith("system.") and self._is_sensitive_method(m)
        ]

        if not sensitive_methods:
            observations.append({
                "test": "sensitiveMethodDiscovery",
                "classification": "NO_CANDIDATES",
            })
            return findings, observations

        tested = 0

        for method in sensitive_methods:
            if tested >= MAX_METHODS_TO_TEST:
                break

            if self._is_destructive_method(method):
                observations.append({
                    "method": method,
                    "classification": "SKIPPED",
                    "reason": "POTENTIALLY_DESTRUCTIVE",
                })
                continue

            tested += 1
            param_sets = self._param_sets_for_method(method)

            method_observations = []
            method_had_success = False
            method_had_auth_denial = False
            method_had_invalid_params = False

            for params in param_sets:
                r = self._send_unauthenticated_call(method, params)
                classification, parsed = self._classify_response(r)
                http_status = r.status_code if r is not None else None

                if classification == "AUTH_DENIED":
                    method_had_auth_denial = True
                    method_observations.append({
                        "method": method,
                        "paramsUsed": params,
                        "classification": "AUTH_DENIED",
                        "httpStatus": http_status,
                    })
                    break

                if classification == "INVALID_PARAMS":
                    method_had_invalid_params = True
                    continue

                if classification == "METHOD_NOT_FOUND":
                    method_observations.append({
                        "method": method,
                        "paramsUsed": params,
                        "classification": "METHOD_NOT_FOUND",
                        "httpStatus": http_status,
                    })
                    break

                if classification == "SUCCESS":
                    method_had_success = True
                    sensitive_data = self._response_contains_sensitive_data(r)

                    findings.append({
                        "type": "SENSITIVE_METHOD_CALLABLE",
                        "method": method,
                        "classification": "SUCCESS",
                        "httpStatus": http_status,
                        "paramsUsed": params,
                        "sensitiveDataIndicators": sensitive_data,
                        "message": (
                            "Sensitive-looking XML-RPC method returned a successful "
                            "response without authentication."
                        ),
                        "resultSummary": self._method_result_summary(parsed),
                    })
                    break

                method_observations.append({
                    "method": method,
                    "paramsUsed": params,
                    "classification": classification,
                    "httpStatus": http_status,
                    "details": self._method_result_summary(parsed),
                })

            if method_had_success:
                continue

            if method_had_auth_denial:
                observations.extend(method_observations)
                continue

            if method_had_invalid_params:
                observations.append({
                    "method": method,
                    "classification": "REACHABLE_BUT_NOT_CONFIRMED",
                })
                continue

            observations.extend(method_observations)

        return findings, observations

    def run(self):
        findings = []
        observations = []

        known_methods = self._get_known_methods_without_introspection()

        if not known_methods:
            ptprint(
                "No previously discovered XML-RPC methods available. "
                "Skipping authentication test. Run the XML-RPC Introspection "
                "test or another discovery module first.",
                "INFO", not self.args.json, indent=4
            )

            self.ptjsonlib.add_properties(
                properties={
                    "xmlrpcAuthenticationTest": {
                        "status": "skipped",
                        "reason": "NO_PREVIOUSLY_DISCOVERED_METHODS",
                        "message": (
                            "Authentication test does not perform introspection. "
                            "No methods were available from previous discovery."
                        )
                    }
                },
                node_key=self.helpers.node_key
            )
            return

        method_findings, method_observations = self._test_sensitive_methods(known_methods)
        findings.extend(method_findings)
        observations.extend(method_observations)

        if findings:
            ptprint("XML-RPC unauthenticated method access found.", "VULN",
                    not self.args.json, indent=4, colortext=True)

            for f in findings:
                ptprint(
                    f"  Sensitive-looking method '{f['method']}' returned "
                    f"success without authentication.",
                    "VULN", not self.args.json, indent=4
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-UNAUTHENTICATED-METHOD-ACCESS",
                node_key=self.helpers.node_key,
                data={
                    "summary": "Unauthenticated XML-RPC method access was observed.",
                    "description": (
                        "One or more sensitive-looking XML-RPC methods returned "
                        "successful responses without authentication."
                    ),
                    "confidence": "black-box heuristic",
                    "methodSource": "previously discovered methods",
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                }
            )
            return

        ptprint("No unauthenticated XML-RPC method access confirmed.",
                "OK", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, common_tests):
    AuthenticationTest(args, ptjsonlib, helpers, http_client, common_tests).run()