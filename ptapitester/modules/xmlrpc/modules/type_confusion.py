"""
XML-RPC Type Confusion test — sends unexpected parameter types
"""

import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Type Confusion test"


MAX_METHODS_TO_TEST = 20
MAX_MUTATIONS_PER_METHOD = 12


DANGEROUS_METHOD_KEYWORDS = [
    "delete","remove","create","new","insert","update","edit","set",
    "change","write","reset","disable","enable",
]


AUTH_DENIED_INDICATORS = [
    "authentication required","auth required","unauthorized","unauthorised",
    "permission denied","login required","not logged in","invalid credentials",
    "invalid token","token required","missing token","api key required",
    "401 unauthorized","403 forbidden",
]


METHOD_NOT_FOUND_INDICATORS = [
    "method not found","unknown method","no such method","method does not exist","procedure not found",
]


INVALID_PARAMS_INDICATORS = [
    "invalid params","invalid parameter","missing parameter","missing argument","wrong number of parameters",
    "wrong number of arguments","takes exactly","takes at least","expected","required positional","bad request",
]


TYPE_ERROR_INDICATORS = [
    "typeerror","valueerror","attributeerror","keyerror","indexerror","has no attribute","object has no attribute",
    "unsupported operand","object is not","object has no","unexpected type","invalid literal","cannot convert",
    "could not convert","not supported","traceback","stack trace","exception",
]


class TypeConfusion:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _has_any(self, text, indicators):
        if not text:
            return False
        low = text.lower()
        return any(ind in low for ind in indicators)

    def _response_excerpt(self, response, limit=220):
        if response is None:
            return ""
        return self._text_excerpt(response.text or "", limit)
    
    def _text_excerpt(self, text, limit=220):
        if not text:
            return ""
        return text[:limit].strip().replace("\n", " ").replace("\r", " ")

    def _normalise_type(self, typ):
        if not typ:
            return "string"

        t = str(typ).lower().strip()

        if ":" in t:
            t = t.split(":", 1)[-1]

        return t

    def _is_dangerous_method(self, method_name):
        low = (method_name or "").lower()
        return any(word in low for word in DANGEROUS_METHOD_KEYWORDS)

    def _build_call(self, method_name, params=None):
        params = tuple(params or ())
        return xmlrpc.client.dumps(
            params,
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

    def _send_call(self, method_name, params=None):
        payload = self._build_call(method_name, params)
        return self.helpers.send_xmlrpc_raw(data=payload)

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

        if response.status_code in (401, 403, 407):
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

            if self._has_any(fault_text, TYPE_ERROR_INDICATORS):
                return "VERBOSE_TYPE_ERROR", parsed

            if self._has_any(fault_text, INVALID_PARAMS_INDICATORS):
                return "CLEAN_REJECTION", parsed

            return "XMLRPC_FAULT", parsed

        if response.status_code >= 500:
            return "SERVER_ERROR", parsed

        if parsed["type"] == "PARSE_ERROR":
            return "PARSE_ERROR", parsed

        return "AMBIGUOUS", parsed

    def _extract_param_types_from_signature(self, sig):
        """
        XML-RPC signature usually looks like:
        [['return_type', 'param1_type', 'param2_type']]
        """
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
                    return param_types, info.get("source", "metadata.param_types")

                signature = info.get("signature")
                parsed = self._extract_param_types_from_signature(signature)
                if parsed is not None:
                    return parsed, "metadata.signature"

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
                    return parsed, attr

                if isinstance(sig, list):
                    return sig, attr

        return None, "none"

    def _default_value_for_type(self, typ):
        t = self._normalise_type(typ)

        if t in ("string", "str"):
            return "test"

        if t in ("int", "i4", "i8", "integer", "long", "short"):
            return 1

        if t in ("double", "float", "decimal"):
            return 1.0

        if t in ("boolean", "bool"):
            return True

        if t in ("array", "list"):
            return ["test"]

        if t in ("struct", "dict"):
            return {"value": "test"}

        if t == "base64":
            return xmlrpc.client.Binary(b"test")

        if t in ("datetime", "datetime.iso8601", "date"):
            return xmlrpc.client.DateTime("20500101T00:00:00")

        return "test"

    def _mutated_values_for_expected_type(self, expected_type):

        t = self._normalise_type(expected_type)

        all_candidates = [
            ("boolean True", True),
            ("boolean False", False),
            ("integer", 99999),
            ("double", 99.99),
            ("string non-numeric", "NOT_A_VALID_EXPECTED_TYPE"),
            ("array/list", [1, 2, 3]),
            ("struct/dict", {"x": 1}),
            ("empty string", ""),
        ]

        expected_groups = {
            "string": {"string", "str"},
            "integer": {"int", "i4", "i8", "integer", "long", "short"},
            "double": {"double", "float", "decimal"},
            "boolean": {"boolean", "bool"},
            "array": {"array", "list"},
            "struct": {"struct", "dict"},
        }

        def candidate_matches_expected(candidate_name):
            if t in expected_groups["string"]:
                return candidate_name == "string non-numeric"
            if t in expected_groups["integer"]:
                return candidate_name == "integer"
            if t in expected_groups["double"]:
                return candidate_name == "double"
            if t in expected_groups["boolean"]:
                return candidate_name.startswith("boolean")
            if t in expected_groups["array"]:
                return candidate_name == "array/list"
            if t in expected_groups["struct"]:
                return candidate_name == "struct/dict"
            return False

        return [
            (name, value)
            for name, value in all_candidates
            if not candidate_matches_expected(name)
        ]

    def _get_methods_to_test(self):
        methods = set()

        for m in getattr(self.helpers, "discovered_methods", []) or []:
            if isinstance(m, str):
                methods.add(m)

        metadata = getattr(self.helpers, "metadata", {}) or {}
        if isinstance(metadata, dict):
            for m in metadata.keys():
                if isinstance(m, str):
                    methods.add(m)

        result = []

        for method in sorted(methods):
            if method.startswith("system."):
                continue

            if method == "ping":
                continue

            if self._is_dangerous_method(method):
                continue

            result.append(method)

        return result

    def _test_method(self, method_name):
        findings = []
        observations = []

        param_types, signature_source = self._get_param_types_for_method(method_name)

        if param_types is None:
            observations.append({
                "method": method_name,
                "classification": "SKIPPED",
                "reason": "NO_PARAMETER_METADATA",
                "message": (
                    "No parameter type metadata available. Skipping to avoid "
                    "wrong-argument-count false positives."
                ),
            })
            return findings, observations

        baseline_params = [
            self._default_value_for_type(t)
            for t in param_types
        ]

        baseline_response = self._send_call(method_name, baseline_params)
        baseline_class, baseline_parsed = self._classify_response(baseline_response)

        if baseline_class != "SUCCESS":
            observations.append({
                "method": method_name,
                "classification": "SKIPPED",
                "reason": "BASELINE_NOT_SUCCESSFUL",
                "baselineClassification": baseline_class,
                "signatureSource": signature_source,
                "message": (
                    "Valid baseline request did not return a successful response; "
                    "type-confusion mutations would be unreliable."
                ),
            })
            return findings, observations

        mutation_count = 0

        for index, expected_type in enumerate(param_types):
            if mutation_count >= MAX_MUTATIONS_PER_METHOD:
                break

            for mutation_name, mutation_value in self._mutated_values_for_expected_type(expected_type):
                if mutation_count >= MAX_MUTATIONS_PER_METHOD:
                    break

                params = list(baseline_params)
                params[index] = mutation_value

                response = self._send_call(method_name, params)
                cls, parsed = self._classify_response(response)
                http_status = response.status_code if response is not None else None

                mutation_record = {
                    "method": method_name,
                    "parameterIndex": index,
                    "expectedType": expected_type,
                    "mutation": mutation_name,
                    "classification": cls,
                    "httpStatus": http_status,
                    "signatureSource": signature_source,
                }

                if cls in ("VERBOSE_TYPE_ERROR", "SERVER_ERROR"):
                    findings.append({
                        **mutation_record,
                        "type": "TYPE_CONFUSION_VERBOSE_ERROR",
                        "faultCode": parsed.get("faultCode"),
                        "faultStringExcerpt": self._text_excerpt(parsed.get("faultString", "") or ""),
                        "responseExcerpt": self._response_excerpt(response),
                        "message": (
                            "Unexpected parameter type caused verbose backend/type error."
                        ),
                    })

                elif cls == "SUCCESS":
                    observations.append({
                        **mutation_record,
                        "type": "UNEXPECTED_TYPE_ACCEPTED",
                        "message": (
                            "Unexpected parameter type was accepted without an error. "
                            "This may be normal type coercion or weak type enforcement; "
                            "not treated as a vulnerability by itself."
                        ),
                    })

                elif cls == "CLEAN_REJECTION":
                    observations.append({
                        **mutation_record,
                        "type": "CLEAN_TYPE_REJECTION",
                        "message": (
                            "Unexpected parameter type was rejected cleanly."
                        ),
                    })

                elif cls == "AUTH_DENIED":
                    observations.append({
                        **mutation_record,
                        "type": "AUTH_DENIED",
                        "message": (
                            "Request resulted in authentication/authorization denial; "
                            "type handling could not be evaluated."
                        ),
                    })

                elif cls == "METHOD_NOT_FOUND":
                    observations.append({
                        **mutation_record,
                        "type": "METHOD_NOT_FOUND",
                        "message": "Method was not found during mutation test.",
                    })

                else:
                    observations.append({
                        **mutation_record,
                        "type": "AMBIGUOUS_TYPE_HANDLING",
                        "message": (
                            "Mutation produced an ambiguous response."
                        ),
                    })

                mutation_count += 1

        return findings, observations

    def run(self):
        methods_to_test = self._get_methods_to_test()

        if not methods_to_test:
            ptprint("No suitable methods for type confusion. Skipping.",
                    "INFO", not self.args.json, indent=4)
            return

        findings = []
        observations = []
        tested_methods = 0

        for method in methods_to_test:
            if tested_methods >= MAX_METHODS_TO_TEST:
                break

            method_findings, method_observations = self._test_method(method)

            findings.extend(method_findings)
            observations.extend(method_observations)
            tested_methods += 1

        if findings:
            ptprint("XML-RPC type confusion issues found.", "VULN",
                    not self.args.json, indent=4, colortext=True)

            grouped_findings = self._group_findings_for_console(findings)

            for group in grouped_findings:
                mutations = ", ".join(group["mutations"])

                ptprint(
                    f"  Method '{group['method']}', parameter "
                    f"#{group['parameterIndex']} expected "
                    f"{group['expectedType']}: verbose backend/type errors "
                    f"for {mutations}.",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-TYPE-CONFUSION",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC type confusion / verbose type handling issues were observed.",
                    "description": (
                        "Unexpected XML-RPC parameter types caused verbose backend/type "
                        "errors or server errors. Clean invalid-parameter responses are "
                        "not treated as vulnerabilities."
                    ),
                    "confidence": "black-box heuristic",
                    "testedMethods": tested_methods,
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                },
            )
            return

        ptprint("Server handled tested XML-RPC type mutations without verbose backend errors.",
                "OK", not self.args.json, indent=4)
        
        self.ptjsonlib.add_properties(
            properties={
                "xmlrpcTypeConfusionTest": {
                    "status": "no_verbose_type_confusion_detected",
                    "testedMethods": tested_methods,
                    "observationCount": len(observations),
                    "observations": observations,
                }
            },
            node_key=self.helpers.node_key,
        )

    def _group_findings_for_console(self, findings):
        
        grouped = {}

        for f in findings:
            key = (
                f.get("method"),
                f.get("parameterIndex"),
                f.get("expectedType"),
            )

            if key not in grouped:
                grouped[key] = {
                    "method": f.get("method"),
                    "parameterIndex": f.get("parameterIndex"),
                    "expectedType": f.get("expectedType"),
                    "mutations": [],
                    "message": f.get("message"),
                }

            mutation = f.get("mutation")
            if mutation and mutation not in grouped[key]["mutations"]:
                grouped[key]["mutations"].append(mutation)

        return list(grouped.values())


def run(args, ptjsonlib, helpers, http_client, common_tests):
    TypeConfusion(args, ptjsonlib, helpers, http_client, common_tests).run()