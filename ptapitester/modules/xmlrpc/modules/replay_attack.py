"""
XML-RPC Replay Attack test
"""

import time
import hashlib
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Replay Attack test"


ANTI_REPLAY_PARAM_KEYWORDS = [
    "nonce","timestamp","timeStamp","created","expires","messageid","message_id","requestid",
    "request_id","correlationid","correlation_id","sequence","seq","signature","digest","token",
]

REPLAY_REJECTION_INDICATORS = [
    "replay detected","replay attack detected","replayed request","request replayed","duplicate",
    "already used","nonce used","nonce already","invalid nonce","stale nonce","expired nonce",
    "timestamp expired","expired timestamp","stale timestamp","message already processed",
    "request already processed","duplicate request","duplicate message","invalid sequence","sequence already",
]

AUTH_DENIED_INDICATORS = [
    "authentication required","auth required","unauthorized","unauthorised","permission denied","login required","not logged in","invalid credentials",
    "invalid token","token required","missing token","api key required","session expired","session required","401 unauthorized","403 forbidden",
]

INVALID_PARAMS_INDICATORS = [
    "invalid params","invalid parameter","missing parameter","missing argument","wrong number of parameters",
    "wrong number of arguments","takes exactly","takes at least","expected","required positional","bad request",
]

METHOD_NOT_FOUND_INDICATORS = [
    "method not found","unknown method","no such method","method does not exist","procedure not found",
]

DESTRUCTIVE_METHOD_KEYWORDS = [
    "delete","remove","drop","destroy","disable","reset",
]

MAX_METHODS_TO_TEST = 20


class ReplayAttack:
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
        return any(ind.lower() in low for ind in indicators)

    def _matched(self, text, indicators):
        if not text:
            return []
        low = text.lower()
        return [ind for ind in indicators if ind.lower() in low]

    def _normalise_type(self, typ):
        if not typ:
            return "string"

        t = str(typ).lower().strip()

        if ":" in t:
            t = t.split(":", 1)[-1]

        return t

    def _is_destructive_method(self, method_name):
        low = (method_name or "").lower()
        return any(k in low for k in DESTRUCTIVE_METHOD_KEYWORDS)

    def _is_anti_replay_param(self, param_name):
        low = (param_name or "").lower()
        return any(k.lower() in low for k in ANTI_REPLAY_PARAM_KEYWORDS)

    def _response_excerpt(self, response, limit=220):
        if response is None:
            return ""
        return (response.text or "")[:limit].strip().replace("\n", " ").replace("\r", " ")

    def _body_hash(self, response):
        if response is None:
            return None
        return hashlib.sha256((response.text or "").encode("utf-8")).hexdigest()

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
        fault = parsed.get("faultString", "") or ""
        combined = raw + "\n" + fault

        if response.status_code in (401, 403, 407):
            return "AUTH_DENIED", parsed

        if self._has_any(combined, AUTH_DENIED_INDICATORS):
            return "AUTH_DENIED", parsed

        if parsed["type"] == "SUCCESS":
            return "SUCCESS", parsed

        if parsed["type"] == "FAULT" and self._has_any(combined, REPLAY_REJECTION_INDICATORS):
            return "REPLAY_REJECTED", parsed

        if parsed["type"] == "FAULT":
            if self._has_any(fault, METHOD_NOT_FOUND_INDICATORS):
                return "METHOD_NOT_FOUND", parsed

            if self._has_any(fault, INVALID_PARAMS_INDICATORS):
                return "INVALID_PARAMS", parsed

            return "XMLRPC_FAULT", parsed

        if response.status_code >= 500:
            return "SERVER_ERROR", parsed

        if parsed["type"] == "PARSE_ERROR":
            return "PARSE_ERROR", parsed

        return "AMBIGUOUS", parsed

    def _send_raw(self, body):
        url = self._endpoint_url()

        if not url:
            return None

        try:
            return self.http_client.send_request(
                url=url,
                method="POST",
                data=body,
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                },
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _build_call(self, method_name, params):
        return xmlrpc.client.dumps(
            tuple(params or []),
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

    def _extract_param_types_from_signature(self, sig):
        if not sig:
            return None

        if isinstance(sig, list) and sig and isinstance(sig[0], (list, tuple)):
            first = list(sig[0])
            if len(first) >= 1:
                return first[1:]

        return None

    def _method_metadata(self, method_name):

        metadata = getattr(self.helpers, "metadata", {}) or {}

        if isinstance(metadata, dict):
            info = metadata.get(method_name)

            if isinstance(info, dict):
                params = info.get("params")
                if isinstance(params, list):
                    clean_params = []
                    for idx, p in enumerate(params, 1):
                        clean_params.append({
                            "name": p.get("name") or f"param{idx}",
                            "type": p.get("type") or "string",
                        })
                    return {
                        "params": clean_params,
                        "source": "metadata.params",
                    }

                param_types = info.get("param_types")
                if isinstance(param_types, list):
                    return {
                        "params": [
                            {"name": f"param{idx}", "type": typ}
                            for idx, typ in enumerate(param_types, 1)
                        ],
                        "source": "metadata.param_types",
                    }

                sig = info.get("signature")
                parsed = self._extract_param_types_from_signature(sig)
                if parsed is not None:
                    return {
                        "params": [
                            {"name": f"param{idx}", "type": typ}
                            for idx, typ in enumerate(parsed, 1)
                        ],
                        "source": "metadata.signature",
                    }
                
        api_schema = getattr(self.helpers, "apiSchema", None)

        if isinstance(api_schema, dict):
            methods = api_schema.get("methods", [])

            if isinstance(methods, list):
                for entry in methods:
                    if not isinstance(entry, dict):
                        continue

                    if entry.get("name") != method_name:
                        continue

                    params = entry.get("params", [])

                    if isinstance(params, list):
                        clean_params = []
                        for idx, p in enumerate(params, 1):
                            clean_params.append({
                                "name": p.get("name") or f"param{idx}",
                                "type": p.get("type") or "string",
                            })

                        return {
                            "params": clean_params,
                            "source": "helpers.apiSchema",
                        }

        return {
            "params": [],
            "source": "none",
        }

    def _default_value_for_param(self, param):
        name = (param.get("name") or "").lower()
        typ = self._normalise_type(param.get("type"))

        if "nonce" in name:
            return "ptapitester-replay-nonce-001"

        if "messageid" in name or "message_id" in name:
            return "ptapitester-message-id-001"

        if "requestid" in name or "request_id" in name:
            return "ptapitester-request-id-001"

        if "correlationid" in name or "correlation_id" in name:
            return "ptapitester-correlation-id-001"

        if "sequence" in name or name == "seq":
            return 1

        if "expires" in name:
            return "2050-01-01T00:00:00Z"

        if "timestamp" in name or "created" in name:
            return "2050-01-01T00:00:00Z"

        if "signature" in name:
            return "ptapitester-static-signature"

        if "digest" in name:
            return "ptapitester-static-digest"

        if "token" in name:
            return "ptapitester-static-token"

        # Type defaults.
        if typ in ("int", "i4", "i8", "integer", "long", "short"):
            return 1

        if typ in ("double", "float", "decimal"):
            return 1.0

        if typ in ("boolean", "bool"):
            return True

        if typ in ("array", "list"):
            return []

        if typ in ("struct", "dict"):
            return {}

        if typ == "base64":
            return xmlrpc.client.Binary(b"test")

        if typ in ("datetime", "datetime.iso8601", "date"):
            return xmlrpc.client.DateTime("20500101T00:00:00")

        return "test"

    def _build_params(self, params_meta):
        return [
            self._default_value_for_param(p)
            for p in params_meta
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

        candidates = []

        for method in sorted(methods):
            if method.startswith("system."):
                continue

            if self._is_destructive_method(method):
                continue

            meta = self._method_metadata(method)
            params = meta.get("params", [])

            anti_replay_params = [
                p for p in params
                if self._is_anti_replay_param(p.get("name", ""))
            ]

            if anti_replay_params:
                candidates.append({
                    "method": method,
                    "params": params,
                    "antiReplayParams": anti_replay_params,
                    "metadataSource": meta.get("source"),
                })

        return candidates

    def run(self):
        candidates = self._get_methods_to_test()

        if not candidates:
            ptprint(
                "No XML-RPC operation with anti-replay parameters was found. "
                "Replay vulnerability cannot be reliably evaluated.",
                "INFO",
                not self.args.json,
                indent=4,
            )

            self.ptjsonlib.add_properties(
                properties={
                    "xmlrpcReplayAttackTest": {
                        "status": "not_evaluable",
                        "reason": "NO_ANTI_REPLAY_PARAMETERS",
                        "note": (
                            "No operation exposing nonce/timestamp/messageId/"
                            "requestId/sequence-like parameters was available. "
                            "The test did not replay ping or other idempotent "
                            "methods to avoid false positives."
                        ),
                    }
                },
                node_key=self.helpers.node_key,
            )
            return

        findings = []
        observations = []

        tested_count = 0

        for candidate in candidates[:MAX_METHODS_TO_TEST]:
            method = candidate["method"]
            params_meta = candidate["params"]
            params = self._build_params(params_meta)
            raw_request = self._build_call(method, params)

            anti_replay_param_names = [
                p.get("name") for p in candidate["antiReplayParams"]
            ]

            first = self._send_raw(raw_request)
            first_class, first_parsed = self._classify_response(first)

            time.sleep(1.5)

            second = self._send_raw(raw_request)
            second_class, second_parsed = self._classify_response(second)

            tested_count += 1

            record = {
                "method": method,
                "metadataSource": candidate["metadataSource"],
                "antiReplayParams": anti_replay_param_names,
                "firstClassification": first_class,
                "secondClassification": second_class,
                "firstHttpStatus": first.status_code if first is not None else None,
                "secondHttpStatus": second.status_code if second is not None else None,
                "firstBodyHash": self._body_hash(first),
                "secondBodyHash": self._body_hash(second),
                "firstFaultCode": first_parsed.get("faultCode"),
                "secondFaultCode": second_parsed.get("faultCode"),
                "secondMatchedReplayIndicators": self._matched(
                    (second.text if second is not None else "")
                    + "\n"
                    + (second_parsed.get("faultString") or ""),
                    REPLAY_REJECTION_INDICATORS,
                ),
                "requestSha256": hashlib.sha256(
                    raw_request.encode("utf-8")
                    if isinstance(raw_request, str)
                    else raw_request
                ).hexdigest(),
            }

            if first_class == "SUCCESS" and second_class == "REPLAY_REJECTED":
                observations.append({
                    **record,
                    "type": "REPLAY_PROTECTION_OBSERVED",
                    "message": (
                        "First request succeeded and identical replay was rejected."
                    ),
                })
                continue

            if first_class == "SUCCESS" and second_class == "SUCCESS":
                findings.append({
                    **record,
                    "type": "REPLAY_ACCEPTED_WITH_ANTI_REPLAY_PARAMETER",
                    "message": (
                        "The operation exposes anti-replay-like parameter(s), "
                        "but the exact same XML-RPC request was accepted more "
                        "than once. This indicates replay protection is missing "
                        "or ineffective for this operation."
                    ),
                })
                continue

            observations.append({
                **record,
                "type": "REPLAY_TEST_NOT_CONFIRMATORY",
                "message": (
                    "Replay vulnerability was not confirmed for this operation. "
                    "The baseline request did not succeed twice, or the response "
                    "was not suitable for a replay decision."
                ),
            })

        if findings:
            ptprint("XML-RPC replay attack vulnerability detected.",
                    "VULN", not self.args.json, indent=4, colortext=True)

            for f in findings:
                ptprint(
                    f"  Method '{f['method']}' accepted identical request twice "
                    f"despite anti-replay parameter(s): "
                    f"{', '.join(f['antiReplayParams'])}.",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-REPLAY-PROTECTION",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC replay protection appears ineffective.",
                    "description": (
                        "At least one XML-RPC operation exposing anti-replay-like "
                        "parameters accepted the exact same request more than once."
                    ),
                    "confidence": "black-box heuristic with anti-replay parameter evidence",
                    "testedOperations": tested_count,
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                    "note": (
                        "The test avoids replaying generic idempotent methods such "
                        "as ping/system.listMethods as vulnerabilities. A finding "
                        "requires nonce/timestamp/messageId/requestId/sequence-like "
                        "input and repeated successful acceptance of the identical "
                        "request."
                    ),
                },
            )
            return

        ptprint("No XML-RPC replay vulnerability confirmed.",
                "OK", not self.args.json, indent=4)

        self.ptjsonlib.add_properties(
            properties={
                "xmlrpcReplayAttackTest": {
                    "status": "no_replay_vulnerability_confirmed",
                    "testedOperations": tested_count,
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "No operation with anti-replay parameters accepted the "
                        "same request twice in a way that confirms a replay "
                        "vulnerability."
                    ),
                }
            },
            node_key=self.helpers.node_key,
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ReplayAttack(args, ptjsonlib, helpers, http_client, common_tests).run()