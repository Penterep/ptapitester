"""
SOAP Replay Attack test
"""

import time
import hashlib
import html
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Replay Attack test"


ANTI_REPLAY_PARAM_KEYWORDS = [
    "nonce","timestamp","timeStamp","created","expires","messageid","message_id",
    "messageId","requestid","request_id","requestId","correlationid","token",
    "correlation_id","correlationId","sequence","seq","signature","digest",
]

REPLAY_REJECTION_INDICATORS = [
    "replay detected","replay attack detected","replayed request","request replayed","duplicate",
    "already used","nonce used","nonce already","invalid nonce","stale nonce","expired nonce",
    "timestamp expired","expired timestamp","stale timestamp","message already processed",
    "request already processed","duplicate request","duplicate message","invalid sequence",
    "sequence already",
]

AUTH_DENIED_INDICATORS = [
    "authentication required","auth required","unauthorized","unauthorised",
    "permission denied","login required","not logged in","invalid credentials",
    "invalid token","token required","missing token","failedauthentication","wsse:failedauthentication",
    "session expired","session required","401 unauthorized","403 forbidden",
]

INVALID_PARAMS_INDICATORS = [
    "invalid parameter","invalid params","missing parameter","missing argument","wrong number of parameters",
    "wrong number of arguments","expected","required","bad request","schema validation","xsd validation",
]

SOAP_FAULT_INDICATORS = [
    "soap:fault","soapenv:fault","<fault>","faultcode","faultstring",
]

DESTRUCTIVE_OPERATION_KEYWORDS = [
    "delete","remove","drop","destroy","disable","reset",
]

URL_LIKE_PARAM_KEYWORDS = [
    "url","uri","endpoint","callback","webhook","href","src","link","fetch",
]

MAX_OPERATIONS_TO_TEST = 20


class ReplayAttack:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _endpoint_url(self, op=None):
        if op and op.get("endpoint"):
            return op.get("endpoint")
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
        t = str(typ).strip().lower()
        if ":" in t:
            t = t.split(":", 1)[-1]
        return t

    def _is_destructive_operation(self, op):
        name = (op.get("name") or "").lower()
        return any(k in name for k in DESTRUCTIVE_OPERATION_KEYWORDS)

    def _has_url_like_params(self, op):
        for p in op.get("input_params", []) or []:
            name = (p.get("name") or "").lower()
            if any(k in name for k in URL_LIKE_PARAM_KEYWORDS):
                return True
        return False

    def _is_anti_replay_param(self, param_name):
        low = (param_name or "").lower()
        return any(k.lower() in low for k in ANTI_REPLAY_PARAM_KEYWORDS)

    def _body_hash(self, response):
        if response is None:
            return None
        return hashlib.sha256((response.text or "").encode("utf-8")).hexdigest()

    def _excerpt(self, response, limit=220):
        if response is None:
            return ""
        return (response.text or "")[:limit].strip().replace("\n", " ").replace("\r", " ")

    def _local_names(self, text):
        if not text:
            return set()

        names = set()

        for tag in re.findall(r"<\/?(?:[A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)", text):
            names.add(tag.lower())

        return names

    def _looks_like_soap_fault(self, text):
        return self._has_any(text, SOAP_FAULT_INDICATORS)

    def _looks_like_operation_output(self, response, op):
        if response is None or not op:
            return False

        if response.status_code < 200 or response.status_code >= 300:
            return False

        text = response.text or ""

        if self._looks_like_soap_fault(text):
            return False

        op_name = (op.get("name") or "").lower()
        names = self._local_names(text)

        if op_name in names:
            return True

        if f"{op_name}response" in names:
            return True

        if f"{op_name}result" in names:
            return True

        low = text.lower()

        if f"{op_name}response" in low or f"{op_name}result" in low:
            return True

        return False

    def _classify_response(self, response, op):
        if response is None:
            return "NO_RESPONSE"

        text = response.text or ""
        combined = text.lower()

        if response.status_code in (401, 403, 407):
            return "AUTH_DENIED"

        if self._has_any(combined, AUTH_DENIED_INDICATORS):
            return "AUTH_DENIED"

        if self._looks_like_operation_output(response, op):
            return "SUCCESS"

        if 200 <= response.status_code < 300 and not self._looks_like_soap_fault(text):
            return "SUCCESS"

        if self._looks_like_soap_fault(text):
            if self._has_any(combined, REPLAY_REJECTION_INDICATORS):
                return "REPLAY_REJECTED"

            if self._has_any(combined, AUTH_DENIED_INDICATORS):
                return "AUTH_DENIED"

            if self._has_any(combined, INVALID_PARAMS_INDICATORS):
                return "INVALID_PARAMS"

            return "SOAP_FAULT"

        if self._has_any(combined, REPLAY_REJECTION_INDICATORS):
            return "REPLAY_REJECTED"

        if self._has_any(combined, INVALID_PARAMS_INDICATORS):
            return "INVALID_PARAMS"

        if response.status_code >= 500:
            return "SERVER_ERROR"

        if response.status_code in (400, 404, 405):
            return "REJECTED"

        return "AMBIGUOUS"

    def _send_raw(self, url, body, op):
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
        }

        action = op.get("soap_action") or op.get("soapAction") or ""

        if action:
            if action.startswith('"') and action.endswith('"'):
                headers["SOAPAction"] = action
            else:
                headers["SOAPAction"] = f'"{action}"'

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
            return "1"

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

        if typ in ("int", "integer", "long", "short", "byte", "unsignedint", "unsignedlong"):
            return "1"

        if typ in ("double", "float", "decimal"):
            return "1.0"

        if typ in ("boolean", "bool"):
            return "true"

        if typ == "date":
            return "2050-01-01"

        if typ in ("datetime", "datetime.iso8601"):
            return "2050-01-01T00:00:00"

        if typ in ("anyuri", "uri"):
            return "http://example.com/"

        return "test"

    def _build_request(self, op):
        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element") or op.get("name")
        params = op.get("input_params", []) or []

        params_xml = ""

        for p in params:
            name = p.get("name")
            if not name:
                continue

            value = self._default_value_for_param(p)
            params_xml += (
                f"<tns:{name}>"
                f"{html.escape(str(value), quote=False)}"
                f"</tns:{name}>"
            )

        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope '
            'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:tns="{html.escape(tns, quote=True)}">'
            "<soap:Body>"
            f"<tns:{input_element}>"
            f"{params_xml}"
            f"</tns:{input_element}>"
            "</soap:Body>"
            "</soap:Envelope>"
        )

    def _get_candidate_operations(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []
        candidates = []

        for op in operations:
            if not op.get("name"):
                continue

            if self._is_destructive_operation(op):
                continue

            if self._has_url_like_params(op):
                continue

            params = op.get("input_params", []) or []

            anti_replay_params = [
                p for p in params
                if self._is_anti_replay_param(p.get("name", ""))
            ]

            if anti_replay_params:
                candidates.append({
                    "operation": op,
                    "antiReplayParams": anti_replay_params,
                })

        return candidates

    def run(self):
        candidates = self._get_candidate_operations()

        if not candidates:
            ptprint(
                "No SOAP operation with anti-replay parameters was found. "
                "Replay vulnerability cannot be reliably evaluated.",
                "INFO",
                not self.args.json,
                indent=4,
            )

            self.ptjsonlib.add_properties(
                properties={
                    "soapReplayAttackTest": {
                        "status": "not_evaluable",
                        "reason": "NO_ANTI_REPLAY_PARAMETERS",
                        "note": (
                            "No operation exposing nonce/timestamp/messageId/"
                            "requestId/sequence-like parameters was available. "
                            "The test did not replay idempotent SOAP operations "
                            "such as echo/add as vulnerabilities."
                        ),
                    }
                },
                node_key=self.helpers.node_key,
            )
            return

        findings = []
        observations = []
        tested_count = 0

        for candidate in candidates[:MAX_OPERATIONS_TO_TEST]:
            op = candidate["operation"]
            endpoint = self._endpoint_url(op)
            raw_request = self._build_request(op)
            anti_replay_param_names = [
                p.get("name") for p in candidate["antiReplayParams"]
            ]

            first = self._send_raw(endpoint, raw_request, op)
            first_class = self._classify_response(first, op)

            time.sleep(1.5)

            second = self._send_raw(endpoint, raw_request, op)
            second_class = self._classify_response(second, op)

            tested_count += 1

            record = {
                "operation": op.get("name"),
                "endpoint": endpoint,
                "soapAction": op.get("soap_action") or op.get("soapAction") or "",
                "inputElement": op.get("input_element") or op.get("name"),
                "antiReplayParams": anti_replay_param_names,
                "firstClassification": first_class,
                "secondClassification": second_class,
                "firstHttpStatus": first.status_code if first is not None else None,
                "secondHttpStatus": second.status_code if second is not None else None,
                "firstBodyHash": self._body_hash(first),
                "secondBodyHash": self._body_hash(second),
                "secondMatchedReplayIndicators": self._matched(
                    second.text if second is not None else "",
                    REPLAY_REJECTION_INDICATORS,
                ),
                "requestSha256": hashlib.sha256(
                    raw_request.encode("utf-8")
                    if isinstance(raw_request, str)
                    else raw_request
                ).hexdigest(),
                "firstExcerpt": self._excerpt(first),
                "secondExcerpt": self._excerpt(second),
            }

            if first_class == "SUCCESS" and second_class == "REPLAY_REJECTED":
                observations.append({
                    **record,
                    "type": "REPLAY_PROTECTION_OBSERVED",
                    "message": (
                        "First SOAP request succeeded and the identical replay "
                        "was rejected."
                    ),
                })
                continue

            if first_class == "SUCCESS" and second_class == "SUCCESS":
                findings.append({
                    **record,
                    "type": "REPLAY_ACCEPTED_WITH_ANTI_REPLAY_PARAMETER",
                    "message": (
                        "The SOAP operation exposes anti-replay-like parameter(s), "
                        "but the exact same SOAP request was accepted more than "
                        "once. This indicates replay protection is missing or "
                        "ineffective for this operation."
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
            ptprint(
                "SOAP replay attack vulnerability detected.",
                "VULN",
                not self.args.json,
                indent=4,
                colortext=True,
            )

            for f in findings:
                ptprint(
                    f"  Operation '{f['operation']}' accepted identical request twice "
                    f"despite anti-replay parameter(s): "
                    f"{', '.join(f['antiReplayParams'])}.",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-REPLAY-ACCEPTED",
                node_key=self.helpers.node_key,
                data={
                    "summary": "SOAP replay protection appears ineffective.",
                    "description": (
                        "At least one SOAP operation exposing anti-replay-like "
                        "parameters accepted the exact same request more than once."
                    ),
                    "confidence": "black-box heuristic with anti-replay parameter evidence",
                    "testedOperations": tested_count,
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                    "note": (
                        "The test avoids treating repeated idempotent SOAP "
                        "operations as replay vulnerabilities. A finding requires "
                        "nonce/timestamp/messageId/requestId/sequence-like input "
                        "and repeated successful acceptance of the identical request."
                    ),
                },
            )
            return

        ptprint(
            "No SOAP replay vulnerability confirmed.",
            "OK",
            not self.args.json,
            indent=4,
        )

        self.ptjsonlib.add_properties(
            properties={
                "soapReplayAttackTest": {
                    "status": "no_replay_vulnerability_confirmed",
                    "testedOperations": tested_count,
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "No operation with anti-replay parameters accepted the same "
                        "request twice in a way that confirms a replay vulnerability."
                    ),
                }
            },
            node_key=self.helpers.node_key,
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ReplayAttack(args, ptjsonlib, helpers, http_client, common_tests).run()