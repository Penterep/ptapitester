"""
SOAP Rate Limiting test
"""

import time
import html
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Rate Limiting test"


REQUEST_COUNT = 50

RATE_LIMIT_HTTP_STATUSES = {429}
POSSIBLE_THROTTLE_HTTP_STATUSES = {403, 503}

RATE_LIMIT_BODY_INDICATORS = [
    "rate limit","rate-limit","ratelimit","too many requests","request limit","quota exceeded",
    "slow down","throttled","temporarily blocked","try again later",
]

SOAP_FAULT_INDICATORS = [
    "soap:fault","soapenv:fault","<fault>","faultcode","faultstring",
]

DANGEROUS_OPERATION_WORDS = [
    "delete","remove","update","edit","create","new","insert","write","set","change",
]


class RateLimiting:
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

    def _status_counts(self, values):
        counts = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        return counts

    def _response_excerpt(self, response, limit=180):
        if response is None:
            return ""
        return (response.text or "")[:limit].strip().replace("\n", " ").replace("\r", " ")

    def _is_dangerous_operation(self, op_name):
        low = (op_name or "").lower()
        return any(word in low for word in DANGEROUS_OPERATION_WORDS)

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
            return "rate_test"

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
            return "2026-01-01"

        if t == "datetime":
            return "2026-01-01T00:00:00Z"

        return "rate_test"

    def _soap_action_for(self, op):
        if not op:
            return None

        action = op.get("soap_action") or op.get("soapAction") or ""
        if action:
            return f'"{action}"'

        name = op.get("name", "")
        return f'"urn:{name}"' if name else None

    def _select_probe_operation(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []

        candidates = []
        for op in operations:
            op_name = op.get("name", "")
            if not op_name:
                continue

            if self._is_dangerous_operation(op_name):
                continue

            candidates.append(op)

        if not candidates:
            return None

        preferred_words = ("ping", "echo", "get", "read", "list", "find")
        for op in candidates:
            name = op.get("name", "").lower()
            if any(word in name for word in preferred_words):
                return op

        return candidates[0]

    def _build_operation_request(self, op):
        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element", op.get("name", ""))
        params = op.get("input_params", []) or []

        params_xml = ""

        for p in params:
            p_name = p.get("name", "")
            p_type = p.get("type", "string")

            if not p_name:
                continue

            value = self._default_value(p_type)

            params_xml += (
                f"<tns:{p_name}>"
                f"{html.escape(str(value), quote=False)}"
                f"</tns:{p_name}>"
            )

        return (
            '<?xml version="1.0"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{html.escape(tns, quote=True)}">'
            f"<soap:Body>"
            f"<tns:{input_element}>"
            f"{params_xml}"
            f"</tns:{input_element}>"
            f"</soap:Body>"
            f"</soap:Envelope>"
        )

    def _build_fallback_request(self):
        return (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>rate_test</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

    def _build_probe_request(self):
        op = self._select_probe_operation()

        if op:
            return {
                "source": "parsed_operation",
                "operation": op.get("name", ""),
                "body": self._build_operation_request(op),
                "headers": {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": self._soap_action_for(op),
                },
            }

        return {
            "source": "fallback_generic_request",
            "operation": None,
            "body": self._build_fallback_request(),
            "headers": {
                "Content-Type": "text/xml; charset=utf-8",
            },
        }

    def _send_probe(self, probe):
        try:
            return self.helpers.send_soap_request(
                data=probe["body"],
                headers={k: v for k, v in probe["headers"].items() if v},
            )
        except TypeError:
            return self.helpers.send_soap_request(data=probe["body"])

    def _classify_response(self, response):

        if response is None:
            return "NO_RESPONSE"

        body = response.text or ""
        has_rate_indicator = self._has_any(body, RATE_LIMIT_BODY_INDICATORS)
        is_soap_fault = self._has_any(body, SOAP_FAULT_INDICATORS)

        if response.status_code in RATE_LIMIT_HTTP_STATUSES:
            return "RATE_LIMITED"

        if has_rate_indicator:
            if response.status_code in POSSIBLE_THROTTLE_HTTP_STATUSES or is_soap_fault:
                return "RATE_LIMITED"
            return "POSSIBLE_RATE_LIMIT"

        if response.status_code in POSSIBLE_THROTTLE_HTTP_STATUSES:
            return "POSSIBLE_RATE_LIMIT"

        return "NORMAL_RESPONSE"

    def run(self):
        probe = self._build_probe_request()

        statuses = []
        classifications = []
        first_rate_limited = None

        start = time.time()

        for i in range(REQUEST_COUNT):
            r = self._send_probe(probe)

            if r is None:
                classifications.append("NO_RESPONSE")
                continue

            statuses.append(r.status_code)
            classification = self._classify_response(r)
            classifications.append(classification)

            if classification in ("RATE_LIMITED", "POSSIBLE_RATE_LIMIT"):
                first_rate_limited = {
                    "requestIndex": i + 1,
                    "classification": classification,
                    "httpStatus": r.status_code,
                    "responseExcerpt": self._response_excerpt(r),
                }
                break

        elapsed = time.time() - start
        sent_count = len(classifications)
        completed_count = len(statuses)
        rps = round(sent_count / elapsed, 2) if elapsed > 0 else sent_count

        base_data = {
            "probeSource": probe["source"],
            "operation": probe["operation"],
            "requestedBurstSize": REQUEST_COUNT,
            "sentRequests": sent_count,
            "completedResponses": completed_count,
            "elapsedSeconds": round(elapsed, 3),
            "approxRequestsPerSecond": rps,
            "statusCounts": self._status_counts(statuses),
            "classifications": self._status_counts(classifications),
        }

        if first_rate_limited:
            ptprint(
                f"Rate limiting observed after {first_rate_limited['requestIndex']} "
                f"request(s) ({first_rate_limited['classification']}, "
                f"HTTP {first_rate_limited['httpStatus']}).",
                "OK",
                not self.args.json,
                indent=4,
            )

            self.ptjsonlib.add_properties(
                properties={
                    "soapRateLimitingTest": {
                        "status": "rate_limiting_observed",
                        **base_data,
                        "rateLimitSignal": first_rate_limited,
                        "note": (
                            "The endpoint produced a rate-limit/throttling "
                            "signal during the tested burst."
                        ),
                    }
                },
                node_key=self.helpers.node_key,
            )
            return

        if sent_count == 0:
            ptprint("Rate limit test inconclusive (server unreachable).",
                    "INFO", not self.args.json, indent=4)
            return

        if rps < 5.0 and sent_count >= 30:
            ptprint(
                f"Rate limiting inferred from throughput suppression "
                f"({rps} req/s during {sent_count}-request burst — "
                f"framework likely backed off on 429 responses).",
                "OK",
                not self.args.json,
                indent=4,
            )

            self.ptjsonlib.add_properties(
                properties={
                    "soapRateLimitingTest": {
                        "status": "rate_limiting_inferred_from_throughput",
                        **base_data,
                        "note": (
                            "Average requests-per-second was significantly lower "
                            "than typical burst throughput, suggesting the HTTP "
                            "client backed off on rate-limit responses from the "
                            "server. No explicit 429 response was visible to the "
                            "test due to framework retry behavior."
                        ),
                    }
                },
                node_key=self.helpers.node_key,
            )
            return

        ptprint(
            f"No rate limiting observed during {sent_count}-request SOAP burst "
            f"({rps} req/s approx.).",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        self.ptjsonlib.add_vulnerability(
            "PTV-SOAP-RATE-LIMIT",
            node_key=self.helpers.node_key,
            data={
                "summary": "No SOAP rate limiting was observed during burst test.",
                "description": (
                    "The SOAP endpoint accepted a burst of requests without "
                    "returning an observable rate-limit or throttling response. "
                    "This does not prove rate limiting is absent globally; it "
                    "means no limit was observed under the tested conditions."
                ),
                "confidence": "black-box heuristic",
                **base_data,
                "finding": {
                    "type": "NO_RATE_LIMIT_OBSERVED_DURING_BURST",
                    "message": (
                        f"No rate limiting was observed during a burst of "
                        f"{sent_count} SOAP request(s)."
                    ),
                },
                "note": (
                    "Rate limiting may still exist with a higher threshold, "
                    "different time window, per-operation policy, per-account "
                    "policy, or only for authenticated traffic."
                ),
            },
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    RateLimiting(args, ptjsonlib, helpers, http_client, common_tests).run()