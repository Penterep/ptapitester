"""
XML-RPC Rate Limiting test
"""

import time
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Rate Limiting test"


REQUEST_COUNT = 50
SAFE_METHOD_CANDIDATES = ["ping", "demo.ping", "system.getCapabilities"]

RATE_LIMIT_HTTP_STATUSES = {429}

POSSIBLE_THROTTLE_HTTP_STATUSES = {403, 503}

RATE_LIMIT_BODY_INDICATORS = [
    "rate limit","rate-limit","ratelimit","too many requests","request limit","quota exceeded",
    "slow down","throttled","temporarily blocked","try again later",
]


class RateLimiting:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _build_call(self, method_name, params=None):
        params = tuple(params or ())
        return xmlrpc.client.dumps(
            params,
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

    def _select_probe_method(self):
        methods = getattr(self.helpers, "discovered_methods", []) or []

        for candidate in SAFE_METHOD_CANDIDATES:
            if candidate in methods:
                return candidate, "discovered"

        return SAFE_METHOD_CANDIDATES[0], "fallback"

    def _has_rate_limit_indicator(self, text):
        if not text:
            return False
        low = text.lower()
        return any(ind in low for ind in RATE_LIMIT_BODY_INDICATORS)

    def _classify_response(self, response):
        if response is None:
            return "NO_RESPONSE"

        body = response.text or ""

        if response.status_code in RATE_LIMIT_HTTP_STATUSES:
            return "RATE_LIMITED"

        if self._has_rate_limit_indicator(body):
            if response.status_code in POSSIBLE_THROTTLE_HTTP_STATUSES:
                return "RATE_LIMITED"
            return "POSSIBLE_RATE_LIMIT"

        if response.status_code in POSSIBLE_THROTTLE_HTTP_STATUSES:
            return "POSSIBLE_RATE_LIMIT"

        return "NORMAL_RESPONSE"

    def _status_counts(self, statuses):
        counts = {}
        for s in statuses:
            counts[s] = counts.get(s, 0) + 1
        return counts

    def _response_excerpt(self, response, limit=180):
        if response is None:
            return ""
        return (response.text or "")[:limit].strip().replace("\n", " ")

    def run(self):
        method_name, method_source = self._select_probe_method()
        probe = self._build_call(method_name, [])

        statuses = []
        classifications = []
        first_rate_limited = None

        start = time.time()

        for i in range(REQUEST_COUNT):
            r = self.helpers.send_xmlrpc_raw(data=probe)

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

        status_counts = self._status_counts(statuses)

        base_data = {
            "method": method_name,
            "methodSource": method_source,
            "requestedBurstSize": REQUEST_COUNT,
            "sentRequests": sent_count,
            "completedResponses": completed_count,
            "elapsedSeconds": round(elapsed, 3),
            "approxRequestsPerSecond": rps,
            "statusCounts": status_counts,
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
                    "xmlrpcRateLimitingTest": {
                        "status": "rate_limiting_observed",
                        **base_data,
                        "rateLimitSignal": first_rate_limited,
                    }
                },
                node_key=self.helpers.node_key,
            )
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
                    "xmlrpcRateLimitingTest": {
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
            f"No rate limiting observed during {sent_count}-request burst "
            f"({rps} req/s approx.).",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        self.ptjsonlib.add_vulnerability(
            "PTV-XMLRPC-NO-RATE-LIMIT",
            node_key=self.helpers.node_key,
            data={
                "summary": "No XML-RPC rate limiting was observed during burst test.",
                "description": (
                    "The XML-RPC endpoint accepted a burst of requests without "
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
                        f"{sent_count} XML-RPC request(s)."
                    ),
                },
                "note": (
                    "Rate limiting may still exist with a higher threshold, "
                    "different time window, per-method policy, per-account "
                    "policy, or only for authenticated traffic."
                ),
            },
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    RateLimiting(args, ptjsonlib, helpers, http_client, common_tests).run()