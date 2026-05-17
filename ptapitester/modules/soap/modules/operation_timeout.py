"""
SOAP DoS / Operation timeout test
"""

import html
import time
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Operation timeout test"


DEFAULT_SLOW_THRESHOLD_SECONDS = 5.0
DEFAULT_RATIO_THRESHOLD = 8.0
DEFAULT_MIN_RATIO_SIGNAL_SECONDS = 2.0
DEFAULT_LARGE_PAYLOAD_SIZE = 100000
MAX_OPERATIONS_TO_TEST = 10

DANGEROUS_OPERATION_WORDS = [
    "delete", "remove", "update", "edit", "create", "new", "insert",
    "write", "change", "submit", "payment", "pay", "transfer",
]

URL_LIKE_PARAM_NAMES = {
    "url", "uri", "endpoint", "endpointurl", "callback", "callbackurl","webhook", 
    "location","target", "resource", "feed","image", "imageurl", "avatar", "schema", 
    "wsdl","service","link", "redirect", "fetch", "source", "href", "src",
}


class OperationTimeout:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

        self.slow_threshold = float(
            getattr(args, "slow_threshold", DEFAULT_SLOW_THRESHOLD_SECONDS)
        )
        self.ratio_threshold = float(
            getattr(args, "timeout_ratio_threshold", DEFAULT_RATIO_THRESHOLD)
        )
        self.min_ratio_signal_seconds = float(
            getattr(args, "timeout_min_ratio_seconds", DEFAULT_MIN_RATIO_SIGNAL_SECONDS)
        )
        self.large_payload_size = int(
            getattr(args, "large_payload_size", DEFAULT_LARGE_PAYLOAD_SIZE)
        )

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
            return "timeout_test"

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
            return "2050-01-01"

        if t == "datetime":
            return "2050-01-01T00:00:00Z"

        return "timeout_test"

    def _is_dangerous_operation(self, op_name):
        low = (op_name or "").lower()
        return any(word in low for word in DANGEROUS_OPERATION_WORDS)

    def _is_url_like_param(self, param_name):
        if not param_name:
            return False

        low = param_name.lower()

        if low in URL_LIKE_PARAM_NAMES:
            return True

        return any(word in low for word in URL_LIKE_PARAM_NAMES)

    def _has_url_like_param(self, op):
        params = op.get("input_params", []) or []
        return any(self._is_url_like_param(p.get("name", "")) for p in params)

    def _soap_action_for(self, op):
        if not op:
            return None

        action = op.get("soap_action") or op.get("soapAction") or ""

        if action:
            return f'"{action}"'

        name = op.get("name", "")
        return f'"urn:{name}"' if name else None

    def _build_request(self, op, overrides=None):
        overrides = overrides or {}

        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element", op.get("name", ""))
        params = op.get("input_params", []) or []

        params_xml = ""

        if params:
            for p in params:
                p_name = p.get("name", "")
                p_type = p.get("type", "string")

                if not p_name:
                    continue

                value = overrides.get(p_name, self._default_value(p_type))

                params_xml += (
                    f"<tns:{p_name}>"
                    f"{html.escape(str(value), quote=False)}"
                    f"</tns:{p_name}>"
                )
        else:
            value = overrides.get("message", "timeout_test")
            params_xml = (
                f"<tns:message>"
                f"{html.escape(str(value), quote=False)}"
                f"</tns:message>"
            )

        return (
            '<?xml version="1.0"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{html.escape(tns, quote=True)}">'
            "<soap:Body>"
            f"<tns:{input_element}>"
            f"{params_xml}"
            f"</tns:{input_element}>"
            "</soap:Body>"
            "</soap:Envelope>"
        )

    def _send(self, body, op):
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
        }

        soap_action = self._soap_action_for(op)
        if soap_action:
            headers["SOAPAction"] = soap_action

        return self.http_client.send_request(
            url=self.helpers.endpoint_url,
            method="POST",
            data=body,
            headers=headers,
            merge_headers=False,
            allow_redirects=True,
        )

    def _timed_send(self, body, op):
        start = time.time()

        try:
            response = self._send(body, op)
            elapsed = time.time() - start

            return {
                "response": response,
                "elapsed": elapsed,
                "status": getattr(response, "status_code", None),
                "error": None,
            }

        except Exception as e:
            elapsed = time.time() - start

            return {
                "response": None,
                "elapsed": elapsed,
                "status": None,
                "error": f"{type(e).__name__}: {e}",
            }

    def _operation_candidates(self):
        parsed = getattr(self.helpers, "parsed_operations", []) or []
        candidates = []

        if parsed:
            for op in parsed:
                name = op.get("name", "")
                if not name:
                    continue

                candidates.append(op)

        else:
            known = getattr(self.helpers, "known_operations", []) or []
            for name in known:
                if not name:
                    continue

                candidates.append({
                    "name": name,
                    "input_element": name,
                    "input_params": [
                        {"name": "message", "type": "string"}
                    ],
                })

        if not candidates:
            candidates.append({
                "name": "echo",
                "input_element": "echo",
                "input_params": [
                    {"name": "message", "type": "string"}
                ],
            })

        safe = []

        for op in candidates:
            name = op.get("name", "")

            if self._is_dangerous_operation(name):
                continue

            if self._has_url_like_param(op):
                continue

            safe.append(op)

        return safe[:MAX_OPERATIONS_TO_TEST]

    def _large_payload_targets(self, operations, limit=3):
        targets = []
        seen_ops = set()

        for op in operations:
            op_name = op.get("name", "")

            if op_name in seen_ops:
                continue

            params = op.get("input_params", []) or []

            for p in params:
                p_name = p.get("name", "")
                p_type = p.get("type", "")

                if not p_name:
                    continue

                if self._normalise_type(p_type) == "string":
                    targets.append((op, p_name))
                    seen_ops.add(op_name)
                    break

        return targets[:limit]

    def _is_abnormal_delay(self, baseline_elapsed, probe_elapsed):
        if probe_elapsed >= self.slow_threshold:
            return True

        if baseline_elapsed <= 0:
            return False

        return (
            probe_elapsed >= self.min_ratio_signal_seconds
            and probe_elapsed >= baseline_elapsed * self.ratio_threshold
        )

    def _finding_message(self, finding):
        if finding["type"] == "slow_operation":
            return (
                f"Operation '{finding['operation']}' responded slowly: "
                f"{finding['elapsedSeconds']}s"
                + (
                    f" (HTTP {finding['httpStatus']})."
                    if finding.get("httpStatus") is not None
                    else "."
                )
            )

        if finding["type"] == "operation_timeout":
            return (
                f"Operation '{finding['operation']}' timed out or failed after "
                f"{finding['elapsedSeconds']}s."
            )

        if finding["type"] == "large_payload_delay":
            return (
                f"Large payload caused abnormal delay in operation "
                f"'{finding['operation']}': {finding['elapsedSeconds']}s "
                f"(baseline {finding['baselineElapsedSeconds']}s)."
            )

        return finding.get("message", "Slow SOAP behavior detected.")

    def run(self):
        operations = self._operation_candidates()

        if not operations:
            ptprint("No safe SOAP operations available for timeout test.",
                    "OK", not self.args.json, indent=4)
            return

        findings = []
        operation_timings = {}

        for op in operations:
            op_name = op.get("name", "")
            body = self._build_request(op)
            result = self._timed_send(body, op)
            elapsed = result["elapsed"]

            operation_timings[op_name] = {
                "elapsed": elapsed,
                "status": result["status"],
                "error": result["error"],
            }

            if result["response"] is None:
                if elapsed >= self.slow_threshold:
                    findings.append({
                        "type": "operation_timeout",
                        "operation": op_name,
                        "elapsedSeconds": round(elapsed, 3),
                        "error": result["error"],
                    })
                continue

            if elapsed >= self.slow_threshold:
                findings.append({
                    "type": "slow_operation",
                    "operation": op_name,
                    "elapsedSeconds": round(elapsed, 3),
                    "httpStatus": result["status"],
                })

        for large_op, large_param in self._large_payload_targets(operations):
            large_value = "A" * self.large_payload_size

            large_body = self._build_request(
                large_op,
                overrides={large_param: large_value},
            )

            large_result = self._timed_send(large_body, large_op)

            large_elapsed = large_result["elapsed"]
            large_op_name = large_op.get("name", "")

            baseline_elapsed = operation_timings.get(
                large_op_name, {}
            ).get("elapsed", 0.0)

            if self._is_abnormal_delay(baseline_elapsed, large_elapsed):
                findings.append({
                    "type": "large_payload_delay",
                    "operation": large_op_name,
                    "parameter": large_param,
                    "payloadSizeBytes": self.large_payload_size,
                    "elapsedSeconds": round(large_elapsed, 3),
                    "baselineElapsedSeconds": round(baseline_elapsed, 3),
                    "httpStatus": large_result["status"],
                    "error": large_result["error"],
                })

        if findings:
            ptprint("Slow SOAP operation behavior detected.",
                    "VULN", not self.args.json, indent=4, colortext=True)

            for finding in findings:
                ptprint(f"  {self._finding_message(finding)}",
                        "VULN", not self.args.json, indent=4)

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-OPERATION-TIMEOUT",
                node_key=self.helpers.node_key,
                data={
                    "summary": "Slow SOAP operation behavior was detected.",
                    "description": (
                        "One or more SOAP requests exceeded the configured "
                        "response-time threshold or showed abnormal delay "
                        "compared to a baseline request."
                    ),
                    "confidence": "black-box timing heuristic",
                    "slowThresholdSeconds": self.slow_threshold,
                    "ratioThreshold": self.ratio_threshold,
                    "minRatioSignalSeconds": self.min_ratio_signal_seconds,
                    "largePayloadSizeBytes": self.large_payload_size,
                    "findingCount": len(findings),
                    "findings": findings,
                    "note": (
                        "Timing-based heuristic. Slow responses may have legitimate "
                        "causes such as network latency, downstream service load, "
                        "or natural processing overhead for large payloads. Manual "
                        "verification recommended for high-impact decisions."
                    ),
                },
            )
            return

        ptprint("No slow SOAP operation behavior detected.",
                "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    OperationTimeout(args, ptjsonlib, helpers, http_client, common_tests).run()