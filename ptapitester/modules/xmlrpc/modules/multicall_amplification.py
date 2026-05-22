"""XML-RPC system.multicall amplification test"""

import time
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Multicall Amplification test"


BATCH_SIZES = [5, 20, 50]
SAFE_METHOD_CANDIDATES = ["ping", "demo.ping", "system.getCapabilities"]
MAX_RESPONSE_EXCERPT = 200


class MulticallAmplification:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)
    
    def _pick_safe_method(self, discovered_methods):
        for candidate in SAFE_METHOD_CANDIDATES:
            if candidate in discovered_methods:
                return candidate
        return None

    def _build_call(self, method_name, params=None):
        params = tuple(params or ())
        return xmlrpc.client.dumps(
            params,
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

    def _build_multicall_payload(self, method_name, count):
        calls = [
            {
                "methodName": method_name,
                "params": [],
            }
            for _ in range(count)
        ]

        return xmlrpc.client.dumps(
            (calls,),
            methodname="system.multicall",
            allow_none=True,
            encoding="utf-8",
        )

    def _send_raw_timed(self, payload):
        start = time.time()
        r = self.helpers.send_xmlrpc_raw(data=payload)
        elapsed = time.time() - start
        return r, elapsed

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
        except Exception as e:
            return {
                "type": "PARSE_ERROR",
                "params": [],
                "faultCode": None,
                "faultString": str(e),
                "raw": raw,
            }

    def _classify_multicall_response(self, response, expected_count):
        parsed = self._parse_xmlrpc_response(response)

        if response is None:
            return "NO_RESPONSE", parsed, {
                "resultCount": 0,
                "successCount": 0,
                "faultCount": 0,
            }

        if response.status_code in (401, 403, 407):
            return "AUTH_DENIED", parsed, {
                "resultCount": 0,
                "successCount": 0,
                "faultCount": 0,
            }

        if parsed["type"] == "FAULT":
            return "MULTICALL_FAULT", parsed, {
                "resultCount": 0,
                "successCount": 0,
                "faultCount": 0,
            }

        if parsed["type"] != "SUCCESS":
            return parsed["type"], parsed, {
                "resultCount": 0,
                "successCount": 0,
                "faultCount": 0,
            }

        params = parsed.get("params", [])
        if not params:
            return "EMPTY_SUCCESS", parsed, {
                "resultCount": 0,
                "successCount": 0,
                "faultCount": 0,
            }

        results = params[0]

        if not isinstance(results, (list, tuple)):
            return "UNEXPECTED_RESPONSE_SHAPE", parsed, {
                "resultCount": 0,
                "successCount": 0,
                "faultCount": 0,
            }

        result_count = len(results)
        fault_count = sum(1 for item in results if isinstance(item, dict) and "faultCode" in item)
        success_count = result_count - fault_count

        metrics = {
            "resultCount": result_count,
            "successCount": success_count,
            "faultCount": fault_count,
        }

        if result_count == expected_count and success_count == expected_count:
            return "FULL_BATCH_EXECUTED", parsed, metrics

        if result_count == expected_count and success_count > 0:
            return "PARTIAL_BATCH_WITH_FAULTS", parsed, metrics

        if 0 < result_count < expected_count:
            return "BATCH_LIMITED_OR_PARTIAL", parsed, metrics

        if result_count == 0:
            return "NO_SUBCALL_RESULTS", parsed, metrics

        return "UNEXPECTED_RESULT_COUNT", parsed, metrics

    def _response_excerpt(self, response):
        if response is None:
            return ""
        return (response.text or "")[:MAX_RESPONSE_EXCERPT].strip().replace("\n", " ")

    def _finding_to_text(self, finding):
        return (
            f"system.multicall executed {finding['successCount']} successful "
            f"subcall(s) in one request for batch size {finding['batchSize']}."
        )

    def _observation_to_text(self, observation):
        return observation.get("message", "Multicall observation.")

    def run(self):
        discovered_methods = getattr(self.helpers, "discovered_methods", []) or []

        if "system.multicall" not in discovered_methods:
            ptprint("system.multicall not available.", "OK",
                    not self.args.json, indent=4)
            return

        observations = []
        findings = []

        safe_method = self._pick_safe_method(discovered_methods)
        if safe_method is None:
            observations.append({
                "type": "BASELINE_SKIPPED",
                "candidates": SAFE_METHOD_CANDIDATES,
                "message": (
                    f"No safe baseline method available "
                    f"(tried: {', '.join(SAFE_METHOD_CANDIDATES)}). "
                    "Cannot safely test multicall amplification."
                )
            })

            ptprint(
                f"No safe baseline method available "
                f"(tried: {', '.join(SAFE_METHOD_CANDIDATES)}). Skipping.",
                "INFO", not self.args.json, indent=4)
            return

        baseline_payload = self._build_call(safe_method, [])
        baseline_r, baseline_elapsed = self._send_raw_timed(baseline_payload)
        baseline_parsed = self._parse_xmlrpc_response(baseline_r)

        if baseline_r is None or baseline_parsed["type"] != "SUCCESS":
            ptprint("Baseline method did not return a successful XML-RPC response. "
                    "Skipping multicall test.",
                    "INFO", not self.args.json, indent=4)

            self.ptjsonlib.add_properties(
                properties={
                    "xmlrpcMulticallAmplificationTest": {
                        "status": "skipped",
                        "reason": "BASELINE_METHOD_NOT_SUCCESSFUL",
                        "baselineMethod": safe_method if (safe_method, self._pick_safe_method(discovered_methods)) else None,
                        "baselineResponseType": baseline_parsed["type"],
                    }
                },
                node_key=self.helpers.node_key
            )
            return

        observations.append({
            "type": "BASELINE_SUCCESS",
            "method": safe_method,
            "httpStatus": baseline_r.status_code,
            "elapsedSeconds": round(baseline_elapsed, 3),
            "message": (
                f"Baseline method '{safe_method}' returned a successful response."
            )
        })

        best_result = None

        for batch_size in BATCH_SIZES:
            payload = self._build_multicall_payload(safe_method, batch_size)
            r, elapsed = self._send_raw_timed(payload)

            classification, parsed, metrics = self._classify_multicall_response(
                r,
                expected_count=batch_size,
            )

            observation = {
                "type": "MULTICALL_PROBE",
                "batchSize": batch_size,
                "classification": classification,
                "httpStatus": r.status_code if r is not None else None,
                "elapsedSeconds": round(elapsed, 3),
                "resultCount": metrics["resultCount"],
                "successCount": metrics["successCount"],
                "faultCount": metrics["faultCount"],
                "responseExcerpt": self._response_excerpt(r),
                "message": (
                    f"system.multicall probe with {batch_size} subcall(s) "
                    f"classified as {classification}."
                )
            }

            observations.append(observation)

            if classification in (
                "FULL_BATCH_EXECUTED",
                "PARTIAL_BATCH_WITH_FAULTS",
                "BATCH_LIMITED_OR_PARTIAL",
            ):
                if best_result is None or metrics["successCount"] > best_result["successCount"]:
                    expected_sequential = baseline_elapsed * batch_size
                    amplification_factor = (
                        round(expected_sequential / elapsed, 2)
                        if elapsed > 0 else None
                    )
                    best_result = {
                        "batchSize": batch_size,
                        "classification": classification,
                        "httpStatus": r.status_code if r is not None else None,
                        "elapsedSeconds": round(elapsed, 3),
                        "baselineElapsedSeconds": round(baseline_elapsed, 3),
                        "expectedSequentialSeconds": round(expected_sequential, 3),
                        "amplificationFactor": amplification_factor,
                        "resultCount": metrics["resultCount"],
                        "successCount": metrics["successCount"],
                        "faultCount": metrics["faultCount"],
                    }
        
        if best_result and best_result["successCount"] >= 20:
            findings.append({
                "type": "MULTICALL_BATCH_EXECUTION",
                "method": "system.multicall",
                "subcallMethod": safe_method,
                "batchSize": best_result["batchSize"],
                "classification": best_result["classification"],
                "httpStatus": best_result["httpStatus"],
                "resultCount": best_result["resultCount"],
                "successCount": best_result["successCount"],
                "faultCount": best_result["faultCount"],
                "elapsedSeconds": best_result["elapsedSeconds"],
                "baselineElapsedSeconds": best_result["baselineElapsedSeconds"],
                "expectedSequentialSeconds": best_result["expectedSequentialSeconds"],
                "amplificationFactor": best_result["amplificationFactor"],
                "message": (
                    "system.multicall executed many subcalls in a single "
                    "HTTP request. This may amplify brute-force, enumeration "
                    "or resource-consumption attacks if sensitive or expensive "
                    "methods are callable."
                )
            })

        if findings:
            f = findings[0]

            ptprint(
                f"system.multicall amplification possible "
                f"({f['successCount']} successful subcall(s) in one request)!",
                "VULN",
                not self.args.json,
                indent=4,
                colortext=True,
            )

            ptprint(
                f"  Highest successful batch: {f['successCount']}/{f['batchSize']} "
                f"subcall(s), classification: {f['classification']}.",
                "VULN",
                not self.args.json,
                indent=4,
            )

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-MULTICALL-AMPLIFICATION",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC system.multicall batch execution was observed.",
                    "description": (
                        "The endpoint allowed many XML-RPC method calls to be "
                        "executed inside a single HTTP request using system.multicall."
                    ),
                    "confidence": "black-box heuristic",
                    "method": "system.multicall",
                    "subcallMethod": safe_method,
                    "testedBatchSizes": BATCH_SIZES,
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                }
            )
            return

        ptprint("system.multicall batch amplification not confirmed.", "OK",
        not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    MulticallAmplification(args, ptjsonlib, helpers, http_client, common_tests).run()