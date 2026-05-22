"""
XML-RPC SSRF via pingback.ping test
"""

import time
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC SSRF Pingback test"

PINGBACK_METHOD = "pingback.ping"

INTERNAL_PROBE_URLS = [
    "http://127.0.0.1:22/",
    "http://127.0.0.1:80/",
    "http://localhost:80/",
    "http://[::1]:80/",
    "http://10.255.255.1:80/",
]

BASELINE_SOURCE_URL = "http://example.invalid/ptapitester-pingback-baseline"
BASELINE_TARGET_URL = "http://example.com/"

OUTBOUND_CONNECTION_INDICATORS = [
    "connection refused","connection reset","connection timed out","connect timed out","connect timeout","timed out while connecting",
    "failed to connect","could not connect","refused to connect","no route to host","network unreachable","host unreachable",
    "errno 111","errno 104","errno 110","errno 113","connectionerror","requests.exceptions.connectionerror",
    "urlopen error","socket error","socket.timeout","remote end closed connection",
]

DNS_RESOLUTION_INDICATORS = [
    "name or service not known","temporary failure in name resolution","nodename nor servname provided",
    "failed to resolve","could not resolve","unknown host","unable to resolve host","dns",
]

PINGBACK_REJECTION_INDICATORS = [
    "pingback disabled","pingback is disabled","invalid source","source uri does not exist","source url does not exist",
    "target uri cannot be used","target uri does not exist","target url does not exist","not a valid target","no link to target",
    "does not contain a link","pingback error",
]

GENERIC_INVALID_INPUT_INDICATORS = [
    "invalid uri","invalid url","malformed url","bad request","invalid params","missing parameter","method not found",
]

TIMING_MIN_ABS_SECONDS = 1.5
TIMING_RATIO_THRESHOLD = 2.0


class SSRFPingback:
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

    def _matched_indicators(self, text, indicators):
        if not text:
            return []
        low = text.lower()
        return [ind for ind in indicators if ind in low]

    def _response_excerpt(self, value, limit=220):
        if value is None:
            return ""
        return str(value)[:limit].strip().replace("\n", " ").replace("\r", " ")

    def _call_pingback(self, source_url, target_url):

        server = self.helpers.get_xmlrpc_proxy()
        start = time.time()

        try:
            result = server.pingback.ping(source_url, target_url)
            elapsed = time.time() - start
            return {
                "type": "SUCCESS",
                "result": result,
                "faultCode": None,
                "faultString": "",
                "clientException": None,
                "elapsedSeconds": elapsed,
                "text": str(result),
            }

        except xmlrpc.client.Fault as fault:
            elapsed = time.time() - start
            return {
                "type": "XMLRPC_FAULT",
                "result": None,
                "faultCode": fault.faultCode,
                "faultString": fault.faultString or "",
                "clientException": None,
                "elapsedSeconds": elapsed,
                "text": fault.faultString or "",
            }

        except Exception as e:
            elapsed = time.time() - start
            return {
                "type": "CLIENT_EXCEPTION",
                "result": None,
                "faultCode": None,
                "faultString": "",
                "clientException": f"{type(e).__name__}: {e}",
                "elapsedSeconds": elapsed,
                "text": str(e),
            }

    def _classify_pingback_response(self, response):

        text = response.get("text", "") or ""

        if response["type"] == "CLIENT_EXCEPTION":
            return "CLIENT_EXCEPTION"

        if self._has_any(text, OUTBOUND_CONNECTION_INDICATORS):
            return "OUTBOUND_CONNECTION_ERROR"

        if self._has_any(text, DNS_RESOLUTION_INDICATORS):
            return "DNS_RESOLUTION_ERROR"

        if self._has_any(text, GENERIC_INVALID_INPUT_INDICATORS):
            return "GENERIC_INVALID_INPUT"

        if self._has_any(text, PINGBACK_REJECTION_INDICATORS):
            return "PINGBACK_REJECTED"

        if response["type"] == "SUCCESS":
            return "SUCCESS"

        if response["type"] == "XMLRPC_FAULT":
            return "OTHER_FAULT"

        return "AMBIGUOUS"

    def _target_specific_markers(self, probe_url):
        
        markers = []

        if "127.0.0.1" in probe_url:
            markers.extend(["127.0.0.1", "localhost"])

        if "localhost" in probe_url:
            markers.extend(["localhost", "127.0.0.1"])

        if "[::1]" in probe_url or "::1" in probe_url:
            markers.extend(["::1", "[::1]"])

        if "10.255.255.1" in probe_url:
            markers.append("10.255.255.1")

        if ":22" in probe_url:
            markers.extend([":22", "port 22"])

        if ":80" in probe_url:
            markers.extend([":80", "port 80"])

        return markers

    def _has_target_specific_evidence(self, response_text, probe_url):
        
        if not response_text:
            return False

        low = response_text.lower()

        for marker in self._target_specific_markers(probe_url):
            if marker.lower() in low:
                return True

        return False
    
    def run(self):
        discovered_methods = getattr(self.helpers, "discovered_methods", []) or []

        if PINGBACK_METHOD not in discovered_methods:
            ptprint("pingback.ping not available. Skipping.",
                    "OK", not self.args.json, indent=4)
            return

        ptprint("pingback.ping detected — testing SSRF behavior.",
                "INFO", not self.args.json, indent=4)

        findings = []
        observations = []

        baseline_response = self._call_pingback(
            BASELINE_SOURCE_URL,
            BASELINE_TARGET_URL,
        )
        baseline_class = self._classify_pingback_response(baseline_response)

        observations.append({
            "type": "BASELINE",
            "sourceUrl": BASELINE_SOURCE_URL,
            "targetUrl": BASELINE_TARGET_URL,
            "classification": baseline_class,
            "responseType": baseline_response["type"],
            "faultCode": baseline_response.get("faultCode"),
            "elapsedSeconds": round(baseline_response["elapsedSeconds"], 3),
            "excerpt": self._response_excerpt(baseline_response.get("text")),
            "message": (
                "Baseline pingback.ping request completed and was used for "
                "differential comparison."
            ),
        })

        for probe_url in INTERNAL_PROBE_URLS:
            probe_response = self._call_pingback(
                probe_url,
                BASELINE_TARGET_URL,
            )
            probe_class = self._classify_pingback_response(probe_response)

            matched_connection = self._matched_indicators(
                probe_response.get("text", ""),
                OUTBOUND_CONNECTION_INDICATORS,
            )

            baseline_matched_connection = self._matched_indicators(
                baseline_response.get("text", ""),
                OUTBOUND_CONNECTION_INDICATORS,
            )

            target_specific_evidence = self._has_target_specific_evidence(
                probe_response.get("text", ""),
                probe_url,
            )

            matched_dns = self._matched_indicators(
                probe_response.get("text", ""),
                DNS_RESOLUTION_INDICATORS,
            )

            timing_signal = (
                probe_response["elapsedSeconds"] >= TIMING_MIN_ABS_SECONDS
                and baseline_response["elapsedSeconds"] > 0
                and probe_response["elapsedSeconds"]
                >= baseline_response["elapsedSeconds"] * TIMING_RATIO_THRESHOLD
            )

            record = {
                "sourceUrl": probe_url,
                "targetUrl": BASELINE_TARGET_URL,
                "classification": probe_class,
                "baselineClassification": baseline_class,
                "responseType": probe_response["type"],
                "faultCode": probe_response.get("faultCode"),
                "elapsedSeconds": round(probe_response["elapsedSeconds"], 3),
                "baselineElapsedSeconds": round(baseline_response["elapsedSeconds"], 3),
                "matchedConnectionIndicators": matched_connection,
                "baselineMatchedConnectionIndicators": baseline_matched_connection,
                "matchedDnsIndicators": matched_dns,
                "targetSpecificEvidence": target_specific_evidence,
                "excerpt": self._response_excerpt(probe_response.get("text")),
            }

            strong_differential_connection_signal = (
                probe_class == "OUTBOUND_CONNECTION_ERROR"
                and baseline_class != "OUTBOUND_CONNECTION_ERROR"
                and bool(matched_connection)
            )

            target_specific_connection_signal = (
                probe_class == "OUTBOUND_CONNECTION_ERROR"
                and bool(matched_connection)
                and target_specific_evidence
            )

            timing_differential_signal = (
                timing_signal
                and probe_class != "PINGBACK_REJECTED"
                and probe_class != "GENERIC_INVALID_INPUT"
            )

            if (strong_differential_connection_signal
                    or target_specific_connection_signal
                    or timing_differential_signal):
                signal_reasons = []
                if strong_differential_connection_signal:
                    signal_reasons.append("differential_connection_error")
                if target_specific_connection_signal:
                    signal_reasons.append("target_specific_evidence")
                if timing_differential_signal:
                    signal_reasons.append("timing_anomaly")

                finding = {
                    **record,
                    "type": "PINGBACK_SSRF_CONNECTION_ATTEMPT",
                    "signalReasons": signal_reasons,
                    "message": (
                        "pingback.ping produced backend connection behavior "
                        "for an internal URL. The signal is either different "
                        "from baseline behavior, contains target-specific "
                        "evidence, or shows significantly increased response time."
                    ),
                }

                findings.append(finding)
                continue

            observations.append({
                **record,
                "type": "PINGBACK_PROBE",
                "timingSignal": timing_signal,
                "message": (
                    "No strong pingback SSRF signal was observed for this probe."
                ),
            })

        if findings:
            f = findings[0]

            ptprint("Possible SSRF via pingback.ping detected.",
                    "VULN", not self.args.json, indent=4, colortext=True)

            
            reason = "differential behavior"

            if f.get("targetSpecificEvidence"):
                reason = "target-specific backend error"

            ptprint(
                f"  Internal URL {f['sourceUrl']} caused "
                f"{f['classification']} "
                f"(baseline: {f['baselineClassification']}, reason: {reason}).",
                "VULN",
                not self.args.json,
                indent=4,
            )

            if f.get("matchedConnectionIndicators"):
                ptprint(
                    f"  Matched indicators: "
                    f"{', '.join(f['matchedConnectionIndicators'])}.",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-SSRF-PINGBACK",
                node_key=self.helpers.node_key,
                data={
                    "summary": "Possible SSRF via XML-RPC pingback.ping was observed.",
                    "description": (
                        "The XML-RPC pingback.ping method accepted an internal "
                        "source URI and produced backend connection-related "
                        "behavior. This suggests the server may attempt to fetch "
                        "user-supplied URLs server-side."
                    ),
                    "confidence": "black-box heuristic",
                    "method": PINGBACK_METHOD,
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                    "note": (
                        "This test specifically checks the pingback.ping SSRF "
                        "vector. It does not use XXE or generic URL parameter "
                        "injection. Strongest evidence is a backend connection "
                        "error or differential behavior for internal URLs."
                    ),
                },
            )
            return

        ptprint("No SSRF indicators detected via pingback.ping.",
                "OK", not self.args.json, indent=4)

        self.ptjsonlib.add_properties(
            properties={
                "xmlrpcPingbackSSRFTest": {
                    "status": "no_pingback_ssrf_signal_detected",
                    "method": PINGBACK_METHOD,
                    "baselineClassification": baseline_class,
                    "testedProbeUrls": INTERNAL_PROBE_URLS,
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "No backend connection-specific behavior was observed "
                        "for tested pingback.ping internal URL probes. This does "
                        "not prove all SSRF vectors are impossible."
                    ),
                }
            },
            node_key=self.helpers.node_key,
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    SSRFPingback(args, ptjsonlib, helpers, http_client, common_tests).run()