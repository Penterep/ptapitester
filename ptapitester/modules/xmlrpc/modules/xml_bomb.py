"""
XML-RPC XML Bomb (Billion Laughs) resistance test
"""

import time
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC XML Bomb resistance test"


REQUEST_TIMEOUT_SECONDS = 15

BOMB_DTD = (
    '<!DOCTYPE lolz ['
    '  <!ENTITY lol "lol">'
    '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
    ']>'
)

ENTITY_REF = "&lol3;"

EXPANSION_MARKER = "lol"
EXPANSION_MARKER_BASELINE_REGEX = r"\blol\b"
EXPANDED_MARKER_THRESHOLD = 30
EXPANDED_MARKER_MIN_DENSITY = 0.02

TIMING_MIN_ABS_SECONDS = 2.0
TIMING_RATIO_THRESHOLD = 3.0

DOCTYPE_BLOCKED_INDICATORS = [
    "doctype is disallowed","doctype declarations are disallowed","dtd is prohibited","dtd is disabled",
    "disallow-doctype-decl","for security reasons dtd is prohibited","doctype not allowed","dtd not allowed",
]

ENTITY_EXPANSION_BLOCKED_INDICATORS = [
    "entity expansion limit","entity expansions","maximum entity","entity amplification","amplification factor",
    "billion laughs","too many entity","recursive entity","entity loop","entity nesting",
]

ENTITY_UNRESOLVED_INDICATORS = [
    "entity 'lol3' not defined",'entity "lol3" not defined',
    "undefined entity","reference to undeclared entity","undeclared entity",
]

XML_PARSE_ERROR_INDICATORS = [
    "xmlsyntaxerror","xml syntax error","parse error","not well-formed",
    "malformed xml","start tag expected","premature end",
]


class XMLBomb:
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

    def _response_excerpt(self, response_text, limit=220):
        if not response_text:
            return ""
        return response_text[:limit].strip().replace("\n", " ").replace("\r", " ")

    def _endpoint_url(self):
        return getattr(self.helpers, "endpoint_url", None) or getattr(self.args, "url", None)

    def _send_raw_timed(self, payload):
        url = self._endpoint_url()
        start = time.time()

        try:
            r = self.http_client.send_request(
                url=url,
                method="POST",
                data=payload,
                headers={"Content-Type": "text/xml; charset=utf-8"},
                merge_headers=False,
                allow_redirects=True,
            )
            elapsed = time.time() - start

            if r is None:
                return {
                    "response": None,
                    "elapsedSeconds": elapsed,
                    "timedOut": elapsed >= getattr(
                        self.args, "timeout", REQUEST_TIMEOUT_SECONDS
                    ),
                    "errorType": "NO_RESPONSE",
                    "errorMessage": "http_client returned no response",
                    "text": "",
                    "httpStatus": None,
                }

            return {
                "response": r,
                "elapsedSeconds": elapsed,
                "timedOut": False,
                "errorType": None,
                "errorMessage": None,
                "text": r.text or "",
                "httpStatus": r.status_code,
            }

        except Exception as e:
            elapsed = time.time() - start
            error_name = type(e).__name__
            is_timeout = (
                "timeout" in error_name.lower()
                or "timeout" in str(e).lower()
            )
            is_connect_error = (
                "connect" in error_name.lower()
                and not is_timeout
            )

            return {
                "response": None,
                "elapsedSeconds": elapsed,
                "timedOut": is_timeout and not is_connect_error,
                "errorType": error_name,
                "errorMessage": str(e),
                "text": "",
                "httpStatus": None,
            }

    def _normalise_type(self, typ):
        if not typ:
            return "string"

        t = str(typ).lower().strip()

        if ":" in t:
            t = t.split(":", 1)[-1]

        return t

    def _value_xml_for_type(self, typ, value=None):
        t = self._normalise_type(typ)

        if value is None:
            if t in ("int", "i4", "i8", "integer", "long", "short"):
                value = "0"
            elif t in ("double", "float", "decimal"):
                value = "0.0"
            elif t in ("boolean", "bool"):
                value = "0"
            elif t in ("array", "list"):
                return "<array><data></data></array>"
            elif t in ("struct", "dict"):
                return "<struct></struct>"
            else:
                value = "string"

        if t in ("int", "i4", "i8", "integer", "long", "short"):
            return f"<int>{value}</int>"

        if t in ("double", "float", "decimal"):
            return f"<double>{value}</double>"

        if t in ("boolean", "bool"):
            return f"<boolean>{value}</boolean>"

        return f"<string>{value}</string>"

    def _get_known_methods(self):
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

    def _get_param_types_for_method(self, method_name):
        metadata = getattr(self.helpers, "metadata", {}) or {}

        if isinstance(metadata, dict):
            info = metadata.get(method_name)
            if isinstance(info, dict):
                param_types = info.get("param_types")
                if isinstance(param_types, list):
                    return param_types

        return None

    def _select_string_param_method(self):

        methods = self._get_known_methods()

        preferred = ["process_data", "echo", "read_user"]

        for method in preferred:
            if method in methods:
                param_types = self._get_param_types_for_method(method)
                if param_types and any(self._normalise_type(t) in ("string", "str") for t in param_types):
                    return method, param_types, "metadata"

        for method in methods:
            if method.startswith("system."):
                continue

            param_types = self._get_param_types_for_method(method)

            if param_types and any(self._normalise_type(t) in ("string", "str") for t in param_types):
                return method, param_types, "metadata"

        if "process_data" in methods:
            return "process_data", ["string"], "fallback_process_data"

        if "echo" in methods:
            return "echo", ["string"], "fallback_echo"

        return None, None, "none"
    
    def _build_baseline_request(self):
        return (
            '<?xml version="1.0"?>'
            '<methodCall>'
            '<methodName>ping</methodName>'
            '<params></params>'
            '</methodCall>'
        )

    def _build_methodname_bomb(self):
        return (
            '<?xml version="1.0"?>'
            f'{BOMB_DTD}'
            '<methodCall>'
            f'<methodName>{ENTITY_REF}</methodName>'
            '<params></params>'
            '</methodCall>'
        )

    def _build_string_param_bomb(self, method_name, param_types):

        if not param_types:
            param_types = ["string"]

        string_index = 0

        for idx, typ in enumerate(param_types):
            if self._normalise_type(typ) in ("string", "str"):
                string_index = idx
                break

        params_xml = ""

        for idx, typ in enumerate(param_types):
            if idx == string_index:
                value_xml = f"<string>{ENTITY_REF}</string>"
            else:
                value_xml = self._value_xml_for_type(typ)

            params_xml += f"<param><value>{value_xml}</value></param>"

        return (
            '<?xml version="1.0"?>'
            f'{BOMB_DTD}'
            '<methodCall>'
            f'<methodName>{method_name}</methodName>'
            '<params>'
            f'{params_xml}'
            '</params>'
            '</methodCall>'
        )

    def _build_raw_value_bomb(self, method_name):
        return (
            '<?xml version="1.0"?>'
            f'{BOMB_DTD}'
            '<methodCall>'
            f'<methodName>{method_name}</methodName>'
            '<params>'
            f'<param><value>{ENTITY_REF}</value></param>'
            '</params>'
            '</methodCall>'
        )

    def _build_payloads(self):
        payloads = [
            {
                "name": "entity expansion in methodName",
                "location": "methodName",
                "method": None,
                "payload": self._build_methodname_bomb(),
            }
        ]

        method_name, param_types, source = self._select_string_param_method()

        if method_name:
            payloads.append({
                "name": "entity expansion in string parameter",
                "location": "string_parameter",
                "method": method_name,
                "methodSource": source,
                "payload": self._build_string_param_bomb(method_name, param_types),
            })

            payloads.append({
                "name": "entity expansion as raw value parameter",
                "location": "raw_value_parameter",
                "method": method_name,
                "methodSource": source,
                "payload": self._build_raw_value_bomb(method_name),
            })

        return payloads

    def _classify_response(self, result, baseline_elapsed):

        text = result.get("text", "") or ""
        elapsed = result.get("elapsedSeconds", 0)

        marker_count = text.lower().count(EXPANSION_MARKER)
        text_length = len(text) if text else 1
        marker_density = marker_count / text_length

        if (marker_count >= EXPANDED_MARKER_THRESHOLD
                and marker_density >= EXPANDED_MARKER_MIN_DENSITY):
            return "ENTITY_EXPANDED_IN_RESPONSE", {
                "expandedMarkerCount": marker_count,
                "markerDensity": round(marker_density, 4),
                "matchedIndicators": [],
            }

        if result.get("timedOut"):
            error_type = (result.get("errorType") or "").lower()
            if "connect" in error_type and "timeout" not in error_type:
                return "REQUEST_ERROR", {
                    "expandedMarkerCount": marker_count,
                    "matchedIndicators": [],
                }
            return "TIMEOUT_OR_RESOURCE_EXHAUSTION", {
                "expandedMarkerCount": marker_count,
                "matchedIndicators": [],
            }

        if (
            elapsed >= TIMING_MIN_ABS_SECONDS
            and baseline_elapsed > 0
            and elapsed >= baseline_elapsed * TIMING_RATIO_THRESHOLD
        ):
            return "SLOW_RESPONSE", {
                "expandedMarkerCount": marker_count,
                "matchedIndicators": [],
            }

        matched_expansion_blocked = self._matched_indicators(
            text,
            ENTITY_EXPANSION_BLOCKED_INDICATORS,
        )
        if matched_expansion_blocked:
            return "ENTITY_EXPANSION_BLOCKED", {
                "expandedMarkerCount": marker_count,
                "matchedIndicators": matched_expansion_blocked,
            }

        matched_doctype = self._matched_indicators(
            text,
            DOCTYPE_BLOCKED_INDICATORS,
        )
        if matched_doctype:
            return "DOCTYPE_BLOCKED", {
                "expandedMarkerCount": marker_count,
                "matchedIndicators": matched_doctype,
            }

        matched_unresolved = self._matched_indicators(
            text,
            ENTITY_UNRESOLVED_INDICATORS,
        )
        if matched_unresolved:
            return "ENTITY_UNRESOLVED", {
                "expandedMarkerCount": marker_count,
                "matchedIndicators": matched_unresolved,
            }

        matched_parse = self._matched_indicators(
            text,
            XML_PARSE_ERROR_INDICATORS,
        )
        if matched_parse:
            return "XML_PARSE_ERROR", {
                "expandedMarkerCount": marker_count,
                "matchedIndicators": matched_parse,
            }

        if result.get("errorType"):
            return "REQUEST_ERROR", {
                "expandedMarkerCount": marker_count,
                "matchedIndicators": [],
            }

        return "NO_BOMB_EVIDENCE", {
            "expandedMarkerCount": marker_count,
            "matchedIndicators": [],
        }

    def run(self):
        findings = []
        observations = []

        baseline = self._send_raw_timed(self._build_baseline_request())

        if baseline.get("response") is None and baseline.get("errorType"):
            ptprint("Could not complete XML Bomb test (baseline request failed).",
                    "INFO", not self.args.json, indent=4)
            return

        baseline_elapsed = baseline.get("elapsedSeconds", 0)

        observations.append({
            "type": "BASELINE",
            "classification": "BASELINE_RESPONSE",
            "httpStatus": baseline.get("httpStatus"),
            "elapsedSeconds": round(baseline_elapsed, 3),
            "message": "Baseline XML-RPC request completed.",
        })

        payloads = self._build_payloads()

        for payload_info in payloads:
            result = self._send_raw_timed(payload_info["payload"])
            classification, details = self._classify_response(result, baseline_elapsed)

            record = {
                "payload": payload_info["name"],
                "location": payload_info["location"],
                "method": payload_info.get("method"),
                "methodSource": payload_info.get("methodSource"),
                "classification": classification,
                "httpStatus": result.get("httpStatus"),
                "elapsedSeconds": round(result.get("elapsedSeconds", 0), 3),
                "baselineElapsedSeconds": round(baseline_elapsed, 3),
                "expandedMarkerCount": details.get("expandedMarkerCount", 0),
                "markerDensity": details.get("markerDensity", 0.0),
                "matchedIndicators": details.get("matchedIndicators", []),
                "errorType": result.get("errorType"),
                "errorMessage": result.get("errorMessage"),
                "responseExcerpt": self._response_excerpt(result.get("text")),
            }

            if classification in (
                "ENTITY_EXPANDED_IN_RESPONSE",
                "TIMEOUT_OR_RESOURCE_EXHAUSTION",
                "SLOW_RESPONSE",
            ):
                finding = {
                    **record,
                    "type": "XML_BOMB_BEHAVIOR_OBSERVED",
                    "message": (
                        "Bounded XML entity expansion payload caused observable "
                        "XML bomb behavior: reflected expansion, timeout, or "
                        "significant slowdown compared to baseline."
                    ),
                }
                findings.append(finding)

            else:
                observations.append({
                    **record,
                    "type": "XML_BOMB_PROBE",
                    "message": (
                        "No XML bomb vulnerability signal was observed for this payload."
                    ),
                })

        if findings:
            ptprint("XML Bomb behavior observed.", "VULN",
                    not self.args.json, indent=4, colortext=True)

            for f in findings:
                if f["classification"] == "ENTITY_EXPANDED_IN_RESPONSE":
                    ptprint(
                        f"  {f['location']}: entity expansion reflected "
                        f"({f['expandedMarkerCount']} '{EXPANSION_MARKER}' markers).",
                        "VULN",
                        not self.args.json,
                        indent=4,
                    )

                elif f["classification"] == "TIMEOUT_OR_RESOURCE_EXHAUSTION":
                    ptprint(
                        f"  {f['location']}: request timed out after "
                        f"{f['elapsedSeconds']}s.",
                        "VULN",
                        not self.args.json,
                        indent=4,
                    )

                elif f["classification"] == "SLOW_RESPONSE":
                    ptprint(
                        f"  {f['location']}: slow response "
                        f"{f['elapsedSeconds']}s vs baseline "
                        f"{f['baselineElapsedSeconds']}s.",
                        "VULN",
                        not self.args.json,
                        indent=4,
                    )

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-XMLBOMB",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC XML Bomb behavior was observed.",
                    "description": (
                        "A bounded nested-entity XML payload caused reflected "
                        "entity expansion, timeout, or significant slowdown. "
                        "This suggests the XML parser may be vulnerable to "
                        "entity expansion resource exhaustion."
                    ),
                    "confidence": "black-box heuristic",
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "baselineElapsedSeconds": round(baseline_elapsed, 3),
                    "findings": findings,
                    "observations": observations,
                    "note": (
                        "The payload is intentionally bounded and small. "
                        "This test does not send a destructive full Billion "
                        "Laughs payload."
                    ),
                },
            )
            return

        meaningful_observations = [
            obs for obs in observations
            if obs.get("classification") in (
                "ENTITY_EXPANSION_BLOCKED",
                "DOCTYPE_BLOCKED",
                "ENTITY_UNRESOLVED",
                "XML_PARSE_ERROR",
            )
        ]

        ptprint("No XML Bomb behavior observed with tested bounded payloads.",
                "OK", not self.args.json, indent=4)

        for obs in meaningful_observations[:5]:
            msg = obs.get("classification")
            indicators = obs.get("matchedIndicators") or []

            if indicators:
                ptprint(
                    f"  {obs['location']}: {msg} "
                    f"({', '.join(indicators)}).",
                    "INFO",
                    not self.args.json,
                    indent=4,
                )
            else:
                ptprint(
                    f"  {obs['location']}: {msg}.",
                    "INFO",
                    not self.args.json,
                    indent=4,
                )

        self.ptjsonlib.add_properties(
            properties={
                "xmlrpcXMLBombTest": {
                    "status": "no_xml_bomb_behavior_observed",
                    "baselineElapsedSeconds": round(baseline_elapsed, 3),
                    "payloadCount": len(payloads),
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "No XML bomb behavior was observed with the tested "
                        "bounded payloads."
                    ),
                }
            },
            node_key=self.helpers.node_key,
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XMLBomb(args, ptjsonlib, helpers, http_client, common_tests).run()