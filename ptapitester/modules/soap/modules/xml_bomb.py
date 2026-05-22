"""
SOAP XML Bomb (Billion Laughs) resistance test
"""

import time
import html
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP XML Bomb resistance test"


REQUEST_TIMEOUT_SECONDS = 15

BOMB_DTD = (
    '<!DOCTYPE lolz ['
    '<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
    ']>'
)

ENTITY_REF = "&lol3;"
EXPANSION_MARKER = "lol"
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
    "entity 'lol3' not defined",'entity "lol3" not defined',"undefined entity",
    "reference to undeclared entity","undeclared entity",
]

XML_PARSE_ERROR_INDICATORS = [
    "xmlsyntaxerror","xml syntax error","xml parse error","parse error",
    "not well-formed","malformed xml","start tag expected","premature end",
]

DESTRUCTIVE_OPERATION_WORDS = [
    "delete","remove","drop","destroy","disable","reset","update",
    "edit","create","new","write","insert","change","transfer",
]

URL_LIKE_PARAM_WORDS = [
    "url","uri","endpoint","callback","webhook",
    "target","href","src","link","fetch","source",
]

SAFE_OPERATION_HINTS = [
    "echo","ping","add","sum","calculate",
    "get","read","list","search","find","lookup",
]


class XMLBomb:
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

    def _normalise_type(self, typ):
        if not typ:
            return "string"
        t = str(typ).strip().lower()
        if ":" in t:
            t = t.split(":", 1)[-1]
        return t

    def _default_value(self, typ):
        t = self._normalise_type(typ)

        if t in ("int", "integer", "long", "short", "byte", "unsignedint", "unsignedlong"):
            return "0"

        if t in ("float", "double", "decimal"):
            return "0.0"

        if t in ("boolean", "bool"):
            return "true"

        if t == "date":
            return "2050-01-01"

        if t in ("datetime", "datetime.iso8601"):
            return "2050-01-01T00:00:00"

        if t in ("anyuri", "uri"):
            return "http://example.com/"

        return "string"

    def _is_destructive_operation(self, op):
        name = (op.get("name") or "").lower()
        return any(word in name for word in DESTRUCTIVE_OPERATION_WORDS)

    def _has_url_like_params(self, op):
        for p in op.get("input_params", []) or []:
            name = (p.get("name") or "").lower()
            if any(word in name for word in URL_LIKE_PARAM_WORDS):
                return True
        return False

    def _safe_score(self, op):
        name = (op.get("name") or "").lower()
        score = 0

        for idx, hint in enumerate(SAFE_OPERATION_HINTS):
            if hint in name:
                score += 100 - idx

        params = op.get("input_params", []) or []

        if any(self._normalise_type(p.get("type")) in ("string", "str") for p in params):
            score += 50

        if not params:
            score += 10

        if self._has_url_like_params(op):
            score -= 100

        if self._is_destructive_operation(op):
            score -= 1000

        return score

    def _select_string_operation(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []
        valid_ops = [op for op in operations if op.get("name")]

        candidates = []

        for op in valid_ops:
            if self._is_destructive_operation(op):
                continue

            if self._has_url_like_params(op):
                continue

            params = op.get("input_params", []) or []

            if any(self._normalise_type(p.get("type")) in ("string", "str") for p in params):
                candidates.append(op)

        if not candidates:
            return None

        candidates.sort(key=self._safe_score, reverse=True)
        return candidates[0]

    def _soap_headers(self, op=None):
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
        }

        if op:
            action = op.get("soap_action") or op.get("soapAction") or ""
            if action:
                if action.startswith('"') and action.endswith('"'):
                    headers["SOAPAction"] = action
                else:
                    headers["SOAPAction"] = f'"{action}"'

        return headers

    def _send_raw_timed(self, payload, op=None):
        url = self._endpoint_url(op)
        start = time.time()

        try:
            r = self.http_client.send_request(
                url=url,
                method="POST",
                data=payload,
                headers=self._soap_headers(op),
                merge_headers=False,
                allow_redirects=True,
            )
            elapsed = time.time() - start

            return {
                "response": r,
                "elapsedSeconds": elapsed,
                "timedOut": False,
                "errorType": None,
                "errorMessage": None,
                "text": r.text if r is not None else "",
                "httpStatus": r.status_code if r is not None else None,
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

    def _operation_body(self, op, bomb=False):
        if not op:
            value = ENTITY_REF if bomb else "string"
            return f"<message>{value}</message>"

        input_element = op.get("input_element") or op.get("name")
        params = op.get("input_params", []) or []

        string_index = None

        for idx, p in enumerate(params):
            if self._normalise_type(p.get("type")) in ("string", "str"):
                string_index = idx
                break

        params_xml = ""

        for idx, p in enumerate(params):
            name = p.get("name")
            if not name:
                continue

            if bomb and idx == string_index:
                value = ENTITY_REF
            else:
                value = self._default_value(p.get("type", "string"))

            params_xml += (
                f"<tns:{name}>"
                f"{html.escape(str(value), quote=False) if value != ENTITY_REF else value}"
                f"</tns:{name}>"
            )

        return f"<tns:{input_element}>{params_xml}</tns:{input_element}>"

    def _envelope(self, body_xml, include_dtd=False, header_xml=""):
        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        dtd = BOMB_DTD if include_dtd else ""

        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            f"{dtd}"
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:tns="{html.escape(tns, quote=True)}">'
            f"{header_xml}"
            "<soap:Body>"
            f"{body_xml}"
            "</soap:Body>"
            "</soap:Envelope>"
        )

    def _build_baseline_request(self, op):
        return self._envelope(
            self._operation_body(op, bomb=False),
            include_dtd=False,
        )

    def _build_payloads(self, op):
        payloads = []

        payloads.append({
            "name": "entity expansion in generic SOAP body",
            "location": "generic_body",
            "operation": None,
            "payload": self._envelope(
                "<message>&lol3;</message>",
                include_dtd=True,
            ),
        })

        if op:
            payloads.append({
                "name": "entity expansion in operation string parameter",
                "location": "operation_string_parameter",
                "operation": op.get("name"),
                "payload": self._envelope(
                    self._operation_body(op, bomb=True),
                    include_dtd=True,
                ),
            })

            payloads.append({
                "name": "entity expansion in SOAP header",
                "location": "soap_header",
                "operation": op.get("name"),
                "payload": self._envelope(
                    self._operation_body(op, bomb=False),
                    include_dtd=True,
                    header_xml="<soap:Header><tns:tracking>&lol3;</tns:tracking></soap:Header>",
                ),
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

        op = self._select_string_operation()
        baseline_payload = self._build_baseline_request(op)
        baseline = self._send_raw_timed(baseline_payload, op)

        if baseline.get("response") is None and baseline.get("errorType"):
            ptprint(
                "Could not complete XML Bomb test (baseline request failed).",
                "INFO",
                not self.args.json,
                indent=4,
            )
            return

        baseline_elapsed = baseline.get("elapsedSeconds", 0)

        observations.append({
            "type": "BASELINE",
            "classification": "BASELINE_RESPONSE",
            "operation": op.get("name") if op else None,
            "httpStatus": baseline.get("httpStatus"),
            "elapsedSeconds": round(baseline_elapsed, 3),
            "message": "Baseline SOAP request completed.",
        })

        payloads = self._build_payloads(op)

        for payload_info in payloads:
            result = self._send_raw_timed(payload_info["payload"], op)
            classification, details = self._classify_response(result, baseline_elapsed)

            record = {
                "payload": payload_info["name"],
                "location": payload_info["location"],
                "operation": payload_info.get("operation"),
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
                findings.append({
                    **record,
                    "type": "XML_BOMB_BEHAVIOR_OBSERVED",
                    "message": (
                        "Bounded SOAP XML entity expansion payload caused observable "
                        "XML bomb behavior: reflected expansion, timeout, or significant "
                        "slowdown compared to baseline."
                    ),
                })
            else:
                observations.append({
                    **record,
                    "type": "XML_BOMB_PROBE",
                    "message": (
                        "No SOAP XML bomb vulnerability signal was observed for this payload."
                    ),
                })

        if findings:
            ptprint(
                "SOAP XML Bomb behavior observed.",
                "VULN",
                not self.args.json,
                indent=4,
                colortext=True,
            )

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
                "PTV-SOAP-XML-BOMB",
                node_key=self.helpers.node_key,
                data={
                    "summary": "SOAP XML Bomb behavior was observed.",
                    "description": (
                        "A bounded nested-entity SOAP XML payload caused reflected "
                        "entity expansion, timeout, or significant slowdown. This "
                        "suggests the SOAP XML parser may be vulnerable to entity "
                        "expansion resource exhaustion."
                    ),
                    "confidence": "black-box heuristic",
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "baselineElapsedSeconds": round(baseline_elapsed, 3),
                    "operation": op.get("name") if op else None,
                    "findings": findings,
                    "observations": observations,
                    "note": (
                        "The payload is intentionally bounded and small. This test "
                        "does not send a destructive full Billion Laughs payload."
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

        ptprint(
            "No SOAP XML Bomb behavior observed with tested bounded payloads.",
            "OK",
            not self.args.json,
            indent=4,
        )

        for obs in meaningful_observations[:5]:
            classification = obs.get("classification")
            indicators = obs.get("matchedIndicators") or []

            if indicators:
                ptprint(
                    f"  {obs['location']}: {classification} "
                    f"({', '.join(indicators)}).",
                    "INFO",
                    not self.args.json,
                    indent=4,
                )
            else:
                ptprint(
                    f"  {obs['location']}: {classification}.",
                    "INFO",
                    not self.args.json,
                    indent=4,
                )

        self.ptjsonlib.add_properties(
            properties={
                "soapXMLBombTest": {
                    "status": "no_xml_bomb_behavior_observed",
                    "operation": op.get("name") if op else None,
                    "baselineElapsedSeconds": round(baseline_elapsed, 3),
                    "payloadCount": len(payloads),
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "No SOAP XML bomb behavior was observed with the tested "
                        "bounded payloads. This does not prove that all XML entity "
                        "expansion DoS vectors are impossible."
                    ),
                }
            },
            node_key=self.helpers.node_key,
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XMLBomb(args, ptjsonlib, helpers, http_client, common_tests).run()