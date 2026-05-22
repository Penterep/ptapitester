"""
XML-RPC Content-Type response  test
"""

import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Content-Type response audit"


XML_CONTENT_TYPES = {
    "text/xml","application/xml",
}

HTML_CONTENT_TYPES = {
    "text/html","application/xhtml+xml",
}

JSON_CONTENT_TYPES = {
    "application/json","text/json",
}

BINARY_CONTENT_TYPES = {
    "application/octet-stream","application/pdf","application/zip","application/x-zip-compressed",
}


class ContentTypeValidation:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _parse_content_type(self, header_value):
        
        result = {
            "raw": header_value or "",
            "mime": "",
            "params": {},
            "malformed": False,
            "errors": [],
        }

        if not header_value:
            return result

        parts = [p.strip() for p in header_value.split(";")]
        mime = parts[0].lower()

        if not re.match(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$", mime):
            result["malformed"] = True
            result["errors"].append("invalid MIME type syntax")
            result["mime"] = mime
            return result

        result["mime"] = mime

        seen_params = set()

        for token in parts[1:]:
            if not token:
                continue

            if "=" not in token:
                result["malformed"] = True
                result["errors"].append(f"malformed parameter: {token!r}")
                continue

            key, _, value = token.partition("=")
            key = key.strip().lower()
            value = value.strip()

            if not key:
                result["malformed"] = True
                result["errors"].append("empty parameter name")
                continue

            if key in seen_params:
                result["malformed"] = True
                result["errors"].append(f"duplicate parameter: {key}")
                continue

            seen_params.add(key)

            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]

            result["params"][key] = value

        return result

    def _body_text(self, response):
        return response.text or ""

    def _body_bytes(self, response):
        content = getattr(response, "content", None)
        if content is not None:
            return content
        return (response.text or "").encode("utf-8", errors="ignore")

    def _body_looks_like_xmlrpc_response(self, body):
        if not body:
            return False

        text = body.lstrip()[:500].lower()

        return (
            text.startswith("<?xml")
            or "<methodresponse" in text
        )

    def _body_looks_like_xmlrpc_fault(self, body):
        if not body:
            return False

        low = body.lower()

        return (
            "<methodresponse" in low
            and "<fault>" in low
            and "faultcode" in low
            and "faultstring" in low
        )

    def _body_looks_like_html(self, body):
        if not body:
            return False

        text = body.lstrip()[:500].lower()

        return (
            text.startswith("<!doctype html")
            or text.startswith("<html")
            or "<head>" in text
            or "<body>" in text
        )

    def _body_looks_like_json(self, body):
        if not body:
            return False

        text = body.lstrip()[:200]

        return (
            text.startswith("{")
            or text.startswith("[")
        )

    def _body_looks_binary(self, response):
        data = self._body_bytes(response)

        if not data:
            return False

        sample = data[:512]

        if not sample:
            return False

        non_printable = sum(
            1 for b in sample
            if b < 9 or (13 < b < 32) or b == 127
        )

        return non_printable / max(len(sample), 1) > 0.10

    def _classify_response_body(self, response):
        body = self._body_text(response)

        if self._body_looks_like_xmlrpc_fault(body):
            return "xmlrpc_fault"

        if self._body_looks_like_xmlrpc_response(body):
            return "xmlrpc_response"

        if self._body_looks_like_html(body):
            return "html"

        if self._body_looks_like_json(body):
            return "json"

        if self._body_looks_binary(response):
            return "binary"

        return "unknown"

    def _classify_content_type(self, parsed_ct):
        mime = parsed_ct.get("mime", "")

        if not mime:
            return "missing"

        if mime in XML_CONTENT_TYPES:
            return "xml"

        if mime in HTML_CONTENT_TYPES:
            return "html"

        if mime in JSON_CONTENT_TYPES:
            return "json"

        if mime in BINARY_CONTENT_TYPES:
            return "binary"

        if mime.startswith("text/"):
            return "text"

        if mime.startswith("application/"):
            return "application"

        return "unknown"

    def _build_probe_request(self):
        methods = getattr(self.helpers, "discovered_methods", []) or []

        preferred_names = [
            "ping",
            "demo.ping",
            "system.getCapabilities",
        ]

        for name in preferred_names:
            if name in methods:
                return (
                    '<?xml version="1.0"?>'
                    '<methodCall>'
                    f'<methodName>{name}</methodName>'
                    '<params></params>'
                    '</methodCall>'
                )
        return (
            '<?xml version="1.0"?>'
            '<methodCall>'
            '<methodName>ping</methodName>'
            '<params></params>'
            '</methodCall>'
        )

    def _finding_to_text(self, finding):
        return finding.get("message", "Content-Type issue detected.")

    def _observation_to_text(self, observation):
        return observation.get("message", "Content-Type observation.")

    def run(self):
        probe = self._build_probe_request()
        r = self.helpers.send_xmlrpc_raw(data=probe)

        if r is None:
            ptprint("Could not complete Content-Type audit.", "INFO",
                    not self.args.json, indent=4)
            return

        raw_ct = r.headers.get("Content-Type", "")
        parsed_ct = self._parse_content_type(raw_ct)

        ct_class = self._classify_content_type(parsed_ct)
        body_class = self._classify_response_body(r)

        findings = []
        observations = []

        if parsed_ct["malformed"]:
            findings.append({
                "type": "MALFORMED_CONTENT_TYPE",
                "httpStatus": r.status_code,
                "contentType": raw_ct,
                "contentTypeClass": ct_class,
                "bodyClass": body_class,
                "errors": parsed_ct["errors"],
                "message": (
                    "Malformed Content-Type header detected. Different clients "
                    "or intermediaries may parse this response inconsistently."
                )
            })

        if ct_class == "missing":
            if body_class in ("xmlrpc_response", "xmlrpc_fault"):
                findings.append({
                    "type": "MISSING_CONTENT_TYPE",
                    "httpStatus": r.status_code,
                    "contentType": raw_ct or "(absent)",
                    "contentTypeClass": ct_class,
                    "bodyClass": body_class,
                    "message": (
                        "XML-RPC response body was returned without a "
                        "Content-Type header."
                    )
                })
            else:
                observations.append({
                    "type": "MISSING_CONTENT_TYPE_UNKNOWN_BODY",
                    "httpStatus": r.status_code,
                    "contentType": raw_ct or "(absent)",
                    "contentTypeClass": ct_class,
                    "bodyClass": body_class,
                    "message": (
                        "Response does not include Content-Type header, but "
                        "the body was not clearly recognised as XML-RPC."
                    )
                })

        elif body_class in ("xmlrpc_response", "xmlrpc_fault"):
            if ct_class == "xml":
                observations.append({
                    "type": "NORMAL_XMLRPC_CONTENT_TYPE",
                    "httpStatus": r.status_code,
                    "contentType": raw_ct,
                    "contentTypeClass": ct_class,
                    "bodyClass": body_class,
                    "message": (
                        "XML-RPC response uses an XML Content-Type."
                    )
                })

                if "charset" not in parsed_ct["params"]:
                    observations.append({
                        "type": "MISSING_CHARSET",
                        "httpStatus": r.status_code,
                        "contentType": raw_ct,
                        "contentTypeClass": ct_class,
                        "bodyClass": body_class,
                        "message": (
                            "Content-Type does not specify a charset. This is "
                            "informational for XML-RPC and is not treated as "
                            "a vulnerability."
                        )
                    })

            else:
                findings.append({
                    "type": "XMLRPC_BODY_MIME_MISMATCH",
                    "httpStatus": r.status_code,
                    "contentType": raw_ct,
                    "contentTypeClass": ct_class,
                    "bodyClass": body_class,
                    "message": (
                        "Response body looks like XML-RPC XML, but the "
                        "Content-Type is not an XML MIME type."
                    )
                })

        elif body_class == "html" or ct_class == "html":
            findings.append({
                "type": "HTML_RESPONSE_FROM_XMLRPC_ENDPOINT",
                "httpStatus": r.status_code,
                "contentType": raw_ct,
                "contentTypeClass": ct_class,
                "bodyClass": body_class,
                "message": (
                    "XML-RPC endpoint returned HTML content. This may indicate "
                    "an error page, proxy/WAF response, or response-type confusion."
                )
            })

        elif body_class == "json" or ct_class == "json":
            observations.append({
                "type": "JSON_RESPONSE_FROM_XMLRPC_ENDPOINT",
                "httpStatus": r.status_code,
                "contentType": raw_ct,
                "contentTypeClass": ct_class,
                "bodyClass": body_class,
                "message": (
                    "XML-RPC endpoint returned JSON or JSON-like content. "
                    "This may be a gateway/proxy response or non-standard behaviour."
                )
            })
        
        elif body_class == "binary":
            if ct_class in ("xml", "text"):
                findings.append({
                    "type": "BINARY_BODY_TEXT_MIME_MISMATCH",
                    "httpStatus": r.status_code,
                    "contentType": raw_ct,
                    "contentTypeClass": ct_class,
                    "bodyClass": body_class,
                    "message": (
                        "Response body appears binary, but Content-Type declares "
                        "text/XML content."
                    )
                })
            else:
                observations.append({
                    "type": "BINARY_RESPONSE",
                    "httpStatus": r.status_code,
                    "contentType": raw_ct,
                    "contentTypeClass": ct_class,
                    "bodyClass": body_class,
                    "message": (
                        "XML-RPC endpoint returned binary-looking content."
                    )
                })
        
        else:
            observations.append({
                "type": "UNRECOGNISED_RESPONSE_TYPE",
                "httpStatus": r.status_code,
                "contentType": raw_ct or "(absent)",
                "contentTypeClass": ct_class,
                "bodyClass": body_class,
                "message": (
                    "Response type could not be clearly classified."
                )
            })

        if findings:
            ptprint("XML-RPC Content-Type issues found.", "VULN",
                    not self.args.json, indent=4, colortext=True)

            for finding in findings:
                ptprint(f"  {self._finding_to_text(finding)}",
                        "VULN", not self.args.json, indent=4)

            for observation in observations[:8]:
                ptprint(f"  (info) {self._observation_to_text(observation)}",
                        "INFO", not self.args.json, indent=4)

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-CONTENT-TYPE-MISCONFIGURED",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC response Content-Type issues were observed.",
                    "description": (
                        "The XML-RPC endpoint returned a response whose "
                        "Content-Type header was missing, malformed, or "
                        "inconsistent with the response body."
                    ),
                    "confidence": "black-box heuristic",
                    "httpStatus": r.status_code,
                    "rawContentType": raw_ct or "(absent)",
                    "contentType": parsed_ct,
                    "contentTypeClass": ct_class,
                    "bodyClass": body_class,
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                }
            )
            return

        ptprint("XML-RPC Content-Type audit completed.", "OK",
                not self.args.json, indent=4)

        for observation in observations[:8]:
            ptprint(f"  {self._observation_to_text(observation)}",
                    "INFO", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ContentTypeValidation(args, ptjsonlib, helpers, http_client, common_tests).run()