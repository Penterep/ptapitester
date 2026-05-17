"""
SOAP HTTP method test
"""

from urllib.parse import quote
import hashlib
import html
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP HTTP method test"

SOAP_FAULT_INDICATORS = [
    "soap:fault","soapenv:fault","<fault>","faultcode","faultstring",
]

XML_PARSER_INDICATORS = [
    "xml parse error","xml syntax error","xmlsyntaxerror","not well-formed","malformed xml","premature end",
    "unclosed token","undeclared prefix","namespace error","invalid element","invalid tag",
]

SOAP_PROCESSING_INDICATORS = [
    "operation not found","unknown operation","method not found","soap processing",
    "schema validation","xsd validation","cannot find dispatch method","no such operation",
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
    "echo","ping","add","sum","calculate","get","read","list","search","find","lookup",
]

class HTTPMethodTest:
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

    def _matched(self, text, indicators):
        if not text:
            return []
        low = text.lower()
        return [ind for ind in indicators if ind in low]

    def _body_hash(self, response):
        if response is None:
            return None
        return hashlib.sha256((response.text or "").encode("utf-8")).hexdigest()

    def _excerpt(self, response, limit=220):
        if response is None:
            return ""
        return (response.text or "")[:limit].strip().replace("\n", " ").replace("\r", " ")

    def _send(self, method, url, body=None, headers=None):
        try:
            return self.http_client.send_request(
                url=url,
                method=method,
                data=body,
                headers=headers or {},
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

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

    def _default_value(self, type_name):
        t = (type_name or "string").split(":")[-1].lower()

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

        if not op.get("input_params"):
            score += 10

        if self._has_url_like_params(op):
            score -= 50

        if self._is_destructive_operation(op):
            score -= 1000

        return score

    def _select_operation(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []
        valid_ops = [op for op in operations if op.get("name")]

        if not valid_ops:
            return None

        candidates = [
            op for op in valid_ops
            if not self._is_destructive_operation(op)
            and not self._has_url_like_params(op)
        ]

        if not candidates:
            candidates = [
                op for op in valid_ops
                if not self._is_destructive_operation(op)
            ]

        if not candidates:
            return None

        candidates.sort(key=self._safe_score, reverse=True)
        return candidates[0]

    def _build_request(self, op):
        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element") or op.get("name")
        params = op.get("input_params", []) or []

        params_xml = ""

        for p in params:
            name = p.get("name")
            if not name:
                continue

            value = self._default_value(p.get("type", "string"))
            params_xml += (
                f"<tns:{name}>"
                f"{html.escape(str(value), quote=False)}"
                f"</tns:{name}>"
            )

        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:tns="{html.escape(tns, quote=True)}">'
            "<soap:Body>"
            f"<tns:{input_element}>"
            f"{params_xml}"
            f"</tns:{input_element}>"
            "</soap:Body>"
            "</soap:Envelope>"
        )

    def _build_generic_valid_request(self):
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soap:Body>"
            "<message>method_test</message>"
            "</soap:Body>"
            "</soap:Envelope>"
        )

    def _build_malformed_request(self):
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soap:Body><message>malformed"
            "</soap:Envelope>"
        )

    def _build_namespace_error_request(self):
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            "<bad:Envelope>"
            "<bad:Body><message>namespace_test</message></bad:Body>"
            "</bad:Envelope>"
        )

    def _query_url(self, key, value):
        sep = "&" if "?" in self.helpers.endpoint_url else "?"
        return self.helpers.endpoint_url + sep + key + "=" + quote(value, safe="")

    def _local_names(self, text):
        if not text:
            return set()

        names = set()

        for tag in re.findall(r"<\/?(?:[A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)", text):
            names.add(tag.lower())

        return names

    def _looks_like_operation_output(self, response, op):
        if response is None or not op:
            return False

        if response.status_code < 200 or response.status_code >= 300:
            return False

        text = response.text or ""

        if self._has_any(text, SOAP_FAULT_INDICATORS):
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

    def _classify(self, response, op=None):
        if response is None:
            return {
                "classification": "NO_RESPONSE",
                "parserEvidence": False,
                "matchedIndicators": [],
            }

        text = response.text or ""

        if response.status_code in (405, 501):
            return {
                "classification": "METHOD_NOT_ALLOWED",
                "parserEvidence": False,
                "matchedIndicators": [],
            }

        matched_fault = self._matched(text, SOAP_FAULT_INDICATORS)
        matched_xml = self._matched(text, XML_PARSER_INDICATORS)
        matched_processing = self._matched(text, SOAP_PROCESSING_INDICATORS)

        if self._looks_like_operation_output(response, op):
            return {
                "classification": "OPERATION_OUTPUT",
                "parserEvidence": True,
                "matchedIndicators": [],
            }

        if matched_fault:
            return {
                "classification": "SOAP_FAULT",
                "parserEvidence": True,
                "matchedIndicators": matched_fault,
            }

        if matched_xml:
            return {
                "classification": "XML_PARSE_ERROR",
                "parserEvidence": True,
                "matchedIndicators": matched_xml,
            }

        if matched_processing:
            return {
                "classification": "SOAP_PROCESSING_ERROR",
                "parserEvidence": True,
                "matchedIndicators": matched_processing,
            }

        low = text.lower()

        if "<definitions" in low or "<wsdl:" in low or "wsdl:definitions" in low:
            return {
                "classification": "WSDL_OR_METADATA",
                "parserEvidence": False,
                "matchedIndicators": [],
            }

        if response.status_code >= 500:
            return {
                "classification": "SERVER_ERROR",
                "parserEvidence": False,
                "matchedIndicators": [],
            }

        if 200 <= response.status_code < 300:
            return {
                "classification": "NON_SOAP_SUCCESS",
                "parserEvidence": False,
                "matchedIndicators": [],
            }

        return {
            "classification": "OTHER",
            "parserEvidence": False,
            "matchedIndicators": [],
        }

    def _record(self, name, method, url, response, classification):
        return {
            "name": name,
            "method": method,
            "url": url,
            "httpStatus": response.status_code if response is not None else None,
            "classification": classification["classification"],
            "parserEvidence": classification["parserEvidence"],
            "matchedIndicators": classification.get("matchedIndicators", []),
            "bodySha256": self._body_hash(response),
            "excerpt": self._excerpt(response),
        }

    def run(self):
        endpoint = self.helpers.endpoint_url
        op = self._select_operation()

        valid_body = self._build_request(op) if op else self._build_generic_valid_request()
        malformed_body = self._build_malformed_request()
        namespace_body = self._build_namespace_error_request()

        observations = []
        findings = []

        post_response = self._send(
            "POST",
            endpoint,
            body=valid_body,
            headers=self._soap_headers(op),
        )
        post_class = self._classify(post_response, op)
        observations.append(self._record(
            "post_baseline_valid_soap",
            "POST",
            endpoint,
            post_response,
            post_class,
        ))

        plain_get_response = self._send("GET", endpoint)
        plain_get_class = self._classify(plain_get_response, op)
        observations.append(self._record(
            "plain_get",
            "GET",
            endpoint,
            plain_get_response,
            plain_get_class,
        ))

        control_url = self._query_url("ptapitester_control", "not_xml")
        control_response = self._send("GET", control_url)
        control_class = self._classify(control_response, op)
        observations.append(self._record(
            "control_get_non_xml_query",
            "GET",
            control_url,
            control_response,
            control_class,
        ))

        get_body_response = self._send(
            "GET",
            endpoint,
            body=valid_body,
            headers=self._soap_headers(op),
        )
        get_body_class = self._classify(get_body_response, op)
        observations.append(self._record(
            "get_with_valid_soap_body",
            "GET",
            endpoint,
            get_body_response,
            get_body_class,
        ))

        query_valid_url = self._query_url("xml", valid_body)
        query_valid_response = self._send("GET", query_valid_url)
        query_valid_class = self._classify(query_valid_response, op)
        observations.append(self._record(
            "get_with_valid_soap_in_xml_query",
            "GET",
            query_valid_url,
            query_valid_response,
            query_valid_class,
        ))

        query_malformed_url = self._query_url("xml", malformed_body)
        query_malformed_response = self._send("GET", query_malformed_url)
        query_malformed_class = self._classify(query_malformed_response, op)
        observations.append(self._record(
            "get_with_malformed_soap_in_xml_query",
            "GET",
            query_malformed_url,
            query_malformed_response,
            query_malformed_class,
        ))

        query_namespace_url = self._query_url("xml", namespace_body)
        query_namespace_response = self._send("GET", query_namespace_url)
        query_namespace_class = self._classify(query_namespace_response, op)
        observations.append(self._record(
            "get_with_namespace_error_in_xml_query",
            "GET",
            query_namespace_url,
            query_namespace_response,
            query_namespace_class,
        ))

        post_hash = self._body_hash(post_response)
        get_body_hash = self._body_hash(get_body_response)

        post_success = post_class["classification"] == "OPERATION_OUTPUT"
        get_body_same_as_post = (
            post_response is not None
            and get_body_response is not None
            and post_response.status_code == get_body_response.status_code
            and post_hash is not None
            and post_hash == get_body_hash
            and post_class["classification"] != "WSDL_OR_METADATA"
        )

        control_has_parser_evidence = control_class["parserEvidence"]
        plain_has_parser_evidence = plain_get_class["parserEvidence"]

        query_valid_differential = (
            query_valid_class["parserEvidence"]
            and not control_has_parser_evidence
            and query_valid_class["classification"] != "WSDL_OR_METADATA"
        )

        query_malformed_differential = (
            query_malformed_class["parserEvidence"]
            and not control_has_parser_evidence
            and query_malformed_class["classification"] != "WSDL_OR_METADATA"
        )

        query_namespace_differential = (
            query_namespace_class["parserEvidence"]
            and not control_has_parser_evidence
            and query_namespace_class["classification"] != "WSDL_OR_METADATA"
        )

        get_body_differential = (
            get_body_class["parserEvidence"]
            and not plain_has_parser_evidence
            and get_body_class["classification"] != "WSDL_OR_METADATA"
        )

        if post_success and get_body_same_as_post:
            findings.append({
                "type": "GET_BODY_OPERATION_BEHAVES_LIKE_POST",
                "message": (
                    "A GET request carrying the SOAP envelope in the request body "
                    "returned the same response as the POST baseline."
                ),
                "postBaseline": observations[0],
                "getProbe": observations[3],
            })

        if get_body_differential and not (post_success and get_body_same_as_post):
            findings.append({
                "type": "GET_BODY_SOAP_PARSER_REACHED",
                "message": (
                    "A GET request carrying a SOAP body reached SOAP/XML parser "
                    "logic while plain GET did not."
                ),
                "getProbe": observations[3],
                "plainGet": observations[1],
            })

        if query_valid_differential:
            findings.append({
                "type": "GET_QUERY_VALID_SOAP_PARSER_REACHED",
                "message": (
                    "A GET request carrying a valid SOAP envelope in the xml query "
                    "parameter reached SOAP/XML parser logic while non-XML control "
                    "GET did not."
                ),
                "getProbe": observations[4],
                "controlGet": observations[2],
            })

        if query_malformed_differential:
            findings.append({
                "type": "GET_QUERY_MALFORMED_SOAP_PARSER_REACHED",
                "message": (
                    "A GET request carrying malformed SOAP XML in the xml query "
                    "parameter triggered XML parser-specific behavior while "
                    "non-XML control GET did not."
                ),
                "getProbe": observations[5],
                "controlGet": observations[2],
            })

        if query_namespace_differential:
            findings.append({
                "type": "GET_QUERY_NAMESPACE_SOAP_PARSER_REACHED",
                "message": (
                    "A GET request carrying namespace-invalid XML in the xml query "
                    "parameter triggered XML parser-specific behavior while "
                    "non-XML control GET did not."
                ),
                "getProbe": observations[6],
                "controlGet": observations[2],
            })

        if findings:
            ptprint(
                "SOAP processing via GET was detected.",
                "VULN",
                not self.args.json,
                indent=4,
                colortext=True,
            )

            for finding in findings:
                ptprint(
                    f"  {finding['type']}: {finding['message']}",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-HTTP-METHOD",
                node_key=self.helpers.node_key,
                data={
                    "summary": "SOAP endpoint appears to process SOAP/XML payloads via GET.",
                    "description": (
                        "The endpoint showed evidence that SOAP/XML payloads sent "
                        "with HTTP GET reached SOAP operation or parser logic. "
                        "This broadens the attack surface compared to accepting "
                        "SOAP payloads only via POST."
                    ),
                    "confidence": "black-box differential evidence",
                    "operation": op.get("name") if op else None,
                    "findings": findings,
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "Plain GET returning WSDL or metadata is not treated as "
                        "a vulnerability. The finding requires differential "
                        "parser/operation evidence for GET-carried SOAP payloads."
                    ),
                },
            )
            return

        if plain_get_class["classification"] == "WSDL_OR_METADATA":
            ptprint(
                "Endpoint responds to plain GET with WSDL/metadata only "
                "(informational, not a vulnerability).",
                "INFO",
                not self.args.json,
                indent=4,
            )

        ptprint(
            "No evidence that tested GET requests are processed as SOAP operations.",
            "OK",
            not self.args.json,
            indent=4,
        )

        self.ptjsonlib.add_properties(
            properties={
                "soapHttpMethodTest": {
                    "status": "no_get_soap_processing_observed",
                    "operation": op.get("name") if op else None,
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "No SOAP operation or parser processing was observed for "
                        "the tested GET vectors."
                    ),
                }
            },
            node_key=self.helpers.node_key,
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    HTTPMethodTest(args, ptjsonlib, helpers, http_client, common_tests).run()