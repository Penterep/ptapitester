"""
SOAP Information Disclosure assessment
"""

import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Information Disclosure assessment"


SOAP_FAULT_RE = re.compile(
    r"<(?:\w+:)?fault\b[^>]*>(.*?)</(?:\w+:)?fault>",
    re.DOTALL | re.IGNORECASE,
)
SOAP11_FAULTCODE_RE = re.compile(
    r"<(?:\w+:)?faultcode\b[^>]*>(.*?)</(?:\w+:)?faultcode>",
    re.DOTALL | re.IGNORECASE,
)
SOAP11_FAULTSTRING_RE = re.compile(
    r"<(?:\w+:)?faultstring\b[^>]*>(.*?)</(?:\w+:)?faultstring>",
    re.DOTALL | re.IGNORECASE,
)
SOAP11_DETAIL_RE = re.compile(
    r"<(?:\w+:)?detail\b[^>]*>(.*?)</(?:\w+:)?detail>",
    re.DOTALL | re.IGNORECASE,
)
SOAP12_CODE_VALUE_RE = re.compile(
    r"<(?:\w+:)?Code\b[^>]*>.*?<(?:\w+:)?Value\b[^>]*>(.*?)"
    r"</(?:\w+:)?Value>.*?</(?:\w+:)?Code>",
    re.DOTALL | re.IGNORECASE,
)
SOAP12_REASON_RE = re.compile(
    r"<(?:\w+:)?Reason\b[^>]*>(.*?)</(?:\w+:)?Reason>",
    re.DOTALL | re.IGNORECASE,
)
SOAP12_DETAIL_RE = re.compile(
    r"<(?:\w+:)?Detail\b[^>]*>(.*?)</(?:\w+:)?Detail>",
    re.DOTALL | re.IGNORECASE,
)

JAVA_TRACE_RE = re.compile(
    r"(?:[a-z][a-z0-9_]*\.){2,}[A-Z][A-Za-z0-9_]*(?:Exception|Error)"
    r"[\s\S]{0,300}?\bat\s+(?:[a-z][a-z0-9_]*\.){2,}[A-Za-z0-9_$<>]+",
    re.IGNORECASE,
)
PYTHON_TRACE_RE = re.compile(
    r"Traceback\s+\(most\s+recent\s+call\s+last\):[\s\S]{0,500}?"
    r"File\s+\"[^\"]+\",\s+line\s+\d+",
    re.IGNORECASE,
)
DOTNET_TRACE_RE = re.compile(
    r"(?:System|Microsoft)\.[A-Z][A-Za-z0-9_]*"
    r"(?:Exception|Error)[\s\S]{0,300}?"
    r"\bat\s+(?:[A-Z][A-Za-z0-9_]*\.){1,}[A-Za-z0-9_]+\s*\(",
)
PHP_TRACE_RE = re.compile(
    r"(?:Fatal\s+error|Warning|Parse\s+error|Notice|Stack\s+trace)"
    r"\s*:[\s\S]{0,200}?(?:in\s+/[^\s]+\.php\s+on\s+line\s+\d+"
    r"|#\d+\s+/[^\s]+\.php\(\d+\))",
    re.IGNORECASE,
)
NODEJS_TRACE_RE = re.compile(
    r"(?:Error|TypeError|RangeError|ReferenceError|SyntaxError)"
    r"\s*:[\s\S]{0,200}?\bat\s+[^\s]+\s+"
    r"\([^\)\s]+\.(?:js|ts|mjs):\d+:\d+\)",
)
GO_TRACE_RE = re.compile(
    r"panic:[\s\S]{0,300}?(?:goroutine\s+\d+\s+"
    r"|[/.][^\s]+\.go:\d+\s+\+0x[0-9a-f]+)",
    re.IGNORECASE,
)
RUBY_TRACE_RE = re.compile(
    r"(?:NoMethodError|NameError|RuntimeError|ArgumentError|TypeError|"
    r"StandardError)[\s\S]{0,200}?[a-zA-Z0-9_/\-]+\.rb:\d+:in\s+`",
)

STACK_TRACE_CLASSIFIERS = [
    ("java", JAVA_TRACE_RE),("python", PYTHON_TRACE_RE),("dotnet", DOTNET_TRACE_RE),("php", PHP_TRACE_RE),
    ("nodejs", NODEJS_TRACE_RE),("go", GO_TRACE_RE),("ruby", RUBY_TRACE_RE),
]

PATH_DISCLOSURE_PATTERNS = [
    (
        re.compile(
            r"(?<![A-Za-z0-9_/.\-])(?:/[A-Za-z0-9_\-.]+){2,}"
            r"\.(?:py|java|php|rb|go|js|ts|class|jsp|aspx|jar|war)"
            r"(?::\d+|\b)"
        ),
        "unix source path",
    ),
    (
        re.compile(
            r"(?<![A-Za-z0-9_/.\-])(?:/(?:var/www|home/[A-Za-z0-9_\-]+"
            r"|opt|srv|app|usr/local)/)[A-Za-z0-9_\-./]+\.[A-Za-z0-9]{1,8}"
        ),
        "deployment directory file",
    ),
    (
        re.compile(
            r"\b[A-Za-z]:\\(?:[A-Za-z0-9_\-. ]+\\){1,}[A-Za-z0-9_\-. ]+"
            r"\.(?:cs|vb|aspx|cshtml|exe|dll|config)\b"
        ),
        "windows source path",
    ),
    (
        re.compile(
            r"(?<![A-Za-z0-9_/.\-])/tmp/[A-Za-z0-9_\-./]+\.[a-z]{1,8}"
            r"(?::\d+|\b)"
        ),
        "temp path",
    ),
]

PARSER_ERROR_INDICATORS = [
    "xml parse error","xmlsyntaxerror","not well-formed","premature end of data",
    "opening and ending tag mismatch","expected one of","unexpected token",
]

FRAMEWORK_LEAKAGE_TOKENS = [
    "system.web.services","system.servicemodel","javax.xml.ws","org.apache.cxf","org.apache.axis",
    "weblogic.wsee","spring framework","jboss","wildfly","glassfish","spyne.application",
    "zeep.client","lxml.etree","werkzeug","flask","django.core","nodejs","express","asp.net",
]

FINGERPRINT_HEADERS = (
    "Server","X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version",
    "X-Generator","X-Runtime","X-Drupal-Cache","X-Debug-Token",
)


class InformationDisclosure:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _normalize_evidence(self, text, limit=200):
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

    def _build_valid_request(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []

        for op in operations:
            if op.get("name"):
                tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
                input_element = op.get("input_element", op["name"])
                params = op.get("input_params", [])

                params_xml = ""
                for p in params:
                    p_name = p.get("name", "")
                    p_type = p.get("type", "string")

                    if not p_name:
                        continue

                    value = self._default_value(p_type)
                    params_xml += f"<tns:{p_name}>{value}</tns:{p_name}>"

                return (
                    '<?xml version="1.0"?>'
                    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
                    f' xmlns:tns="{tns}">'
                    f"<soap:Body><tns:{input_element}>{params_xml}</tns:{input_element}></soap:Body>"
                    "</soap:Envelope>"
                )

        return (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soapenv:Body><message>info_disclosure_baseline</message></soapenv:Body>"
            "</soapenv:Envelope>"
        )

    def _malformed_payloads(self):
        return [
            ("invalid_xml", "<not_valid_xml!!!"),
            (
                "malformed_envelope",
                '<?xml version="1.0"?>'
                "<soapenv:Envelope><BROKEN",
            ),
            (
                "nonexistent_operation",
                '<?xml version="1.0"?>'
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                "<soapenv:Body><nonexistentOperation_z9x>x</nonexistentOperation_z9x></soapenv:Body>"
                "</soapenv:Envelope>",
            ),
            (
                "invalid_namespace",
                '<?xml version="1.0"?>'
                "<undeclared:Envelope><undeclared:Body><x/></undeclared:Body></undeclared:Envelope>",
            ),
            (
                "malformed_encoding",
                '<?xml version="1.0" encoding="!!INVALID!!"?>'
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                "<soapenv:Body><x/></soapenv:Body></soapenv:Envelope>",
            ),
        ]

    def _extract_soap_fault(self, body):
        if not body:
            return None

        m = SOAP_FAULT_RE.search(body)
        if not m:
            return None

        fault_block = m.group(1)
        result = {"raw": fault_block}

        c = SOAP11_FAULTCODE_RE.search(fault_block)
        if c:
            result["faultcode"] = c.group(1).strip()

        s = SOAP11_FAULTSTRING_RE.search(fault_block)
        if s:
            result["faultstring"] = s.group(1).strip()

        d = SOAP11_DETAIL_RE.search(fault_block)
        if d:
            result["detail"] = d.group(1).strip()

        c12 = SOAP12_CODE_VALUE_RE.search(fault_block)
        if c12:
            result["code_value"] = c12.group(1).strip()

        r12 = SOAP12_REASON_RE.search(fault_block)
        if r12:
            result["reason"] = r12.group(1).strip()

        d12 = SOAP12_DETAIL_RE.search(fault_block)
        if d12:
            result["detail_12"] = d12.group(1).strip()

        return result

    def _detect_stack_trace(self, body):
        if not body:
            return None, None

        for lang, regex in STACK_TRACE_CLASSIFIERS:
            m = regex.search(body)
            if m:
                return lang, m.group(0)

        return None, None

    def _detect_path_disclosure(self, body):
        if not body:
            return []

        results = []
        for regex, label in PATH_DISCLOSURE_PATTERNS:
            for m in regex.finditer(body):
                results.append((m.group(0), label))

        seen_paths = set()
        deduped = []

        for path, label in results:
            if path not in seen_paths:
                seen_paths.add(path)
                deduped.append((path, label))

        return deduped

    def _detect_framework_tokens(self, body):
        if not body:
            return []

        low = body.lower()
        return [tok for tok in FRAMEWORK_LEAKAGE_TOKENS if tok in low]

    def _detect_parser_errors(self, body):
        if not body:
            return []

        low = body.lower()
        return [tok for tok in PARSER_ERROR_INDICATORS if tok in low]

    def _extract_fingerprint_headers(self, response):
        if response is None:
            return []

        findings = []
        for header_name in FINGERPRINT_HEADERS:
            value = response.headers.get(header_name)

            if not value:
                continue

            clean_value = self._normalize_evidence(value.strip(), 160)
            findings.append({
                "header": header_name,
                "value": clean_value,
                "message": (
                    f"Technology/fingerprint header disclosed: "
                    f"{header_name}: {clean_value}"
                ),
            })

        return findings

    def _analyse_response(self, trigger, response, baseline_body):
        verbose_findings = []
        path_findings = []

        if response is None:
            return verbose_findings, path_findings

        body = response.text or ""

        lang, trace = self._detect_stack_trace(body)
        if lang:
            evidence = self._normalize_evidence(trace, 220)
            verbose_findings.append({
                "trigger": trigger,
                "type": "stack_trace",
                "language": lang,
                "evidence": evidence,
                "message": (
                    f"{trigger}: {lang} stack trace disclosed in response — "
                    f"{self._normalize_evidence(trace, 160)}"
                ),
            })

        fault = self._extract_soap_fault(body)
        if fault:
            fault_text = " ".join(v for v in fault.values() if isinstance(v, str))

            fault_lang, fault_trace = self._detect_stack_trace(fault_text)
            if fault_lang:
                verbose_findings.append({
                    "trigger": trigger,
                    "type": "soap_fault_stack_trace",
                    "language": fault_lang,
                    "evidence": self._normalize_evidence(fault_trace, 220),
                    "message": (
                        f"{trigger}: {fault_lang} stack trace disclosed inside SOAP Fault."
                    ),
                })

            for token in self._detect_framework_tokens(fault_text):
                verbose_findings.append({
                    "trigger": trigger,
                    "type": "framework_token",
                    "token": token,
                    "evidence": token,
                    "message": (
                        f"{trigger}: framework/parser token disclosed in SOAP Fault: {token}"
                    ),
                })

            for token in self._detect_parser_errors(fault_text):
                verbose_findings.append({
                    "trigger": trigger,
                    "type": "parser_error_detail",
                    "token": token,
                    "evidence": token,
                    "message": (
                        f"{trigger}: verbose parser/validation error disclosed: {token}"
                    ),
                })

        for token in self._detect_framework_tokens(body):
            verbose_findings.append({
                "trigger": trigger,
                "type": "framework_token",
                "token": token,
                "evidence": token,
                "message": (
                    f"{trigger}: framework/parser token disclosed in response: {token}"
                ),
            })

        for token in self._detect_parser_errors(body):
            verbose_findings.append({
                "trigger": trigger,
                "type": "parser_error_detail",
                "token": token,
                "evidence": token,
                "message": (
                    f"{trigger}: verbose parser/validation error disclosed: {token}"
                ),
            })

        for path, kind in self._detect_path_disclosure(body):
            if path in baseline_body:
                continue

            path_findings.append({
                "trigger": trigger,
                "path": self._normalize_evidence(path, 140),
                "kind": kind,
                "message": (
                    f"{trigger}: internal path disclosed: "
                    f"{self._normalize_evidence(path, 140)}"
                ),
            })

        return verbose_findings, path_findings
    
    def _dedupe_for_console(self, findings, key_fields):
        seen = set()
        result = []

        for finding in findings:
            key = tuple(finding.get(field, "") for field in key_fields)
            if key in seen:
                continue

            seen.add(key)
            result.append(finding)

        return result

    def _summarize_finding_triggers(self, all_findings, key_fields):
        """Group findings by (type, evidence) and collect their triggers."""
        groups = {}

        for finding in all_findings:
            key = tuple(finding.get(field, "") for field in key_fields)
            if key not in groups:
                groups[key] = {
                    "finding": finding,
                    "triggers": [],
                }
            trig = finding.get("trigger")
            if trig and trig not in groups[key]["triggers"]:
                groups[key]["triggers"].append(trig)

        return list(groups.values())

    def _dedupe_findings(self, findings, key_fields):
        seen = set()
        result = []

        for finding in findings:
            key = tuple(finding.get(field, "") for field in key_fields)
            if key in seen:
                continue

            seen.add(key)
            result.append(finding)

        return result

    def _consolidate_findings_by_evidence(self, findings, key_fields):
        groups = {}

        for finding in findings:
            key = tuple(finding.get(field, "") for field in key_fields)

            if key not in groups:
                base = {k: v for k, v in finding.items() if k != "trigger" and k != "message"}
                base["triggers"] = []
                base["triggerCount"] = 0
                groups[key] = base

            trig = finding.get("trigger")
            if trig and trig not in groups[key]["triggers"]:
                groups[key]["triggers"].append(trig)
            groups[key]["triggerCount"] = len(groups[key]["triggers"])

        return list(groups.values())

    def _add_vulnerability(self, vuln_code, summary, description, findings,
                          consolidate_keys=None):
        if not findings:
            return

        if consolidate_keys:
            consolidated = self._consolidate_findings_by_evidence(
                findings, consolidate_keys
            )
        else:
            consolidated = findings

        self.ptjsonlib.add_vulnerability(
            vuln_code,
            node_key=self.helpers.node_key,
            data={
                "summary": summary,
                "description": description,
                "confidence": "black-box evidence",
                "findingCount": len(consolidated),
                "findings": consolidated,
            },
        )

    def run(self):
        valid_payload = self._build_valid_request()
        baseline = self.helpers.send_soap_request(data=valid_payload)
        baseline_body = (baseline.text or "") if baseline is not None else ""

        verbose_findings = []
        path_findings = []
        tech_findings = self._extract_fingerprint_headers(baseline)

        if baseline is not None:
            v, p = self._analyse_response("baseline", baseline, "")
            verbose_findings.extend(v)
            path_findings.extend(p)

        for trigger, payload in self._malformed_payloads():
            response = self.helpers.send_soap_request(data=payload)
            v, p = self._analyse_response(trigger, response, baseline_body)
            verbose_findings.extend(v)
            path_findings.extend(p)

        verbose_findings = self._dedupe_findings(
            verbose_findings,
            ("trigger", "type", "evidence"),
        )
        path_findings = self._dedupe_findings(
            path_findings,
            ("path",),
        )
        tech_findings = self._dedupe_findings(
            tech_findings,
            ("header", "value"),
        )

        if not verbose_findings and not path_findings and not tech_findings:
            ptprint(
                "Information disclosure assessment completed (no confirmed disclosures).",
                "OK",
                not self.args.json,
                indent=4,
            )
            return
        
        ptprint(
            "Information disclosure detected.",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        verbose_groups = self._summarize_finding_triggers(
            verbose_findings,
            ("type", "evidence"),
        )

        for group in verbose_groups:
            f = group["finding"]
            triggers_count = len(group["triggers"])

            if triggers_count > 1:
                trigger_label = f"{triggers_count} triggers"
            else:
                trigger_label = group["triggers"][0] if group["triggers"] else "baseline"

            ptprint(
                f"  [{trigger_label}] {f.get('type', 'finding')}: "
                f"{f.get('evidence', f.get('message', ''))[:160]}",
                "VULN",
                not self.args.json,
                indent=4,
            )

        path_groups = self._summarize_finding_triggers(
            path_findings,
            ("path",),
        )

        for group in path_groups:
            f = group["finding"]
            triggers_count = len(group["triggers"])
            label = f"{triggers_count} triggers" if triggers_count > 1 else (
                group["triggers"][0] if group["triggers"] else "baseline"
            )

            ptprint(
                f"  [{label}] internal path disclosed: {f.get('path', '')} ({f.get('kind', '')})",
                "VULN",
                not self.args.json,
                indent=4,
            )

        for finding in tech_findings:
            ptprint(f"  (info) {finding['message']}", "INFO",
                    not self.args.json, indent=4)

        self._add_vulnerability(
            "PTV-SOAP-VERBOSE-ERRORS",
            "SOAP verbose error details were disclosed.",
            (
                "The SOAP endpoint returned verbose parser, framework, SOAP Fault, "
                "or stack trace details in response to malformed requests."
            ),
            verbose_findings,
            consolidate_keys=("type", "evidence"),
        )

        self._add_vulnerability(
            "PTV-SOAP-PATH-LEAK",
            "Internal filesystem paths were disclosed.",
            (
                "The SOAP endpoint returned internal filesystem paths in responses, "
                "revealing deployment or source file locations."
            ),
            path_findings,
            consolidate_keys=("path",),
        )

        self._add_vulnerability(
            "PTV-SOAP-TECH-DISCLOSURE",
            "SOAP technology or server fingerprint information was disclosed.",
            (
                "The SOAP endpoint exposed server, framework, runtime, or debug "
                "fingerprint information through HTTP response headers."
            ),
            tech_findings,
        )

def run(args, ptjsonlib, helpers, http_client, common_tests):
    InformationDisclosure(args, ptjsonlib, helpers, http_client, common_tests).run()
