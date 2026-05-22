"""
XML-RPC Information Disclosure audit test
"""

import re
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Information Disclosure test"
ERROR_TRIGGER_PROBES = [
    {
        "name": "Non-XML body",
        "body": "not xmlrpc at all",
    },
    {
        "name": "Malformed XML",
        "body": '<?xml version="1.0"?><methodCall><BROKEN',
    },
    {
        "name": "Invalid XML-RPC structure",
        "body": '<?xml version="1.0"?><methodCall><params></params></methodCall>',
    },
    {
        "name": "Non-existent method",
        "body": (
            '<?xml version="1.0"?>'
            '<methodCall>'
            '<methodName>nonexistent.method.12345</methodName>'
            '<params></params>'
            '</methodCall>'
        ),
    },
]


TECH_DISCLOSURE_HEADERS = [
    "server","x-powered-by","x-aspnet-version","x-aspnetmvc-version","x-runtime","x-generator","x-framework",
]

DEBUG_HEADERS = [
    "x-debug","x-debug-token","x-debug-token-link","x-trace-id","x-request-id",
]


STACK_TRACE_PATTERNS = [
    re.compile(r"traceback\s+\(most recent call last\)", re.IGNORECASE),
    re.compile(r"\bFile\s+\"[^\"]+\",\s+line\s+\d+", re.IGNORECASE),
    re.compile(r"\bat\s+[A-Za-z0-9_.$]+\([A-Za-z0-9_.]+:\d+\)", re.IGNORECASE),
    re.compile(r"\bstack trace\b", re.IGNORECASE),
]

PATH_PATTERNS = [
    re.compile(r"/(?:app|var|home|opt|usr|tmp|srv|etc|data)/[^\s<>'\"]+", re.IGNORECASE),
    re.compile(r"/[^\s<>'\"]+\.py\b", re.IGNORECASE),
    re.compile(r"/[^\s<>'\"]*site-packages/[^\s<>'\"]+", re.IGNORECASE),
    re.compile(r"[A-Za-z]:\\[^\s<>'\"]+", re.IGNORECASE),
]

INTERNAL_EXCEPTION_PATTERNS = [
    re.compile(r"\bxmlsyntaxerror\b", re.IGNORECASE),
    re.compile(r"\blxml\.etree\b", re.IGNORECASE),
    re.compile(r"\bsqlalchemy(?:\.[A-Za-z0-9_]+)*\b", re.IGNORECASE),
    re.compile(r"\b(?:ValueError|TypeError|AttributeError|KeyError|IndexError|ImportError)\b"),
    re.compile(r"\b(?:OperationalError|ProgrammingError|IntegrityError)\b"),
    re.compile(r"\b(?:NullPointerException|SQLException|RuntimeException)\b"),
]

SENSITIVE_INFO_PATTERNS = [
    re.compile(r"\bsecret[_-]?key\b", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key\b", re.IGNORECASE),
    re.compile(r"\baccess[_-]?token\b", re.IGNORECASE),
    re.compile(r"\bjwt\b", re.IGNORECASE),
    re.compile(r"\bpassword\b", re.IGNORECASE),
    re.compile(r"\bpasswd\b", re.IGNORECASE),
    re.compile(r"\bdatabase\b", re.IGNORECASE),
    re.compile(r"sqlite:///[^\s<>'\"]+", re.IGNORECASE),
    re.compile(r"postgres(?:ql)?://[^\s<>'\"]+", re.IGNORECASE),
    re.compile(r"mysql://[^\s<>'\"]+", re.IGNORECASE),
]

GENERIC_SAFE_ERROR_PATTERNS = [
    "parse error","malformed xml","invalid request","method not found",
]

NOISY_CONSOLE_OBSERVATION_TYPES = {
    "GENERIC_ERROR_RESPONSE",
    "NO_DISCLOSURE_IN_RESPONSE",
}

MAX_EXCERPT_LEN = 240


class InformationDisclosure:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _response_excerpt(self, text, limit=MAX_EXCERPT_LEN):
        if not text:
            return ""
        return text[:limit].strip().replace("\n", " ").replace("\r", " ")
    
    def _normalise_match(self, value):
        if not value:
            return value
        return value.strip().rstrip(".,:;)")

    def _normalise_header_dict(self, headers):
        result = {}
        for k, v in headers.items():
            result[str(k).lower()] = str(v)
        return result

    def _parse_xmlrpc_fault(self, response_text):
       
        result = {
            "isXmlRpc": False,
            "isFault": False,
            "faultCode": None,
            "faultString": "",
        }

        if not response_text:
            return result

        try:
            xmlrpc.client.loads(response_text)
            result["isXmlRpc"] = True
            return result
        except xmlrpc.client.Fault as fault:
            result["isXmlRpc"] = True
            result["isFault"] = True
            result["faultCode"] = fault.faultCode
            result["faultString"] = fault.faultString or ""
            return result
        except Exception:
            return result

    def _find_regex_matches(self, text, patterns, max_matches=5):
        matches = []
        if not text:
            return matches

        for pattern in patterns:
            for m in pattern.finditer(text):
                value = self._normalise_match(m.group(0))
                if value not in matches:
                    matches.append(value)
                if len(matches) >= max_matches:
                    return matches

        return matches

    def _looks_like_generic_safe_error(self, text):
        if not text:
            return False
        low = text.lower()
        return any(p in low for p in GENERIC_SAFE_ERROR_PATTERNS)

    def _add_unique(self, items, item, key_fields):
        key = tuple(item.get(k) for k in key_fields)
        for existing in items:
            existing_key = tuple(existing.get(k) for k in key_fields)
            if key == existing_key:
                return
        items.append(item)

    def _analyse_headers(self, response, observations, findings):
        headers = self._normalise_header_dict(response.headers)

        for header_name in TECH_DISCLOSURE_HEADERS:
            if header_name in headers:
                self._add_unique(observations, {
                    "type": "TECH_HEADER_DISCLOSURE",
                    "header": header_name,
                    "value": headers[header_name],
                    "message": (
                        f"Response exposes technology/fingerprint header "
                        f"'{header_name}: {headers[header_name]}'."
                    )
                }, key_fields=["type", "header", "value"])

        for header_name in DEBUG_HEADERS:
            if header_name in headers:
                self._add_unique(findings, {
                    "type": "DEBUG_HEADER_DISCLOSURE",
                    "header": header_name,
                    "value": headers[header_name],
                    "message": (
                        f"Response exposes debug/trace header "
                        f"'{header_name}: {headers[header_name]}'."
                    )
                }, key_fields=["type", "header", "value"])

    def _analyse_response_body(self, trigger_name, response, findings, observations):
        raw_body = response.text or ""
        fault_info = self._parse_xmlrpc_fault(raw_body)
        fault_text = fault_info.get("faultString", "") or ""
        analysis_text = fault_text if fault_text else raw_body
        combined_text = f"{fault_text}\n{raw_body}"

        stack_matches = self._find_regex_matches(combined_text, STACK_TRACE_PATTERNS)
        if stack_matches:
            self._add_unique(findings, {
                "type": "STACK_TRACE_DISCLOSURE",
                "trigger": trigger_name,
                "httpStatus": response.status_code,
                "xmlRpcFault": fault_info,
                "matches": stack_matches,
                "responseExcerpt": self._response_excerpt(analysis_text),
                "message": (
                    "Response contains stack trace indicators."
                )
            }, key_fields=["type"])

        path_matches = self._find_regex_matches(combined_text, PATH_PATTERNS)
        if path_matches:
            for path in path_matches:
                self._add_unique(findings, {
                    "type": "PATH_DISCLOSURE",
                    "trigger": trigger_name,
                    "httpStatus": response.status_code,
                    "path": path,
                    "paths": [path],
                    "responseExcerpt": self._response_excerpt(analysis_text),
                    "message": (
                        "Response discloses filesystem path."
                    )
                }, key_fields=["type", "path"])

        exception_matches = self._find_regex_matches(combined_text, INTERNAL_EXCEPTION_PATTERNS)
        if exception_matches:
            self._add_unique(findings, {
                "type": "INTERNAL_EXCEPTION_DISCLOSURE",
                "trigger": trigger_name,
                "httpStatus": response.status_code,
                "exceptions": exception_matches,
                "responseExcerpt": self._response_excerpt(analysis_text),
                "message": (
                    "Response discloses internal exception or framework details."
                )
            }, key_fields=["type"])

        sensitive_matches = self._find_regex_matches(combined_text, SENSITIVE_INFO_PATTERNS)
        if sensitive_matches:
            self._add_unique(findings, {
                "type": "SENSITIVE_INFORMATION_DISCLOSURE",
                "trigger": trigger_name,
                "httpStatus": response.status_code,
                "indicators": sensitive_matches,
                "responseExcerpt": self._response_excerpt(analysis_text),
                "message": (
                    "Response contains sensitive-looking configuration or credential-related data."
                )
            }, key_fields=["type"])
        if not (stack_matches or path_matches or exception_matches or sensitive_matches):
            if fault_info["isFault"] or self._looks_like_generic_safe_error(raw_body):
                self._add_unique(observations, {
                    "type": "GENERIC_ERROR_RESPONSE",
                    "trigger": trigger_name,
                    "httpStatus": response.status_code,
                    "xmlRpcFault": fault_info,
                    "message": (
                        "Server returned an error response, but no internal "
                        "paths, stack traces, sensitive data or framework "
                        "details were detected."
                    )
                }, key_fields=["type", "trigger"])
            else:
                observations.append({
                    "type": "NO_DISCLOSURE_IN_RESPONSE",
                    "trigger": trigger_name,
                    "httpStatus": response.status_code,
                    "message": (
                        "No information disclosure indicators detected in this response."
                    )
                })

    def _finding_to_text(self, finding):
        return finding.get("message", "Information disclosure detected.")

    def _observation_to_text(self, observation):
        return observation.get("message", "Information disclosure observation.")

    def _console_observations(self, observations):
        result = []
        seen = set()

        for obs in observations:
            if obs.get("type") in NOISY_CONSOLE_OBSERVATION_TYPES:
                continue

            key = (
                obs.get("type"),
                obs.get("header"),
                obs.get("value"),
                obs.get("message"),
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(obs)

        return result
    
    def run(self):
        findings = []
        observations = []

        for probe in ERROR_TRIGGER_PROBES:
            trigger_name = probe["name"]
            trigger_data = probe["body"]

            r = self.helpers.send_xmlrpc_raw(data=trigger_data)
            if r is None:
                observations.append({
                    "type": "NO_RESPONSE",
                    "trigger": trigger_name,
                    "message": "No response received for this trigger."
                })
                continue

            self._analyse_headers(r, observations, findings)
            self._analyse_response_body(trigger_name, r, findings, observations)

        if findings:
            ptprint("XML-RPC information disclosure issues found.", "VULN",
                    not self.args.json, indent=4, colortext=True)

            for finding in findings:
                ptprint(f"  {self._finding_to_text(finding)}",
                        "VULN", not self.args.json, indent=4)

                if finding.get("paths"):
                    ptprint(f"    Paths: {', '.join(finding['paths'][:3])}",
                            "VULN", not self.args.json, indent=4)

                if finding.get("exceptions"):
                    ptprint(f"    Exceptions: {', '.join(finding['exceptions'][:3])}",
                            "VULN", not self.args.json, indent=4)

                if finding.get("indicators"):
                    ptprint(f"    Indicators: {', '.join(finding['indicators'][:3])}",
                            "VULN", not self.args.json, indent=4)

            for obs in self._console_observations(observations)[:10]:
                ptprint(f"  (info) {self._observation_to_text(obs)}",
                        "INFO", not self.args.json, indent=4)

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-INFORMATION-DISCLOSURE",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC information disclosure issues were observed.",
                    "description": (
                        "Error responses or headers disclosed internal implementation "
                        "details such as stack traces, filesystem paths, framework "
                        "exceptions, debug headers or sensitive configuration indicators."
                    ),
                    "confidence": "black-box heuristic",
                    "findingCount": len(findings),
                    "observationCount": len(observations),
                    "findings": findings,
                    "observations": observations,
                }
            )
            return

        ptprint("No XML-RPC information disclosure detected.",
                "OK", not self.args.json, indent=4)

        for obs in self._console_observations(observations)[:10]:
            ptprint(f"  {self._observation_to_text(obs)}",
                    "INFO", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    InformationDisclosure(args, ptjsonlib, helpers, http_client, common_tests).run()