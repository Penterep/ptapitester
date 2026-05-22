"""
SOAP Mass Assignment / Hidden Privilege Parameter test
"""

import html
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Mass Assignment test"


MAX_OPERATIONS_TO_TEST = 10

HIDDEN_PRIVILEGE_PARAMS = [
    ("isAdmin", "true"),
    ("admin", "true"),
    ("admin", "1"),
    ("role", "admin"),
    ("userRole", "admin"),
    ("privilege", "admin"),
    ("accessLevel", "admin"),
    ("debug", "true"),
    ("includeDeleted", "true"),
    ("includeSecrets", "true"),
    ("showSecrets", "true"),
    ("bypassAuth", "true"),
    ("authenticated", "true"),
    ("internal", "true"),
    ("verbose", "true"),
]

DANGEROUS_OPERATION_WORDS = [
    "delete", "remove", "update", "edit", "create", "insert",
    "submit", "payment", "transfer", "set", "change", "new", "write",
]

STRONG_SIGNAL_TOKENS = [
    "password_hash","password","secret","api key","apikey","all users",
    "user list","database","db path","config","deleted","access granted",
    "authorization bypass","superuser",
]

WEAK_SIGNAL_TOKENS = [
    "admin","role","debug","hash","root","privilege","elevated","token","internal",
]

PRIVILEGED_SIGNAL_TOKENS = STRONG_SIGNAL_TOKENS + WEAK_SIGNAL_TOKENS

SIGNAL_TO_TYPE = {
    "admin": "admin_data_exposed",
    "role": "role_data_exposed",
    "privilege": "privilege_data_exposed",
    "access granted": "access_granted_exposed",
    "debug": "debug_data_exposed",
    "secret": "secret_disclosed",
    "api key": "api_key_disclosed",
    "apikey": "api_key_disclosed",
    "token": "token_disclosed",
    "password": "password_disclosed",
    "password_hash": "password_hash_disclosed",
    "hash": "hash_disclosed",
    "deleted": "deleted_records_exposed",
    "internal": "internal_data_exposed",
    "config": "config_data_exposed",
    "database": "database_info_exposed",
    "db path": "db_path_disclosed",
    "all users": "user_list_exposed",
    "user list": "user_list_exposed",
    "superuser": "superuser_data_exposed",
    "root": "root_data_exposed",
    "elevated": "elevated_access_exposed",
    "authorization bypass": "authorization_bypass",
}

SOAP_FAULT_INDICATORS = [
    "soap:fault", "soapenv:fault", "<fault>", "faultcode", "faultstring",
]

AUTH_DENIED_INDICATORS = [
    "access denied", "unauthorized", "unauthorised", "forbidden",
    "authentication failed", "authentication required",
    "failedauthentication", "invalidsecuritytoken", "wsse:",
]

BACKEND_ERROR_INDICATORS = [
    "traceback", "stack trace", "exception", "valueerror", "typeerror",
    "sqlalchemy", "database error", "internal server error",
]

SOAP_ENVELOPE_INDICATORS = [
    "<soap:envelope", "<soapenv:envelope", "<env:envelope",
    "<soap:body", "<soapenv:body", "<env:body",
]

AUTH_DENIED_HTTP_STATUS = {401, 403, 407}

WORD_BOUNDARY_RE_CACHE = {}


class MassAssignmentTest:
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

    def _word_regex(self, token):
        if token not in WORD_BOUNDARY_RE_CACHE:
            escaped = re.escape(token)
            WORD_BOUNDARY_RE_CACHE[token] = re.compile(
                rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])",
                re.IGNORECASE,
            )
        return WORD_BOUNDARY_RE_CACHE[token]

    def _signal_present(self, text, signal):
        if not text:
            return False
        return bool(self._word_regex(signal).search(text))

    def _detected_signals(self, text):
        if not text:
            return []
        found = []
        for signal in PRIVILEGED_SIGNAL_TOKENS:
            if self._signal_present(text, signal):
                found.append(signal)
        return found

    def _remove_reflected_probe(self, text, param_name, param_value):
        if not text:
            return ""

        scrubbed = text

        patterns = [
            rf"<[^<>]*{re.escape(param_name)}[^<>]*>\s*{re.escape(param_value)}\s*</[^<>]*>",
            rf"{re.escape(param_name)}\s*=\s*['\"]?{re.escape(param_value)}['\"]?",
            rf"{re.escape(param_name)}\s*:\s*['\"]?{re.escape(param_value)}['\"]?",
            rf"{re.escape(param_name)}\s+{re.escape(param_value)}",
        ]

        for pattern in patterns:
            scrubbed = re.sub(pattern, " ", scrubbed, flags=re.IGNORECASE)

        return scrubbed

    def _signal_diff(self, baseline_text, scrubbed_mutated_text):
        baseline_signals = set(self._detected_signals(baseline_text))
        mutated_signals = set(self._detected_signals(scrubbed_mutated_text))
        return sorted(mutated_signals - baseline_signals)

    def _classify_signal_strength(self, new_signals):
        strong = [s for s in new_signals if s in STRONG_SIGNAL_TOKENS]
        weak = [s for s in new_signals if s in WEAK_SIGNAL_TOKENS]
        return strong, weak

    def _is_dangerous_operation(self, op_name):
        low = (op_name or "").lower()
        return any(word in low for word in DANGEROUS_OPERATION_WORDS)

    def _normalise_type(self, param_type):
        if not param_type:
            return "string"
        t = str(param_type).lower().strip()
        if ":" in t:
            t = t.split(":", 1)[-1]
        return t

    def _default_value(self, param_type):
        t = self._normalise_type(param_type)
        if t in ("string", "normalizedstring", "token"):
            return "test"
        if t in ("int", "integer", "long", "short", "byte",
                 "nonnegativeinteger", "positiveinteger"):
            return "1"
        if t in ("decimal", "float", "double"):
            return "1.0"
        if t in ("boolean", "bool"):
            return "true"
        if t == "date":
            return "2050-01-01"
        if t == "datetime":
            return "2050-01-01T00:00:00Z"
        return "test"

    def _soap_action_for(self, op):
        if not op:
            return None
        action = op.get("soap_action") or op.get("soapAction") or ""
        if action:
            if action.startswith('"') and action.endswith('"'):
                return action
            return f'"{action}"'
        name = op.get("name", "")
        return f'"urn:{name}"' if name else None

    def _build_request(self, op, extra=None):
        extra = extra or {}
        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element", op.get("name", ""))
        params = op.get("input_params", []) or []

        params_xml = ""
        for p in params:
            p_name = p.get("name", "")
            p_type = p.get("type", "string")
            if not p_name:
                continue
            value = self._default_value(p_type)
            params_xml += (
                f"<tns:{p_name}>"
                f"{html.escape(str(value), quote=False)}"
                f"</tns:{p_name}>"
            )

        for name, value in extra.items():
            params_xml += (
                f"<tns:{name}>"
                f"{html.escape(str(value), quote=False)}"
                f"</tns:{name}>"
            )

        return (
            '<?xml version="1.0"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{html.escape(tns, quote=True)}">'
            "<soap:Body>"
            f"<tns:{input_element}>"
            f"{params_xml}"
            f"</tns:{input_element}>"
            "</soap:Body>"
            "</soap:Envelope>"
        )

    def _send(self, body, op):
        headers = {"Content-Type": "text/xml; charset=utf-8"}
        soap_action = self._soap_action_for(op)
        if soap_action:
            headers["SOAPAction"] = soap_action

        try:
            return self.http_client.send_request(
                url=self.helpers.endpoint_url,
                method="POST",
                data=body,
                headers=headers,
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _is_soap_fault(self, response):
        if response is None:
            return False
        return self._has_any(response.text or "", SOAP_FAULT_INDICATORS)

    def _is_auth_denied(self, response):
        if response is None:
            return False
        if response.status_code in AUTH_DENIED_HTTP_STATUS:
            return True
        return self._has_any(response.text or "", AUTH_DENIED_INDICATORS)

    def _is_backend_error(self, response):
        if response is None:
            return False
        if response.status_code >= 500:
            return True
        return self._has_any(response.text or "", BACKEND_ERROR_INDICATORS)

    def _looks_like_operation_response(self, response, op_name):
        if response is None:
            return False

        body = response.text or ""
        low = body.lower()

        if not self._has_any(body, SOAP_ENVELOPE_INDICATORS):
            return False

        if self._is_soap_fault(response):
            return False

        op_lower = (op_name or "").lower()
        expected_tokens = [
            op_lower,
            f"{op_lower}response",
            f"{op_lower}result",
            f"{op_lower}output",
            "return",
            "result",
        ]

        return any(token and token in low for token in expected_tokens)

    def _classify_response(self, response, op_name):
        if response is None:
            return "NO_RESPONSE"
        if self._is_auth_denied(response):
            return "AUTH_DENIED"
        if self._is_backend_error(response):
            return "BACKEND_ERROR"
        if self._is_soap_fault(response):
            return "SOAP_FAULT"
        if 200 <= response.status_code < 300:
            return "OPERATION_REACHED"
        if self._looks_like_operation_response(response, op_name):
            return "OPERATION_REACHED"
        return "AMBIGUOUS"

    def _has_documented_param(self, op, param_name):
        params = op.get("input_params", []) or []
        low = param_name.lower()
        return any((p.get("name", "") or "").lower() == low for p in params)

    def _candidate_operations(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []
        candidates = []

        for op in operations:
            name = op.get("name", "")
            if not name:
                continue
            if self._is_dangerous_operation(name):
                continue
            candidates.append(op)

        return candidates[:MAX_OPERATIONS_TO_TEST]

    def _signals_to_issue_types(self, signals):
        return sorted({SIGNAL_TO_TYPE[s] for s in signals if s in SIGNAL_TO_TYPE})

    def _evidence_excerpt(self, text, signals, limit=160):
        if not text or not signals:
            return ""

        flat = re.sub(r"\s+", " ", text).strip()
        flat = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", flat)

        best_index = -1
        for signal in signals:
            match = self._word_regex(signal).search(flat)
            if match:
                if best_index == -1 or match.start() < best_index:
                    best_index = match.start()

        if best_index == -1:
            if len(flat) > limit:
                return flat[:limit] + "..."
            return flat

        half = limit // 2
        start = max(0, best_index - half)
        end = min(len(flat), start + limit)

        excerpt = flat[start:end]
        if start > 0:
            excerpt = "..." + excerpt
        if end < len(flat):
            excerpt = excerpt + "..."

        return excerpt

    def _test_operation(self, op):
        op_name = op.get("name", "")

        baseline_body = self._build_request(op)
        baseline_response = self._send(baseline_body, op)
        baseline_class = self._classify_response(baseline_response, op_name)

        if baseline_class not in ("OPERATION_REACHED", "AUTH_DENIED"):
            return []

        baseline_text = baseline_response.text or ""
        op_findings = []

        for extra_name, extra_value in HIDDEN_PRIVILEGE_PARAMS:
            if self._has_documented_param(op, extra_name):
                continue

            mutated_body = self._build_request(op, extra={extra_name: extra_value})
            mutated_response = self._send(mutated_body, op)
            mutated_class = self._classify_response(mutated_response, op_name)

            auth_bypass = (
                baseline_class == "AUTH_DENIED"
                and mutated_class == "OPERATION_REACHED"
            )

            if mutated_class != "OPERATION_REACHED":
                continue

            if baseline_class == "AUTH_DENIED" and not auth_bypass:
                continue

            mutated_text = mutated_response.text or ""
            scrubbed_mutated = self._remove_reflected_probe(
                mutated_text, extra_name, extra_value,
            )

            new_signals = self._signal_diff(baseline_text, scrubbed_mutated)
            strong, weak = self._classify_signal_strength(new_signals)

            confirmed = False
            signal_strength = None

            if strong:
                confirmed = True
                signal_strength = "strong"
            elif auth_bypass:
                confirmed = True
                signal_strength = "auth_bypass" if not weak else "auth_bypass+weak"
            elif len(weak) >= 2:
                confirmed = True
                signal_strength = "weak_multi"

            if not confirmed:
                continue

            issue_types = self._signals_to_issue_types(new_signals)
            if auth_bypass:
                issue_types.append("authorization_bypass")
                issue_types = sorted(set(issue_types))

            op_findings.append({
                "operation": op_name,
                "parameter": extra_name,
                "value": extra_value,
                "signals": new_signals,
                "issueTypes": issue_types,
                "signalStrength": signal_strength,
                "mutatedClassification": mutated_class,
                "authBypass": auth_bypass,
                "evidenceExcerpt": self._evidence_excerpt(
                    scrubbed_mutated, new_signals,
                ),
            })

        return op_findings

    def _group_findings(self, findings):
        grouped = {}
        for finding in findings:
            op_name = finding.get("operation", "unknown")
            grouped.setdefault(op_name, {
                "operation": op_name,
                "parameters": [],
            })
            grouped[op_name]["parameters"].append({
                "name": finding.get("parameter"),
                "value": finding.get("value"),
                "signals": finding.get("signals", []),
                "issueTypes": finding.get("issueTypes", []),
                "signalStrength": finding.get("signalStrength"),
                "mutatedClassification": finding.get("mutatedClassification"),
                "authBypass": finding.get("authBypass", False),
                "evidenceExcerpt": finding.get("evidenceExcerpt", ""),
            })
        return sorted(grouped.values(), key=lambda x: x["operation"])

    def _summarise_for_console(self, finding):
        issue_types = finding.get("issueTypes", [])

        if finding.get("authBypass") and (
            not issue_types or issue_types == ["authorization_bypass"]
        ):
            return "bypassed authorization."

        category_map = {
            "admin_data_exposed": "admin data",
            "role_data_exposed": "role data",
            "privilege_data_exposed": "privilege data",
            "access_granted_exposed": "access granted state",
            "debug_data_exposed": "debug/internal data",
            "secret_disclosed": "secret",
            "api_key_disclosed": "API key",
            "token_disclosed": "token",
            "password_disclosed": "password",
            "password_hash_disclosed": "password hash",
            "hash_disclosed": "hash",
            "deleted_records_exposed": "deleted records",
            "internal_data_exposed": "internal data",
            "config_data_exposed": "config data",
            "database_info_exposed": "database info",
            "db_path_disclosed": "DB path",
            "user_list_exposed": "user list",
            "superuser_data_exposed": "superuser data",
            "root_data_exposed": "root data",
            "elevated_access_exposed": "elevated access",
            "authorization_bypass": "authorization bypass",
        }

        if not issue_types:
            return "exposed privileged data."

        categories = sorted({category_map.get(it, it) for it in issue_types})
        return f"exposed {', '.join(categories)}."

    def _print_console_summary(self, findings):
        ptprint(
            "SOAP mass assignment / hidden parameter behavior detected.",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        by_operation = {}
        for finding in findings:
            by_operation.setdefault(finding["operation"], []).append(finding)

        for op_name in sorted(by_operation.keys()):
            op_findings = by_operation[op_name]
            by_signal_group = {}

            for finding in op_findings:
                key = tuple(sorted(finding.get("issueTypes", [])))
                by_signal_group.setdefault(key, []).append(finding)

            for _key, group in by_signal_group.items():
                param_labels = ", ".join(
                    f"{f['parameter']}={f['value']}" for f in group
                )
                summary = self._summarise_for_console(group[0])
                ptprint(
                    f"  {op_name}: {param_labels} {summary}",
                    "VULN",
                    not self.args.json,
                    indent=4,
                )

    def run(self):
        operations = self._candidate_operations()

        if not operations:
            ptprint(
                "No suitable SOAP operations available for mass assignment test.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        findings = []
        for op in operations:
            findings.extend(self._test_operation(op))

        if not findings:
            ptprint(
                "No SOAP mass assignment behavior observed with tested hidden parameters.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        self._print_console_summary(findings)

        affected_operations = self._group_findings(findings)
        issue_types = sorted({
            issue
            for finding in findings
            for issue in finding.get("issueTypes", [])
        })

        self.ptjsonlib.add_vulnerability(
            "PTV-SOAP-MASS-ASSIGNMENT",
            node_key=self.helpers.node_key,
            data={
                "summary": "SOAP mass assignment / hidden privilege parameter behavior was observed.",
                "description": (
                    "The SOAP endpoint accepted undocumented extra parameters that "
                    "caused privileged, sensitive, or debug-related data to appear "
                    "in responses, or that bypassed an authorization decision. This "
                    "indicates a possible mass-assignment style vulnerability."
                ),
                "confidence": "black-box heuristic",
                "testedOperationCount": len(operations),
                "findingCount": len(findings),
                "affectedOperations": affected_operations,
                "issueTypes": issue_types,
            },
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    MassAssignmentTest(args, ptjsonlib, helpers, http_client, common_tests).run()