"""XML-RPC Undocumented Parameters discovery"""

import json
import re
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Undocumented Parameters discovery"

MAX_METHODS_TO_TEST = 15
MAX_KEYS_PER_STRUCT_PARAM = 250
UNKNOWN_BASELINE_KEY = "__pt_unknown_param_839274"

DANGEROUS_METHOD_WORDS = [
    "delete", "remove", "update", "edit", "create", "new", "insert",
    "write", "set", "change", "submit", "payment", "pay", "transfer",
    "execute", "exec", "admin",
]

SYSTEM_METHOD_PREFIXES = ("system.", "demo.")

URL_LIKE_PARAM_NAMES = {
    "url", "uri", "endpoint", "endpointurl", "callback", "callbackurl",
    "webhook", "location", "target", "resource", "feed", "image",
    "imageurl", "avatar", "schema", "wsdl", "service", "link",
    "redirect", "fetch", "source", "href", "src",
}

BUILTIN_PARAM_CANDIDATES = [
    "isAdmin", "is_admin", "admin", "role", "userRole", "accessLevel",
    "debug", "verbose", "internal", "include_deleted", "includeDeleted",
    "include_password_hash", "includePasswordHash", "password_hash",
    "passwordHash", "show_password_hash", "showPasswordHash", "include_hash",
    "includeSecrets", "include_secrets", "showSecrets", "show_secrets",
    "bypassAuth", "bypass_auth", "authenticated", "all", "full", "details",
]

SENSITIVE_OR_PRIVILEGED_TOKENS = [
    "admin_panel", "administrator", "admin", "role", "privilege",
    "debug_info", "debug", "internal_id", "internal", "password_hash",
    "password", "secret", "api_key", "apikey", "token", "database",
    "sqlite", "db", "config", "deleted", "all_users", "user_list",
    "access_granted", "authorization_bypass",
]

TOKEN_TO_ISSUE_TYPE = {
    "admin_panel": "admin_panel_exposed",
    "administrator": "admin_role_exposed",
    "admin": "admin_data_exposed",
    "role": "role_data_exposed",
    "privilege": "privilege_data_exposed",
    "debug_info": "debug_data_exposed",
    "debug": "debug_data_exposed",
    "internal_id": "internal_identifier_exposed",
    "internal": "internal_data_exposed",
    "password_hash": "password_hash_disclosed",
    "password": "password_data_disclosed",
    "secret": "secret_disclosed",
    "api_key": "api_key_disclosed",
    "apikey": "api_key_disclosed",
    "token": "token_data_exposed",
    "database": "database_detail_exposed",
    "sqlite": "database_detail_exposed",
    "db": "database_detail_exposed",
    "config": "configuration_data_exposed",
    "deleted": "deleted_records_exposed",
    "all_users": "user_list_exposed",
    "user_list": "user_list_exposed",
    "access_granted": "authorization_bypass_indicator",
    "authorization_bypass": "authorization_bypass_indicator",
}


class UndocumentedParameters:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _normalise_type(self, value):
        if not value:
            return "string"

        value = str(value).lower().strip()
        if ":" in value:
            value = value.split(":", 1)[-1]

        aliases = {
            "str": "string",
            "text": "string",
            "unicode": "string",
            "i4": "int",
            "i8": "int",
            "integer": "int",
            "boolean": "bool",
            "dict": "struct",
            "map": "struct",
        }

        return aliases.get(value, value)

    def _safe_excerpt(self, text, limit=180):
        if not text:
            return ""

        value = re.sub(r"\s+", " ", str(text)).strip()
        value = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value)

        if len(value) > limit:
            value = value[:limit] + "..."

        return value

    def _is_system_method(self, method_name):
        low = (method_name or "").lower()
        return low.startswith(SYSTEM_METHOD_PREFIXES)

    def _is_dangerous_method(self, method_name):
        low = (method_name or "").lower()
        return any(word in low for word in DANGEROUS_METHOD_WORDS)

    def _is_url_like_param(self, param_name):
        low = (param_name or "").lower()
        if low in URL_LIKE_PARAM_NAMES:
            return True
        return any(word in low for word in URL_LIKE_PARAM_NAMES)

    def _default_value(self, param_type="string", param_name=""):
        ptype = self._normalise_type(param_type)
        pname = (param_name or "").lower()

        if ptype == "struct":
            return {}
        if ptype in ("array", "list"):
            return []
        if ptype in ("int", "long", "short", "byte"):
            return 1
        if ptype in ("decimal", "float", "double"):
            return 1.0
        if ptype == "bool":
            return True
        if ptype in ("date", "datetime", "datetime.iso8601"):
            return "2050-01-01T00:00:00"

        if pname == "id" or pname.endswith("id") or pname.endswith("_id"):
            return "1"
        if "email" in pname:
            return "user@example.test"
        if "format" in pname:
            return "safe"
        if "nonce" in pname:
            return "hidden-param-test-nonce"
        if "account" in pname:
            return "test-account"

        return "test"

    def _candidate_value(self, key_name):
        low = key_name.lower()

        if low in ("admin", "isadmin", "is_admin", "debug", "verbose", "internal"):
            return True
        if low.startswith("include") or low.startswith("show"):
            return True
        if low in ("bypassauth", "bypass_auth", "authenticated", "force", "confirm"):
            return True
        if "role" in low or "accesslevel" in low or "privilege" in low:
            return "admin"
        if low in ("limit", "offset", "page", "count", "depth", "timeout", "retry"):
            return 1
        if low in ("all", "full", "details", "raw"):
            return True

        return "test"

    def _send_raw(self, method_name, params):
        data = xmlrpc.client.dumps(
            tuple(params),
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

        try:
            return self.http_client.send_request(
                url=self.helpers.endpoint_url,
                method="POST",
                data=data,
                headers={"Content-Type": "text/xml; charset=utf-8"},
                merge_headers=False,
                allow_redirects=True,
            )
        except Exception:
            return None

    def _parse_xmlrpc_response(self, response):
        if response is None:
            return {
                "kind": "NO_RESPONSE",
                "status": None,
                "result": None,
                "text": "",
                "faultCode": None,
                "faultString": "",
            }

        text = response.text or ""
        status = getattr(response, "status_code", None)

        try:
            values, _method = xmlrpc.client.loads(text)
            result = values[0] if values else None
            return {
                "kind": "SUCCESS",
                "status": status,
                "result": result,
                "text": text,
                "faultCode": None,
                "faultString": "",
            }
        except xmlrpc.client.Fault as fault:
            return {
                "kind": "FAULT",
                "status": status,
                "result": None,
                "text": fault.faultString or text,
                "faultCode": fault.faultCode,
                "faultString": fault.faultString or "",
            }
        except Exception:
            return {
                "kind": "RAW_RESPONSE",
                "status": status,
                "result": None,
                "text": text,
                "faultCode": None,
                "faultString": "",
            }

    def _parse_method_help_params(self, method_name, help_text):
        if not help_text or not isinstance(help_text, str):
            return []

        start = help_text.find("(")
        end = help_text.find(")", start + 1)

        if start == -1 or end == -1 or end <= start:
            return []

        inside = help_text[start + 1:end].strip()
        if not inside:
            return []

        params = []
        for index, part in enumerate(inside.split(","), 1):
            tokens = part.strip().split()
            if not tokens:
                continue

            if len(tokens) >= 2:
                ptype = tokens[0]
                name = tokens[-1]
            else:
                ptype = tokens[0]
                name = f"param{index}"

            clean_name = "".join(
                ch for ch in name
                if ch.isalnum() or ch in "_.-"
            ) or f"param{index}"

            params.append({
                "name": clean_name,
                "type": self._normalise_type(ptype),
                "source": "methodHelp",
            })

        return params

    def _direct_introspection_methods(self):
        response = self._send_raw("system.listMethods", [])
        parsed = self._parse_xmlrpc_response(response)

        if parsed["kind"] != "SUCCESS" or not isinstance(parsed["result"], (list, tuple)):
            return []

        methods = []
        seen = set()

        for method_name in parsed["result"]:
            if not isinstance(method_name, str) or method_name in seen:
                continue

            seen.add(method_name)
            signature_params = []

            sig_response = self._send_raw("system.methodSignature", [method_name])
            sig_parsed = self._parse_xmlrpc_response(sig_response)

            if sig_parsed["kind"] == "SUCCESS" and isinstance(sig_parsed["result"], list):
                signatures = sig_parsed["result"]
                if signatures and isinstance(signatures[0], list) and len(signatures[0]) > 1:
                    for index, ptype in enumerate(signatures[0][1:], 1):
                        signature_params.append({
                            "name": f"param{index}",
                            "type": self._normalise_type(ptype),
                            "source": "methodSignature",
                        })

            help_response = self._send_raw("system.methodHelp", [method_name])
            help_parsed = self._parse_xmlrpc_response(help_response)
            help_params = []

            if help_parsed["kind"] == "SUCCESS":
                help_params = self._parse_method_help_params(method_name, help_parsed["result"])

            if signature_params and help_params and len(signature_params) == len(help_params):
                params = []
                for sig_param, help_param in zip(signature_params, help_params):
                    params.append({
                        "name": help_param.get("name") or sig_param.get("name"),
                        "type": sig_param.get("type") or help_param.get("type") or "string",
                        "source": "methodSignature+methodHelp",
                    })
            elif signature_params:
                params = signature_params
            else:
                params = help_params

            methods.append({
                "name": method_name,
                "params": params,
                "source": "direct_introspection",
            })

        return methods

    def _helper_methods(self):
        methods = []
        seen = set()

        for attr in (
            "resolved_methods",
            "method_metadata",
            "parsed_methods",
            "discovered_method_details",
            "introspection_methods",
            "xmlrpc_methods",
        ):
            value = getattr(self.helpers, attr, None)
            if not isinstance(value, list):
                continue

            for item in value:
                if not isinstance(item, dict):
                    continue

                name = item.get("name") or item.get("method") or item.get("methodName")
                if not name or name in seen:
                    continue

                raw_params = item.get("params") or item.get("parameters") or []
                params = []
                if isinstance(raw_params, list):
                    for index, param in enumerate(raw_params, 1):
                        if isinstance(param, dict):
                            params.append({
                                "name": param.get("name") or f"param{index}",
                                "type": self._normalise_type(param.get("type") or "string"),
                                "source": param.get("source") or "helper_metadata",
                            })

                methods.append({
                    "name": name,
                    "params": params,
                    "source": "helper_metadata",
                })
                seen.add(name)

        return methods

    def _candidate_methods(self):
        methods = self._helper_methods()

        if not methods:
            methods = self._direct_introspection_methods()

        if not methods:
            return []

        candidates = []
        seen = set()

        for method in methods:
            name = method.get("name", "")
            if not name or name in seen:
                continue

            seen.add(name)

            if self._is_system_method(name) or self._is_dangerous_method(name):
                continue

            params = method.get("params") or []
            struct_indexes = [
                index for index, param in enumerate(params)
                if self._normalise_type(param.get("type")) == "struct"
                and not self._is_url_like_param(param.get("name", ""))
            ]

            if not struct_indexes:
                continue

            candidates.append({
                "name": name,
                "params": params,
                "structIndexes": struct_indexes,
                "source": method.get("source", "unknown"),
            })

        return candidates[:MAX_METHODS_TO_TEST]

    def _load_param_candidates(self):
        wordlist = self.helpers.load_wordlist("xmlrpc_params.txt") or []
        candidates = []
        seen = set()

        for value in list(wordlist) + BUILTIN_PARAM_CANDIDATES:
            if value is None:
                continue

            key = str(value).strip()
            if not key or key.startswith("#") or key in seen:
                continue

            seen.add(key)
            candidates.append(key)

        return candidates[:MAX_KEYS_PER_STRUCT_PARAM]

    def _build_params(self, method, struct_index, struct_value):
        values = []

        for index, param in enumerate(method.get("params", []) or []):
            if index == struct_index:
                values.append(struct_value)
            else:
                values.append(self._default_value(param.get("type"), param.get("name", "")))

        return values

    def _canonical_result(self, result):
        try:
            return json.dumps(result, sort_keys=True, default=str, ensure_ascii=False)
        except Exception:
            return repr(result)

    def _flatten_keys(self, value, prefix=""):
        keys = set()

        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                full = f"{prefix}.{key_text}" if prefix else key_text
                keys.add(full)
                keys.add(key_text)
                keys.update(self._flatten_keys(child, full))

        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                keys.update(self._flatten_keys(child, f"{prefix}[{index}]"))

        return keys

    def _flatten_text(self, value):
        parts = []

        if isinstance(value, dict):
            for key, child in value.items():
                parts.append(str(key))
                parts.append(self._flatten_text(child))
        elif isinstance(value, (list, tuple)):
            for child in value:
                parts.append(self._flatten_text(child))
        else:
            parts.append(str(value))

        return " ".join(part for part in parts if part)

    def _remove_reflection(self, text, param_name, param_value):
        if not text:
            return ""

        scrubbed = str(text)
        names = {param_name}
        values = {str(param_value)}

        for name in names:
            if not name:
                continue

            patterns = [
                rf"<(\w*:)?{re.escape(name)}(\s[^>]*)?>[^<]*</(\w*:)?{re.escape(name)}\s*>",
                rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*[:=]\s*[^,;\s}}<>]+",
                rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])",
            ]

            for pattern in patterns:
                scrubbed = re.sub(pattern, " ", scrubbed, flags=re.IGNORECASE)

        for value in values:
            if not value or str(value).lower() in ("true", "false", "1", "0", "test"):
                continue
            scrubbed = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(str(value))}(?![A-Za-z0-9_])",
                " ",
                scrubbed,
                flags=re.IGNORECASE,
            )

        return scrubbed

    def _new_signals(self, baseline_result, mutated_result, param_name, param_value):
        baseline_text = self._flatten_text(baseline_result).lower()
        mutated_text = self._flatten_text(mutated_result).lower()
        mutated_text = self._remove_reflection(mutated_text, param_name, param_value).lower()

        signals = []
        for token in SENSITIVE_OR_PRIVILEGED_TOKENS:
            token_low = token.lower()
            if token_low in mutated_text and token_low not in baseline_text:
                signals.append(token)

        return sorted(set(signals))

    def _issue_types(self, added_keys, signals):
        issues = set()

        if added_keys:
            issues.add("hidden_struct_key_affects_response")

        for signal in signals:
            issues.add(TOKEN_TO_ISSUE_TYPE.get(signal, "sensitive_or_privileged_data_exposed"))

        return sorted(issues)

    def _evidence_excerpt(self, result, signals, added_keys):
        text = self._flatten_text(result)
        low = text.lower()
        needles = list(signals) + list(added_keys)

        for needle in needles:
            if not needle:
                continue

            idx = low.find(str(needle).lower())
            if idx == -1:
                continue

            start = max(0, idx - 60)
            end = min(len(text), idx + 120)
            return self._safe_excerpt(text[start:end], 180)

        return self._safe_excerpt(text, 180)

    def _is_meaningful_change(self, baseline_result, mutated_result, param_name, param_value):
        baseline_canonical = self._canonical_result(baseline_result)
        mutated_canonical = self._canonical_result(mutated_result)

        if baseline_canonical == mutated_canonical:
            return None

        baseline_keys = self._flatten_keys(baseline_result)
        mutated_keys = self._flatten_keys(mutated_result)
        added_keys = sorted(k for k in (mutated_keys - baseline_keys) if k != param_name)
        signals = self._new_signals(baseline_result, mutated_result, param_name, param_value)

        non_reflection_added_keys = [
            key for key in added_keys
            if key.lower() != param_name.lower()
            and key.lower() != str(param_value).lower()
            and not key.startswith(f"{param_name}.")
        ]

        if not non_reflection_added_keys and not signals:
            return None

        return {
            "addedKeys": non_reflection_added_keys,
            "signals": signals,
            "issueTypes": self._issue_types(non_reflection_added_keys, signals),
            "evidenceExcerpt": self._evidence_excerpt(
                mutated_result,
                signals,
                non_reflection_added_keys,
            ),
        }

    def _test_struct_param(self, method, struct_index, param_candidates):
        method_name = method["name"]
        struct_param = method["params"][struct_index]
        struct_param_name = struct_param.get("name") or f"param{struct_index + 1}"

        baseline_struct = {UNKNOWN_BASELINE_KEY: "test"}
        baseline_response = self._send_raw(
            method_name,
            self._build_params(method, struct_index, baseline_struct),
        )
        baseline = self._parse_xmlrpc_response(baseline_response)

        if baseline["kind"] != "SUCCESS":
            empty_response = self._send_raw(
                method_name,
                self._build_params(method, struct_index, {}),
            )
            baseline = self._parse_xmlrpc_response(empty_response)

        if baseline["kind"] != "SUCCESS":
            return []

        findings = []
        documented_names = {
            p.get("name") for p in method.get("params", []) or []
            if p.get("name")
        }

        for candidate in param_candidates:
            if candidate in documented_names:
                continue

            candidate_value = self._candidate_value(candidate)
            mutated_struct = {candidate: candidate_value}
            mutated_response = self._send_raw(
                method_name,
                self._build_params(method, struct_index, mutated_struct),
            )
            mutated = self._parse_xmlrpc_response(mutated_response)

            if mutated["kind"] != "SUCCESS":
                continue

            change = self._is_meaningful_change(
                baseline["result"],
                mutated["result"],
                candidate,
                candidate_value,
            )

            if not change:
                continue

            findings.append({
                "method": method_name,
                "structParameter": struct_param_name,
                "name": candidate,
                "value": candidate_value,
                "addedKeys": change["addedKeys"],
                "signals": change["signals"],
                "issueTypes": change["issueTypes"],
                "httpStatus": mutated["status"],
                "evidenceExcerpt": change["evidenceExcerpt"],
            })

        return findings

    def _group_findings(self, findings):
        grouped = {}

        for finding in findings:
            key = (finding["method"], finding["structParameter"])
            grouped.setdefault(key, {
                "method": finding["method"],
                "structParameter": finding["structParameter"],
                "parameters": [],
            })

            grouped[key]["parameters"].append({
                "name": finding["name"],
                "value": finding["value"],
                "addedKeys": finding["addedKeys"],
                "signals": finding["signals"],
                "issueTypes": finding["issueTypes"],
                "httpStatus": finding["httpStatus"],
                "evidenceExcerpt": finding["evidenceExcerpt"],
            })

        return sorted(grouped.values(), key=lambda item: (item["method"], item["structParameter"]))

    def _dedupe_findings(self, findings):
        seen = set()
        out = []

        for finding in findings:
            key = (
                finding["method"],
                finding["structParameter"],
                finding["name"],
                tuple(finding.get("addedKeys", [])),
                tuple(finding.get("signals", [])),
            )

            if key in seen:
                continue

            seen.add(key)
            out.append(finding)

        return out

    def _print_findings(self, affected):
        ptprint(
            "Hidden XML-RPC struct parameters detected.",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        for item in affected:
            params = []
            for param in item["parameters"]:
                if param.get("signals"):
                    detail = ", ".join(param["signals"])
                elif param.get("addedKeys"):
                    detail = ", ".join(param["addedKeys"][:4])
                else:
                    detail = "response changed"

                params.append(f"{param['name']} ({detail})")

            ptprint(
                f"  {item['method']}.{item['structParameter']}: "
                f"{'; '.join(params)}.",
                "VULN",
                not self.args.json,
                indent=4,
            )

    def run(self):
        param_candidates = self._load_param_candidates()
        if not param_candidates:
            ptprint(
                "No XML-RPC parameter wordlist available.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        methods = self._candidate_methods()
        if not methods:
            ptprint(
                "No XML-RPC methods with struct parameters available for hidden-parameter testing.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        findings = []
        tested_struct_params = 0

        for method in methods:
            for struct_index in method["structIndexes"]:
                tested_struct_params += 1
                findings.extend(self._test_struct_param(method, struct_index, param_candidates))

        findings = self._dedupe_findings(findings)

        if not findings:
            ptprint(
                "No hidden XML-RPC struct parameters found with tested keys.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        affected = self._group_findings(findings)
        self._print_findings(affected)

        issue_types = sorted({
            issue
            for finding in findings
            for issue in finding.get("issueTypes", [])
        })

        self.ptjsonlib.add_vulnerability(
            "PTV-XMLRPC-UNDOCUMENTED-PARAMS",
            node_key=self.helpers.node_key,
            data={
                "summary": "Hidden XML-RPC struct parameters were detected.",
                "description": (
                    "The XML-RPC endpoint appears to process undocumented keys inside "
                    "struct parameters. Mutated requests produced new response fields "
                    "or sensitive/privileged response signals compared with a baseline "
                    "request using an unknown struct key."
                ),
                "confidence": "black-box heuristic",
                "testedMethodCount": len(methods),
                "testedStructParameterCount": tested_struct_params,
                "testedKeyCount": len(param_candidates),
                "findingCount": len(findings),
                "affectedMethods": affected,
                "issueTypes": issue_types,
                "hiddenParameterNames": sorted({f["name"] for f in findings}),
            },
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    UndocumentedParameters(args, ptjsonlib, helpers, http_client, common_tests).run()
