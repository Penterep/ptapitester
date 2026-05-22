"""
SOAP Session and Token Security test
"""

import base64
import json
import re
import time
from http.cookies import SimpleCookie
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Session and Token Security test"


JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)

AUTH_COOKIE_NAME_TOKENS = (
    "session","sess","sid","auth","token","jwt","access","refresh",
    "login","sso","phpsessid","jsessionid","asp.net_sessionid",
)

TOKEN_HEADER_NAMES = (
    "Authorization","X-Auth-Token","X-Access-Token",
    "X-Refresh-Token","X-Token","Authentication",
)

AUTH_OPERATION_NAME_TOKENS = (
    "login","auth","authenticate","signin",
    "signon","token","session",
)

SENSITIVE_CLAIM_NAMES = {
    "password","passwd","pwd","secret","secret_key","api_key","apikey","private_key",
    "credit_card","card_number","ssn","access_token","refresh_token",
}

EXCESSIVE_COOKIE_MAX_AGE_SECONDS = 86400 * 30
EXCESSIVE_JWT_LIFETIME_SECONDS = 86400 * 7


class TokenExpiration:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _normalise_evidence(self, text, limit=180):
        if not text:
            return ""

        norm = re.sub(r"\s+", " ", str(text)).strip()
        norm = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", norm)

        if len(norm) > limit:
            norm = norm[:limit] + "..."

        return norm

    def _b64url_decode_json(self, value):
        try:
            padded = value + "=" * ((4 - len(value) % 4) % 4)
            raw = base64.urlsafe_b64decode(padded.encode("ascii"))
            return json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            return None

    def _decode_jwt(self, token):
        parts = token.split(".")

        if len(parts) != 3:
            return None

        header = self._b64url_decode_json(parts[0])
        payload = self._b64url_decode_json(parts[1])

        if not isinstance(payload, dict):
            return None

        return {
            "header": header if isinstance(header, dict) else {},
            "payload": payload,
        }

    def _header_values(self, response, header_name):
        values = []

        try:
            raw_headers = getattr(getattr(response, "raw", None), "headers", None)
            get_all = getattr(raw_headers, "get_all", None)
            if callable(get_all):
                raw_values = get_all(header_name)
                if raw_values:
                    values.extend(raw_values)
        except Exception:
            pass

        value = response.headers.get(header_name)
        if value and value not in values:
            values.append(value)

        return [v for v in values if v]

    def _split_combined_set_cookie(self, header_value):
        if not header_value:
            return []

        parts = []
        start = 0
        in_expires = False
        i = 0

        while i < len(header_value):
            chunk = header_value[i:i + 8].lower()
            if chunk.startswith("expires"):
                in_expires = True

            if in_expires and header_value[i] == ";":
                in_expires = False

            if header_value[i] == "," and not in_expires:
                rest = header_value[i + 1:]
                if re.match(r"\s*[A-Za-z0-9_!#$%&'*+.^`|~-]+\s*=", rest):
                    parts.append(header_value[start:i].strip())
                    start = i + 1

            i += 1

        parts.append(header_value[start:].strip())
        return [p for p in parts if p]

    def _set_cookie_headers(self, response):
        headers = []

        for value in self._header_values(response, "Set-Cookie"):
            headers.extend(self._split_combined_set_cookie(value))

        seen = set()
        out = []
        for header in headers:
            if header not in seen:
                seen.add(header)
                out.append(header)

        return out

    def _parse_cookie(self, set_cookie_header):
        try:
            cookie = SimpleCookie()
            cookie.load(set_cookie_header)
        except Exception:
            return None

        if not cookie:
            return None

        name = next(iter(cookie.keys()))
        morsel = cookie[name]

        attrs = {}
        for key in (
            "secure","httponly","samesite","expires","max-age","path","domain",
        ):
            value = morsel[key]
            if value:
                attrs[key.lower()] = value

        return {
            "name": name,
            "value": morsel.value,
            "attributes": attrs,
            "raw": set_cookie_header,
        }

    def _is_auth_cookie(self, cookie):
        name = (cookie.get("name") or "").lower()
        value = cookie.get("value") or ""

        if any(token in name for token in AUTH_COOKIE_NAME_TOKENS):
            return True

        if JWT_RE.search(value):
            return True

        return False

    def _cookie_findings(self, response):
        findings = []

        for raw_cookie in self._set_cookie_headers(response):
            cookie = self._parse_cookie(raw_cookie)

            if not cookie:
                continue

            if not self._is_auth_cookie(cookie):
                continue

            name = cookie["name"]
            attrs = cookie["attributes"]
            evidence_cookie = self._normalise_evidence(raw_cookie, 140)

            if "secure" not in attrs:
                findings.append({
                    "type": "missing_secure",
                    "cookie": name,
                    "evidence": evidence_cookie,
                    "message": f"Auth/session cookie '{name}' is missing Secure flag.",
                })

            if "httponly" not in attrs:
                findings.append({
                    "type": "missing_httponly",
                    "cookie": name,
                    "evidence": evidence_cookie,
                    "message": f"Auth/session cookie '{name}' is missing HttpOnly flag.",
                })

            same_site = attrs.get("samesite")
            if not same_site:
                findings.append({
                    "type": "missing_samesite",
                    "cookie": name,
                    "evidence": evidence_cookie,
                    "message": f"Auth/session cookie '{name}' is missing SameSite attribute.",
                })
            elif same_site.lower() == "none" and "secure" not in attrs:
                findings.append({
                    "type": "samesite_none_without_secure",
                    "cookie": name,
                    "evidence": evidence_cookie,
                    "message": (
                        f"Auth/session cookie '{name}' uses SameSite=None without Secure flag."
                    ),
                })

            max_age_raw = attrs.get("max-age")
            if max_age_raw:
                try:
                    max_age = int(max_age_raw)
                    if max_age > EXCESSIVE_COOKIE_MAX_AGE_SECONDS:
                        findings.append({
                            "type": "excessive_max_age",
                            "cookie": name,
                            "maxAgeSeconds": max_age,
                            "maxAgeDays": round(max_age / 86400, 2),
                            "evidence": evidence_cookie,
                            "message": (
                                f"Auth/session cookie '{name}' has excessive Max-Age "
                                f"({max_age}s, about {int(max_age / 86400)} days)."
                            ),
                        })
                except ValueError:
                    findings.append({
                        "type": "malformed_max_age",
                        "cookie": name,
                        "evidence": evidence_cookie,
                        "message": (
                            f"Auth/session cookie '{name}' has malformed Max-Age value."
                        ),
                    })

        return self._dedupe_findings(findings, ("type", "cookie", "evidence"))

    def _extract_jwts_from_response(self, response):
        tokens = []

        for header_name in TOKEN_HEADER_NAMES:
            for value in self._header_values(response, header_name):
                for match in JWT_RE.finditer(value or ""):
                    tokens.append({
                        "location": f"{header_name} header",
                        "token": match.group(0),
                    })

        for raw_cookie in self._set_cookie_headers(response):
            cookie = self._parse_cookie(raw_cookie)
            if not cookie:
                continue

            for match in JWT_RE.finditer(cookie.get("value") or ""):
                tokens.append({
                    "location": f"Set-Cookie '{cookie.get('name')}'",
                    "token": match.group(0),
                })

        for match in JWT_RE.finditer(response.text or ""):
            tokens.append({
                "location": "response body",
                "token": match.group(0),
            })

        seen = set()
        out = []
        for item in tokens:
            key = (item["location"], item["token"])
            if key not in seen:
                seen.add(key)
                out.append(item)

        return out

    def _flatten_claim_names(self, value, prefix=""):
        names = []

        if isinstance(value, dict):
            for key, child in value.items():
                full_key = f"{prefix}.{key}" if prefix else str(key)
                names.append(full_key)
                names.extend(self._flatten_claim_names(child, full_key))

        elif isinstance(value, list):
            for index, child in enumerate(value):
                names.extend(self._flatten_claim_names(child, f"{prefix}[{index}]"))

        return names

    def _jwt_findings(self, response):
        findings = []
        now = int(time.time())

        for jwt_item in self._extract_jwts_from_response(response):
            token = jwt_item["token"]
            location = jwt_item["location"]
            decoded = self._decode_jwt(token)

            if not decoded:
                continue

            payload = decoded["payload"]
            token_preview = self._normalise_evidence(token[:40] + "...", 60)

            exp = payload.get("exp")
            if exp is None:
                findings.append({
                    "type": "jwt_missing_exp",
                    "location": location,
                    "tokenPreview": token_preview,
                    "message": f"JWT token in {location} has no expiration (exp) claim.",
                })
            else:
                try:
                    exp_value = int(exp)
                    seconds_left = exp_value - now

                    if seconds_left < 0:
                        findings.append({
                            "type": "jwt_expired",
                            "location": location,
                            "tokenPreview": token_preview,
                            "exp": exp_value,
                            "message": f"JWT token in {location} is already expired.",
                        })
                    elif seconds_left > EXCESSIVE_JWT_LIFETIME_SECONDS:
                        findings.append({
                            "type": "jwt_excessive_lifetime",
                            "location": location,
                            "tokenPreview": token_preview,
                            "exp": exp_value,
                            "expiresInDays": round(seconds_left / 86400, 2),
                            "message": (
                                f"JWT token in {location} has excessive remaining lifetime "
                                f"({int(seconds_left / 86400)} days)."
                            ),
                        })
                except (TypeError, ValueError):
                    findings.append({
                        "type": "jwt_malformed_exp",
                        "location": location,
                        "tokenPreview": token_preview,
                        "message": f"JWT token in {location} has malformed exp claim.",
                    })

            claim_names = self._flatten_claim_names(payload)
            sensitive_claims = []

            for claim_name in claim_names:
                last_part = claim_name.split(".")[-1].lower()
                last_part = re.sub(r"\[\d+\]$", "", last_part)

                if last_part in SENSITIVE_CLAIM_NAMES:
                    sensitive_claims.append(claim_name)

            if sensitive_claims:
                findings.append({
                    "type": "jwt_sensitive_claims",
                    "location": location,
                    "claims": sorted(set(sensitive_claims)),
                    "tokenPreview": token_preview,
                    "message": (
                        f"JWT token in {location} contains sensitive claim(s): "
                        f"{', '.join(sorted(set(sensitive_claims)))}."
                    ),
                })

        return self._dedupe_findings(findings, ("type", "location", "message"))

    def _response_has_token_material(self, response):
        for raw_cookie in self._set_cookie_headers(response):
            cookie = self._parse_cookie(raw_cookie)
            if cookie and self._is_auth_cookie(cookie):
                return True

        if self._extract_jwts_from_response(response):
            return True

        return False

    def _cache_findings(self, response):
        if not self._response_has_token_material(response):
            return []

        cache_control = (response.headers.get("Cache-Control", "") or "").lower()
        pragma = (response.headers.get("Pragma", "") or "").lower()

        findings = []

        if "no-store" not in cache_control:
            findings.append({
                "type": "missing_no_store",
                "cacheControl": response.headers.get("Cache-Control", ""),
                "pragma": response.headers.get("Pragma", ""),
                "message": (
                    "Response containing auth/session material does not set "
                    "Cache-Control: no-store."
                ),
            })

        if "no-cache" not in cache_control and "no-cache" not in pragma:
            findings.append({
                "type": "missing_no_cache",
                "cacheControl": response.headers.get("Cache-Control", ""),
                "pragma": response.headers.get("Pragma", ""),
                "message": (
                    "Response containing auth/session material does not set "
                    "Cache-Control/Pragma no-cache."
                ),
            })

        return findings

    def _operation_candidates(self):
        operations = getattr(self.helpers, "parsed_operations", []) or []

        preferred = []
        fallback = []

        for op in operations:
            name = op.get("name", "")
            if not name:
                continue

            if any(token in name.lower() for token in AUTH_OPERATION_NAME_TOKENS):
                preferred.append(op)
            else:
                fallback.append(op)

        selected = preferred if preferred else fallback[:1]

        if selected:
            return selected[:3]

        return []

    def _default_value(self, param_type, param_name=""):
        name = (param_name or "").lower()
        ptype = (param_type or "string").lower()

        if "user" in name or "login" in name or "account" in name:
            return "test"
        if "pass" in name:
            return "test"
        if "nonce" in name:
            return "token-security-test-nonce"

        if ":" in ptype:
            ptype = ptype.split(":", 1)[-1]

        if ptype in ("int", "integer", "long", "short", "byte"):
            return "1"
        if ptype in ("decimal", "float", "double"):
            return "1.0"
        if ptype in ("boolean", "bool"):
            return "true"

        return "token_test"

    def _build_request_for_operation(self, op):
        tns = getattr(self.helpers, "target_namespace", "") or "http://tempuri.org/"
        input_element = op.get("input_element", op.get("name", ""))
        params = op.get("input_params", []) or []

        params_xml = ""
        for param in params:
            name = param.get("name", "")
            ptype = param.get("type", "string")

            if not name:
                continue

            value = self._default_value(ptype, name)
            params_xml += f"<tns:{name}>{value}</tns:{name}>"

        return (
            '<?xml version="1.0"?>'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{tns}">'
            f"<soap:Body><tns:{input_element}>{params_xml}</tns:{input_element}></soap:Body>"
            "</soap:Envelope>"
        )

    def _soap_action_for(self, op):
        action = op.get("soap_action") or op.get("soapAction") or ""
        if action:
            return f'"{action}"'
        name = op.get("name", "")
        return f'"urn:{name}"' if name else ""

    def _send_operation_request(self, op):
        headers = {"Content-Type": "text/xml; charset=utf-8"}
        soap_action = self._soap_action_for(op)
        if soap_action:
            headers["SOAPAction"] = soap_action

        return self.http_client.send_request(
            url=self.helpers.endpoint_url,
            method="POST",
            data=self._build_request_for_operation(op),
            headers=headers,
            merge_headers=False,
            allow_redirects=True,
        )

    def _generic_request(self):
        return (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            "<soapenv:Body><message>token_test</message></soapenv:Body>"
            "</soapenv:Envelope>"
        )

    def _send_generic_request(self):
        return self.helpers.send_soap_request(data=self._generic_request())

    def _collect_responses(self):
        responses = []

        for op in self._operation_candidates():
            try:
                response = self._send_operation_request(op)
                if response is not None:
                    responses.append({
                        "source": f"operation:{op.get('name', '')}",
                        "response": response,
                    })
            except Exception:
                continue

        if not responses:
            response = self._send_generic_request()
            if response is not None:
                responses.append({
                    "source": "generic_probe",
                    "response": response,
                })

        return responses

    def _dedupe_findings(self, findings, key_fields):
        seen = set()
        out = []

        for finding in findings:
            key = tuple(str(finding.get(field, "")) for field in key_fields)
            if key in seen:
                continue
            seen.add(key)
            out.append(finding)

        return out

    def _add_vulnerability_data(self, vuln_code, data):
        self.ptjsonlib.add_vulnerability(
            vuln_code,
            node_key=self.helpers.node_key,
            data=data,
        )

    def _group_cookie_findings(self, findings):
        grouped = {}

        for finding in findings:
            cookie = finding.get("cookie", "unknown")
            grouped.setdefault(cookie, [])
            grouped[cookie].append(finding.get("type", "unknown"))

        return [
            {
                "cookie": cookie,
                "issues": sorted(set(issues)),
            }
            for cookie, issues in sorted(grouped.items())
        ]

    def _group_jwt_expiration_findings(self, findings):
        grouped = {}

        for finding in findings:
            location = finding.get("location", "unknown")
            grouped.setdefault(location, [])
            grouped[location].append(finding.get("type", "unknown"))

        return [
            {
                "location": location,
                "issues": sorted(set(issues)),
            }
            for location, issues in sorted(grouped.items())
        ]

    def _group_jwt_sensitive_findings(self, findings):
        grouped = {}

        for finding in findings:
            location = finding.get("location", "unknown")
            grouped.setdefault(location, set())

            for claim in finding.get("claims", []):
                grouped[location].add(claim)

        return [
            {
                "location": location,
                "claims": sorted(claims),
            }
            for location, claims in sorted(grouped.items())
        ]

    def _compact_cookie_data(self, findings):
        return {
            "summary": "SOAP response set insecure authentication/session cookies.",
            "description": (
                "One or more auth/session cookies are missing security attributes "
                "or contain unsafe lifetime settings."
            ),
            "confidence": "black-box evidence",
            "findingCount": len(findings),
            "affectedCookies": self._group_cookie_findings(findings),
            "issueTypes": sorted(set(f.get("type", "unknown") for f in findings)),
        }

    def _compact_jwt_expiration_data(self, findings):
        return {
            "summary": "SOAP response exposed JWT tokens with expiration issues.",
            "description": (
                "One or more JWT tokens are missing expiration, are expired, "
                "have malformed expiration, or have excessive lifetime."
            ),
            "confidence": "black-box evidence",
            "findingCount": len(findings),
            "affectedLocations": self._group_jwt_expiration_findings(findings),
            "issueTypes": sorted(set(f.get("type", "unknown") for f in findings)),
        }

    def _compact_jwt_sensitive_data(self, findings):
        claims = set()
        for finding in findings:
            for claim in finding.get("claims", []):
                claims.add(claim)

        return {
            "summary": "SOAP response exposed JWT tokens containing sensitive claims.",
            "description": "One or more JWT payloads contain credential-like or sensitive claim names.",
            "confidence": "black-box evidence",
            "findingCount": len(findings),
            "sensitiveClaims": sorted(claims),
            "affectedLocations": self._group_jwt_sensitive_findings(findings),
        }

    def _compact_cache_data(self, findings):
        return {
            "summary": "SOAP response containing token/session material may be cacheable.",
            "description": (
                "A response exposing authentication/session material is missing "
                "strict cache-control directives."
            ),
            "confidence": "black-box evidence",
            "findingCount": len(findings),
            "issueTypes": sorted(set(f.get("type", "unknown") for f in findings)),
        }

    def _print_console_summary(self, cookie_findings, jwt_findings, cache_findings):
        ptprint(
            "Token/session security issues found.",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        if cookie_findings:
            affected = sorted(set(f["cookie"] for f in cookie_findings if f.get("cookie")))
            issue_types = sorted(set(f["type"] for f in cookie_findings))
            ptprint(
                f"  Insecure auth/session cookie configuration: "
                f"{', '.join(affected)} ({', '.join(issue_types)}).",
                "VULN",
                not self.args.json,
                indent=4,
            )

        jwt_exp_issues = [
            f for f in jwt_findings
            if f["type"] in (
                "jwt_missing_exp",
                "jwt_expired",
                "jwt_excessive_lifetime",
                "jwt_malformed_exp",
            )
        ]
        jwt_sensitive_issues = [
            f for f in jwt_findings
            if f["type"] == "jwt_sensitive_claims"
        ]

        if jwt_exp_issues:
            issue_types = sorted(set(f["type"] for f in jwt_exp_issues))
            locations = sorted(set(f["location"] for f in jwt_exp_issues))
            ptprint(
                f"  JWT expiration issue(s): {', '.join(issue_types)} "
                f"in {', '.join(locations)}.",
                "VULN",
                not self.args.json,
                indent=4,
            )

        if jwt_sensitive_issues:
            claims = []
            for finding in jwt_sensitive_issues:
                claims.extend(finding.get("claims", []))
            claims = sorted(set(claims))
            ptprint(
                f"  JWT contains sensitive claim(s): {', '.join(claims)}.",
                "VULN",
                not self.args.json,
                indent=4,
            )

        if cache_findings:
            issue_types = sorted(set(f["type"] for f in cache_findings))
            ptprint(
                f"  Token/session response cache-control issue(s): {', '.join(issue_types)}.",
                "VULN",
                not self.args.json,
                indent=4,
            )

    def run(self):
        responses = self._collect_responses()

        if not responses:
            ptprint(
                "Could not complete token/session security test.",
                "OK",
                not self.args.json,
                indent=4,
            )
            return

        cookie_findings = []
        jwt_findings = []
        cache_findings = []
        token_material_seen = False

        for item in responses:
            response = item["response"]

            if self._response_has_token_material(response):
                token_material_seen = True

            cookie_findings.extend(self._cookie_findings(response))
            jwt_findings.extend(self._jwt_findings(response))
            cache_findings.extend(self._cache_findings(response))

        cookie_findings = self._dedupe_findings(
            cookie_findings,
            ("type", "cookie", "message"),
        )
        jwt_findings = self._dedupe_findings(
            jwt_findings,
            ("type", "location", "message"),
        )
        cache_findings = self._dedupe_findings(
            cache_findings,
            ("type", "message"),
        )

        if not cookie_findings and not jwt_findings and not cache_findings:
            if token_material_seen:
                ptprint(
                    "Token/session security appears properly configured.",
                    "OK",
                    not self.args.json,
                    indent=4,
                )
            else:
                ptprint(
                    "No auth/session tokens or cookies detected in tested SOAP response(s).",
                    "OK",
                    not self.args.json,
                    indent=4,
                )
            return

        self._print_console_summary(cookie_findings, jwt_findings, cache_findings)

        jwt_exp_findings = [
            f for f in jwt_findings
            if f["type"] in (
                "jwt_missing_exp",
                "jwt_expired",
                "jwt_excessive_lifetime",
                "jwt_malformed_exp",
            )
        ]

        jwt_sensitive_findings = [
            f for f in jwt_findings
            if f["type"] == "jwt_sensitive_claims"
        ]

        if cookie_findings:
            self._add_vulnerability_data(
                "PTV-SOAP-INSECURE-COOKIE",
                self._compact_cookie_data(cookie_findings),
            )

        if jwt_exp_findings:
            self._add_vulnerability_data(
                "PTV-SOAP-JWT-EXPIRATION",
                self._compact_jwt_expiration_data(jwt_exp_findings),
            )

        if jwt_sensitive_findings:
            self._add_vulnerability_data(
                "PTV-SOAP-JWT-SENSITIVE-DATA",
                self._compact_jwt_sensitive_data(jwt_sensitive_findings),
            )

        if cache_findings:
            self._add_vulnerability_data(
                "PTV-SOAP-TOKEN-CACHEABLE",
                self._compact_cache_data(cache_findings),
            )

def run(args, ptjsonlib, helpers, http_client, common_tests):
    TokenExpiration(args, ptjsonlib, helpers, http_client, common_tests).run()
