"""
SOAP Content-Type response-header test
"""
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Content-Type response-header audit"

FULLY_VALID_SOAP_MIME_TYPES = ("text/xml", "application/soap+xml")
ACCEPTABLE_XML_MIME_TYPES = ("application/xml",)
HTML_MIME_TYPES = ("text/html", "application/xhtml+xml")

MIME_TYPE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+\-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+\-]*$"
)

MIME_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+\-]+$")

XML_DECL_RE = re.compile(
    r"<\?xml\b[^?>]*\?>", re.IGNORECASE
)

XML_DECL_ENCODING_RE = re.compile(
    r"""encoding\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)

KNOWN_CHARSETS = {
    "utf-8", "utf-16", "utf-16be", "utf-16le", "utf-32",
    "us-ascii", "ascii", "iso-8859-1", "iso-8859-2", "iso-8859-15",
    "windows-1250", "windows-1251", "windows-1252",
}


class ContentTypeTest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _default_value(self, param_type):
        if param_type == 'string':
            return 'test'
        if param_type in ('int', 'integer', 'long', 'short'):
            return '1'
        if param_type in ('decimal', 'float', 'double'):
            return '1.0'
        if param_type == 'boolean':
            return 'true'
        return 'test'

    def _build_request(self, op):
        tns = getattr(self.helpers, 'target_namespace', '') or 'http://tempuri.org/'
        input_element = op.get('input_element', op.get('name', ''))
        params = op.get('input_params', [])

        params_xml = ''
        for p in params:
            p_name = p.get('name', '')
            p_type = p.get('type', 'string')
            if not p_name:
                continue
            val = self._default_value(p_type)
            params_xml += f'<tns:{p_name}>{val}</tns:{p_name}>'

        return (
            f'<?xml version="1.0"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{tns}">'
            f'<soap:Body><tns:{input_element}>{params_xml}'
            f'</tns:{input_element}></soap:Body></soap:Envelope>'
        )

    def _generic_request(self):
        return (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>content_type_audit</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

    def _parse_content_type(self, header_value):
        errors = []
        if header_value is None:
            return None, {}, ["header absent"]

        raw = header_value.strip()
        if not raw:
            return None, {}, ["header empty"]

        if "," in raw:
            errors.append("multiple Content-Type values in a single header")
            raw = raw.split(",", 1)[0].strip()

        parts = raw.split(";")
        mime_raw = parts[0].strip().lower()

        if not MIME_TYPE_RE.match(mime_raw):
            errors.append(f"invalid type/subtype syntax: {parts[0]!r}")
            return None, {}, errors

        params = {}
        for token in parts[1:]:
            seg = token.strip()
            if not seg:
                errors.append("empty parameter segment")
                continue
            if "=" not in seg:
                errors.append(f"parameter without value: {seg!r}")
                continue

            key, _, value = seg.partition("=")
            key = key.strip().lower()
            value = value.strip()

            if not MIME_PARAM_NAME_RE.match(key):
                errors.append(f"invalid parameter name: {key!r}")
                continue

            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]

            params[key] = value

        return mime_raw, params, errors

    def _classify_mime(self, mime_type):
        if mime_type is None:
            return "unknown"
        if mime_type in FULLY_VALID_SOAP_MIME_TYPES:
            return "soap"
        if mime_type in ACCEPTABLE_XML_MIME_TYPES:
            return "xml_non_standard"
        if mime_type in HTML_MIME_TYPES:
            return "html"
        if mime_type.startswith("multipart/"):
            return "multipart"
        if mime_type.startswith("application/") or mime_type.startswith("image/") or \
                mime_type.startswith("audio/") or mime_type.startswith("video/"):
            return "binary_or_other"
        return "other"

    def _validate_charset(self, charset):
        if charset is None:
            return None, None

        ch = charset.strip().lower()

        if not ch:
            return None, "charset parameter is empty"

        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_\-.:+]*$", ch):
            return ch, f"malformed charset value: {charset!r}"

        return ch, None

    def _extract_xml_encoding(self, body_text):
        if not body_text:
            return None, None

        head = body_text.lstrip()[:200]
        m = XML_DECL_RE.match(head)

        if not m:
            return None, None

        decl = m.group(0)
        em = XML_DECL_ENCODING_RE.search(decl)

        if not em:
            return None, None

        enc = em.group(1).strip()

        if not enc:
            return None, "XML declaration has empty encoding attribute"

        if not re.match(r"^[A-Za-z][A-Za-z0-9_\-.:+]*$", enc):
            return enc.lower(), f"malformed XML encoding name: {enc!r}"

        return enc.lower(), None

    def _body_looks_like_soap(self, body_text):
        if not body_text:
            return False

        head = body_text.lstrip()[:400].lower()

        return (
            "<soap:envelope" in head
            or "<soapenv:envelope" in head
            or "<env:envelope" in head
        )

    def _body_looks_like_xml(self, body_text):
        if not body_text:
            return False

        head = body_text.lstrip()[:200].lower()

        return head.startswith("<?xml") or self._body_looks_like_soap(body_text)

    def _body_looks_like_html(self, body_text):
        if not body_text:
            return False

        head = body_text.lstrip()[:200].lower()

        return (
            head.startswith("<!doctype html")
            or head.startswith("<html")
            or "<head>" in head
            or "<body>" in head
        )

    def _check_duplicate_content_type(self, response):
        ct = response.headers.get("Content-Type", "")

        if "," in ct:
            return True

        try:
            getall = getattr(response.raw.headers, "get_all", None)
            if callable(getall):
                vals = getall("Content-Type")
                if vals and len(vals) > 1:
                    return True
        except Exception:
            pass

        return False

    def _analyse_response(self, op_name, response):
        findings = []
        prefix = f"Operation '{op_name}': " if op_name else ""

        raw_ct = response.headers.get("Content-Type", "")
        mime, params, mime_errors = self._parse_content_type(raw_ct)
        mime_class = self._classify_mime(mime)

        charset = params.get("charset")
        norm_charset, charset_err = self._validate_charset(charset)

        body_text = response.text or ""
        body_soap = self._body_looks_like_soap(body_text)
        body_html = self._body_looks_like_html(body_text)

        xml_encoding, xml_decl_err = self._extract_xml_encoding(body_text)

        if mime_errors and raw_ct and raw_ct.strip():
            real_errors = [
                e for e in mime_errors
                if e not in ("header absent", "header empty")
            ]

            if real_errors:
                findings.append(
                    f"{prefix}malformed Content-Type header "
                    f"({raw_ct!r}): {'; '.join(real_errors)}."
                )

        if self._check_duplicate_content_type(response):
            findings.append(
                f"{prefix}server returned multiple Content-Type values in "
                f"the response header — clients may parse the header inconsistently."
            )

        if mime_class == "html" or body_html:
            findings.append(
                f"{prefix}SOAP endpoint returned HTML content (Content-Type: "
                f"{raw_ct or 'unknown'}). This is unexpected for a SOAP service "
                f"and may indicate fallback error pages or response-type confusion."
            )

        elif body_soap and mime_class not in ("soap", "xml_non_standard", "multipart"):
            findings.append(
                f"{prefix}response body appears to contain a SOAP envelope "
                f"but Content-Type is {raw_ct or '(absent)'} "
                f"(classified as {mime_class}). MIME/body inconsistency may "
                f"cause client parsers to misinterpret the response."
            )

        elif mime_class == "soap":
            if charset is not None:
                if charset_err:
                    findings.append(
                        f"{prefix}{charset_err} in Content-Type ({raw_ct!r})."
                    )

            if xml_decl_err:
                findings.append(f"{prefix}{xml_decl_err}.")

            if norm_charset and xml_encoding and norm_charset != xml_encoding:
                findings.append(
                    f"{prefix}HTTP charset ({norm_charset}) does not match "
                    f"XML declaration encoding ({xml_encoding}). Mismatched "
                    f"encodings cause character corruption and may be exploited "
                    f"for parser confusion."
                )

        return findings

    def run(self):
        all_findings = []

        operations = getattr(self.helpers, 'parsed_operations', []) or []
        valid_ops = [op for op in operations if op.get('name')]

        if valid_ops:
            for op in valid_ops:
                op_name = op['name']
                r = self.helpers.send_soap_request(data=self._build_request(op))

                if r is None:
                    continue

                findings = self._analyse_response(op_name, r)
                all_findings.extend(findings)
        else:
            r = self.helpers.send_soap_request(data=self._generic_request())

            if r is None:
                ptprint("Content-Type audit could not be completed.",
                        "OK", not self.args.json, indent=4)
                return

            findings = self._analyse_response("", r)
            all_findings.extend(findings)

        if all_findings:
            ptprint("Content-Type protocol inconsistency detected.",
                    "VULN", not self.args.json, indent=4, colortext=True)

            for finding in all_findings:
                ptprint(f"  {finding}", "VULN", not self.args.json, indent=4)

            evidence = (
                f"Content-Type audit on SOAP endpoint "
                f"{self.helpers.endpoint_url}. "
                + " || ".join(all_findings)
            )

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-CONTENT-TYPE",
                node_key=self.helpers.node_key,
                data={
                    "summary": "SOAP response Content-Type issue detected.",
                    "description": (
                        "The SOAP endpoint returned a response with a malformed, "
                        "duplicate, or body-inconsistent Content-Type header."
                    ),
                    "confidence": "black-box heuristic",
                    "findingCount": len(all_findings),
                    "findings": all_findings,
                    "evidence": evidence,
                }
            )
            return

        ptprint("No SOAP Content-Type issues detected.",
                "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ContentTypeTest(args, ptjsonlib, helpers, http_client, common_tests).run()