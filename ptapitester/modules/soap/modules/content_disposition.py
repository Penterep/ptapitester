"""
SOAP Content-Disposition response-header  test 
"""
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Content-Disposition response-header audit"

STANDARD_SOAP_CONTENT_TYPES = (
    "text/xml","application/soap+xml","application/xml",
)

DOWNLOAD_CONTENT_TYPES = (
    "application/octet-stream","application/pdf","application/zip","application/x-zip-compressed",
    "application/x-msdownload","application/x-executable","application/force-download","application/download",
)

JSON_CONTENT_TYPES = (
    "application/json","text/json",
)

ATTACHMENT_CONTENT_TYPES = (
    "multipart/related","multipart/form-data","application/xop+xml",
)

HTML_CONTENT_TYPES = (
    "text/html","application/xhtml+xml",
)

SUSPICIOUS_FILENAME_PATTERNS = [
    (re.compile(r"[\r\n]"), "CRLF characters (header injection risk)"),
    (re.compile(r"\.\.[/\\]"), "path traversal sequence"),
    (re.compile(r"^/"), "absolute Unix-style path"),
    (re.compile(r"^[A-Za-z]:[\\/]"), "absolute Windows-style path"),
    (re.compile(r"\x00"), "null byte"),
    (re.compile(
        r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|txt)"
        r"\.(exe|bat|cmd|sh|ps1|jar|scr|vbs|com)$", re.IGNORECASE),
     "double-extension trick (e.g. invoice.pdf.exe)"),
]


class ContentDispositionTest:
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

    def _classify_content_type(self, content_type):
        ct = (content_type or "").lower()
        if any(ct.startswith(t) for t in STANDARD_SOAP_CONTENT_TYPES):
            return "standard_soap_xml"
        if any(ct.startswith(t) for t in ATTACHMENT_CONTENT_TYPES):
            return "attachment_like"
        if any(ct.startswith(t) for t in DOWNLOAD_CONTENT_TYPES):
            return "download"
        if any(ct.startswith(t) for t in HTML_CONTENT_TYPES):
            return "html"
        if any(ct.startswith(t) for t in JSON_CONTENT_TYPES):
            return "json"
        if ct.startswith("image/") or ct.startswith("audio/") or ct.startswith("video/"):
            return "binary"
        if ct.startswith("application/"):
            return "application_other"
        return "unknown"

    def _body_looks_binary(self, body):
        if not body:
            return False
        if isinstance(body, bytes):
            sample = body[:512]
            non_print = sum(1 for b in sample
                            if b < 9 or (13 < b < 32) or b == 127)
            return non_print / max(len(sample), 1) > 0.10
        sample = body[:512]
        ctrl = sum(1 for c in sample
                   if ord(c) < 9 or (13 < ord(c) < 32))
        return ctrl / max(len(sample), 1) > 0.10

    def _body_looks_like_xml(self, body):
        if not body:
            return False
        text = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) \
            else body
        head = text.lstrip()[:200].lower()
        return head.startswith("<?xml") or "<soap:envelope" in head or \
            "<soapenv:envelope" in head or "<env:envelope" in head

    def _body_looks_like_html(self, body):
        if not body:
            return False
        text = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) \
            else body
        head = text.lstrip()[:200].lower()
        return head.startswith("<!doctype html") or head.startswith("<html") \
            or "<head>" in head or "<body>" in head

    def _parse_content_disposition(self, header_value):
        """Parse a Content-Disposition header into (type, params_dict).
        Returns (None, None) if missing.
        Returns ('__malformed__', {}) if present but unparseable."""
        if not header_value:
            return None, None

        parts = [p.strip() for p in header_value.split(';')]
        if not parts or not parts[0]:
            return "__malformed__", {}

        disp_type = parts[0].lower()
        if not re.match(r"^[A-Za-z][\w\-]*$", disp_type):
            return "__malformed__", {}

        params = {}
        for token in parts[1:]:
            if "=" not in token:
                if token:
                    return "__malformed__", params
                continue
            key, _, value = token.partition("=")
            key = key.strip().lower()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            params[key] = value

        return disp_type, params

    def _suspicious_filename(self, filename):
        """Return description string if filename is suspicious, or None."""
        if not filename:
            return None
        for pat, desc in SUSPICIOUS_FILENAME_PATTERNS:
            if pat.search(filename):
                return desc
        return None

    def _analyse_response(self, op_name, response):
        findings = []
        info_notes = []

        content_type = response.headers.get("Content-Type", "")
        content_disposition = response.headers.get("Content-Disposition", "")

        ct_category = self._classify_content_type(content_type)
        body_binary = self._body_looks_binary(response.text)
        body_xml = self._body_looks_like_xml(response.text)
        body_html = self._body_looks_like_html(response.text)

        disp_type, disp_params = self._parse_content_disposition(content_disposition)
        disp_filename = (disp_params or {}).get("filename") if disp_params else None

        prefix = f"Operation '{op_name}': " if op_name else ""

        if ct_category == "standard_soap_xml" or body_xml:
            if not content_disposition:
                info_notes.append(
                    f"{prefix}standard SOAP XML response returned without "
                    f"Content-Disposition header (normal RFC-compliant behaviour).")
            else:
                if disp_type == "inline":
                    info_notes.append(
                        f"{prefix}SOAP XML response includes "
                        f"Content-Disposition: inline.")
                elif disp_type == "attachment":
                    info_notes.append(
                        f"{prefix}SOAP XML response unexpectedly served "
                        f"with Content-Disposition: attachment — clients may "
                        f"prompt to save the SOAP envelope as a file.")
                elif disp_type == "__malformed__":
                    findings.append(
                        f"{prefix}malformed Content-Disposition header "
                        f"detected: {content_disposition!r}.")
                else:
                    info_notes.append(
                        f"{prefix}SOAP XML response includes "
                        f"Content-Disposition: {disp_type}.")

        elif ct_category == "html" or body_html:
            findings.append(
                f"{prefix}SOAP endpoint returned HTML content (Content-Type: "
                f"{content_type or 'unknown'}). This is unexpected for a SOAP "
                f"service and may indicate misconfiguration or response-type "
                f"confusion.")
            
        elif ct_category == "json":
            return findings, []

        elif ct_category in ("download", "binary", "attachment_like") or body_binary:
            if not content_disposition:
                findings.append(
                    f"{prefix}downloadable/binary content returned "
                    f"(Content-Type: {content_type or 'unknown'}) without a "
                    f"Content-Disposition header. Clients may handle this response "
                    f"inconsistently because no filename or download/inline handling "
                    f"is explicitly specified.")
            elif disp_type == "__malformed__":
                findings.append(
                    f"{prefix}malformed Content-Disposition header on a "
                    f"downloadable response: {content_disposition!r}.")
            else:
                susp = self._suspicious_filename(disp_filename)
                if susp:
                    findings.append(
                        f"{prefix}downloadable response includes a suspicious "
                        f"filename parameter ({disp_filename!r}): {susp}.")
                else:
                    info_notes.append(
                        f"{prefix}downloadable response includes "
                        f"Content-Disposition: {disp_type}"
                        + (f" (filename: {disp_filename!r})"
                           if disp_filename else "") + ".")

        else:
            info_notes.append(
                f"{prefix}response of unrecognised type (Content-Type: "
                f"{content_type or 'unknown'}, "
                f"Content-Disposition: {content_disposition or '(absent)'}).")

        if (disp_filename and disp_type not in (None, "__malformed__")
                and not any("suspicious filename" in f.lower() for f in findings)):
            susp = self._suspicious_filename(disp_filename)
            if susp:
                findings.append(
                    f"{prefix}Content-Disposition filename parameter is "
                    f"suspicious ({disp_filename!r}): {susp}.")

        return findings, info_notes

    def _generic_request(self):
        return (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>content_disposition_audit</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

    def run(self):
        all_findings = []   
        all_info = []       

        operations = getattr(self.helpers, 'parsed_operations', []) or []
        valid_ops = [op for op in operations if op.get('name')]

        if valid_ops:
            for op in valid_ops:
                op_name = op['name']
                request_body = self._build_request(op)
                r = self.helpers.send_soap_request(data=request_body)
                if r is None:
                    ptprint(f"  Operation '{op_name}': no response.", "INFO",
                            not self.args.json, indent=4)
                    continue
                findings, info_notes = self._analyse_response(op_name, r)
                all_findings.extend((op_name, f) for f in findings)
                all_info.extend((op_name, n) for n in info_notes)
        else:
            r = self.helpers.send_soap_request(data=self._generic_request())
            if r is None:
                ptprint("Could not complete Content-Disposition audit "
                        "(no response from server).", "INFO",
                        not self.args.json, indent=4)
                return
            findings, info_notes = self._analyse_response("", r)
            all_findings.extend(("", f) for f in findings)
            all_info.extend(("", n) for n in info_notes)

        if all_findings:
            ptprint("Potentially unsafe response-download behaviour detected.",
                    "VULN", not self.args.json, indent=4, colortext=True)

            evidence_parts = []
            for op_name, f in all_findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
                evidence_parts.append(f)

            evidence = (
                f"Content-Disposition audit on SOAP endpoint "
                f"{self.helpers.endpoint_url}. "
                + " || ".join(evidence_parts)
            )

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-CONTENT-DISPOSITION",
                node_key=self.helpers.node_key,
                data={"evidence": evidence})
            return

        ptprint("No unsafe Content-Disposition behaviour detected.",
            "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ContentDispositionTest(args, ptjsonlib, helpers, http_client, common_tests).run()