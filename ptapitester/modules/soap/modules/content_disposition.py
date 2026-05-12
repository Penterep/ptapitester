"""
SOAP Content-Disposition response-header test
"""
import re
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP Content-Disposition response-header test"

STANDARD_SOAP_CONTENT_TYPES = (
    "text/xml",
    "application/soap+xml",
    "application/xml",
)

DOWNLOAD_CONTENT_TYPES = (
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-msdownload",
    "application/x-executable",
    "application/force-download",
    "application/download",
)

ATTACHMENT_CONTENT_TYPES = (
    "multipart/related",
    "multipart/form-data",
    "application/xop+xml",
)

HTML_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
)

SUSPICIOUS_FILENAME_PATTERNS = [
    re.compile(r"[\r\n]"),
    re.compile(r"\.\.[/\\]"),
    re.compile(r"^/"),
    re.compile(r"^[A-Za-z]:[\\/]"),
    re.compile(r"\x00"),
    re.compile(r"\.(pdf|doc|xls|jpg|png|gif)\.(exe|bat|cmd|sh|ps1|jar|scr)$",
               re.IGNORECASE),
]


class ContentDispositionTest:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _classify_content_type(self, content_type):
        """Return a short string describing what kind of content this is."""
        ct = (content_type or "").lower()
        if any(ct.startswith(t) for t in STANDARD_SOAP_CONTENT_TYPES):
            return "standard_soap_xml"
        if any(ct.startswith(t) for t in ATTACHMENT_CONTENT_TYPES):
            return "attachment_like"
        if any(ct.startswith(t) for t in DOWNLOAD_CONTENT_TYPES):
            return "download"
        if any(ct.startswith(t) for t in HTML_CONTENT_TYPES):
            return "html"
        if ct.startswith("application/") or ct.startswith("image/") or \
                ct.startswith("audio/") or ct.startswith("video/"):
            return "binary"
        return "unknown"

    def _body_looks_binary(self, body):
        """Heuristic: does the response body look like binary (not text)?"""
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

        Returns (None, None) if header is missing.
        Returns ('__malformed__', {}) if the header is present but cannot
        be parsed reasonably."""
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
        """Return a description string if filename is suspicious, or None."""
        if not filename:
            return None
        for pat in SUSPICIOUS_FILENAME_PATTERNS:
            if pat.search(filename):
                return f"filename matches suspicious pattern: {pat.pattern!r}"
        return None

    def run(self):
        soap_request = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>content_disposition_audit</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )

        r = self.helpers.send_soap_request(data=soap_request)
        if r is None:
            ptprint("Could not complete Content-Disposition audit "
                    "(no response from server).", "INFO",
                    not self.args.json, indent=4)
            return

        content_type = r.headers.get("Content-Type", "")
        content_disposition = r.headers.get("Content-Disposition", "")

        ct_category = self._classify_content_type(content_type)
        body_binary = self._body_looks_binary(r.text)
        body_xml = self._body_looks_like_xml(r.text)
        body_html = self._body_looks_like_html(r.text)

        disp_type, disp_params = self._parse_content_disposition(content_disposition)
        disp_filename = (disp_params or {}).get("filename") if disp_params else None

        findings = []
        info_notes = []

        if ct_category == "standard_soap_xml" or body_xml:
            if not content_disposition:
                info_notes.append(
                    "Standard SOAP XML response returned without "
                    "Content-Disposition header (normal RFC-compliant "
                    "behaviour for SOAP endpoints).")
            else:
                if disp_type == "inline":
                    info_notes.append(
                        f"SOAP XML response includes Content-Disposition: "
                        f"inline (Content-Type: {content_type or 'unknown'}).")
                elif disp_type == "attachment":
                    info_notes.append(
                        f"SOAP XML response unexpectedly served with "
                        f"Content-Disposition: attachment — clients may "
                        f"prompt to save the SOAP envelope as a file.")
                elif disp_type == "__malformed__":
                    findings.append(
                        f"Malformed Content-Disposition header detected: "
                        f"{content_disposition!r}. Malformed headers may be "
                        f"parsed inconsistently by different clients.")
                else:
                    info_notes.append(
                        f"SOAP XML response includes Content-Disposition: "
                        f"{disp_type}.")

        elif ct_category == "html" or body_html:
            findings.append(
                f"SOAP endpoint returned HTML content (Content-Type: "
                f"{content_type or 'unknown'}). This is unexpected for a "
                f"SOAP service and may indicate misconfiguration, error "
                f"page leakage, or response-type confusion. If untrusted "
                f"input can influence this response, an attacker may be "
                f"able to deliver HTML/JS rendered by browsers (reflected "
                f"file download / XSS-via-SOAP).")

        elif ct_category in ("download", "binary", "attachment_like") or body_binary:
            if not content_disposition:
                findings.append(
                    f"SOAP endpoint returned downloadable/binary content "
                    f"(Content-Type: {content_type or 'unknown'}) without "
                    f"a Content-Disposition header. Browsers and clients "
                    f"may sniff the content type or render the response "
                    f"inline. RFC 6266 recommends an explicit "
                    f"Content-Disposition (inline or attachment with a "
                    f"safe filename) for such payloads.")
            elif disp_type == "__malformed__":
                findings.append(
                    f"Malformed Content-Disposition header on a "
                    f"downloadable response: {content_disposition!r}.")
            else:
                susp = self._suspicious_filename(disp_filename)
                if susp:
                    findings.append(
                        f"Downloadable response includes a suspicious "
                        f"filename parameter ({disp_filename!r}): {susp}. "
                        f"This may enable CRLF injection, path traversal "
                        f"or extension-based deception.")
                else:
                    info_notes.append(
                        f"Downloadable response includes "
                        f"Content-Disposition: {disp_type}"
                        + (f" (filename: {disp_filename!r})"
                           if disp_filename else "") + ".")

        else:
            info_notes.append(
                f"SOAP endpoint returned response of unrecognised type "
                f"(Content-Type: {content_type or 'unknown'}). "
                f"Content-Disposition: {content_disposition or '(absent)'}.")

        if disp_filename and disp_type not in (None, "__malformed__"):
            susp = self._suspicious_filename(disp_filename)
            if susp and not any("suspicious filename" in f for f in findings):
                findings.append(
                    f"Content-Disposition filename parameter is suspicious "
                    f"({disp_filename!r}): {susp}.")

        if findings:
            ptprint("Potentially unsafe response-download behaviour detected.",
                    "VULN", not self.args.json, indent=4, colortext=True)
            evidence_parts = []
            for f in findings:
                ptprint(f"  {f}", "VULN", not self.args.json, indent=4)
                evidence_parts.append(f)

            if info_notes:
                for n in info_notes:
                    ptprint(f"  (info) {n}", "INFO",
                            not self.args.json, indent=4)

            evidence = (
                f"Content-Disposition audit on SOAP endpoint "
                f"{self.helpers.endpoint_url}. "
                f"Response Content-Type: {content_type or '(absent)'}, "
                f"Content-Disposition: {content_disposition or '(absent)'}. "
                + " || ".join(evidence_parts)
            )
            if info_notes:
                evidence += " Additional observations: " + " ".join(info_notes)

            self.ptjsonlib.add_vulnerability(
                "PTV-SOAP-CONTENT-DISPOSITION",
                node_key=self.helpers.node_key,
                data={"evidence": evidence})
            return

        if info_notes:
            ptprint("Content-Disposition audit completed (informational).",
                    "OK", not self.args.json, indent=4)
            for n in info_notes:
                ptprint(f"  {n}", "INFO", not self.args.json, indent=4)
        else:
            ptprint("Content-Disposition audit completed (no observations).",
                    "OK", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    ContentDispositionTest(args, ptjsonlib, helpers, http_client, common_tests).run()