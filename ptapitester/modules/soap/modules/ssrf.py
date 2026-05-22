"""
SOAP SSRF (URL fetching) heuristic test
"""
import time
import statistics
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP SSRF (URL fetching) test"

URL_LIKE_PARAM_NAMES = {
    "url", "uri", "endpoint", "endpointurl", "callback", "callbackurl",
    "webhook", "location", "target", "resource", "feed",
    "image", "imageurl", "avatar", "schema", "wsdl", "service",
    "link", "redirect", "fetch", "source", "href", "src",
}

SAFE_PROBE_URLS = [
    "http://10.255.255.1/probe",
    "http://192.0.2.1/probe",        
    "http://198.51.100.1/probe",     
]

OUTBOUND_FETCH_INDICATORS = [
    "connection refused", "connection reset", "could not connect",
    "connect timed out", "connect timeout", "connection timed out",
    "socket timeout", "socket error", "errno",
    "urlopen error", "urlerror", "ioerror", "oserror",
    "unknown host", "name or service not known", "no route to host",
    "network unreachable", "host unreachable",
    "failed to fetch", "unable to resolve host", "http client exception",
    "requests.exceptions", "connectionerror",
]

URL_VALIDATION_INDICATORS = [
    "invalid url", "url format error", "uri malformed",
    "malformed url", "invalid uri", "url validation",
]

SOAP_FAULT_INDICATORS = [
    "soap:fault", "soapenv:fault", "<fault>", "faultcode", "faultstring",
]

TIMING_MIN_ABS_SECONDS = 1.5
TIMING_RATIO_THRESHOLD = 2.0
BASELINE_SAMPLES = 3
PROBE_SAMPLES = 3

FINDING_THRESHOLD = 3


class SSRFTest:
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
        text_lower = text.lower()
        return any(ind in text_lower for ind in indicators)

    def _is_url_like(self, param_name):
        """Return True if the parameter name suggests a URL-like value."""
        if not param_name:
            return False
        name_lower = param_name.lower()
        if name_lower in URL_LIKE_PARAM_NAMES:
            return True
        for url_word in URL_LIKE_PARAM_NAMES:
            if url_word in name_lower:
                return True
        return False

    def _build_request(self, op, params_values):
        """Build a SOAP envelope for an operation with given parameter values."""
        tns = getattr(self.helpers, 'target_namespace', '') or 'http://tempuri.org/'
        input_element = op.get('input_element', op.get('name', ''))

        params_xml = ''
        for name, value in params_values.items():
            value_safe = (str(value).replace('&', '&amp;')
                          .replace('<', '&lt;').replace('>', '&gt;'))
            params_xml += f'<tns:{name}>{value_safe}</tns:{name}>'

        return (
            f'<?xml version="1.0"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"'
            f' xmlns:tns="{tns}">'
            f'<soap:Body><tns:{input_element}>{params_xml}'
            f'</tns:{input_element}></soap:Body></soap:Envelope>'
        )

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

    def _send(self, body):
        """Send a SOAP request and return (response, elapsed_seconds)."""
        start = time.time()
        try:
            r = self.http_client.send_request(
                url=self.helpers.endpoint_url, method="POST",
                data=body, headers={"Content-Type": "text/xml"},
                merge_headers=False, allow_redirects=True
            )
        except Exception:
            r = None
        elapsed = time.time() - start
        return r, elapsed
    
    def _categorise(self, response):
        cats = set()
        if response is None:
            cats.add("NO_RESPONSE")
            return cats
        body = response.text or ""
        if self._has_any(body, OUTBOUND_FETCH_INDICATORS):
            cats.add("OUTBOUND_FETCH_ERROR")
        if self._has_any(body, URL_VALIDATION_INDICATORS):
            cats.add("URL_VALIDATION_ERROR")
        if self._has_any(body, SOAP_FAULT_INDICATORS):
            cats.add("SOAP_FAULT")
        return cats

    def _test_operation(self, op, url_param_name):
        """Test a single operation+URL-like parameter combination.
        Returns (confidence, signals_list, evidence_dict) or None if skipped."""
        params = op.get('input_params', [])
        defaults = {p['name']: self._default_value(p.get('type', 'string'))
                    for p in params}

        baseline_values = defaults.copy()
        baseline_values[url_param_name] = ""

        baseline_times = []
        baseline_cats_union = set()
        for _ in range(BASELINE_SAMPLES):
            req = self._build_request(op, baseline_values)
            r, t = self._send(req)
            if r is None:
                continue
            baseline_times.append(t)
            baseline_cats_union |= self._categorise(r)

        if not baseline_times:
            return None

        baseline_median = statistics.median(baseline_times)

        probe_times = []
        probe_cats_union = set()
        for probe_url in SAFE_PROBE_URLS:
            probe_values = defaults.copy()
            probe_values[url_param_name] = probe_url
            req = self._build_request(op, probe_values)
            r, t = self._send(req)
            if r is None:
                continue
            probe_times.append(t)
            probe_cats_union |= self._categorise(r)

        if not probe_times:
            return None

        probe_median = statistics.median(probe_times)

        confidence = 0
        signals = []

        if ("OUTBOUND_FETCH_ERROR" in probe_cats_union and
                "OUTBOUND_FETCH_ERROR" not in baseline_cats_union):
            confidence += 3
            signals.append(
                "(+3) outbound fetch error appeared in probe response "
                "(backend likely attempted to connect to the supplied URL)")

        if (probe_median >= TIMING_MIN_ABS_SECONDS and
                probe_median >= baseline_median * TIMING_RATIO_THRESHOLD):
            confidence += 2
            signals.append(
                f"(+2) timing anomaly: probe median {probe_median:.2f}s "
                f"vs baseline median {baseline_median:.2f}s")

        if ("SOAP_FAULT" in probe_cats_union and
                "SOAP_FAULT" not in baseline_cats_union):
            confidence += 1
            signals.append(
                "(+1) SOAP Fault appeared in probe but not in baseline "
                "(server reacted to URL value)")

        if "URL_VALIDATION_ERROR" in probe_cats_union:
            confidence += 1
            signals.append(
                "(+1) URL validation triggered (parser recognised the URL "
                "but may not have fetched it)")

        if (probe_cats_union == baseline_cats_union and
                probe_median < baseline_median * 1.2):
            confidence -= 2
            signals.append(
                "(-2) probe behavior identical to baseline (no differential)")

        evidence = {
            "operation": op.get('name', ''),
            "url_param": url_param_name,
            "baseline_median_s": round(baseline_median, 3),
            "probe_median_s": round(probe_median, 3),
            "baseline_categories": sorted(baseline_cats_union),
            "probe_categories": sorted(probe_cats_union),
            "probe_urls": SAFE_PROBE_URLS,
        }
        return confidence, signals, evidence

    def run(self):
        operations = getattr(self.helpers, 'parsed_operations', []) or []
        if not operations:
            ptprint("No parsed operations available. Skipping.", "INFO",
                    not self.args.json, indent=4)
            return

        candidates = []
        for op in operations:
            for p in op.get('input_params', []):
                if self._is_url_like(p.get('name', '')):
                    candidates.append((op, p['name']))

        if not candidates:
            ptprint("No URL-like parameters found in WSDL operations. "
                    "Nothing to probe.", "INFO",
                    not self.args.json, indent=4)
            return

        ptprint(f"Found {len(candidates)} URL-like parameter(s) to probe.",
                "INFO", not self.args.json, indent=4)

        findings = []
        for op, url_param_name in candidates:
            op_name = op.get('name', '')
            ptprint(f"  Probing operation '{op_name}', parameter "
                    f"'{url_param_name}'...", "INFO",
                    not self.args.json, indent=4)

            result = self._test_operation(op, url_param_name)
            if result is None:
                ptprint(f"    Could not complete probe for '{op_name}'.",
                        "INFO", not self.args.json, indent=4)
                continue

            confidence, signals, ev = result
            if confidence >= FINDING_THRESHOLD:
                findings.append((confidence, signals, ev))
                ptprint(f"    Confidence {confidence} >= {FINDING_THRESHOLD} "
                        f"— possible URL fetching.", "VULN",
                        not self.args.json, indent=4)
            else:
                ptprint(f"    Confidence {confidence} < {FINDING_THRESHOLD} "
                        f"— no finding.", "OK",
                        not self.args.json, indent=4)
                for s in signals:
                    ptprint(f"      Signal: {s}", "INFO",
                            not self.args.json, indent=4)

        if not findings:
            ptprint("No server-side URL fetching behavior detected.", "OK",
                    not self.args.json, indent=4)
            return

        ptprint("Possible server-side URL fetching behavior detected.",
                "VULN", not self.args.json, indent=4, colortext=True)

        evidence_parts = []
        for confidence, signals, ev in findings:
            ptprint(f"  Operation '{ev['operation']}' "
                    f"(param '{ev['url_param']}'): "
                    f"confidence {confidence}", "VULN",
                    not self.args.json, indent=4)
            for s in signals:
                ptprint(f"    Signal: {s}", "VULN",
                        not self.args.json, indent=4)

            evidence_parts.append(
                f"Operation '{ev['operation']}' parameter '{ev['url_param']}': "
                f"confidence {confidence} (threshold {FINDING_THRESHOLD}). "
                f"Signals: {' | '.join(signals)}. "
                f"Baseline median {ev['baseline_median_s']}s, "
                f"probe median {ev['probe_median_s']}s. "
                f"Baseline categories: {ev['baseline_categories']}, "
                f"probe categories: {ev['probe_categories']}."
            )

        evidence = (
            "Possible server-side URL fetching behavior detected on SOAP "
            f"endpoint {self.helpers.endpoint_url}. "
            f"Probe URLs (non-routable / TEST-NET, safe): "
            f"{', '.join(SAFE_PROBE_URLS)}. "
            + " || ".join(evidence_parts) +
            " This is a heuristic assessment based on differential behavior "
            "analysis, not a confirmed SSRF exploit. Manual verification "
            "recommended."
        )

        self.ptjsonlib.add_vulnerability(
            "PTV-SOAP-SSRF",
            node_key=self.helpers.node_key,
            data={"evidence": evidence})


def run(args, ptjsonlib, helpers, http_client, common_tests):
    SSRFTest(args, ptjsonlib, helpers, http_client, common_tests).run()