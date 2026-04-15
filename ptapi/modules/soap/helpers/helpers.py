"""
Helpers module for shared SOAP functionality used across test modules.
"""
import re
import os
import time
from urllib.parse import urlparse
from ptlibs.ptprinthelper import ptprint


class Helpers:
    def __init__(self, args: object, ptjsonlib: object, http_client: object):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = http_client

        self.endpoint_url = args.url
        self.base_url = f"{urlparse(args.url).scheme}://{urlparse(args.url).netloc}"
        self.wsdl_content = ""
        self.wsdl_url = ""
        self.known_operations = []
        self.node_key = None

        # Full WSDL parsed data (populated by wsdl_exposure module)
        self.parsed_services = []
        self.parsed_operations = []
        self.type_definitions = {}

    def print_header(self, test_label):
        ptprint(f"Testing: {test_label}", "TITLE", not self.args.json, colortext=True)

    def send_soap_request(self, url=None, data=None, headers=None, timeout=None):
        if url is None:
            url = self.endpoint_url
        if headers is None:
            headers = {"Content-Type": "text/xml; charset=utf-8"}

        max_retries = 3
        for attempt in range(max_retries):
            try:
                r = self.http_client.send_request(
                    url=url, method="POST", data=data,
                    headers=headers, merge_headers=False, allow_redirects=True
                )
                if r.status_code == 429:
                    wait = 5 * (attempt + 1)
                    ptprint(f"Rate limit hit, backing off {wait}s...", "INFO",
                            not self.args.json, indent=4)
                    time.sleep(wait)
                    continue
                return r
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(2 * (attempt + 1))
                else:
                    ptprint(f"Request failed after {max_retries} attempts: {e}",
                            "WARNING", not self.args.json, indent=4)
        return None

    def send_get_request(self, url=None):
        if url is None:
            url = self.endpoint_url

        max_retries = 3
        for attempt in range(max_retries):
            try:
                return self.http_client.send_request(url=url, method="GET", allow_redirects=True)
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(2 * (attempt + 1))
                else:
                    ptprint(f"GET request failed after {max_retries} attempts: {e}",
                            "WARNING", not self.args.json, indent=4)
        return None

    def resolve_target_endpoint(self):
        ptprint("Resolving SOAP endpoint from WSDL...", "INFO", not self.args.json, indent=4)

        wsdl_candidates = list(filter(None, [
            self.args.url if "wsdl" in self.args.url.lower() else None,
            self.args.url.rstrip('/') + "?wsdl",
            self.args.url.rstrip('/') + "?WSDL",
            self.base_url + "/?wsdl",
            self.args.url,
            self.base_url + "/",
        ]))

        seen = set()
        unique = []
        for url in wsdl_candidates:
            n = url.rstrip('/')
            if n not in seen:
                seen.add(n)
                unique.append(url)

        for wsdl_url in unique:
            r = self.send_get_request(wsdl_url)
            if r is None or r.status_code != 200:
                continue

            content_type = r.headers.get("Content-Type", "").lower()
            body_lower = r.text.lower()
            is_xml = "xml" in content_type or body_lower.lstrip().startswith("<?xml")
            has_wsdl = "definitions" in body_lower or "wsdl:" in body_lower

            if not (is_xml and has_wsdl):
                continue

            self.wsdl_content = r.text
            self.wsdl_url = wsdl_url

            address_patterns = [
                r'<[\w:]*address\s+location\s*=\s*["\']([^"\']+)["\']',
                r'location\s*=\s*["\']([^"\']+)["\']',
            ]

            for pattern in address_patterns:
                match = re.search(pattern, r.text, re.IGNORECASE)
                if match:
                    extracted_url = match.group(1)
                    if not extracted_url.startswith("http"):
                        extracted_url = self.base_url.rstrip('/') + '/' + extracted_url.lstrip('/')

                    extracted_parsed = urlparse(extracted_url)
                    target_parsed = urlparse(self.args.url)
                    extracted_host = extracted_parsed.hostname or ""
                    target_host = target_parsed.hostname or ""

                    if extracted_host in ("localhost", "127.0.0.1", "::1") and \
                       target_host not in ("localhost", "127.0.0.1", "::1", ""):
                        fixed_url = extracted_url.replace(
                            f"{extracted_parsed.scheme}://{extracted_parsed.netloc}",
                            self.base_url
                        )
                        ptprint(f"WSDL contains localhost endpoint: {extracted_url}",
                                "WARNING", not self.args.json, indent=4)
                        ptprint(f"Remapped to: {fixed_url}", "INFO", not self.args.json, indent=4)
                        self.endpoint_url = fixed_url
                    else:
                        self.endpoint_url = extracted_url

                    ptprint(f"Resolved endpoint: {self.endpoint_url}", "INFO", not self.args.json, indent=4)
                    return

            ptprint("WSDL found but no explicit endpoint address.", "INFO", not self.args.json, indent=4)
            return

    def extract_operations_from_wsdl(self):
        if not self.wsdl_content:
            return []
        operations = re.findall(r'<\w*:?operation\s+name="([^"]+)"', self.wsdl_content)
        self.known_operations = list(set(operations))
        return self.known_operations

    def load_wordlist(self, filename):
        wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "data", "wordlists", filename
        )
        if os.path.exists(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        return []