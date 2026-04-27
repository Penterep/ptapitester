"""
Helpers module for shared XML-RPC functionality used across test modules.
"""
import os
import time
import xmlrpc.client
from urllib.parse import urlparse, urljoin
from ptlibs.ptprinthelper import ptprint


COMMON_XMLRPC_PATHS = [
    "/xmlrpc.php",      
    "/xmlrpc/",         
    "/xmlrpc",
    "/RPC2",            
    "/RPC2/",
    "/api/xmlrpc",
    "/services/xmlrpc",
    "/rpc",
    "/",                
]


class RedirectTransport(xmlrpc.client.SafeTransport if True else xmlrpc.client.Transport):
    """XML-RPC transport that follows 301/302 redirects automatically."""

    def __init__(self, use_https=True, max_redirects=5):
        super().__init__()
        self._max_redirects = max_redirects
        self._redirect_count = 0
        # Reset on each new request - tracked outside

    def single_request(self, host, handler, request_body, verbose=False):
        # Try the request normally
        try:
            response = super().single_request(host, handler, request_body, verbose)
            return response
        except xmlrpc.client.ProtocolError as e:
            if e.errcode in (301, 302) and self._redirect_count < self._max_redirects:
                self._redirect_count += 1
                # Get redirect target from headers
                new_location = None
                if hasattr(e, 'headers') and e.headers:
                    new_location = e.headers.get('Location')
                if not new_location:
                    raise

                # Parse new location and retry
                parsed = urlparse(new_location)
                new_host = parsed.netloc or host
                new_handler = parsed.path or '/'
                if parsed.query:
                    new_handler += '?' + parsed.query

                return self.single_request(new_host, new_handler, request_body, verbose)
            raise


class Helpers:
    def __init__(self, args: object, ptjsonlib: object, http_client: object):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = http_client

        self.endpoint_url = args.url
        self.discovered_methods = []
        self.metadata = {}
        self.node_key = None
        self.undocumented_methods = []

    def print_header(self, test_label):
        ptprint(f"Testing: {test_label}", "TITLE", not self.args.json, colortext=True)

    def resolve_target_endpoint(self):
        ptprint("Resolving XML-RPC endpoint...", "INFO", not self.args.json, indent=4)

        probe = ('<?xml version="1.0"?>'
                 '<methodCall><methodName>system.listMethods</methodName>'
                 '</methodCall>')
        headers = {"Content-Type": "text/xml"}

        # Build candidate URLs
        parsed = urlparse(self.args.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidates = []

        # If user provided a path, try that first
        if parsed.path and parsed.path != '/':
            candidates.append(self.args.url)
            # Also try with trailing slash if missing
            if not self.args.url.endswith('/'):
                candidates.append(self.args.url + '/')

        # Then try common paths under the base URL
        for path in COMMON_XMLRPC_PATHS:
            candidate = base + path
            if candidate not in candidates:
                candidates.append(candidate)

        for url in candidates:
            try:
                r = self.http_client.send_request(
                    url=url, method="POST", data=probe,
                    headers=headers, merge_headers=False, allow_redirects=True
                )
                if r is None:
                    continue

                # Check if response looks like XML-RPC
                ct = r.headers.get('Content-Type', '').lower()
                body = r.text or ''
                is_xmlrpc = (
                    r.status_code == 200 and
                    ('xml' in ct) and
                    ('<methodResponse>' in body or '<?xml' in body)
                )

                if is_xmlrpc:
                    # Use the URL after redirect (if any)
                    final_url = r.url if hasattr(r, 'url') and r.url else url
                    if final_url != self.endpoint_url:
                        ptprint(f"Resolved endpoint: {final_url}", "INFO",
                                not self.args.json, indent=4)
                    self.endpoint_url = final_url
                    return

            except Exception:
                continue

        # Nothing worked — keep original URL
        ptprint(f"Could not auto-resolve XML-RPC endpoint. "
                f"Using {self.endpoint_url}", "WARNING",
                not self.args.json, indent=4)

    def send_xmlrpc_raw(self, data, url=None, headers=None):
        """Send raw XML-RPC request using http_client."""
        if url is None:
            url = self.endpoint_url
        if headers is None:
            headers = {"Content-Type": "text/xml"}

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

    def get_xmlrpc_proxy(self):
        """Get xmlrpc.client.ServerProxy for the endpoint with redirect support."""
        # Use custom transport that follows redirects
        parsed = urlparse(self.endpoint_url)
        if parsed.scheme == 'https':
            transport = xmlrpc.client.SafeTransport()
        else:
            transport = xmlrpc.client.Transport()
        return xmlrpc.client.ServerProxy(
            self.endpoint_url,
            transport=transport,
            verbose=False,
            allow_none=True
        )

    def load_wordlist(self, filename):
        """Load wordlist from data/wordlists/ directory."""
        wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "data", "wordlists", filename
        )
        if os.path.exists(wordlist_path):
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        return []