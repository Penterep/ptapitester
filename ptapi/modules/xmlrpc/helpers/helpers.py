"""
Helpers module for shared XML-RPC functionality used across test modules.
"""
import os
import time
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint


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

    def send_xmlrpc_raw(self, data, url=None, headers=None):
        """Send raw XML-RPC request using http_client."""
        if url is None:
            url = self.endpoint_url
        if headers is None:
            headers = {"Content-Type": "text/xml"}

        try:
            r = self.http_client.send_request(
                url=url, method="POST", data=data,
                headers=headers, merge_headers=False, allow_redirects=True
            )
            if r.status_code == 429:
                ptprint("Rate limit hit, backing off 11s...", "INFO",
                        not self.args.json, indent=4)
                time.sleep(11)
                r = self.http_client.send_request(
                    url=url, method="POST", data=data,
                    headers=headers, merge_headers=False, allow_redirects=True
                )
            return r
        except Exception as e:
            ptprint(f"Request failed: {e}", "WARNING", not self.args.json, indent=4)
            return None

    def get_xmlrpc_proxy(self):
        """Get xmlrpc.client.ServerProxy for the endpoint."""
        return xmlrpc.client.ServerProxy(self.endpoint_url, verbose=False)

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
