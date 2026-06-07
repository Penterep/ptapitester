"""
API HTTPS test

Contains:
- Https class to perform the test
- run() function as an entry point for running the test
"""
from urllib.parse import urlparse
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import SSLError, Timeout, TooManyRedirects

__TESTLABEL__ = "API HTTPS security test"

class Https:
    """
    Class for testing if an API is accessible through HTTP or HTTPS
    """
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, base_indent) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.base_indent = base_indent
        self.helpers.print_header(__TESTLABEL__, self.base_indent)

    def _probe(self, url: str, *, verify_ssl: bool = True) -> dict:
        """
        Send a GET request and return a result dict with keys:
            reachable, status_code, final_url, redirect_chain, ssl_error, error_msg
        """
        result = {
            "reachable": False,
            "status_code": None,
            "final_url": None,
            "redirect_chain": [],
            "ssl_error": False,
            "error_msg": None,
        }
        try:
            resp = self.http_client.send_request(
                url,
                timeout=5,
                allow_redirects=True,
                verify=verify_ssl,
                headers=self.args.headers,
            )
            result["reachable"] = True
            result["status_code"] = resp.status_code
            result["final_url"] = resp.url
            result["redirect_chain"] = [
                (r.url, r.status_code) for r in resp.history
            ]
        except SSLError as e:
            result["ssl_error"] = True
            result["error_msg"] = str(e).split("\n")[0]
        except ConnectionError as e:
            result["error_msg"] = f"Connection refused / DNS failure"
        except Timeout:
            result["error_msg"] = f"Timed out after 5s"
        except TooManyRedirects:
            result["error_msg"] = "Too many redirects"
        except Exception as e:
            result["error_msg"] = str(e)

        return result

    def _check_hsts(self, domain: str) -> tuple[bool, str | None]:
        """Return (has_hsts, header_value) by inspecting the HTTPS response headers."""
        try:
            resp = self.http_client.send_request(
                f"https://{domain}",
                timeout=5,
                allow_redirects=True,
                verify=True,
                headers={"User-Agent": "check-https/1.0"},
            )
            hsts = resp.headers.get("Strict-Transport-Security")
            return bool(hsts), hsts
        except Exception:
            return False, None

    def run(self) -> None:
        """
        Tests to see if an API is accessible through HTTP or HTTPS
        """
        parsed = urlparse(self.args.url if "://" in self.args.url else f"https://{self.args.url}")
        host = parsed.netloc or parsed.path

        http_r = self._probe(f"http://{host}")
        https_r = self._probe(f"https://{host}")
        https_no_verify = self._probe(f"https://{host}", verify_ssl=False) if https_r["ssl_error"] else None

        if https_no_verify:
            ptprint("HTTPS cert verification disabled", "INFO", not self.args.json, indent=4)

        hsts, hsts_value = self._check_hsts(host)

        if hsts:
            ptprint(f"The host has the HSTS header set to {hsts_value}", "INFO", not self.args.json, indent=4)
        else:
            ptprint(f"The HSTS header is not present", "INFO", not self.args.json, indent=4)

        http_ok = http_r["reachable"]
        https_ok = https_r["reachable"]

        http_to_https = (
                http_ok
                and https_ok
                and http_r["final_url"]
                and http_r["final_url"].startswith("https://")
        )

        if not http_ok and not https_ok:
            ptprint(f"Neither HTTP nor HTTPS is reachable", "ERROR", not self.args.json, indent=4)

        elif not http_ok and https_ok:
            ptprint(f"HTTPS is accessible, HTTP is blocked", "OK", not self.args.json, indent=4)

        elif http_ok and not https_ok:
            ptprint(f"HTTP is accessible but HTTPS is not", "VULN", not self.args.json, indent=4)

        elif http_to_https:
            ptprint(f"HTTP redirects to HTTPS", "OK", not self.args.json, indent=4)

            if hsts:
                ptprint(f"HSTS header present. The browser will enforce HTTPS", "OK", not self.args.json,
                        indent=4)

        else:
            ptprint(f"Both HTTP and HTTPS are accessible with no redirect", "ERROR", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, base_indent):
    """Entry point for running the HTTPS test"""
    Https(args, ptjsonlib, helpers, http_client, base_indent).run()
