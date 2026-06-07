"""
API identification test

This module implements a test that checks if the provided URL is hosting an API and what kind of API

Contains:
-
- run() function as an entry point for running the test
"""
import re
import selectors
import threading
from http import HTTPStatus

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from urllib.parse import urlparse
from requests.exceptions import JSONDecodeError
from requests import Response
import os, requests
import concurrent.futures
from ..helpers.helpers import BaseRequest
from ptthreads.ptthreads import ptthreads


__TESTLABEL__ = "API identification test"


class IsGraphQL:
    """Class for executing the GraphQL availability test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, printer: bool,
                 brute: bool) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.stop_event = threading.Event()
        self.found_url = ""
        self.base_request = None
        self.brute = brute

        if printer:
            self.helpers.print_header(__TESTLABEL__)

    def _check_JSON(self, response: Response) -> bool:
        """
        This method checks if the JSON response is equal to the expected response of a basic GraphQL query {"query": "query{__typename}"}.

        Parameters
        ----------
        response
            HTTP response of the host
        Returns
        -------
        bool
            True if the received response matches the expected. False otherwise
        """
        expected = [{"data": {"__typename": "Query"}}, {"data": {"__typename": "RootQueryType"}},
                    {"data": {"__typename": "RootQuery"}}, {"data": {"__typename": "query"}}]

        try:
            json_response = response.json()
        except JSONDecodeError as e:
            ptprint(f"Error decoding JSON from response: {e}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return False

        return json_response in expected

    def _check_response_GET(self, url: str) -> tuple[bool, BaseRequest]:
        """
        This method test the presence of GraphQL on a given endpoint with the HTTP method GET.

        Parameters
        ----------
        url: str
            URL of the host

        Returns
        -------
        bool
            True if the method detects GraphQL on the endpoint with the GET HTTP method. False otherwise
        """

        final_url = url + "?query=query%7B__typename%7D"

        base_request = BaseRequest("GET", {"query": "{__typename}"})

        headers = self.args.headers.copy()
        if "content-type" in headers.keys():
            headers.pop("content-type")
        elif "Content-Type" in headers.keys():
            headers.pop("Content-Type")

        ptprint(f"Trying endpoint {url} with method GET", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
        response = self.http_client.send_request(url=final_url, method="GET", allow_redirects=True, headers=headers,
                                                 merge_headers=False)

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            #ptprint(f"The host has authentication enabled for method GET at {url}", "OK", not self.args.json,
            #        indent=4)
            return False, base_request

        if response.status_code != HTTPStatus.OK:
            ptprint(f"Could not GET {final_url}. Received status code: {response.status_code}", "ADDITIONS",
                    self.args.verbose,
                    indent=4, colortext=True)
            return False, base_request

        return self._check_JSON(response), base_request

    def _check_response_POST(self, url: str) -> tuple[bool, BaseRequest]:
        """
        This method test the presence of GraphQL on a given endpoint with the HTTP method POST.

        Parameters
        ----------
        url: str
            URL of the host

        Returns
        -------
        bool
            True if the method detects GraphQL on the endpoint with the POST HTTP method. False otherwise
        """

        payload = '{"query": "query{__typename}"}'
        base_request = BaseRequest("POST", payload)

        ptprint(f"Trying {url} with method POST", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
        response = self.http_client.send_request(method="POST", url=url, data=payload, allow_redirects=True)

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            #ptprint(f"The host has authentication enabled for method POST at {url}", "OK", not self.args.json, indent=4)
            return False, base_request

        if response.status_code != HTTPStatus.OK:
            ptprint(f"Could not POST {url}. Received status code: {response.status_code}", "ADDITIONS",
                    self.args.verbose,
                    indent=4, colortext=True)
            return False, base_request

        return self._check_JSON(response), base_request

    def _worker(self, test_url: str):
        """
        Worker function for the thread pool.

        Parameters
        ----------
        test_url: str
            URL to probe for GraphQL
        """
        if self.stop_event.is_set():
            return None

        if self._check_response(test_url):
            self.found_url = test_url
            self.stop_event.set()
            return test_url

        return None

    def _brute_force(self, url: str) -> str:
        """
        This method probes suspected GraphQL endpoints from a wordlist specified with the -w/--wordlist argument (default data/wordlists/endpoints.txt).
        If the response is verified with the _check_response() method to be a GraphQL response. We return a URL of the host and verified endpoint.

        Returns
        -------
        str
            URL of the verified GraphQL endpoint. Empty string if none is found
        """

        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, f"../../../wordlists/graphql.txt")

        with open(wordlist_path, "r") as wordlist:
            endpoints = [url + new_url for new_url in wordlist.read().split('\n')]

        max_workers = 30

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(self._worker, url): url for url in endpoints}

            for future in concurrent.futures.as_completed(future_to_url):
                if self.stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

        return self.found_url

    def _check_response(self, url: str) -> str:
        """
        This method tests to see if the provided endpoint hosts GraphQL or not.
        It first tries to detect GraphQL with the HTTP GET method and then with the HTTP POST method.
        If any of the HTTP methods is successful, the HTTP method is added to a set of supported HTTP methods.


        Parameters
        ----------
        url: str
            URL to probe for the presence of GraphQL

        Returns
        -------
        str
            URL of GraphQL API endpoint
        """
        if self.stop_event.is_set():
            return ""

        found = ""

        try:
            detected, base_request = self._check_response_GET(url)
            if detected:
                found = url
                self.base_request = base_request

            detected, base_request = self._check_response_POST(url)
            if detected:
                found = url
                self.base_request = base_request
        except requests.exceptions.RequestException as error_msg:
            ptprint(f"Error trying to connect with HTTPS: {error_msg}.", "ADDITIONS",
                    self.args.verbose, indent=4, colortext=True)
            self.ptjsonlib.end_error(f"Error retrieving initial responses:", details=error_msg,
                                     condition=self.args.json)

        return found

    def run(self) -> tuple[bool, BaseRequest]:
        """
        Executes the GraphQL availability test

        Sends the following query to test if GraphQL is present on the provided URL: {'query': 'query{__typename}'}.
        If GraphQL is not detected on the provided URL, we try to bruteforce common GraphQL endpoints with a wordlist.
        Ends with an error if GraphQL is not detected.
        """
        if self._check_response(self.args.url):
            return True, self.base_request
        else:
            if new_url := self._brute_force(self.args.url):
                self.args.url = new_url
                return True, self.base_request
            else:
                if not self.brute:
                    return False, self.base_request

                parsed = urlparse(self.args.url)
                url = parsed.scheme + "://" + parsed.netloc

                if new_url := self._brute_force(url):
                    self.args.url = new_url
                    return True, self.base_request
                else:

                    return False, self.base_request
                
class IsSOAP:
    """Class for detecting SOAP API on a given URL"""
 
    SOAP_INDICATORS = [
        "wsdl:definitions", "definitions", "targetnamespace",
        "schemas.xmlsoap.org", "soap:body", "soap:envelope",
        "soap:binding", "wsdl:service", "wsdl:port",
    ]
 
    COMMON_SOAP_PATHS = [
        "/service", "/soap", "/ws", "/webservice", "/services",
        "/Service.asmx", "/Service.svc", "/service.asmx", "/service.svc",
        "/api/soap", "/v1/soap", "/v2/soap", "/wsdl", "/endpoint",
        "/api", "/rpc", "/server", "/gateway",
    ]
 
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, printer: bool,
                 brute: bool) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.stop_event = threading.Event()
        self.found_url = ""
        self.base_request = None
        self.brute = brute
 
        if printer:
            self.helpers.print_header(__TESTLABEL__)
 
    def _check_wsdl(self, url: str) -> bool:
        """Check if URL returns WSDL/SOAP XML content via GET."""
        wsdl_urls = [url, url.rstrip('/') + "?wsdl", url.rstrip('/') + "?WSDL"]
 
        for wsdl_url in wsdl_urls:
            try:
                response = self.http_client.send_request(
                    url=wsdl_url, method="GET", allow_redirects=True)
 
                if response.status_code != 200:
                    continue
 
                body_lower = response.text.lower()
                ct = response.headers.get("Content-Type", "").lower()
                is_xml = "xml" in ct or body_lower.lstrip().startswith("<?xml")
 
                if is_xml and any(ind in body_lower for ind in self.SOAP_INDICATORS):
                    self.base_request = BaseRequest(
                        "POST",
                        '<?xml version="1.0"?>'
                        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                        '<soapenv:Body><message>test</message></soapenv:Body>'
                        '</soapenv:Envelope>'
                    )
                    return True
            except Exception:
                continue
 
        return False
 
    def _check_soap_post(self, url: str) -> bool:
        """Check if URL accepts SOAP POST requests."""
        soap_probe = (
            '<?xml version="1.0"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soapenv:Body><message>probe</message></soapenv:Body>'
            '</soapenv:Envelope>'
        )
 
        try:
            response = self.http_client.send_request(
                url=url, method="POST", data=soap_probe,
                headers={"Content-Type": "text/xml; charset=utf-8"},
                merge_headers=False, allow_redirects=True)
 
            if response.status_code in (404, 405):
                return False
 
            body_lower = response.text.lower()
            ct = response.headers.get("Content-Type", "").lower()
 
            # HTML response = not SOAP
            if "html" in ct and "xml" not in ct:
                return False
 
            # Reject XML-RPC responses — they have <methodResponse> or
            # <fault> without SOAP namespace
            xmlrpc_indicators = ["<methodresponse", "<methodcall", "faultcode</name>"]
            if any(ind in body_lower for ind in xmlrpc_indicators):
                return False
 
            # SOAP-specific indicators — must contain SOAP namespace or envelope
            soap_specific = [
                "schemas.xmlsoap.org", "soap:envelope", "soapenv:envelope",
                "soap:fault", "soapenv:fault", "soap:body", "soapenv:body",
                "wsdl:definitions", "targetnamespace",
            ]
 
            if any(ind in body_lower for ind in soap_specific):
                self.base_request = BaseRequest("POST", soap_probe)
                return True
 
        except Exception:
            pass
 
        return False
 
    def _check_response(self, url: str) -> bool:
        """Check if URL hosts SOAP API (via GET WSDL or POST probe)."""
        if self.stop_event.is_set():
            return False
 
        if self._check_wsdl(url):
            return True
 
        if self._check_soap_post(url):
            return True
 
        return False
 
    def _brute_force(self, url: str) -> str:
        """Try common SOAP paths to find the endpoint."""
        base_url = url.rstrip('/')
 
        for path in self.COMMON_SOAP_PATHS:
            if self.stop_event.is_set():
                break
 
            test_url = base_url + path
            if self._check_response(test_url):
                self.found_url = test_url
                self.stop_event.set()
                return test_url
 
        return ""
 
    def run(self) -> tuple[bool, BaseRequest]:
        """
        Executes SOAP API detection.
 
        First checks the provided URL directly for WSDL or SOAP response.
        If not found, brute-forces common SOAP endpoint paths.
        """
        if self._check_response(self.args.url):
            ptprint(f"Found API: SOAP at {self.args.url}", "INFO",
                    not self.args.json, indent=4)
            return True, self.base_request
        else:
            if not self.brute:
                return False, self.base_request

            if new_url := self._brute_force(self.args.url):
                self.args.url = new_url
                ptprint(f"Found API: SOAP at {new_url}", "INFO",
                        not self.args.json, indent=4)
                return True, self.base_request
            else:
                # Try from base URL (without path)
                parsed = urlparse(self.args.url)
                base_url = parsed.scheme + "://" + parsed.netloc
 
                if new_url := self._brute_force(base_url):
                    self.args.url = new_url
                    ptprint(f"Found API: SOAP at {new_url}", "INFO",
                            not self.args.json, indent=4)
                    return True, self.base_request
 
                return False, self.base_request
            
class IsXMLRPC:
    """Class for detecting XML-RPC API on a given URL"""
 
    COMMON_XMLRPC_PATHS = [
        "/xmlrpc.php", "/xmlrpc", "/RPC2", "/rpc",
        "/api/xmlrpc", "/server.php", "/xmlrpc/api",
    ]
 
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, printer: bool,
                 brute: bool) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.stop_event = threading.Event()
        self.base_request = None
        self.brute = brute
 
        if printer:
            self.helpers.print_header(__TESTLABEL__)
 
    def _check_xmlrpc(self, url: str) -> bool:
        """Check if URL responds to XML-RPC methodCall."""
        probe = ('<?xml version="1.0"?>'
                 '<methodCall><methodName>system.listMethods</methodName></methodCall>')
 
        try:
            response = self.http_client.send_request(
                url=url, method="POST", data=probe,
                headers={"Content-Type": "text/xml"},
                merge_headers=False, allow_redirects=True)
 
            if response.status_code in (404, 405):
                return False
 
            body_lower = response.text.lower()
 
            xmlrpc_indicators = ["<methodresponse", "<params>", "<value>",
                                  "faultcode", "faultstring", "<array>"]
 
            if "soap:envelope" in body_lower or "soapenv:envelope" in body_lower:
                return False
 
            if any(ind in body_lower for ind in xmlrpc_indicators):
                self.base_request = BaseRequest("POST", probe)
                return True
        except Exception:
            pass
 
        try:
            response = self.http_client.send_request(
                url=url, method="GET", allow_redirects=True)
            if response and "xml-rpc server accepts post requests only" in response.text.lower():
                self.base_request = BaseRequest("POST", probe)
                return True
        except Exception:
            pass
 
        return False
 
    def _brute_force(self, url: str) -> str:
        """Try common XML-RPC paths."""
        base_url = url.rstrip('/')
        for path in self.COMMON_XMLRPC_PATHS:
            if self.stop_event.is_set():
                break
            test_url = base_url + path
            if self._check_xmlrpc(test_url):
                self.stop_event.set()
                return test_url
        return ""
 
    def run(self) -> tuple[bool, BaseRequest]:
        """Detect XML-RPC API."""
        if self._check_xmlrpc(self.args.url):
            ptprint(f"Found API: XMLRPC at {self.args.url}", "INFO",
                    not self.args.json, indent=4)
            return True, self.base_request

        if not self.brute:
            return False, self.base_request

        if new_url := self._brute_force(self.args.url):
            self.args.url = new_url
            ptprint(f"Found API: XMLRPC at {new_url}", "INFO",
                    not self.args.json, indent=4)
            return True, self.base_request
 
        parsed = urlparse(self.args.url)
        base_url = parsed.scheme + "://" + parsed.netloc
        if new_url := self._brute_force(base_url):
            self.args.url = new_url
            ptprint(f"Found API: XMLRPC at {new_url}", "INFO",
                    not self.args.json, indent=4)
            return True, self.base_request
 
        return False, self.base_request


class IsRest:
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient,
                 printer: bool, brute: bool) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.stop_event = threading.Event()
        self.base_request = BaseRequest(method="GET", data=None)
        self.brute = brute


    def _check_content_type(self, response: Response) -> bool:
        json_pattern = re.compile(r"^\s*application/json\s*(?:;|$)", re.IGNORECASE)
        xml_pattern = re.compile(r"^\s*(?:application|text)/xml\s*(?:;|$)", re.IGNORECASE)

        if (not json_pattern.search(response.headers.get("content-type", "")) and
                not xml_pattern.search(response.headers.get("content-type", ""))):
            return False

        return True

    def _check_nonexistent_endpoint(self, path: str) -> bool:
        path = path[:path.rfind("/")]
        new_path = path + "/id0n0tex1st_yaho000o"

        response: Response = self.http_client.send_request(url=self.args.url+new_path, method="GET", headers=self.args.headers,
                                                           allow_redirects=self.args.redirects)

        if response == HTTPStatus.NOT_FOUND:
            return False

        return True

    def run(self) -> tuple[bool, BaseRequest]:
        response: Response = self.http_client.send_request(url=self.args.url, method="GET", allow_redirects=self.args.redirects,
                                                           headers=self.args.headers)

        self.base_request = BaseRequest(method="GET", data=None)

        if not 500 <= response.status_code < 599:

            if response.status_code == HTTPStatus.UNAUTHORIZED and self._check_nonexistent_endpoint(self.args.url):
                return False, self.base_request


            if self._check_content_type(response):
                return True, self.base_request

        return False, self.base_request


def _identify_all(args, ptjsonlib, helpers, http_client, brute=True, printer=False) -> tuple[str, BaseRequest] | tuple[None, BaseRequest]:
    detected, base_request = IsGraphQL(args, ptjsonlib, helpers, http_client, printer, brute).run()

    if detected:
        return "graphql", base_request

    detected, base_request = IsSOAP(args, ptjsonlib, helpers, http_client, printer, brute).run()

    if detected:
        return "soap", base_request
    
    detected, base_request = IsXMLRPC(args, ptjsonlib, helpers, http_client, printer, brute).run()
 
    if detected:
        return "xmlrpc", base_request

    detected, base_request = IsRest(args, ptjsonlib, helpers, http_client, printer, brute).run()

    if detected:
        return "rest", base_request

    return None, base_request

class ApiEndpointIdentifier:
    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, printer: bool) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.stop_event = threading.Event()
        self.found_url = ""
        self.base_request = None
        self.printer = printer

    def locate_endpoints(self, wordlist: list[str]) -> set[str]|None:
        def _probe_endpoint(url) -> str|None:
            response: Response = self.http_client.send_request(url, method="GET", headers=self.args.headers,
                                                               allow_redirects=self.args.redirects)

            if response.status_code == HTTPStatus.NOT_FOUND:
                return None

            if 500 <= response.status_code < 599:
                return None

            return url

        threads: ptthreads = ptthreads()
        found_endpoints = set(threads.threads(wordlist, _probe_endpoint, self.args.threads))

        if not found_endpoints:
            return None

        return found_endpoints


    def run(self) -> None:
        ptprint("API discovery", "TITLE", not self.args.json, colortext=True)

        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, f"../data/wordlists/api_paths.txt")

        with open(wordlist_path, "r") as file:
            wordlist = [self.args.url + new_url for new_url in file.read().split('\n')]

        found_endpoints = self.locate_endpoints(wordlist)

        if found_endpoints is None:
            ptprint("No API found", "INFO", not self.args.json, indent=4)
            return

        original_url = self.args.url

        for endpoint in found_endpoints:
            if endpoint is None:
                continue

            self.args.url = endpoint

            api_type, base_request = identify_api(self.args, self.ptjsonlib, self.helpers, self.http_client, None,
                                                  printer=self.printer, brute=False)

            if api_type is not None:
                ptprint(f"API found on {endpoint}", "INFO", not self.args.json, indent=4)
                ptprint(f"Detected API type: {api_type.upper()}", "INFO", not self.args.json, indent=8)

        self.args.url = original_url


def identify_api(args, ptjsonlib, helpers, http_client, module_name: str|None, printer=False, brute=True) -> tuple[str, BaseRequest] | tuple[None, None]:
    """Entry point for API identification"""
    detected = False
    base_request = None
    #ptprint(f"Module: {module_name}", "INFO")
    match module_name:
        case "graphql":
            detected, base_request = IsGraphQL(args, ptjsonlib, helpers, http_client, printer, brute).run()
        case "soap":
            detected, base_request = IsSOAP(args, ptjsonlib, helpers, http_client, printer, brute).run()
        case "rest":
            detected, base_request = IsRest(args, ptjsonlib, helpers, http_client, printer, brute).run()
        case "xmlrpc":
            detected, base_request = IsXMLRPC(args, ptjsonlib, helpers, http_client, printer, brute).run()
        case "grpc":
            pass
        case "json-rpc":
            pass
        case "thrift":
            pass
        case _:
            detected, base_request = _identify_all(args, ptjsonlib, helpers, http_client, printer)

    if detected:
        ptprint(f"Found API: {detected.upper() if isinstance(detected, str) else module_name.upper()} at {args.url}", "INFO", not args.json and printer, indent=4)
        return detected if isinstance(detected, str) else module_name, base_request

    return None, None
