from argparse import Namespace
from ptlibs import ptprint
from dataclasses import dataclass
from requests.models import Response
from urllib.parse import urlencode

@dataclass
class BaseRequest:
    method: str
    data: object


class Helpers:
    def __init__(self, args: Namespace, ptjsonlib: object, http_client: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = http_client

    def print_header(self, test_label, indent=0):
        ptprint(f"Testing: {test_label}", "TITLE", not self.args.json, colortext=True, indent=indent)

    def send_request(self, base_request: BaseRequest, headers) -> Response:
        response = None

        if not headers:
            headers = self.args.headers

        if base_request.method == "POST":
            response = self.http_client.send_request(url=self.args.url, method=base_request.method, data=base_request.data,
                                                     headers=headers, merge_headers=False, allow_redirects=False)
        if base_request.method == "GET":
            url = self.args.url + '?' + urlencode(base_request.data)
            response = self.http_client.send_request(url=url, method=base_request.method, headers=headers, merge_headers=False,
                                                     allow_redirects=False)

        return response