"""
API requests JSON parser

This module maps an API from a file of API requests/responses

Contains:
- Mapper class to run the test
- run() function as an entry point for running the test
"""
import base64
import json
import os
import re
from collections import defaultdict
from json import JSONDecodeError
from typing import LiteralString

from ptlibs import ptprint
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from http import HTTPStatus, HTTPMethod
import xml.etree.ElementTree as ET
import email
from dataclasses import dataclass

__TESTLABEL__ = "API request JSON parser"

_PARAM_RE = [
    re.compile(r"^\d+$"),  # pure integer: 42, 1001
    re.compile(r"^[a-zA-Z]\w*\d+$"),  # word+digits: user1, item42
    re.compile(  # UUID v4
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
        r"-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    re.compile(r"^[0-9a-f]{24}$", re.I),  # MongoDB ObjectId
    re.compile(r"^[0-9a-zA-Z_\-]{32,}$"),  # long token / hash
]


def _is_param(segment: str) -> bool:
    return any(p.match(segment) for p in _PARAM_RE)


def _to_segs(path: str) -> list[str]:
    return [s for s in path.strip("/").split("/") if s]


def _from_segs(segs: list[str]) -> str:
    return ("/" + "/".join(segs)) if segs else "/"


def _quick_normalise(path: str) -> str:
    """Per-segment heuristic: replace obvious param values with {param}."""
    return _from_segs(["{param}" if _is_param(s) else s for s in _to_segs(path)])


def _merge_segment(a: str, b: str) -> str | None:
    """Merge two segments. Returns None if they are incompatible fixed words."""
    if a == b:
        return a
    if a == "{param}" or b == "{param}":
        return "{param}"
    if _is_param(a) or _is_param(b):
        return "{param}"
    return None  # two different fixed words → cannot merge


def _compute_template(paths: list[str]) -> str | None:
    """Derive a single template from a list of same-depth paths, or None if incompatible."""
    if not paths:
        return None
    template = _to_segs(paths[0])
    for path in paths[1:]:
        segs = _to_segs(path)
        if len(segs) != len(template):
            return None
        merged = [_merge_segment(t, s) for t, s in zip(template, segs)]
        if None in merged:
            return None
        template = merged  # type: ignore[assignment]
    return _from_segs(template)


def _cross_path_cluster(paths: list[str], min_variants: int = 3) -> dict[str, list[str]]:
    """
    Catch non-obvious parameters (e.g. /org/alice, /org/bob, /org/carol).
    Uses a position-context approach: paths are considered the same endpoint
    with a varying parameter ONLY if they are identical at every position
    except one.  Requires at least min_variants paths to promote a position.
    """
    by_depth: dict[int, list[str]] = defaultdict(list)
    for p in paths:
        by_depth[len(_to_segs(p))].append(p)

    result: dict[str, list[str]] = {}

    for depth, group in by_depth.items():
        if len(group) < min_variants:
            for p in group:
                result.setdefault(p, []).append(p)
            continue

        param_groups: dict[tuple, list[str]] = defaultdict(list)
        for i in range(depth):
            for p in group:
                segs = _to_segs(p)
                context = (i,) + tuple(segs[j] for j in range(depth) if j != i)
                param_groups[context].append(p)

        covered: dict[str, tuple] = {}
        for ctx_key, pp in param_groups.items():
            if len(set(pp)) >= min_variants:
                pos = ctx_key[0]
                ctx = ctx_key[1:]
                for p in pp:
                    covered.setdefault(p, (pos, ctx))

        template_groups: dict[tuple, list[str]] = defaultdict(list)
        for p, key in covered.items():
            template_groups[key].append(p)

        for (pos, ctx), pp in template_groups.items():
            ctx_list = list(ctx)
            tpl_segs = ctx_list[:pos] + ["{param}"] + ctx_list[pos:]
            result.setdefault(_from_segs(tpl_segs), []).extend(pp)

        for p in group:
            if p not in covered:
                result.setdefault(p, []).append(p)

    return result


def _cluster_paths(paths: list[str], cross_path_threshold: int = 3) -> dict[str, list[str]]:
    """
    Two-pass clustering:
      Pass 1 – heuristic normalisation (integers, UUIDs, word+digit slugs).
      Pass 2 – cross-path clustering for non-obvious slugs (alice/bob/carol).
    Returns {template: [original_paths]}.
    """
    # Pass 1: heuristic grouping
    heuristic_groups: dict[str, list[str]] = defaultdict(list)
    for p in paths:
        heuristic_groups[_quick_normalise(p)].append(p)

    pass1: dict[str, list[str]] = {}
    for norm_key, group in heuristic_groups.items():
        tpl = _compute_template(group)
        if tpl is None:
            for p in group:
                pass1.setdefault(p, []).append(p)
        else:
            pass1.setdefault(tpl, []).extend(group)

    # Pass 2: cross-path clustering on remaining singletons
    singletons = [tpl for tpl, orig in pass1.items()
                  if "{param}" not in tpl and len(orig) == 1]

    if len(singletons) >= cross_path_threshold:
        singleton_paths = [pass1[t][0] for t in singletons]
        for t in singletons:
            del pass1[t]
        for tpl, orig in _cross_path_cluster(singleton_paths, cross_path_threshold).items():
            pass1.setdefault(tpl, []).extend(orig)

    return pass1


class Parser:
    """Class for executing the API request JSON parser"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, common_tests: object,
                 endpoints: set[str]) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.endpoints = endpoints

        self.helpers.print_header(__TESTLABEL__)

        self.TYPE_MAP = {
            "int": "Integer",
            "float": "Float",
            "str": "String",
            "bool": "Boolean",
            "list": "Array",
            "object": "Object",
            "file": "File",
        }

    @dataclass
    class ParsedResponse:
        status_code: HTTPStatus
        headers: dict
        body: str

    @dataclass
    class ParsedRequest:
        method: HTTPMethod
        endpoint: str
        headers: dict
        body: str

    @staticmethod
    def _check_b64(attrib, text) -> str:
        """Checks if a request/response is in Base64 or plaintext."""
        if attrib.get("base64", "") == "true":
            return base64.b64decode(text).decode("ascii")

        return text

    def _parse_response(self, item) -> ParsedResponse:
        """Parses the response from Base64 or plaintext to the ParsedRequest dataclass."""
        parsed = self._check_b64(item.attrib, item.text)
        split_char = "\r\n" if "\r\n" in parsed else "\n"

        status_code, msg = parsed.split(split_char, 1)
        status_code: HTTPStatus = status_code.split(" ")[1]
        headers = dict(email.message_from_string(msg).items())

        body = parsed.split(f"{split_char}{split_char}", 1)[1]

        return self.ParsedResponse(status_code, headers, body)


    def _parse_request(self, item) -> ParsedRequest:
        """Parses the request from Base64 or plaintext to the ParsedRequest dataclass."""
        parsed = self._check_b64(item.attrib, item.text)
        split_char = "\r\n" if "\r\n" in parsed else "\n"

        endpoint, msg = parsed.split(split_char, 1)
        method, endpoint, _ = endpoint.split(" ")
        headers = dict(email.message_from_string(msg).items())
        body = parsed.split(split_char*2, 1)[1]

        return self.ParsedRequest(method, endpoint, headers, body=body or None)


    def _map_endpoint(self, request: ParsedRequest, response: ParsedResponse) -> dict:
        try:
            response_json = json.loads(response.body)
        except JSONDecodeError as e:
            response_json = {}

        body = {}

        for field, value in response_json.items():
            mapped_type = self.TYPE_MAP.get(type(value).__name__)
            value_type = mapped_type or type(value).__name__.capitalize()
            body.update({field: f"webInputType{value_type}"})

        mapped = {request.method: body}

        return {request.endpoint: mapped}

    def _aggregate_endpoints(self, raw_endpoints: dict) -> dict:
        """
        Collapse parameterised paths into a single template endpoint.

        e.g. /user/user1, /user/user2, /user/user3  →  /user/{param}

        When multiple paths share a template their method→parameter dicts are
        merged (union), so no discovered fields are lost.
        """
        template_map = _cluster_paths(list(raw_endpoints))  # {template: [orig_paths]}

        aggregated: dict = {}
        for template, originals in template_map.items():
            merged_methods: dict = {}
            for orig_path in originals:
                for method, params in raw_endpoints.get(orig_path, {}).items():
                    merged_methods.setdefault(method, {}).update(params)
            aggregated[template] = merged_methods

        return aggregated

    def _gather_endpoints(self, xml_file_path: LiteralString | str | bytes) -> dict:
        """Gathers endpoints and the request/response data from the XML requests file."""
        endpoints = {}

        tree = ET.parse(xml_file_path)

        for item in tree.getroot().findall("item"):
            for request in item.findall("request"):
                if request.text is None:
                    continue

                parsed_request = self._parse_request(request)

            for response in item.findall("response"):
                if response.text is None:
                    continue

                parsed_response = self._parse_response(response)

            if parsed_response.status_code == HTTPStatus.NOT_FOUND:
                continue

            endpoints.update(self._map_endpoint(parsed_request, parsed_response))


        aggregated = self._aggregate_endpoints(endpoints)
        return aggregated


    def run(self) -> None:
        """
        Executes the API requests JSON parser.
        """

        if not self.args.requests_file:
            ptprint("No requests file provided", "ERROR", not self.args.json, indent=4)
            return

        current_dir = os.path.dirname(os.path.abspath(__file__))
        requests_file_path = os.path.join(current_dir, self.args.requests_file)

        found_endpoints = self._gather_endpoints(requests_file_path)

        root: dict = self.ptjsonlib.create_node_object(
            "webApi",
            properties={
                "name": "unknown",
                "webApiType": "webApiTypeRest",
                "description": "",
            }
        )

        nodes = [root]

        for endpoint, requests in found_endpoints.items():
            endpoint_node: dict = self.ptjsonlib.create_node_object(
                "webApiEndpoint",
                parent=root["key"],
                properties={"name": endpoint}
            )
            nodes.append(endpoint_node)

            for method, parameters in requests.items():
                method_node = self.ptjsonlib.create_node_object(
                    "webApiMethod",
                    parent=endpoint_node["key"],
                    properties={
                        "name": method.upper(),
                        "webHttpMethod": f"webHttpMethod{method.capitalize()}",
                    }
                )
                nodes.append(method_node)
                for parameter_name, parameter_type in parameters.items():
                    parameter_node = self.ptjsonlib.create_node_object(
                        "webInput",
                        parent=method_node["key"],
                        properties={
                            "name": parameter_name,
                            "webInputType": parameter_type,
                        }
                    )
                    nodes.append(parameter_node)

        self.ptjsonlib.add_nodes(nodes)

def run(args, ptjsonlib, helpers, http_client, common_tests, endpoints):
    """Entry point for running the API requests JSON parser"""
    Parser(args, ptjsonlib, helpers, http_client, common_tests, endpoints).run()
