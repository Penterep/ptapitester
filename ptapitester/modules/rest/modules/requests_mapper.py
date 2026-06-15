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
from urllib.parse import parse_qs, urlparse

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

OPERATION_RE = re.compile(
    r'(?:^\s*|\b)(query|mutation|subscription)\s*([A-Za-z_][A-Za-z0-9_]*)?'
    r'\s*(\(([^)]*)\))?\s*\{',
    re.I,
)
FRAGMENT_RE = re.compile(
    r'\bfragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+[A-Za-z_][A-Za-z0-9_]*\s*\{',
    re.I,
)
VAR_DECL_RE = re.compile(r'\$([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([\[\]A-Za-z0-9_!]+)')
FIELD_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)'
)


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
        url: str
        method: str
        endpoint: str
        headers: dict
        body: str

    @staticmethod
    def _check_b64(attrib, text) -> str:
        """Checks if a request/response is in Base64 or plaintext."""
        if attrib.get("base64", "") == "true":
            return base64.b64decode(text).decode("ascii")

        return text


    def _is_graphql(self, request: ParsedRequest, response: ParsedResponse) -> dict | None:
        content_type = response.headers.get("Content-Type", "").lower()

        if not content_type:
            return None

        if content_type not in ["application/graphql-response+json", "application/json"]:
            return None

        try:
            response_json = json.loads(response.body)
        except JSONDecodeError as e:
            ptprint(f"Failed loading JSON from response. The API is not GraphQL", "ADDITIONS", self.args.verbose,
                    indent=4, colortext=True)
            return None

        if "data" not in response_json:
            return None

        if request.method == "POST":
            try:
                query = json.loads(request.body)
            except JSONDecodeError as e:
                ptprint(f"Could not load GraphQL query from request: {e}", "ERROR", self.args.verbose, indent=4)

        elif request.method == "GET":
            query = parse_qs(urlparse(request.url).query)
            if "query" not in query:
                return None

            query["query"] = query.get("query", [])[0]

        parsed = self.parse_graphql_document(query["query"])

        op_name = parsed["operation_name"] or "<anonymous>"

        return {
            'operation_type': parsed['operation_type'],
            'operation_name': op_name,
            'variables_declared': parsed['variables'],
            'variables_provided': {},
            'fields': parsed['fields'],
            'query': query["query"].strip(),
        }


    def find_matching_brace(self, text: str, open_idx: int) -> int:
        """Given the index of a '{', return the index of its matching '}', or -1."""
        depth = 0
        for i in range(open_idx, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    return i
        return -1

    def extract_fragments(self, text: str) -> dict[str, str]:
        """Find all `fragment Name on Type { ... }` definitions and return name -> body."""
        fragments = {}
        for m in FRAGMENT_RE.finditer(text):
            name = m.group(1)
            brace_start = m.end() - 1
            brace_end = self.find_matching_brace(text, brace_start)
            if brace_end != -1:
                fragments[name] = text[brace_start + 1:brace_end]
        return fragments

    def _skip_directives(self, body: str, i: int, n: int) -> int:
        """Skip whitespace and any GraphQL directives (e.g. @include(if: $x), @skip, @deprecated)."""
        while True:
            while i < n and body[i] in ' \t\r\n':
                i += 1
            if i < n and body[i] == '@':
                i += 1
                m_dir = re.match(r'[A-Za-z_][A-Za-z0-9_]*', body[i:])
                if m_dir:
                    i += m_dir.end()
                while i < n and body[i] in ' \t\r\n':
                    i += 1
                if i < n and body[i] == '(':
                    depth = 0
                    while i < n:
                        if body[i] == '(':
                            depth += 1
                        elif body[i] == ')':
                            depth -= 1
                            if depth == 0:
                                i += 1
                                break
                        i += 1
                continue
            break
        return i

    def extract_selection_fields(self, body: str, fragments: dict[str, str],
                                 prefix: str = '', visited: set | None = None) -> list[str]:
        """Recursively walk a GraphQL selection set, returning dotted field paths.

        Fragment spreads (`...FragmentName`) are expanded inline if their
        definition was found in the same document. Inline fragments
        (`... on Type { ... }`) are flattened into the parent selection.
        """
        if visited is None:
            visited = set()

        fields: list[str] = []
        i = 0
        n = len(body)

        while i < n:
            c = body[i]

            if c in ' \t\r\n,':
                i += 1
                continue

            if body[i:i + 3] == '...':
                i += 3
                while i < n and body[i] in ' \t\r\n':
                    i += 1

                m_on = re.match(r'on\s+[A-Za-z_][A-Za-z0-9_]*', body[i:])
                if m_on:
                    i += m_on.end()
                    i = self._skip_directives(body, i, n)
                    if i < n and body[i] == '{':
                        close = self.find_matching_brace(body, i)
                        if close != -1:
                            fields.extend(self.extract_selection_fields(body[i + 1:close], fragments, prefix, visited))
                            i = close + 1
                        else:
                            i = n
                    continue

                m_name = re.match(r'[A-Za-z_][A-Za-z0-9_]*', body[i:])
                if m_name:
                    frag_name = m_name.group(0)
                    i += m_name.end()
                    if frag_name in fragments and frag_name not in visited:
                        visited.add(frag_name)
                        fields.extend(self.extract_selection_fields(fragments[frag_name], fragments, prefix, visited))
                        visited.discard(frag_name)
                    else:
                        fields.append(f"{prefix}...{frag_name}" if prefix else f"...{frag_name}")
                    i = self._skip_directives(body, i, n)
                continue

            if c == '}':
                i += 1
                continue

            m = FIELD_RE.match(body[i:])
            if not m:
                i += 1
                continue

            field_name = m.group(2) or m.group(3)
            i += m.end()
            full_name = f"{prefix}.{field_name}" if prefix else field_name
            fields.append(full_name)

            while i < n and body[i] in ' \t\r\n':
                i += 1

            if i < n and body[i] == '(':
                depth = 0
                while i < n:
                    if body[i] == '(':
                        depth += 1
                    elif body[i] == ')':
                        depth -= 1
                        if depth == 0:
                            i += 1
                            break
                    i += 1

            i = self._skip_directives(body, i, n)

            if i < n and body[i] == '{':
                close = self.find_matching_brace(body, i)
                if close != -1:
                    fields.extend(self.extract_selection_fields(body[i + 1:close], fragments, full_name, visited))
                    i = close + 1
                else:
                    i = n

        return fields
    
    def parse_graphql_document(self, query_text: str) -> dict | None:
        """Parse a GraphQL document string into operation type/name, variables, and fields."""
        text = re.sub(r'#[^\n]*', '', query_text)

        fragments = self.extract_fragments(text)

        op_match = OPERATION_RE.search(text)
        if op_match:
            op_type = op_match.group(1).lower()
            op_name = op_match.group(2)
            variables_decl = op_match.group(4) or ''
            body_start = op_match.end() - 1
        else:
            brace_idx = text.find('{')
            if brace_idx == -1:
                return None
            op_type = 'query'
            op_name = None
            variables_decl = ''
            body_start = brace_idx

        body_end = self.find_matching_brace(text, body_start)
        if body_end == -1:
            return None
        body = text[body_start + 1:body_end]

        variables = {m.group(1): m.group(2) for m in VAR_DECL_RE.finditer(variables_decl)}
        fields = self.extract_selection_fields(body, fragments)

        return {
            'operation_type': op_type,
            'operation_name': op_name,
            'variables': variables,
            'fields': fields,
        }

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

        return self.ParsedRequest(method=method, endpoint=endpoint, headers=headers, body=body or None, url="")


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
        template_map = _cluster_paths(list(raw_endpoints))

        aggregated: dict = {}
        for template, originals in template_map.items():
            merged_methods: dict = {}
            for orig_path in originals:
                for method, params in raw_endpoints.get(orig_path, {}).items():
                    merged_methods.setdefault(method, {}).update(params)
            aggregated[template] = merged_methods

        return aggregated

    def _gather_endpoints(self, xml_file_path: LiteralString | str | bytes) -> tuple[dict, list]:
        """Gathers endpoints and the request/response data from the XML requests file."""
        endpoints = {}

        tree = ET.parse(xml_file_path)

        graphql_ops = []

        for item in tree.getroot().findall("item"):
            for request in item.findall("request"):
                if request.text is None:
                    continue

                parsed_request = self._parse_request(request)
                parsed_request.url = item.find("url").text

            for response in item.findall("response"):
                if response.text is None:
                    continue

                parsed_response = self._parse_response(response)

            if parsed_response.status_code == HTTPStatus.NOT_FOUND:
                continue

            gql = self._is_graphql(parsed_request, parsed_response)

            if gql:
                graphql_ops.append(gql)

            endpoints.update(self._map_endpoint(parsed_request, parsed_response))

        aggregated = self._aggregate_endpoints(endpoints)

        return aggregated, graphql_ops

    def build_tree(self, paths):
        tree = {}
        for path in paths:
            node = tree
            for part in path.split("."):
                node = node.setdefault(part, {})



        return tree

    def create_nodes_from_tree(self, tree: dict, node_type: str = "graphQLField", parent: str = None,
                               parent_type: str = None, path: str = "") -> list[dict]:

        new_nodes = []
        known_nodes = self.ptjsonlib.json_object["results"]["nodes"]

        for name, children in tree.items():
            full_path = f"{path}.{name}" if path else name
            properties = {"name": name, "path": full_path, "isLeaf": not bool(children)}

            node_object = self.ptjsonlib.create_node_object(node_type, parent_type, parent, properties, new_nodes, known_nodes)
            if type(node_object) is not str:
                self.ptjsonlib.add_node(node_object)
                new_nodes.append(node_object)
                node_key = node_object["key"]
            else:
                node_key = node_object

            if children:
                new_nodes.extend(
                    self.create_nodes_from_tree(children, node_type, node_key, node_type, full_path)
                )

        return new_nodes

    def run(self) -> None:
        """
        Executes the API requests JSON parser.
        """

        if not self.args.requests_file:
            ptprint("No requests file provided", "ERROR", not self.args.json, indent=4)
            return

        current_dir = os.path.dirname(os.path.abspath(__file__))
        requests_file_path = os.path.join(current_dir, self.args.requests_file)

        found_endpoints, graphql_ops = self._gather_endpoints(requests_file_path)

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

        for operation in graphql_ops:
            tree = self.build_tree(operation["fields"])
            self.create_nodes_from_tree(tree, node_type="GraphQL")

        self.ptjsonlib.add_nodes(nodes)

def run(args, ptjsonlib, helpers, http_client, common_tests, endpoints):
    """Entry point for running the API requests JSON parser"""
    Parser(args, ptjsonlib, helpers, http_client, common_tests, endpoints).run()
