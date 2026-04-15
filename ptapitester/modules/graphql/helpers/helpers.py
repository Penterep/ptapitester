"""
Helpers module for shared functionality used across test modules.
"""
import os, ipaddress, socket, argparse
from dataclasses import dataclass
from http.client import HTTPResponse

from ptlibs import ptprint
from urllib.parse import urlencode
import json


class Helpers:
    def __init__(self, args: object, ptjsonlib: object, http_client: object):
        """Helpers provides utility methods"""
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = http_client
        self.cycle_detector = self.CycleDetector(self.args)

    def print_header(self, test_label):
        ptprint(f"Testing: {test_label}", "TITLE", not self.args.json, colortext=True)

    def send_request(self, supported_methods: set, payload: object, headers=None) -> HTTPResponse:
        response = None

        if not headers:
            headers = self.args.headers

        if "POST" in supported_methods:
            response = self.http_client.send_request(url=self.args.url, method="POST", data=json.dumps(payload), allow_redirects=True,
                                                     headers=headers, merge_headers=False)
            return response
        elif "GET" in supported_methods:
            headers = headers.copy()
            if "content-type" in headers.keys():
                headers.pop("content-type")
            elif "Content-Type" in headers.keys():
                headers.pop("Content-Type")

            url = self.args.url + '?' + urlencode(payload)
            response = self.http_client.send_request(url=url, method="GET", allow_redirects=True, headers=headers, merge_headers=False)

        return response

    def get_base_kind(self, field) -> str:
        """
        This method finds the base kind of a GraphQL field

        Parameters
        ----------
        field: dict
            Field to get base kind of

        Returns
        -------
        str
            Base kind of a GraphQL field
        """
        if not field:
            return ""
        if field.get('kind') and not field.get('ofType'):
            return field.get("kind")
        return self.get_base_kind(field.get('ofType'))

    def get_base_type(self, field):
        """
        This method finds the base type of a GraphQL field

        Parameters
        ----------
        field: dict
            Field to get base type of

        Returns
        -------
        str
            Base type of a GraphQL field
        """
        if not field:
            return None
        if field.get('name') and field.get('kind') not in ['NON_NULL', 'LIST']:
            return field.get("name")
        return self.get_base_type(field.get('ofType'))

    def get_arg_string(self, arguments: list) -> str:
        """
        This method returns the arguments for a query in a formatted manner '(arg1: type, arg2: type, ...)'.

        Parameters
        ----------
        arguments: list
            List of arguments

        Returns
        -------
        str
            Arguments string. Empty string if arguments list is empty
        """
        if not arguments:
            return ""
        return f'({", ".join(arguments)})'

    def get_field_type_string(self, t: dict) -> str:
        """
        This method gets the type of a field in a GraphQL schema recursively. It also checks for the 'NON_NULL' and
        'LIST' modifiers.

        Parameters
        ----------
        type: dict
            GraphQL 'type' field

        Returns
        -------
        str
            Name of the found field and any modifiers.
        """
        if not t:
            return ""

        field_type = t.get("name")

        kind = t.get("kind")

        if field_type is None:
            if kind == "NON_NULL":
                field_type = self.get_field_type_string(t.get("ofType")) + "!"
            elif kind == "LIST":
                field_type = "[" + self.get_field_type_string(t.get("ofType")) + "]"
            else:
                field_type = self.get_field_type_string(t.get("ofType"))

        if kind == "NON_NULL":
            field_type = self.get_field_type_string(t.get("ofType")) + "!"
        elif kind == "LIST":
            field_type = "[" + self.get_field_type_string(t.get("ofType")) + "]"

        return field_type

    class CycleDetector:
        def __init__(self, args: object):
            self.args = args

        def _build_dependency_graph(self, schema_data):
            """
            Parses introspection data to build a directed graph (adjacency list).
            Returns: dict { 'TypeName': set(['Dependency1', 'Dependency2']) }
            """
            types = schema_data['__schema']['types']
            graph = {}

            ignored_types = {'String', 'Int', 'Float', 'Boolean', 'ID'}

            for t in types:
                name = t['name']

                if name.startswith('__') or name in ignored_types:
                    continue

                if t['kind'] not in ['OBJECT', 'INTERFACE', 'INPUT_OBJECT']:
                    continue

                if name not in graph:
                    graph[name] = set()

                if t.get('fields'):
                    for field in t['fields']:
                        target_type = Helpers(None, None, None).get_base_type(field.get("type", {}))

                        if target_type and target_type not in ignored_types:
                            graph[name].add(target_type)

                if t.get('inputFields'):
                    for field in t['inputFields']:
                        target_type = Helpers(None, None, None).get_base_type(field.get("type", {}))
                        if target_type and target_type not in ignored_types:
                            graph[name].add(target_type)

            return graph

        def _find_cycles(self, graph):
            """
            Uses DFS to detect cycles in the graph.
            Returns a list of cycles, where each cycle is a list of type names.
            """
            visited = set()
            cycles = []

            def dfs(node, path):
                visited.add(node)
                path.append(node)

                if node in graph:
                    for neighbor in graph[node]:
                        if neighbor not in visited:
                            dfs(neighbor, path)
                        elif neighbor in path:
                            cycle_start_index = path.index(neighbor)
                            cycle_path = path[cycle_start_index:] + [neighbor]
                            cycles.append(cycle_path)

                path.pop()

            for node in graph:
                if node not in visited:
                    dfs(node, [])

            return cycles

        def run_detection(self) -> bool:
            introspection_data = self.args.schema

            if not introspection_data:
                ptprint("No schema available to detect cyclic relationships", "OK", not self.args.json, indent=4)
                return False

            dependency_graph = self._build_dependency_graph(introspection_data)
            found_cycles = self._find_cycles(dependency_graph)

            if found_cycles:
                ptprint(f"Found {len(found_cycles)} circular relationships", "VULN", not self.args.json, indent=4)
                for i, cycle in enumerate(found_cycles, 1):
                    ptprint(f"{i}. {' -> '.join(cycle)}", "VULN", not self.args.json, indent=8)
                return True
            else:
                ptprint("No circular relationships found.", "OK", not self.args.json, indent=4)
                return False


@dataclass
class Target:
    ip: str
    port: int


def valid_target(target: str, port_required: bool = False, domain_allowed: bool = False) -> Target:
    """
    Decides whether the target argument is a valid IP address or hostname
    with optional valid port definition. Designed for automatic usage by argparse.

    Args:
        target (str): target argument
        port_required (bool, optional): whether to require port definition. Defaults to False.
        domain_allowed (bool, optional): whether to allow hostnames. Defaults to False.

    Raises:
        argparse.ArgumentError: invalid format
        argparse.ArgumentError: missing port number
        argparse.ArgumentError: invalid ip address
        argparse.ArgumentError: unresolvable hostname
        argparse.ArgumentError: invalid port number

    Returns:
        Target: parsed Target
    """
    split = target.split(":")
    if not port_required and len(split) > 2:
        raise argparse.ArgumentError(None, "The target has to be IP[:PORT]")

    if port_required and len(split) != 2:
        raise argparse.ArgumentError(None, "The target has to be IP:PORT")

    try:
        ipaddress.ip_address(split[0])
    except:
        if domain_allowed:
            try:
                socket.gethostbyname(split[0])
            except Exception:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve target name '{split[0]}' into IP address"
                )
        else:
            raise argparse.ArgumentError(None, "Invalid target IP address")

    if len(split) > 1:
        try:
            port = int(split[1])
            if port <= 0 or port >= 65536:
                raise ValueError
        except:
            raise argparse.ArgumentError(None, "Invalid PORT number")
    else:
        port = 0

    return Target(split[0], port)