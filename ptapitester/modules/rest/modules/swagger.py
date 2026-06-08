"""
OpenAPI definition file parser

This module parses an OpenAPI definitions file

Contains:
- Swagger class to parse OpenAPI definition files
- run() function as an entry point for running the test
"""
import os
import urllib

from ptlibs import ptprint
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from requests import Response
from http import HTTPStatus
import yaml
import json
from json import JSONDecodeError

__TESTLABEL__ = "OpenAPI definition file parser"


class Swagger:
    """Class for parsing the OpenAPI definition file"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient, common_tests: object,
                 endpoints: set[str]) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.endpoints = endpoints
        self._resolved_refs: set = set()

        self.helpers.print_header(__TESTLABEL__)

    def _load_yaml_or_json(self, source: str) -> dict:
        """
        This method loads the content of a YAML/JSON OpenAPI definition file
        
        Parameters
        ----------
        source: str
            URL or path to the OpenAPI definition file
            
        Returns
        -------
        dict
            Loaded content 
        """
        try:
            content = self._read_source(source)
        except Exception as e:
            ptprint(f"Cannot load {source}: {e}", "ERROR", not self.args.json, indent=4)
            return {}

        try:
            return yaml.safe_load(content)
        except yaml.YAMLError:
            try:
                return json.loads(content)
            except JSONDecodeError:
                ptprint(f"'{source}' is not valid YAML or JSON", "ERROR", not self.args.json, indent=4)
                return {}


    def _read_source(self, source: str) -> str:
        """
        This method retrieves the OpenAPI definition file from a URL or reads the file locally.

        Parameters
        ----------
        source : str
            Source of the OpenAPI definition file (URL or path)

        Returns
        -------
        str
            Read content
        """
        if "http://" in source or "https://" in source:
            response: Response = self.http_client.send_request(url=source, method="GET", allow_redirects=self.args.redirects,
                                                              headers=self.args.headers)

            if response.status_code != HTTPStatus.OK:
                ptprint(f"Could not retrieve OpenAPI definition from {source}. Received status code: {response.status_code}", "ERROR",
                        not self.args.json, indent=4)
                ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)

                return ""

            return response.text
        else:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            openapi_path = os.path.join(current_dir, source)

            with open(openapi_path, "r") as file:
                return file.read()


    def resolve_refs(self, data: dict | list, root: dict, source: str) -> dict | list:
        """
        Goes through the OpenAPI definition file recursively and replaces any $ref references with the object that they point to.

        Supports:
          - internal references:  "#/components/parameters/petId"
          - external files:    "./common/params.yaml"
          - external + fragment: "./common/params.yaml#/Pet"
          - URL references:      "https://example.com/api.yaml#/Pet"

        Parameters
        ----------
        data : dict | list
            Current object being resolved.

        root : dict
            The whole document.

        source : str
            Path or URL of the current document.

        Returns
        -------
        dict | list
            Document without references
        """
        if isinstance(data, dict):
            if "$ref" in data:
                return self._resolve_single_ref(data["$ref"], root, source)
            return {k: self.resolve_refs(v, root, source) for k, v in data.items()}
        if isinstance(data, list):
            return [self.resolve_refs(item, root, source) for item in data]
        return data


    def _resolve_single_ref(self, ref: str, root: dict, source: str) -> dict:
        """
        Resolves a single $ref reference.

        Parameters
        ----------
        ref : str
            Current reference

        root : dict
            Whole document

        source : str
            URL or source file
        """

        if ref in self._resolved_refs:
            return {}
        self._resolved_refs.add(ref)

        try:
            result = self.__resolve_single_ref(ref, root, source)
        finally:
            self._resolved_refs.discard(ref)

        return result


    def __resolve_single_ref(self, ref: str, root: dict, source: str) -> dict:
        if ref.startswith("#"):

            return self._lookup_json_pointer(root, ref[1:])


        fragment = ""
        if "#" in ref:
            ref, fragment = ref.split("#", 1)


        external_source = self._resolve_external_path(ref, source)
        external_doc = self._load_yaml_or_json(external_source)

        if fragment:
            target = self._lookup_json_pointer(external_doc, fragment)
        else:
            target = external_doc


        return self.resolve_refs(target, external_doc, external_source)


    def _lookup_json_pointer(self, doc: dict, pointer: str) -> dict:
        """
        Goes through the document using JSON Pointers.

        Parameters
        ----------
        doc : dict
            Current document

        pointer : str
            JSON pointer
        """
        parts = [p for p in pointer.split("/") if p]
        node = doc
        for part in parts:

            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict):
                if part not in node:
                    raise KeyError(f"Key '{part}' not found in document (pointer: {pointer})")
                node = node[part]
            elif isinstance(node, list):
                node = node[int(part)]
            else:
                raise KeyError(f"Cannot explore type {type(node)} (pointer: {pointer})")
        return node


    def _resolve_external_path(self, ref: str, source: str) -> str:
        """
        Builds and absolute path or URL to an external file

        Parameters
        ----------
        ref : str
            Current reference
        source : str
            URL or source file
        """
        if self._is_url(ref):
            return ref
        if self._is_url(source):
            return urllib.parse.urljoin(source, ref)

        base_dir = os.path.dirname(os.path.abspath(source))
        return os.path.normpath(os.path.join(base_dir, ref))


    def _get_parameter_type(self, parameter: dict) -> str | None:
        """
        Retrieves the type of a parameter

        Parameters
        ----------
        parameter : dict
            Parameter

        Returns
        -------
        str | None
            webInputType string or None if type cannot be determined
        """
        TYPE_MAP = {
            "integer": "Integer",
            "number": "Number",
            "string": "String",
            "boolean": "Boolean",
            "array": "Array",
            "object": "Object",
            "file": "File",
        }

        raw_type = parameter.get("type")

        if raw_type is None:
            schema = parameter.get("schema", {})
            raw_type = schema.get("type")

        if raw_type is None:
            return None

        mapped = TYPE_MAP.get(raw_type.lower())
        return f"webInputType{mapped}" if mapped else f"webInputType{raw_type.capitalize()}"


    def _process_request_body(self, request_body: dict, method_node: dict, nodes_list: list) -> None:
        """
        Handles the requestBody OpenAPI type
        """
        description = request_body.get("description", "Request body")
        content = request_body.get("content", {})

        for media_type, media_obj in content.items():
            schema = media_obj.get("schema", {})
            properties = schema.get("properties", {})

            if properties:
                for prop_name, prop_schema in properties.items():
                    prop_type = prop_schema.get("type")
                    parameter_node = self.ptjsonlib.create_node_object(
                        "webInput",
                        parent=method_node["key"],
                        properties={
                            "name": prop_name,
                            "description": prop_schema.get("description", ""),
                            "webInputType": f"webInputType{prop_type.capitalize()}" if prop_type else None,
                        }
                    )
                    nodes_list.append(parameter_node)
            else:
                parameter_node = self.ptjsonlib.create_node_object(
                    "webInput",
                    parent=method_node["key"],
                    properties={
                        "name": "body",
                        "description": description,
                        "webInputType": None,
                    }
                )
                nodes_list.append(parameter_node)

    def convert(self) -> list:
        source = self.args.swagger_file or self.args.url
        content = self._load_yaml_or_json(source)

        if not content:
            return []

        # Resolve all $ref references
        content = self.resolve_refs(content, content, source)

        info = content.get("info", {})
        root: dict = self.ptjsonlib.create_node_object(
            "webApi",
            properties={
                "name": info.get("title"),
                "webApiType": "webApiTypeRest",
                "description": info.get("description"),
            }
        )
        nodes_list = [root]

        for path, methods in content.get("paths", {}).items():
            path_level_params = methods.pop("parameters", [])

            endpoint_node: dict = self.ptjsonlib.create_node_object(
                "webApiEndpoint",
                parent=root["key"],
                properties={"name": path, "url": path}
            )
            nodes_list.append(endpoint_node)

            for method, details in methods.items():
                if not isinstance(details, dict):
                    continue

                method_node = self.ptjsonlib.create_node_object(
                    "webApiMethod",
                    parent=endpoint_node["key"],
                    properties={
                        "name": method.upper(),
                        "webHttpMethod": f"webHttpMethod{method.capitalize()}",
                        "description": details.get("summary"),
                    }
                )
                nodes_list.append(method_node)

                merged_params: dict[str, dict] = {}
                for param in path_level_params:
                    merged_params[param.get("name")] = param
                for param in details.get("parameters", []):
                    merged_params[param.get("name")] = param

                for parameter in merged_params.values():
                    param_type = self._get_parameter_type(parameter)
                    parameter_node = self.ptjsonlib.create_node_object(
                        "webInput",
                        parent=method_node["key"],
                        properties={
                            "name": parameter.get("name"),
                            "description": parameter.get("description", ""),
                            "webInputType": param_type,
                        }
                    )
                    nodes_list.append(parameter_node)

                # OpenAPI 3.x requestBody
                request_body = details.get("requestBody")
                if request_body:
                    self._process_request_body(request_body, method_node, nodes_list)

                # Swagger 2.0 body/formData parameters
                for parameter in details.get("parameters", []):
                    if parameter.get("in") in ("body", "formData") and self._get_parameter_type(parameter) is None:
                        parameter_node = self.ptjsonlib.create_node_object(
                            "webInput",
                            parent=method_node["key"],
                            properties={
                                "name": parameter.get("name"),
                                "description": parameter.get("description", ""),
                                "webInputType": None,
                            }
                        )
                        nodes_list.append(parameter_node)

        return nodes_list

    def run(self) -> None:
        """
        This module parses a OpenAPI definition file from a URL or source file into a format compatible with the Penterep
        JSON format.
        """
        self.ptjsonlib.add_nodes(self.convert())


def run(args, ptjsonlib, helpers, http_client, common_tests, endpoints):
    """Entry point for running the OpenAPI definition parser"""
    Swagger(args, ptjsonlib, helpers, http_client, common_tests, endpoints).run()
