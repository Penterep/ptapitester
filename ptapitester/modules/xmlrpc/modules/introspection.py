"""
XML-RPC Introspection test
"""

import re
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Introspection test"


HELP_TYPE_MAPPING = {
    "int": "int",
    "integer": "int",
    "i4": "i4",
    "i8": "i8",
    "number": "int",
    "long": "long",

    "string": "string",
    "str": "string",
    "text": "string",

    "double": "double",
    "float": "double",
    "decimal": "double",

    "bool": "boolean",
    "boolean": "boolean",

    "array": "array",
    "list": "array",

    "struct": "struct",
    "hash": "struct",
    "dict": "struct",
    "object": "struct",

    "datetime": "dateTime.iso8601",
    "date": "dateTime.iso8601",
    "datetime.iso8601": "dateTime.iso8601",

    "base64": "base64",
    "bytes": "base64",

    "nil": "nil",
    "null": "nil",
}

KNOWN_XMLRPC_TYPES = {
    "int", "i4", "i8", "long", "double", "boolean", "string", "array", "struct", "dateTime.iso8601",
    "base64", "nil",
}


class Introspection:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

        if not hasattr(self.helpers, "metadata") or self.helpers.metadata is None:
            self.helpers.metadata = {}

    def _normalise_type(self, type_name):
        if not type_name:
            return "string"

        t = str(type_name).strip()

        if ":" in t:
            t = t.split(":", 1)[-1]

        low = t.lower().strip(".,;:()[]{}")

        return HELP_TYPE_MAPPING.get(low, low or "string")

    def _default_value_for_type(self, type_name):

        t = self._normalise_type(type_name)

        if t in ("int", "i4", "i8", "integer", "long"):
            return 0

        if t in ("double", "float"):
            return 0.0

        if t in ("boolean", "bool"):
            return False

        if t == "base64":
            return xmlrpc.client.Binary(b"test")

        if t == "dateTime.iso8601":
            return xmlrpc.client.DateTime("20500101T00:00:00")

        if t == "array":
            return []

        if t == "struct":
            return {}

        if t == "nil":
            return None

        return "string"


    def _extract_types_from_signature(self, sig):

        if not sig or not isinstance(sig, list):
            return None

        if not sig:
            return None

        first = sig[0]

        if not isinstance(first, (list, tuple)) or len(first) < 1:
            return None

        return_type = self._normalise_type(first[0])
        param_types = [self._normalise_type(t) for t in first[1:]]

        params = []
        for idx, param_type in enumerate(param_types, 1):
            params.append({
                "name": f"param{idx}",
                "type": param_type,
                "nameSource": "generated",
                "typeSource": "methodSignature",
            })

        return {
            "return_type": return_type,
            "params": params,
            "source": "methodSignature",
            "confidence": "high",
        }

    def _normalise_return_type_candidate(self, value):

        if not value:
            return None

        words = str(value).strip().split()
        if not words:
            return None

        if words[0].lower() in ("a", "an", "the") and len(words) > 1:
            candidate = words[1]
        else:
            candidate = words[0]

        normalised = self._normalise_type(candidate)

        if normalised in KNOWN_XMLRPC_TYPES:
            return normalised

        return None

    def _extract_return_type_from_help(self, help_text):
        if not help_text:
            return None

        low = help_text.lower()

        if "returns a list" in low or "returns list" in low:
            return "array"
        if "returns an array" in low or "returns array" in low:
            return "array"
        if "returns a string" in low or "returns string" in low:
            return "string"
        if "returns a struct" in low or "returns struct" in low:
            return "struct"
        if "returns a dict" in low or "returns dict" in low:
            return "struct"
        if "returns an integer" in low or "returns integer" in low:
            return "int"
        if "returns a boolean" in low or "returns boolean" in low:
            return "boolean"

        patterns = [
            r"[Rr]eturns?\s*:?\s*([A-Za-z0-9_.:-]+)",
            r"[Rr]eturn\s+[Tt]ype\s*:?\s*([A-Za-z0-9_.:-]+)",
            r"->\s*([A-Za-z0-9_.:-]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, help_text)
            if match:
                result = self._normalise_return_type_candidate(match.group(1))
                if result:
                    return result

        return None

    def _parse_param_token(self, token):

        token = token.strip().strip(",.;")

        if not token:
            return None

        token = re.sub(r"^@param\s+", "", token, flags=re.IGNORECASE)
        token = re.sub(r"^(param|parameter)\s+", "", token, flags=re.IGNORECASE)
        token = token.replace("$", "").strip()

        match = re.match(
            r"^([A-Za-z_][A-Za-z0-9_.-]*)\s*:\s*([A-Za-z0-9_.:-]+)$",
            token,
        )
        if match:
            name = match.group(1)
            typ = self._normalise_type(match.group(2))

            if typ in KNOWN_XMLRPC_TYPES:
                return {
                    "name": name,
                    "type": typ,
                    "nameSource": "methodHelp",
                    "typeSource": "methodHelp",
                }

        words = token.split()
        if len(words) >= 2:
            raw_type = words[0].lower().strip(".,;:")
            typ = self._normalise_type(raw_type)
            name = words[1].strip(",.;:")

            if raw_type in HELP_TYPE_MAPPING or typ in KNOWN_XMLRPC_TYPES:
                return {
                    "name": name,
                    "type": typ,
                    "nameSource": "methodHelp",
                    "typeSource": "methodHelp",
                }

        if len(words) == 1:
            raw_type = words[0].lower().strip(".,;:")
            typ = self._normalise_type(raw_type)

            if raw_type in HELP_TYPE_MAPPING or typ in KNOWN_XMLRPC_TYPES:
                return {
                    "name": None,
                    "type": typ,
                    "nameSource": "unknown",
                    "typeSource": "methodHelp",
                }

        return None

    def _fill_missing_param_names(self, params):
        fixed = []

        for idx, param in enumerate(params, 1):
            p = dict(param)

            if not p.get("name"):
                p["name"] = f"param{idx}"
                p["nameSource"] = "generated"

            fixed.append(p)

        return fixed

    def _extract_types_from_help(self, method_name, help_text):

        if not help_text or not isinstance(help_text, str):
            return None

        params = []

        pattern = re.escape(method_name) + r"\s*\(([^)]*)\)"
        match = re.search(pattern, help_text)

        if match:
            params_str = match.group(1).strip()

            if params_str:
                for part in params_str.split(","):
                    parsed = self._parse_param_token(part)
                    if parsed:
                        params.append(parsed)

            return_type = self._extract_return_type_from_help(help_text)

            return {
                "return_type": return_type,
                "params": self._fill_missing_param_names(params),
                "source": "methodHelp",
                "confidence": "medium" if params or return_type else "low",
            }

        match = re.search(r"[Pp]arameters?\s*:?\s*([^\n]+)", help_text)

        if match:
            params_str = match.group(1).strip()

            if params_str.lower() not in ("none", "no parameters", "no params"):
                for part in params_str.split(","):
                    parsed = self._parse_param_token(part)
                    if parsed:
                        params.append(parsed)

            return_type = self._extract_return_type_from_help(help_text)

            return {
                "return_type": return_type,
                "params": self._fill_missing_param_names(params),
                "source": "methodHelp",
                "confidence": "medium" if params or return_type else "low",
            }

        line_params = []

        for line in help_text.splitlines():
            line = line.strip()

            if not line:
                continue

            if line.lower().startswith("@param"):
                parsed = self._parse_param_token(line)
                if parsed:
                    line_params.append(parsed)

        if line_params:
            return_type = self._extract_return_type_from_help(help_text)

            return {
                "return_type": return_type,
                "params": self._fill_missing_param_names(line_params),
                "source": "methodHelp",
                "confidence": "medium",
            }

        return_type = self._extract_return_type_from_help(help_text)
        if return_type:
            return {
                "return_type": return_type,
                "params": [],
                "source": "methodHelp",
                "confidence": "low",
            }

        return None

    def _generate_sample_request(self, method_name, params):

        values = []

        for param in params or []:
            values.append(self._default_value_for_type(param.get("type", "string")))

        return xmlrpc.client.dumps(
            tuple(values),
            methodname=method_name,
            allow_none=True,
            encoding="utf-8",
        )

    def _format_signature_display(self, return_type, params):
        param_types = [p.get("type", "unknown") for p in params or []]

        if param_types:
            return f"{return_type}({', '.join(param_types)})"

        return f"{return_type}()"

    def _schema_entry(self, method, info):

        return {
            "name": method,
            "returnType": info.get("return_type"),
            "params": [
                {
                    "name": p.get("name"),
                    "type": p.get("type"),
                    "nameSource": p.get("nameSource"),
                    "typeSource": p.get("typeSource"),
                }
                for p in (info.get("params") or [])
            ],
            "source": info.get("source"),
            "confidence": info.get("confidence"),
            "sampleRequest": info.get("sample_request"),
        }

    def run(self):
        try:
            server = self.helpers.get_xmlrpc_proxy()
            self.helpers.discovered_methods = server.system.listMethods()

            if not self.helpers.discovered_methods:
                ptprint("Introspection returned no methods.", "INFO",
                        not self.args.json, indent=4)

                self.ptjsonlib.add_properties(
                    properties={
                        "xmlrpcIntrospection": {
                            "enabled": True,
                            "status": "no_methods_returned",
                            "methodCount": 0,
                        }
                    },
                    node_key=self.helpers.node_key,
                )
                return

            unresolved_methods = []
            sample_requests_generated = 0

            for method in self.helpers.discovered_methods:
                method_info = {
                    "signature": "N/A",
                    "help": "N/A",
                    "params": [],
                    "param_types": None,
                    "return_type": None,
                    "source": "unknown",
                    "confidence": "none",
                    "sample_request": None,
                }

                try:
                    sig = server.system.methodSignature(method)
                    method_info["signature"] = sig

                    parsed_sig = self._extract_types_from_signature(sig)
                    if parsed_sig:
                        method_info["return_type"] = parsed_sig["return_type"]
                        method_info["params"] = parsed_sig["params"]
                        method_info["param_types"] = [
                            p["type"] for p in parsed_sig["params"]
                        ]
                        method_info["source"] = parsed_sig["source"]
                        method_info["confidence"] = parsed_sig["confidence"]

                except Exception:
                    pass

                try:
                    help_text = server.system.methodHelp(method)
                    method_info["help"] = help_text

                    parsed_help = self._extract_types_from_help(method, help_text)

                    if method_info["param_types"] is None and parsed_help:
                        method_info["return_type"] = parsed_help.get("return_type")
                        method_info["params"] = parsed_help.get("params", [])
                        method_info["param_types"] = [
                            p["type"] for p in method_info["params"]
                        ]
                        method_info["source"] = parsed_help.get("source", "methodHelp")
                        method_info["confidence"] = parsed_help.get("confidence", "low")

                    elif (
                        method_info["params"]
                        and parsed_help
                        and parsed_help.get("params")
                        and len(parsed_help["params"]) == len(method_info["params"])
                        and parsed_help.get("confidence") == "medium"
                    ):
                        for idx, help_param in enumerate(parsed_help["params"]):
                            help_name = help_param.get("name")

                            if help_name and help_param.get("nameSource") == "methodHelp":
                                method_info["params"][idx]["name"] = help_name
                                method_info["params"][idx]["nameSource"] = "methodHelp"

                except Exception:
                    pass

                if method_info["param_types"] is not None:
                    try:
                        method_info["sample_request"] = self._generate_sample_request(
                            method,
                            method_info["params"],
                        )
                        sample_requests_generated += 1
                    except Exception as e:
                        method_info["sample_request"] = None
                        method_info["sampleRequestError"] = type(e).__name__
                else:
                    unresolved_methods.append(method)

                self.helpers.metadata[method] = method_info

            method_count = len(self.helpers.discovered_methods)

            ptprint(
                f"Introspection enabled — extracted {method_count} method(s).",
                "VULN",
                not self.args.json,
                indent=4,
                colortext=True,
            )

            from_sig = sum(
                1 for method in self.helpers.discovered_methods
                if self.helpers.metadata[method]["source"] == "methodSignature"
            )

            from_help = sum(
                1 for method in self.helpers.discovered_methods
                if self.helpers.metadata[method]["source"] == "methodHelp"
            )

            if from_sig or from_help:
                ptprint(
                    f"  Parameters resolved: {from_sig} via methodSignature, "
                    f"{from_help} via methodHelp. "
                    f"Sample requests generated: {sample_requests_generated}.",
                    "INFO",
                    not self.args.json,
                    indent=4,
                )

            for method in self.helpers.discovered_methods:
                info = self.helpers.metadata[method]
                params = info.get("params") or []
                return_type = info.get("return_type")

                if info.get("param_types") is not None and return_type:
                    formatted = self._format_signature_display(return_type, params)
                    ptprint(f"  Method: {method} -> {formatted}",
                            "PARSED", not self.args.json, indent=4)
                else:
                    ptprint(f"  Method: {method}",
                            "PARSED", not self.args.json, indent=4)

            sample_methods = [
                m for m in self.helpers.discovered_methods
                if not m.startswith("system.")
                and self.helpers.metadata[m].get("sample_request") is not None
            ]

            if sample_methods:
                ptprint("Sample requests:", "INFO", not self.args.json, indent=4)

                for method in sample_methods:
                    sample = self.helpers.metadata[method]["sample_request"]

                    ptprint(f"  --- {method} ---", "PARSED",
                            not self.args.json, indent=4)

                    for line in sample.split("\n"):
                        ptprint(f"    {line}", "PARSED",
                                not self.args.json, indent=4)

            application_methods = [
                m for m in self.helpers.discovered_methods
                if not m.startswith("system.")
            ]

            system_methods = [
                m for m in self.helpers.discovered_methods
                if m.startswith("system.")
            ]

            self.ptjsonlib.add_vulnerability(
                "PTV-XMLRPC-INTROSPECTION-ENABLED",
                node_key=self.helpers.node_key,
                data={
                    "summary": "XML-RPC introspection is enabled.",
                    "description": (
                        "The endpoint exposes XML-RPC introspection methods, "
                        "allowing API method enumeration and extraction of "
                        "method metadata where available."
                    ),
                    "methodCount": method_count,
                    "applicationMethodCount": len(application_methods),
                    "systemMethodCount": len(system_methods),
                    "methods": application_methods,
                    "systemMethods": system_methods,
                    "resolvedByMethodSignature": from_sig,
                    "resolvedByMethodHelp": from_help,
                    "unresolvedMethodCount": len(unresolved_methods),
                    "unresolvedMethods": unresolved_methods,
                    "sampleRequestCount": sample_requests_generated,
                    "confidence": "direct evidence",
                },
            )

            api_schema_methods = [
                self._schema_entry(method, self.helpers.metadata[method])
                for method in self.helpers.discovered_methods
            ]

            self.ptjsonlib.add_properties(
                properties={
                    "apiSchema": {
                        "type": "xmlrpc",
                        "methodCount": method_count,
                        "methods": api_schema_methods,
                    },
                    "xmlrpcIntrospection": {
                        "enabled": True,
                        "methodCount": method_count,
                        "resolvedByMethodSignature": from_sig,
                        "resolvedByMethodHelp": from_help,
                        "unresolvedMethods": unresolved_methods,
                        "sampleRequestCount": sample_requests_generated,
                    },
                },
                node_key=self.helpers.node_key,
            )

        except xmlrpc.client.Fault as e:
            ptprint(
                f"Introspection rejected (Fault: {e.faultString}).",
                "OK",
                not self.args.json,
                indent=4,
            )

            self.ptjsonlib.add_properties(
                properties={
                    "xmlrpcIntrospection": {
                        "enabled": False,
                        "status": "rejected",
                        "faultCode": e.faultCode,
                        "faultString": e.faultString,
                    }
                },
                node_key=self.helpers.node_key,
            )

        except Exception as e:
            ptprint(
                f"Introspection failed: {type(e).__name__}",
                "INFO",
                not self.args.json,
                indent=4,
            )

            self.ptjsonlib.add_properties(
                properties={
                    "xmlrpcIntrospection": {
                        "enabled": None,
                        "status": "failed",
                        "errorType": type(e).__name__,
                    }
                },
                node_key=self.helpers.node_key,
            )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    Introspection(args, ptjsonlib, helpers, http_client, common_tests).run()