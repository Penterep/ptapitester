"""
XML-RPC Introspection test

Tests whether introspection is enabled and extracts complete API schema
including method parameters, data types and sample requests.

Uses two sources for parameter info:
1. system.methodSignature - standard XML-RPC introspection (rarely used)
2. system.methodHelp - parses parameter info from help text (WordPress etc.)

Per XML-RPC_API.pdf: "Je potřeba vyčíst poskytované metody, jejich
parametry a datové typy. Ke každé operaci by se měl také vygenerovat
příklad validního reguestu."
"""
import re
import xmlrpc.client
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "XML-RPC Introspection test"

# Default values for generating sample requests
TYPE_DEFAULTS = {
    'int': 0, 'i4': 0, 'i8': 0, 'long': 0,
    'double': 0.0, 'float': 0.0,
    'boolean': False, 'bool': False,
    'string': 'string', 'base64': 'dGVzdA==',
    'dateTime.iso8601': '2025-01-01T00:00:00',
    'array': [], 'struct': {}, 'nil': None,
}

# Mapping of help-text type names to XML-RPC types
HELP_TYPE_MAPPING = {
    'int': 'int', 'integer': 'int', 'i4': 'int', 'number': 'int',
    'long': 'long',
    'string': 'string', 'str': 'string', 'text': 'string',
    'double': 'double', 'float': 'double',
    'bool': 'boolean', 'boolean': 'boolean',
    'array': 'array', 'list': 'array',
    'struct': 'struct', 'hash': 'struct', 'dict': 'struct', 'object': 'struct',
    'datetime': 'dateTime.iso8601', 'date': 'dateTime.iso8601',
    'base64': 'base64', 'bytes': 'base64',
}


class Introspection:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

    def _extract_types_from_signature(self, sig):
        """Extract param types from methodSignature result.
        sig is [[return_type, param1_type, param2_type, ...], ...]
        Returns (return_type, [param_types]) or None if invalid.
        """
        if not sig or not isinstance(sig, list) or not sig:
            return None
        first = sig[0]
        if not isinstance(first, list) or len(first) < 1:
            return None
        return_type = first[0]
        param_types = first[1:] if len(first) > 1 else []
        return (return_type, param_types)

    def _extract_types_from_help(self, method_name, help_text):
        """Parse parameter types from methodHelp text.
        Common formats:
        - 'methodName( int arg1, string arg2, struct arg3 )'
        - 'methodName(int arg1, string arg2)'
        - 'Parameters: int arg1, string arg2'
        Returns (return_type, [param_types]) or None if can't parse.
        """
        if not help_text or not isinstance(help_text, str):
            return None

        # Try 'methodName( type1 name1, type2 name2, ... )'
        pattern = re.escape(method_name) + r'\s*\(([^)]*)\)'
        match = re.search(pattern, help_text)

        if not match:
            # Try 'Parameters: type1 name1, type2 name2'
            match = re.search(r'[Pp]arameters?\s*:?\s*([^\n.]+)', help_text)
            if not match:
                return None

        params_str = match.group(1).strip()
        if not params_str:
            return ('string', [])  # No parameters

        # Split by comma, extract first word (type) from each part
        param_types = []
        for part in params_str.split(','):
            part = part.strip()
            if not part:
                continue
            # First word is the type; rest is parameter name
            words = part.split()
            if not words:
                continue
            type_candidate = words[0].lower().strip('.,;:')
            xmlrpc_type = HELP_TYPE_MAPPING.get(type_candidate)
            if xmlrpc_type:
                param_types.append(xmlrpc_type)
            else:
                # Unknown type - assume string
                param_types.append('string')

        return ('string', param_types)  # return type unknown, assume string

    def _format_signature_display(self, return_type, param_types):
        if param_types:
            return f"{return_type}({', '.join(param_types)})"
        return f"{return_type}()"

    def _generate_sample_request(self, method_name, param_types):
        """Generate XML-RPC sample request for given method + param types."""
        params_xml = ''
        for t in param_types:
            val = TYPE_DEFAULTS.get(t, 'string')
            if isinstance(val, bool):
                val_xml = f'<boolean>{1 if val else 0}</boolean>'
            elif isinstance(val, int):
                val_xml = f'<int>{val}</int>'
            elif isinstance(val, float):
                val_xml = f'<double>{val}</double>'
            elif isinstance(val, list):
                val_xml = '<array><data></data></array>'
            elif isinstance(val, dict):
                val_xml = '<struct></struct>'
            elif val is None:
                val_xml = '<nil/>'
            else:
                val_xml = f'<string>{val}</string>'
            params_xml += f'    <param><value>{val_xml}</value></param>\n'

        return (
            f'<?xml version="1.0"?>\n'
            f'<methodCall>\n'
            f'  <methodName>{method_name}</methodName>\n'
            f'  <params>\n'
            f'{params_xml}'
            f'  </params>\n'
            f'</methodCall>'
        )

    def run(self):
        try:
            server = self.helpers.get_xmlrpc_proxy()
            self.helpers.discovered_methods = server.system.listMethods()

            if not self.helpers.discovered_methods:
                ptprint("Introspection returned no methods.", "INFO",
                        not self.args.json, indent=4)
                return

            # Extract signature and help for each method; determine param types
            for method in self.helpers.discovered_methods:
                method_info = {"signature": "N/A", "help": "N/A",
                               "param_types": None, "return_type": None,
                               "source": "unknown"}

                # Try methodSignature first
                try:
                    sig = server.system.methodSignature(method)
                    method_info["signature"] = sig
                    result = self._extract_types_from_signature(sig)
                    if result:
                        method_info["return_type"] = result[0]
                        method_info["param_types"] = result[1]
                        method_info["source"] = "methodSignature"
                except Exception:
                    pass

                # Try methodHelp - either as fallback or to enrich
                try:
                    help_text = server.system.methodHelp(method)
                    method_info["help"] = help_text
                    # Use help only if signature didn't give us types
                    if method_info["param_types"] is None:
                        result = self._extract_types_from_help(method, help_text)
                        if result:
                            method_info["return_type"] = result[0]
                            method_info["param_types"] = result[1]
                            method_info["source"] = "methodHelp"
                except Exception:
                    pass

                self.helpers.metadata[method] = method_info

            # Report introspection as vulnerability
            ptprint(f"Introspection enabled — extracted {len(self.helpers.discovered_methods)} method(s).",
                    "VULN", not self.args.json, indent=4, colortext=True)

            # Count how many have types from each source
            from_sig = sum(1 for m in self.helpers.metadata.values()
                           if m["source"] == "methodSignature")
            from_help = sum(1 for m in self.helpers.metadata.values()
                            if m["source"] == "methodHelp")
            if from_sig or from_help:
                ptprint(f"  Parameters resolved: {from_sig} via methodSignature, "
                        f"{from_help} via methodHelp",
                        "INFO", not self.args.json, indent=4)

            # Print each method with its signature
            for method in self.helpers.discovered_methods:
                info = self.helpers.metadata[method]
                param_types = info.get("param_types")
                return_type = info.get("return_type")

                if param_types is not None and return_type:
                    formatted = self._format_signature_display(return_type, param_types)
                    ptprint(f"  Method: {method} -> {formatted}", "PARSED",
                            not self.args.json, indent=4)
                else:
                    ptprint(f"  Method: {method}", "PARSED",
                            not self.args.json, indent=4)

            # Generate and display sample requests for non-system methods
            sample_methods = [m for m in self.helpers.discovered_methods
                              if not m.startswith('system.')]

            methods_with_types = [m for m in sample_methods
                                  if self.helpers.metadata[m].get("param_types") is not None]

            if methods_with_types:
                ptprint("Sample requests:", "INFO", not self.args.json, indent=4)
                for method in methods_with_types:
                    param_types = self.helpers.metadata[method]["param_types"]
                    sample = self._generate_sample_request(method, param_types)

                    ptprint(f"  --- {method} ---", "PARSED",
                            not self.args.json, indent=4)
                    for line in sample.split('\n'):
                        ptprint(f"    {line}", "PARSED",
                                not self.args.json, indent=4)

            # Evidence for JSON output
            evidence = f"Exposed {len(self.helpers.discovered_methods)} methods: "
            evidence += ", ".join(self.helpers.discovered_methods[:15])
            if len(self.helpers.discovered_methods) > 15:
                evidence += f"... (+{len(self.helpers.discovered_methods) - 15} more)"
            self.ptjsonlib.add_vulnerability(
                "PTV-RPC-INTROSPECTION-ENABLED",
                node_key=self.helpers.node_key,
                data={"evidence": evidence})

            # Store full API schema
            self.ptjsonlib.add_properties(
                properties={"apiSchema": self.helpers.metadata},
                node_key=self.helpers.node_key
            )

        except xmlrpc.client.Fault as e:
            ptprint(f"Introspection rejected (Fault: {e.faultString}).",
                    "OK", not self.args.json, indent=4)
        except Exception as e:
            ptprint(f"Introspection failed: {type(e).__name__}",
                    "INFO", not self.args.json, indent=4)


def run(args, ptjsonlib, helpers, http_client, common_tests):
    Introspection(args, ptjsonlib, helpers, http_client, common_tests).run()