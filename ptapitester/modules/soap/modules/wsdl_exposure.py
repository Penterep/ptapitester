"""
SOAP WSDL Exposure and Parsing test
"""

from lxml import etree
from urllib.parse import urljoin
from ptlibs.ptprinthelper import ptprint
import html

__TESTLABEL__ = "SOAP WSDL exposure test"


NS = {
    "wsdl": "http://schemas.xmlsoap.org/wsdl/",
    "soap": "http://schemas.xmlsoap.org/wsdl/soap/",
    "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xs": "http://www.w3.org/2001/XMLSchema",
}


XSD_DEFAULTS = {
    "string": "string",
    "int": "0",
    "integer": "0",
    "long": "0",
    "short": "0",
    "byte": "0",
    "float": "0.0",
    "double": "0.0",
    "decimal": "0.0",
    "boolean": "true",
    "date": "2050-01-01",
    "dateTime": "2050-01-01T00:00:00",
    "time": "00:00:00",
    "base64Binary": "dGVzdA==",
    "hexBinary": "74657374",
    "anyURI": "http://example.com",
    "token": "token",
    "normalizedString": "text",
    "positiveInteger": "1",
    "nonNegativeInteger": "0",
    "unsignedInt": "0",
    "unsignedLong": "0",
    "unsignedShort": "0",
}

MAX_WSDL_IMPORTS = 20

class WSDLExposure:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

        self.parsed_services = []
        self.parsed_operations = []

        self.type_definitions = {}

        self.element_types = {}

        self.all_wsdl_docs = []

        self.target_namespace = ""

        self.visited_imports = set()
        self.import_count = 0
        self.max_imports = getattr(self.args, "max_wsdl_imports", MAX_WSDL_IMPORTS)

    def _fetch_wsdl(self):
        if getattr(self.helpers, "wsdl_content", None):
            return True

        wsdl_paths = [
            self.helpers.endpoint_url.rstrip("/") + "?wsdl",
            self.helpers.endpoint_url.rstrip("/") + "?WSDL",
            self.helpers.endpoint_url.rstrip("/") + "?wsdl=1",
            self.helpers.endpoint_url.rstrip("/") + ".wsdl",
            self.helpers.base_url + "/?wsdl",
            self.helpers.base_url + "/service?wsdl",
            self.helpers.base_url + "/services?wsdl",
            self.helpers.base_url + "/",
        ]

        for path in wsdl_paths:
            r = self.helpers.send_get_request(path)

            if r and r.status_code == 200:
                ct = r.headers.get("Content-Type", "").lower()
                body_lower = r.text.lower()

                if ("xml" in ct or body_lower.lstrip().startswith("<?xml")):
                    if "definitions" in body_lower:
                        self.helpers.wsdl_content = r.text
                        self.helpers.wsdl_url = path
                        return True

        return False

    def _parse_wsdl_xml(self, content):
        """Parse WSDL/XML safely into etree."""
        try:
            parser = etree.XMLParser(
                resolve_entities=False,
                load_dtd=False,
                no_network=True,
                recover=False,
                remove_comments=True,
            )

            data = content.encode("utf-8") if isinstance(content, str) else content
            return etree.fromstring(data, parser=parser)

        except Exception as e:
            ptprint(f"  WSDL XML parse error: {e}",
                    "WARNING", not self.args.json, indent=4)
            return None

    def _add_doc(self, url, root):
        self.all_wsdl_docs.append({
            "url": url,
            "root": root,
        })

    def _resolve_imports(self, root, base_url):

        imports = []

        for imp in root.findall(".//wsdl:import", NS):
            location = imp.get("location", "")

            if location:
                imports.append(urljoin(base_url, location))

        for tag in ["xsd:import", "xsd:include", "xs:import", "xs:include"]:
            for imp in root.findall(f".//{tag}", NS):
                location = imp.get("schemaLocation", "")

                if location:
                    imports.append(urljoin(base_url, location))

        for resolved_url in imports:
            self._fetch_and_parse_import(resolved_url)

    def _fetch_and_parse_import(self, url):
        if not url:
            return

        if url in self.visited_imports:
            return

        if self.import_count >= self.max_imports:
            ptprint(
                f"  Import limit reached ({self.max_imports}); skipping {url}",
                "WARNING",
                not self.args.json,
                indent=4,
            )
            return

        self.visited_imports.add(url)
        self.import_count += 1

        try:
            r = self.helpers.send_get_request(url)

            if r and r.status_code == 200:
                imported_root = self._parse_wsdl_xml(r.text)

                if imported_root is not None:
                    self._add_doc(url, imported_root)
                    ptprint(f"  Imported: {url}",
                            "PARSED", not self.args.json, indent=4)

                    self._resolve_imports(imported_root, url)

        except Exception:
            pass

    def _strip_ns(self, value):
        if not value:
            return ""
        return value.split(":")[-1]

    def _extract_types(self, root):
        for schema in root.findall(".//wsdl:types/xsd:schema", NS):
            self._parse_schema(schema)

        if root.tag.endswith("}schema") or root.tag == "schema":
            self._parse_schema(root)

    def _parse_schema(self, schema):

        for ct in schema.findall("xsd:complexType", NS):
            name = ct.get("name", "")

            if not name or name in self.type_definitions:
                continue

            params = self._extract_complex_type_params(ct)

            if params:
                self.type_definitions[name] = params

        for elem in schema.findall("xsd:element", NS):
            name = elem.get("name", "")

            if not name:
                continue

            params = self._extract_element_params(elem)

            if params and name not in self.type_definitions:
                self.type_definitions[name] = params

            type_ref = elem.get("type", "")
            type_name = self._strip_ns(type_ref)

            if type_name and name not in self.element_types:
                self.element_types[name] = type_name

    def _extract_element_params(self, element):
        params = []

        for ct in element.findall("xsd:complexType", NS):
            params.extend(self._extract_complex_type_params(ct))

        type_ref = element.get("type", "")
        type_name = self._strip_ns(type_ref)

        if type_name and not params:
            if type_name in self.type_definitions:
                params = self.type_definitions[type_name]

        return params

    def _extract_complex_type_params(self, complex_type):
        """Extract parameters from xs:complexType.
        Supports xs:complexContent / xs:extension inheritance by recursing
        into the parent type if it has been parsed."""
        params = []
        seen = set()

        for extension in complex_type.findall(
            "xsd:complexContent/xsd:extension", NS
        ):
            base = self._strip_ns(extension.get("base", ""))
            if base and base in self.type_definitions:
                for parent_param in self.type_definitions[base]:
                    name = parent_param.get("name")
                    if name and name not in seen:
                        seen.add(name)
                        params.append(dict(parent_param))

            containers = (
                extension.findall("xsd:sequence", NS)
                + extension.findall("xsd:all", NS)
                + extension.findall("xsd:choice", NS)
            )
            for container in containers:
                for elem in container.findall("xsd:element", NS):
                    param_name = elem.get("name", "") or self._strip_ns(elem.get("ref", ""))
                    param_type = self._strip_ns(elem.get("type", "string"))
                    min_occurs = elem.get("minOccurs", "1")
                    max_occurs = elem.get("maxOccurs", "1")
                    nillable = elem.get("nillable", "false").lower() == "true"

                    if param_name and param_name not in seen:
                        seen.add(param_name)
                        params.append({
                            "name": param_name,
                            "type": param_type or "string",
                            "required": min_occurs != "0",
                            "array": max_occurs == "unbounded",
                            "nillable": nillable,
                        })

        containers = (
            complex_type.findall("xsd:sequence", NS)
            + complex_type.findall("xsd:all", NS)
            + complex_type.findall("xsd:choice", NS)
        )

        for container in containers:
            for elem in container.findall("xsd:element", NS):
                param_name = elem.get("name", "") or self._strip_ns(elem.get("ref", ""))
                param_type = self._strip_ns(elem.get("type", "string"))

                min_occurs = elem.get("minOccurs", "1")
                max_occurs = elem.get("maxOccurs", "1")
                nillable = elem.get("nillable", "false").lower() == "true"

                if param_name and param_name not in seen:
                    seen.add(param_name)

                    params.append({
                        "name": param_name,
                        "type": param_type or "string",
                        "required": min_occurs != "0",
                        "array": max_occurs == "unbounded",
                        "nillable": nillable,
                    })

        return params

    def _get_type_default(self, type_name):
        return XSD_DEFAULTS.get(type_name, "string")

    def _extract_services(self, root):
        for service in root.findall("wsdl:service", NS):
            svc = {
                "name": service.get("name", "unknown"),
                "ports": [],
            }

            for port in service.findall("wsdl:port", NS):
                port_info = {
                    "name": port.get("name", ""),
                    "binding": self._strip_ns(port.get("binding", "")),
                    "address": "",
                }

                for addr in port.findall("soap:address", NS) + port.findall("soap12:address", NS):
                    port_info["address"] = addr.get("location", "")

                svc["ports"].append(port_info)

            self.parsed_services.append(svc)

    def _build_binding_to_ports(self):
        mapping = {}

        for svc in self.parsed_services:
            for port in svc.get("ports", []):
                binding = port.get("binding", "")

                if not binding:
                    continue

                mapping.setdefault(binding, []).append({
                    "service": svc.get("name", ""),
                    "port": port.get("name", ""),
                    "endpoint": port.get("address", ""),
                    "binding": binding,
                })

        return mapping

    def _collect_messages(self):
        messages = {}

        for doc in self.all_wsdl_docs:
            root = doc["root"]

            for msg in root.findall("wsdl:message", NS):
                msg_name = msg.get("name", "")

                if not msg_name:
                    continue

                parts = []

                for part in msg.findall("wsdl:part", NS):
                    parts.append({
                        "name": part.get("name", ""),
                        "element": self._strip_ns(part.get("element", "")),
                        "type": self._strip_ns(part.get("type", "")),
                    })

                messages[msg_name] = parts

        return messages

    def _collect_port_type_ops(self):
        port_type_ops = {}

        for doc in self.all_wsdl_docs:
            root = doc["root"]

            for pt in root.findall("wsdl:portType", NS):
                pt_name = pt.get("name", "")

                for op in pt.findall("wsdl:operation", NS):
                    op_name = op.get("name", "")
                    input_msg = ""
                    output_msg = ""

                    inp = op.find("wsdl:input", NS)
                    if inp is not None:
                        input_msg = self._strip_ns(inp.get("message", ""))

                    out = op.find("wsdl:output", NS)
                    if out is not None:
                        output_msg = self._strip_ns(out.get("message", ""))

                    if pt_name and op_name:
                        port_type_ops[(pt_name, op_name)] = {
                            "input_msg": input_msg,
                            "output_msg": output_msg,
                        }

        return port_type_ops

    def _collect_bindings(self):
        bindings = {}

        for doc in self.all_wsdl_docs:
            root = doc["root"]

            for binding in root.findall("wsdl:binding", NS):
                binding_name = binding.get("name", "")
                port_type = self._strip_ns(binding.get("type", ""))

                if not binding_name:
                    continue

                binding_info = {
                    "name": binding_name,
                    "portType": port_type,
                    "operations": {},
                }

                for op in binding.findall("wsdl:operation", NS):
                    op_name = op.get("name", "")
                    soap_action = ""

                    for soap_op in op.findall("soap:operation", NS) + op.findall("soap12:operation", NS):
                        soap_action = soap_op.get("soapAction", "")

                    if op_name:
                        binding_info["operations"][op_name] = {
                            "name": op_name,
                            "soapAction": soap_action,
                            "soap_action": soap_action,
                        }

                bindings[binding_name] = binding_info

        return bindings

    def _params_from_message_parts(self, parts):
        if not parts:
            return "", []

        if len(parts) == 1:
            part = parts[0]
            element = part.get("element", "")
            part_type = part.get("type", "")

            if element and element in self.type_definitions:
                return element, self.type_definitions[element]

            if element and element in self.element_types:
                return element, [{
                    "name": part.get("name") or element,
                    "type": self.element_types[element],
                    "required": True,
                    "array": False,
                }]

            if part_type and part_type in self.type_definitions:
                return part.get("name", ""), self.type_definitions[part_type]

            if part_type:
                return part.get("name", ""), [{
                    "name": part.get("name") or "param1",
                    "type": part_type,
                    "required": True,
                    "array": False,
                }]
        
        params = []

        for idx, part in enumerate(parts, 1):
            name = part.get("name") or part.get("element") or f"param{idx}"
            typ = part.get("type", "")

            if not typ and part.get("element") in self.element_types:
                typ = self.element_types[part["element"]]

            if not typ and part.get("element") in self.type_definitions:
                typ = part.get("element")

            params.append({
                "name": name,
                "type": typ or "string",
                "required": True,
                "array": False,
            })

        return "", params

    def _extract_operations(self):
 
        messages = self._collect_messages()
        port_type_ops = self._collect_port_type_ops()
        bindings = self._collect_bindings()
        binding_to_ports = self._build_binding_to_ports()

        seen = set()

        for binding_name, binding in bindings.items():
            port_type = binding.get("portType", "")
            port_mappings = binding_to_ports.get(binding_name, [])

            if not port_mappings:
                port_mappings = [{
                    "service": "",
                    "port": "",
                    "endpoint": "",
                    "binding": binding_name,
                }]

            for op_name, binding_op in binding.get("operations", {}).items():
                pt_op = port_type_ops.get((port_type, op_name), {})
                input_msg_name = pt_op.get("input_msg", "")
                output_msg_name = pt_op.get("output_msg", "")

                input_parts = messages.get(input_msg_name, [])
                output_parts = messages.get(output_msg_name, [])

                input_element, input_params = self._params_from_message_parts(input_parts)
                output_element, output_params = self._params_from_message_parts(output_parts)

                for port_info in port_mappings:
                    dedupe_key = (
                        port_info.get("service", ""),
                        port_info.get("port", ""),
                        port_info.get("endpoint", ""),
                        binding_name,
                        op_name,
                    )

                    if dedupe_key in seen:
                        continue

                    seen.add(dedupe_key)

                    self.parsed_operations.append({
                        "name": op_name,
                        "soapAction": binding_op.get("soapAction", ""),
                        "soap_action": binding_op.get("soap_action", ""),
                        "input_params": input_params,
                        "output_params": output_params,
                        "input_element": input_element or op_name,
                        "output_element": output_element,
                        "input_message": input_msg_name,
                        "output_message": output_msg_name,
                        "binding": binding_name,
                        "portType": port_type,
                        "service": port_info.get("service", ""),
                        "port": port_info.get("port", ""),
                        "endpoint": port_info.get("endpoint", ""),
                    })

    def _generate_sample_request(self, operation):
        """Generate approximate sample SOAP request for operation."""
        input_element = operation.get("input_element") or operation["name"]
        params = operation.get("input_params", [])
        tns = self.target_namespace or "http://tempuri.org/"

        params_xml = ""

        for p in params:
            default_val = self._get_type_default(p.get("type", "string"))
            default_val = html.escape(str(default_val), quote=False)

            params_xml += (
                f'      <tns:{p["name"]}>{default_val}</tns:{p["name"]}>\n'
            )

        if not params_xml:
            params_xml = "      <!-- no parameters defined -->\n"

        return (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"\n'
            f'               xmlns:tns="{html.escape(tns, quote=True)}">\n'
            "  <soap:Body>\n"
            f"    <tns:{input_element}>\n"
            f"{params_xml}"
            f"    </tns:{input_element}>\n"
            "  </soap:Body>\n"
            "</soap:Envelope>"
        )

    def run(self):
        if not self._fetch_wsdl():
            ptprint("No WSDL exposure detected.", "OK",
                    not self.args.json, indent=4)
            return

        root = self._parse_wsdl_xml(self.helpers.wsdl_content)

        if root is None:
            ptprint("WSDL found but could not be parsed.", "INFO",
                    not self.args.json, indent=4)
            return

        self.target_namespace = root.get("targetNamespace", "")

        self._add_doc(self.helpers.wsdl_url, root)
        self.visited_imports.add(self.helpers.wsdl_url)

        self._resolve_imports(root, self.helpers.wsdl_url)

        for doc in self.all_wsdl_docs:
            self._extract_types(doc["root"])

        for doc in self.all_wsdl_docs:
            self._extract_services(doc["root"])

        self._extract_operations()

        self.helpers.known_operations = sorted(set(
            op["name"] for op in self.parsed_operations
        ))

        self.helpers.parsed_services = self.parsed_services
        self.helpers.parsed_operations = self.parsed_operations
        self.helpers.type_definitions = self.type_definitions
        self.helpers.target_namespace = self.target_namespace

        op_count = len(self.parsed_operations)
        unique_op_names = sorted(set(op["name"] for op in self.parsed_operations))

        evidence = (
            f"WSDL accessible at {self.helpers.wsdl_url}. "
            f"Namespace: {self.target_namespace}. "
            f"Operations ({len(unique_op_names)} unique, {op_count} endpoint-bound): "
            f"{', '.join(unique_op_names[:15])}"
        )

        self.ptjsonlib.add_vulnerability(
            "PTV-SOAP-WSDL-EXPOSURE",
            node_key=self.helpers.node_key,
            data={
                "summary": "SOAP WSDL is publicly accessible.",
                "description": (
                    "The endpoint exposes a WSDL document, allowing SOAP service, "
                    "endpoint, operation and schema discovery."
                ),
                "wsdlUrl": self.helpers.wsdl_url,
                "targetNamespace": self.target_namespace,
                "serviceCount": len(self.parsed_services),
                "uniqueOperationCount": len(unique_op_names),
                "endpointBoundOperationCount": op_count,
                "importedDocumentCount": max(0, len(self.all_wsdl_docs) - 1),
                "operations": unique_op_names,
                "confidence": "direct evidence",
                "evidence": evidence,
            },
        )

        ptprint(
            f"WSDL exposure confirmed. Namespace: {self.target_namespace}",
            "VULN",
            not self.args.json,
            indent=4,
            colortext=True,
        )

        if len(self.all_wsdl_docs) > 1:
            ptprint(
                f"  Imported documents parsed: {len(self.all_wsdl_docs) - 1} "
                f"(limit {self.max_imports}).",
                "INFO",
                not self.args.json,
                indent=4,
            )

        for svc in self.parsed_services:
            ptprint(f"  Service: {svc['name']}",
                    "PARSED", not self.args.json, indent=4)

            for port in svc["ports"]:
                ptprint(
                    f"    Port: {port['name']} -> {port['address']} "
                    f"(binding: {port['binding']})",
                    "PARSED",
                    not self.args.json,
                    indent=4,
                )

        for op in self.parsed_operations:
            if op["input_params"]:
                param_parts = [
                    f"{p['name']}: {p['type']}"
                    + (" (required)" if p.get("required") else "")
                    + (" []" if p.get("array") else "")
                    for p in op["input_params"]
                ]
                params_str = f"({', '.join(param_parts)})"
            else:
                params_str = "()"

            action_str = (
                f" [SOAPAction: {op['soapAction']}]"
                if op.get("soapAction")
                else ""
            )

            endpoint_str = (
                f" @ {op['endpoint']}"
                if op.get("endpoint")
                else ""
            )

            ptprint(
                f"  Operation: {op['name']}{params_str}{action_str}{endpoint_str}",
                "PARSED",
                not self.args.json,
                indent=4,
            )

        if self.parsed_operations:
            ptprint("Sample requests:", "INFO", not self.args.json, indent=4)

            for op in self.parsed_operations:
                sample = self._generate_sample_request(op)

                label = op["name"]

                if op.get("endpoint"):
                    label += f" @ {op['endpoint']}"

                ptprint(f"  --- {label} ---",
                        "PARSED", not self.args.json, indent=4)

                for line in sample.split("\n"):
                    ptprint(f"    {line}",
                            "PARSED", not self.args.json, indent=4)

        api_structure = {
            "type": "soap",
            "wsdlUrl": self.helpers.wsdl_url,
            "targetNamespace": self.target_namespace,
            "imports": [
                doc["url"] for doc in self.all_wsdl_docs
                if doc["url"] != self.helpers.wsdl_url
            ],
            "services": [],
            "operations": [],
        }

        for svc in self.parsed_services:
            api_structure["services"].append({
                "name": svc["name"],
                "ports": [
                    {
                        "name": p["name"],
                        "address": p["address"],
                        "binding": p["binding"],
                    }
                    for p in svc["ports"]
                ],
            })

        for op in self.parsed_operations:
            api_structure["operations"].append({
                "name": op["name"],
                "service": op.get("service", ""),
                "port": op.get("port", ""),
                "endpoint": op.get("endpoint", ""),
                "binding": op.get("binding", ""),
                "portType": op.get("portType", ""),
                "soapAction": op.get("soapAction", ""),
                "inputElement": op.get("input_element", ""),
                "outputElement": op.get("output_element", ""),
                "inputMessage": op.get("input_message", ""),
                "outputMessage": op.get("output_message", ""),
                "parameters": [
                    {
                        "name": p["name"],
                        "type": p["type"],
                        "required": p.get("required", True),
                        "array": p.get("array", False),
                        "nillable": p.get("nillable", False),
                    }
                    for p in op["input_params"]
                ],
                "outputParameters": [
                    {
                        "name": p["name"],
                        "type": p["type"],
                        "required": p.get("required", True),
                        "array": p.get("array", False),
                        "nillable": p.get("nillable", False),
                    }
                    for p in op.get("output_params", [])
                ],
                "sampleRequest": self._generate_sample_request(op),
            })

        self.ptjsonlib.add_properties(
            properties={
                "apiSchema": api_structure,
                "soapWsdlParsing": {
                    "wsdlAccessible": True,
                    "importedDocumentCount": max(0, len(self.all_wsdl_docs) - 1),
                    "importLimit": self.max_imports,
                    "serviceCount": len(self.parsed_services),
                    "uniqueOperationCount": len(unique_op_names),
                    "endpointBoundOperationCount": op_count,
                },
            },
            node_key=self.helpers.node_key,
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    WSDLExposure(args, ptjsonlib, helpers, http_client, common_tests).run()