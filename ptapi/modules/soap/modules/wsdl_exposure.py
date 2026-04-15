"""
SOAP WSDL Exposure and Parsing test

Tests whether WSDL is publicly accessible and performs full parsing:
- Services and their endpoints
- Operations and their SOAPAction
- Parameters and data types from XSD schema
- Imported/included WSDL documents
- Sample request generation for each operation
"""
from lxml import etree
from urllib.parse import urljoin
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "SOAP WSDL exposure test"

# Common WSDL/XSD namespaces
NS = {
    'wsdl': 'http://schemas.xmlsoap.org/wsdl/',
    'soap': 'http://schemas.xmlsoap.org/wsdl/soap/',
    'soap12': 'http://schemas.xmlsoap.org/wsdl/soap12/',
    'xsd': 'http://www.w3.org/2001/XMLSchema',
    'xs': 'http://www.w3.org/2001/XMLSchema',
}

# XSD type -> example value mapping
XSD_DEFAULTS = {
    'string': 'string', 'int': '0', 'integer': '0',
    'long': '0', 'short': '0', 'byte': '0',
    'float': '0.0', 'double': '0.0', 'decimal': '0.0',
    'boolean': 'true', 'date': '2025-01-01',
    'dateTime': '2025-01-01T00:00:00', 'time': '00:00:00',
    'base64Binary': 'dGVzdA==', 'hexBinary': '74657374',
    'anyURI': 'http://example.com', 'token': 'token',
    'normalizedString': 'text', 'positiveInteger': '1',
    'nonNegativeInteger': '0', 'unsignedInt': '0',
    'unsignedLong': '0', 'unsignedShort': '0',
}


class WSDLExposure:
    def __init__(self, args, ptjsonlib, helpers, http_client, common_tests):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.common_tests = common_tests
        self.helpers.print_header(__TESTLABEL__)

        self.parsed_services = []   # [{name, ports: [{name, address, binding}]}]
        self.parsed_operations = [] # [{name, soapAction, input_params, output_params, sample_request}]
        self.type_definitions = {}  # {type_name: [{param_name, param_type}]}
        self.all_wsdl_docs = []     # list of parsed etree roots (main + imports)
        self.target_namespace = ""

    # =========================================================================
    # WSDL Fetching
    # =========================================================================
    def _fetch_wsdl(self):
        """Try to fetch WSDL from various paths."""
        if self.helpers.wsdl_content:
            return True

        wsdl_paths = [
            self.helpers.endpoint_url.rstrip('/') + "?wsdl",
            self.helpers.endpoint_url.rstrip('/') + "?WSDL",
            self.helpers.base_url + "/?wsdl",
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

    # =========================================================================
    # XML Parsing
    # =========================================================================
    def _parse_wsdl_xml(self, content):
        """Parse WSDL XML content into etree, returns root or None."""
        try:
            parser = etree.XMLParser(recover=True, remove_comments=True)
            return etree.fromstring(content.encode('utf-8') if isinstance(content, str) else content, parser=parser)
        except Exception as e:
            ptprint(f"  WSDL XML parse error: {e}", "WARNING", not self.args.json, indent=4)
            return None

    def _resolve_imports(self, root, base_url):
        """Fetch and parse imported/included WSDL documents."""
        # wsdl:import
        for imp in root.findall('.//wsdl:import', NS):
            location = imp.get('location', '')
            if location:
                resolved_url = urljoin(base_url, location)
                self._fetch_and_parse_import(resolved_url)

        # xsd:import and xsd:include
        for tag in ['xsd:import', 'xsd:include', 'xs:import', 'xs:include']:
            for imp in root.findall(f'.//{tag}', NS):
                location = imp.get('schemaLocation', '')
                if location:
                    resolved_url = urljoin(base_url, location)
                    self._fetch_and_parse_import(resolved_url)

    def _fetch_and_parse_import(self, url):
        """Fetch an imported WSDL/XSD document and add to parsed docs."""
        try:
            r = self.helpers.send_get_request(url)
            if r and r.status_code == 200:
                imported_root = self._parse_wsdl_xml(r.text)
                if imported_root is not None:
                    self.all_wsdl_docs.append(imported_root)
                    ptprint(f"  Imported: {url}", "PARSED", not self.args.json, indent=4)
                    # Recursively resolve imports in the imported doc
                    self._resolve_imports(imported_root, url)
        except Exception:
            pass

    # =========================================================================
    # Type/Schema Extraction
    # =========================================================================
    def _extract_types(self, root):
        """Extract XSD type definitions from wsdl:types."""
        for schema in root.findall('.//wsdl:types/xsd:schema', NS):
            self._parse_schema(schema)

        # Also parse standalone schemas (from imported XSD files)
        if root.tag.endswith('}schema') or root.tag == 'schema':
            self._parse_schema(root)

    def _parse_schema(self, schema):
        """Parse an XSD schema element for type definitions."""
        # 1. First parse complexType definitions (they are referenced by elements)
        for ct in schema.findall('xsd:complexType', NS):
            name = ct.get('name', '')
            if not name or name in self.type_definitions:
                continue
            params = self._extract_complex_type_params(ct, schema)
            if params:
                self.type_definitions[name] = params

        # 2. Then parse element definitions (may reference complexTypes via type= attribute)
        for elem in schema.findall('xsd:element', NS):
            name = elem.get('name', '')
            if not name or name in self.type_definitions:
                continue
            params = self._extract_element_params(elem, schema)
            if params:
                self.type_definitions[name] = params

    def _extract_element_params(self, element, schema):
        """Extract parameters from an xs:element."""
        params = []

        # Inline complexType
        for ct in element.findall('xsd:complexType', NS):
            params.extend(self._extract_complex_type_params(ct, schema))

        # Reference to a type
        type_ref = element.get('type', '')
        if type_ref and not params:
            type_name = type_ref.split(':')[-1]
            if type_name in self.type_definitions:
                params = self.type_definitions[type_name]

        return params

    def _extract_complex_type_params(self, complex_type, schema):
        """Extract parameters from an xs:complexType."""
        params = []
        seen = set()

        # Use single namespace lookup (xsd and xs map to same URI)
        for seq in complex_type.findall('xsd:sequence', NS) + \
                   complex_type.findall('xsd:all', NS):
            for elem in seq.findall('xsd:element', NS):
                param_name = elem.get('name', '')
                param_type = elem.get('type', 'string')
                param_type = param_type.split(':')[-1]

                min_occurs = elem.get('minOccurs', '1')
                max_occurs = elem.get('maxOccurs', '1')

                if param_name and param_name not in seen:
                    seen.add(param_name)
                    params.append({
                        'name': param_name,
                        'type': param_type,
                        'required': min_occurs != '0',
                        'array': max_occurs == 'unbounded',
                    })

        return params

    def _get_type_default(self, type_name):
        """Get a default example value for an XSD type."""
        return XSD_DEFAULTS.get(type_name, '?')

    # =========================================================================
    # Service/Port/Operation Extraction
    # =========================================================================
    def _extract_services(self, root):
        """Extract wsdl:service -> wsdl:port -> soap:address."""
        for service in root.findall('wsdl:service', NS):
            svc = {'name': service.get('name', 'unknown'), 'ports': []}

            for port in service.findall('wsdl:port', NS):
                port_info = {
                    'name': port.get('name', ''),
                    'binding': port.get('binding', '').split(':')[-1],
                    'address': '',
                }
                # soap:address or soap12:address
                for addr in port.findall('soap:address', NS) + port.findall('soap12:address', NS):
                    port_info['address'] = addr.get('location', '')

                svc['ports'].append(port_info)

            self.parsed_services.append(svc)

    def _extract_operations(self, root):
        """Extract operations from wsdl:binding -> wsdl:operation."""
        # Build message -> element mapping
        messages = {}
        for msg in root.findall('wsdl:message', NS):
            msg_name = msg.get('name', '')
            for part in msg.findall('wsdl:part', NS):
                element = part.get('element', '').split(':')[-1]
                part_type = part.get('type', '').split(':')[-1]
                messages[msg_name] = element or part_type

        # Build portType operation -> input/output message mapping
        port_type_ops = {}
        for pt in root.findall('wsdl:portType', NS):
            for op in pt.findall('wsdl:operation', NS):
                op_name = op.get('name', '')
                input_msg = ''
                output_msg = ''
                inp = op.find('wsdl:input', NS)
                if inp is not None:
                    input_msg = inp.get('message', '').split(':')[-1]
                out = op.find('wsdl:output', NS)
                if out is not None:
                    output_msg = out.get('message', '').split(':')[-1]
                port_type_ops[op_name] = {'input_msg': input_msg, 'output_msg': output_msg}

        # Extract from bindings — deduplicate by operation name
        seen_ops = set()
        for binding in root.findall('wsdl:binding', NS):
            for op in binding.findall('wsdl:operation', NS):
                op_name = op.get('name', '')
                if op_name in seen_ops:
                    continue
                seen_ops.add(op_name)

                soap_action = ''

                for soap_op in op.findall('soap:operation', NS) + op.findall('soap12:operation', NS):
                    soap_action = soap_op.get('soapAction', '')

                # Get input parameters from message -> element -> type chain
                input_params = []
                pt_op = port_type_ops.get(op_name, {})
                input_msg_name = pt_op.get('input_msg', '')
                input_element = messages.get(input_msg_name, '')

                if input_element and input_element in self.type_definitions:
                    input_params = self.type_definitions[input_element]

                self.parsed_operations.append({
                    'name': op_name,
                    'soapAction': soap_action,
                    'input_params': input_params,
                    'input_element': input_element,
                })

    # =========================================================================
    # Sample Request Generation
    # =========================================================================
    def _generate_sample_request(self, operation):
        """Generate a sample SOAP request for an operation."""
        op_name = operation['name']
        soap_action = operation.get('soapAction', '')
        input_element = operation.get('input_element', op_name)
        params = operation.get('input_params', [])
        tns = self.target_namespace or 'http://tempuri.org/'

        # Build parameter XML
        params_xml = ''
        for p in params:
            default_val = self._get_type_default(p['type'])
            params_xml += f'      <tns:{p["name"]}>{default_val}</tns:{p["name"]}>\n'

        if not params_xml:
            params_xml = '      <!-- no parameters defined -->\n'

        sample = (
            f'<?xml version="1.0" encoding="utf-8"?>\n'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"\n'
            f'               xmlns:tns="{tns}">\n'
            f'  <soap:Body>\n'
            f'    <tns:{input_element}>\n'
            f'{params_xml}'
            f'    </tns:{input_element}>\n'
            f'  </soap:Body>\n'
            f'</soap:Envelope>'
        )
        return sample

    # =========================================================================
    # Main Run
    # =========================================================================
    def run(self):
        if not self._fetch_wsdl():
            ptprint("No WSDL exposure detected.", "OK", not self.args.json, indent=4)
            return

        # Parse main WSDL
        root = self._parse_wsdl_xml(self.helpers.wsdl_content)
        if root is None:
            ptprint("WSDL found but could not be parsed.", "INFO",
                    not self.args.json, indent=4)
            return

        self.all_wsdl_docs.append(root)
        self.target_namespace = root.get('targetNamespace', '')

        # Resolve imports
        self._resolve_imports(root, self.helpers.wsdl_url)

        # Extract types from all docs
        for doc in self.all_wsdl_docs:
            self._extract_types(doc)

        # Extract services and operations from main doc
        self._extract_services(root)
        self._extract_operations(root)

        # Update helpers with parsed operations
        self.helpers.known_operations = [op['name'] for op in self.parsed_operations]

        # Store parsed structure in helpers for other modules
        self.helpers.parsed_services = self.parsed_services
        self.helpers.parsed_operations = self.parsed_operations
        self.helpers.type_definitions = self.type_definitions

        # =====================================================================
        # Output
        # =====================================================================
        op_count = len(self.parsed_operations)
        evidence = f"WSDL accessible at {self.helpers.wsdl_url}. Namespace: {self.target_namespace}"

        if self.parsed_operations:
            op_names = [op['name'] for op in self.parsed_operations]
            evidence += f". Operations ({op_count}): {', '.join(op_names[:15])}"

        self.ptjsonlib.add_vulnerability("PTV-SOAP-WSDL-EXPOSED",
                                          node_key=self.helpers.node_key,
                                          data={"evidence": evidence})

        ptprint(f"WSDL exposure confirmed. Namespace: {self.target_namespace}",
                "VULN", not self.args.json, indent=4, colortext=True)

        # Print services
        for svc in self.parsed_services:
            ptprint(f"  Service: {svc['name']}", "PARSED", not self.args.json, indent=4)
            for port in svc['ports']:
                ptprint(f"    Port: {port['name']} -> {port['address']}",
                        "PARSED", not self.args.json, indent=4)

        # Print operations with parameters
        for op in self.parsed_operations:
            params_str = ""
            if op['input_params']:
                param_parts = [f"{p['name']}: {p['type']}" +
                               (" (required)" if p.get('required') else "") +
                               (" []" if p.get('array') else "")
                               for p in op['input_params']]
                params_str = f"({', '.join(param_parts)})"
            else:
                params_str = "()"

            action_str = f" [SOAPAction: {op['soapAction']}]" if op['soapAction'] else ""
            ptprint(f"  Operation: {op['name']}{params_str}{action_str}",
                    "PARSED", not self.args.json, indent=4)

        # Print sample requests
        if self.parsed_operations:
            ptprint("", "TEXT", not self.args.json)
            ptprint("Sample requests:", "INFO", not self.args.json, indent=4)
            for op in self.parsed_operations:
                sample = self._generate_sample_request(op)
                ptprint(f"  --- {op['name']} ---", "PARSED", not self.args.json, indent=4)
                for line in sample.split('\n'):
                    ptprint(f"    {line}", "PARSED", not self.args.json, indent=4)

        # Add parsed structure to node properties
        api_structure = {
            "targetNamespace": self.target_namespace,
            "services": [],
            "operations": [],
        }
        for svc in self.parsed_services:
            api_structure["services"].append({
                "name": svc['name'],
                "ports": [{"name": p['name'], "address": p['address'],
                           "binding": p['binding']} for p in svc['ports']],
            })
        for op in self.parsed_operations:
            api_structure["operations"].append({
                "name": op['name'],
                "soapAction": op['soapAction'],
                "parameters": [{"name": p['name'], "type": p['type'],
                                "required": p.get('required', True)}
                               for p in op['input_params']],
                "sampleRequest": self._generate_sample_request(op),
            })

        self.ptjsonlib.add_properties(
            properties={"apiSchema": api_structure},
            node_key=self.helpers.node_key
        )


def run(args, ptjsonlib, helpers, http_client, common_tests):
    WSDLExposure(args, ptjsonlib, helpers, http_client, common_tests).run()