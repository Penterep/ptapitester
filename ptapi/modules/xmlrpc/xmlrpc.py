import argparse
import sys
from argparse import Namespace
from io import StringIO

sys.path.append(__file__.rsplit("/", 1)[0])

import threading, importlib, os
from types import ModuleType
from ptthreads import ptthreads
from _version import __version__
from .helpers.helpers import Helpers
from .helpers._thread_local_stdout import ThreadLocalStdout
from ptlibs import ptjsonlib, ptmisclib
from ptlibs.http.http_client import HttpClient
from ptlibs.ptprinthelper import ptprint


global SCRIPTNAME
SCRIPTNAME = "xmlrpc"


class XMLRPCArgs(Namespace):
    def get_help(self):
        def _get_available_modules_help() -> list:
            rows = []
            available_modules = _get_all_available_modules()
            for module_name in available_modules:
                mod = _import_module_from_path(module_name)
                label = getattr(mod, "__TESTLABEL__", f"Test for {module_name.upper()}")
                row = ["", "", f" {module_name.upper()}", label]
                rows.append(row)
            return sorted(rows, key=lambda x: x[2])

        return [
            {"description": ["XML-RPC API security testing module"]},
            {"usage": ["XMLRPC <options>"]},
            {"usage_example": [
                "ptapi XMLRPC -u https://www.example.com/xmlrpc.php",
                "ptapi XMLRPC -u https://www.example.com -ts introspection",
            ]},
            {"options": [
                ["-u", "--url", "<url>", "Connect to URL"],
                ["-p", "--proxy", "<proxy>", "Set proxy (e.g. http://127.0.0.1:8080)"],
                ["-ts", "--tests", "<test>", "Specify one or more tests to perform:"],
                *_get_available_modules_help(),
                ["-t", "--threads", "<threads>", "Set thread count (default 10)"],
                ["-T", "--timeout", "", "Set timeout (default 10)"],
                ["-c", "--cookie", "<cookie>", "Set cookie"],
                ["-a", "--user-agent", "<a>", "Set User-Agent header"],
                ["-H", "--headers", "<header:value>", "Set custom header(s)"],
                ["-r", "--redirects", "", "Follow redirects (default False)"],
                ["-C", "--cache", "", "Cache HTTP communication (load from tmp in future)"],
                ["-v", "--version", "", "Show script version and exit"],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-j", "--json", "", "Output in JSON format"],
            ]}
        ]

    def add_subparser(self, name, subparsers):
        parser = subparsers.add_parser(
            name,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument("-p", "--proxy", type=str)
        parser.add_argument("-T", "--timeout", type=int, default=10)
        parser.add_argument("-a", "--user-agent", type=str, default="Penterep Tools")
        parser.add_argument("-ts", "--tests", type=lambda s: s.lower(), nargs="+")
        parser.add_argument("-c", "--cookie", type=str)
        parser.add_argument("-H", "--headers", type=ptmisclib.pairs, nargs="+",
                            default={"Content-Type": "text/xml"})
        parser.add_argument("-r", "--redirects", action="store_true")
        parser.add_argument("-C", "--cache", action="store_true")
        parser.add_argument("-v", "--version", action='version',
                            version=f'{SCRIPTNAME} {__version__}')

        parser.add_argument("--socket-address", type=str, default=None)
        parser.add_argument("--socket-port", type=str, default=None)
        parser.add_argument("--process-ident", type=str, default=None)

        return parser


class PtXMLRPC:
    @staticmethod
    def module_args():
        return XMLRPCArgs()

    def __init__(self, args, common_tests: object):
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.ptthreads = ptthreads.ptthreads()
        self._lock = threading.Lock()
        self.args = args
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.helpers = Helpers(args=self.args, ptjsonlib=self.ptjsonlib,
                               http_client=self.http_client)
        self.common_tests = common_tests

        self.thread_local_stdout = ThreadLocalStdout(sys.stdout)
        self.thread_local_stdout.activate()

    def _initialize_scan(self):
        """Create JSON node for the XML-RPC API."""
        # Create JSON node
        node = self.ptjsonlib.create_node_object("xmlrpc_api")
        self.helpers.node_key = node.get("key")
        self.ptjsonlib.add_node(node)

        self.ptjsonlib.add_properties(
            properties={"url": self.helpers.endpoint_url},
            node_key=self.helpers.node_key
        )

        ptprint(f"Target endpoint: {self.helpers.endpoint_url}", "INFO",
                not self.args.json, indent=4)
        ptprint(" ", "TEXT", not self.args.json)

    def run(self) -> None:
        """Main method — orchestrates XML-RPC security testing."""
        self._initialize_scan()

        tests = self.args.tests or _get_all_available_modules()

        # Introspection must run first — other tests depend on discovered methods
        if "introspection" in tests:
            tests.remove("introspection")
            self.run_single_module("introspection")

        # Undocumented methods must run before undocumented parameters
        # (parameters test uses found undocumented methods)
        if "undocumented_methods" in tests:
            tests.remove("undocumented_methods")
            self.run_single_module("undocumented_methods")

        if "undocumented_parameters" in tests:
            tests.remove("undocumented_parameters")

        # Run remaining tests in parallel
        self.ptthreads.threads(tests, self.run_single_module, self.args.threads)

        # Run undocumented parameters last (needs undocumented_methods results)
        if self.args.tests is None or "undocumented_parameters" in (self.args.tests or []):
            self.run_single_module("undocumented_parameters")

        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

    def run_single_module(self, module_name: str) -> None:
        """Dynamically loads and executes an XML-RPC test module."""
        try:
            with self._lock:
                module = _import_module_from_path(module_name)

            if hasattr(module, "run") and callable(module.run):
                buffer = StringIO()
                self.thread_local_stdout.set_thread_buffer(buffer)
                try:
                    module.run(
                        args=self.args,
                        ptjsonlib=self.ptjsonlib,
                        helpers=self.helpers,
                        http_client=self.http_client,
                        common_tests=self.common_tests
                    )
                except Exception as e:
                    ptprint(f"Error in module '{module_name}': {e}", "ERROR",
                            not self.args.json)
                finally:
                    self.thread_local_stdout.clear_thread_buffer()
                    with self._lock:
                        ptprint(buffer.getvalue(), "TEXT", not self.args.json, end="\n")
            else:
                ptprint(f"Module '{module_name}' does not have 'run' function",
                        "WARNING", not self.args.json)
        except FileNotFoundError:
            ptprint(f"Module '{module_name}' not found", "ERROR", not self.args.json)
        except Exception as e:
            ptprint(f"Error running module '{module_name}': {e}", "ERROR",
                    not self.args.json)


def _import_module_from_path(module_name: str) -> ModuleType:
    module_path = os.path.join(os.path.dirname(__file__), "modules", f"{module_name}.py")
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None:
        raise ImportError(f"Cannot find spec for {module_name} at {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _get_all_available_modules() -> list:
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")
    return [
        f.rsplit(".py", 1)[0]
        for f in sorted(os.listdir(modules_folder))
        if f.endswith(".py") and not f.startswith("_")
    ]


def main(args: Namespace, common_tests: object):
    global SCRIPTNAME
    SCRIPTNAME = "xmlrpc"
    script = PtXMLRPC(args, common_tests)
    script.run()