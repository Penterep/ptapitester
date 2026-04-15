import argparse
import sys
import json
from abc import abstractmethod
from argparse import Namespace
from email.policy import default
from io import StringIO
from json import JSONDecodeError

sys.path.append(__file__.rsplit("/", 1)[0])

import threading, importlib, os
from types import ModuleType
from ptthreads import ptthreads
from _version import __version__
from .helpers.helpers import Helpers
from .helpers._thread_local_stdout import ThreadLocalStdout
from ptlibs import ptjsonlib
from ptlibs.http.http_client import HttpClient
from ptlibs.ptprinthelper import ptprint


global SCRIPTNAME
SCRIPTNAME = "soap"


class SOAPArgs(Namespace):
    def get_help(self):
        """
        Generate structured help content for the CLI tool.

        This function dynamically builds a list of help sections including general
        description, usage, examples, and available options. The list of tests (modules)
        is generated at runtime by scanning the 'modules' directory and reading each module's
        optional '__TESTLABEL__' attribute to describe it.

        Returns:
            list: A list of dictionaries, where each dictionary represents a section of help
                    content (e.g., description, usage, options). The 'options' section includes
                    available command-line flags and dynamically discovered test modules.
        """

        # Build dynamic help from available modules
        def _get_available_modules_help() -> list:
            rows = []
            available_modules = _get_all_available_modules()
            modules_folder = os.path.join(os.path.dirname(__file__), "modules")
            for module in available_modules:
                mod = _import_module_from_path(module)
                label = getattr(mod, "__TESTLABEL__", f"Test for {module.upper()}")
                row = ["", "", f" {module.upper()}", label]
                rows.append(row)
            return sorted(rows, key=lambda x: x[2])

        return [
            {"description": ["Penterep template script"]},
            {"usage": ["SOAP <options>"]},
            {"usage_example": [
                "soap -u https://www.example.com",
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
            ]
            }]

    def add_subparser(self, name, subparsers):
        parser = subparsers.add_parser(
            name,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument("-p", "--proxy", type=str)
        parser.add_argument("-T", "--timeout", type=int, default=10)
        parser.add_argument("-a", "--user-agent", type=str, default="Penterep Tools")
        parser.add_argument("-c", "--cookie", type=str)
        parser.add_argument("-r", "--redirects", action="store_true")
        parser.add_argument("-C", "--cache", action="store_true")
        parser.add_argument("-v", "--version", action='version', version=f'{SCRIPTNAME} {__version__}')

        parser.add_argument("--socket-address", type=str, default=None)
        parser.add_argument("--socket-port", type=str, default=None)
        parser.add_argument("--process-ident", type=str, default=None)

        return parser


class PtSOAP:
    @staticmethod
    def module_args():
        return SOAPArgs()

    def __init__(self, args, common_tests: object):
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.ptthreads = ptthreads.ptthreads()
        self._lock = threading.Lock()
        self.args = args
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.helpers = Helpers(args=self.args, ptjsonlib=self.ptjsonlib, http_client=self.http_client)
        self.common_tests = common_tests

        # Activate ThreadLocalStdout stdout proxy
        self.thread_local_stdout = ThreadLocalStdout(sys.stdout)
        self.thread_local_stdout.activate()

    def run(self) -> None:
        """Main method"""

        # Run -ts tests or all modules
        tests = self.args.tests or _get_all_available_modules()

        self.ptthreads.threads(tests, self.run_single_module, self.args.threads)

        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

    def run_single_module(self, module_name: str) -> None:
        """
        Safely loads and executes a specified module's `run()` function.

        The method locates the module file in the "modules" directory, imports it dynamically,
        and executes its `run()` method with provided arguments and a shared `ptjsonlib` object.
        It also redirects stdout/stderr to a thread-local buffer for isolated output capture.

        If the module or its `run()` method is missing, or if an error occurs during execution,
        it logs appropriate messages to the user.

        Args:
            module_name (str): The name of the module (without `.py` extension) to execute.
        """
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
                    ptprint(e, "ERROR", not self.args.json)
                    error = e
                else:
                    error = None
                finally:
                    self.thread_local_stdout.clear_thread_buffer()
                    with self._lock:
                        ptprint(buffer.getvalue(), "TEXT", not self.args.json, end="\n")
            else:
                ptprint(f"Module '{module_name}' does not have 'run' function", "WARNING", not self.args.json)

        except FileNotFoundError as e:
            ptprint(f"Module '{module_name}' not found", "ERROR", not self.args.json)
        except Exception as e:
            ptprint(f"Error running module '{module_name}': {e}", "ERROR", not self.args.json)


def _import_module_from_path(module_name: str) -> ModuleType:
    """
    Dynamically imports a Python module from a given file path.

    This method uses `importlib` to load a module from a specific file location.
    The module is then registered in `sys.modules` under the provided name.

    Args:
        module_name (str): Name under which to register the module.

    Returns:
        ModuleType: The loaded Python module object.

    Raises:
        ImportError: If the module cannot be found or loaded.
    """
    module_path = os.path.join(os.path.dirname(__file__), "modules", f"{module_name}.py")

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None:
        raise ImportError(f"Cannot find spec for {module_name} at {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _get_all_available_modules() -> list:
    """
    Returns a list of available Python module names from the 'modules' directory.

    Modules must:
    - Not start with an underscore
    - Have a '.py' extension
    """
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")
    available_modules = [
        f.rsplit(".py", 1)[0]
        for f in sorted(os.listdir(modules_folder))
        if f.endswith(".py") and not f.startswith("_")
    ]
    return available_modules


def main(args: Namespace, common_tests: object):
    global SCRIPTNAME
    SCRIPTNAME = "soap"
    script = PtSOAP(args, common_tests)
    script.run()
