import sys
from argparse import Namespace


sys.path.append(__file__.rsplit("/", 1)[0])

import threading, importlib, os
from types import ModuleType
from ptthreads import ptthreads
from _version import __version__
from .helpers.helpers import Helpers, BaseRequest
from .helpers._thread_local_stdout import ThreadLocalStdout
from ptlibs import ptjsonlib
from ptlibs.http.http_client import HttpClient
from ptlibs.ptprinthelper import ptprint
from .modules.api_identify import identify_api


class CommonTests:
    def __init__(self, args, base_request=None):
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.ptthreads = ptthreads.ptthreads()
        self._lock = threading.Lock()
        self.args = args
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.helpers = Helpers(args=self.args, ptjsonlib=self.ptjsonlib, http_client=self.http_client)

        # Activate ThreadLocalStdout stdout proxy
        self.thread_local_stdout = ThreadLocalStdout(sys.stdout)
        self.thread_local_stdout.activate()
        self.base_request = base_request
        self.base_indent = 0


    def identify_api(self, module_name: str|None) -> tuple[str, BaseRequest]|None:
        return identify_api(self.args, self.ptjsonlib, self.helpers, self.http_client, module_name, printer=True)

    def run(self) -> None:
        """Main method"""
        tests = self.args.tests or _get_all_available_modules()

        if "api_identify" in tests:
            tests.remove("api_identify")

        for test in tests:
            self.run_single_module(test)

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
            module = _import_module_from_path(module_name)

            if hasattr(module, "run") and callable(module.run):

                try:
                    module.run(
                        args=self.args,
                        ptjsonlib=self.ptjsonlib,
                        helpers=self.helpers,
                        http_client=self.http_client,
                        base_indent=self.base_indent
                    )

                except Exception as e:
                    ptprint(e, "ERROR", not self.args.json)
                    error = e
                else:
                    error = None
                finally:
                    ptprint(" ", "TEXT", not self.args.json, end="\n")
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


def main(args: Namespace):
    global SCRIPTNAME
    SCRIPTNAME = "common tests"
    script = CommonTests(args)
    script.run()
