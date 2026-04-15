#!/usr/bin/python3
"""
    Copyright (c) 2025 Penterep Security s.r.o.

    graphql is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    graphql is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with graphql.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import re
import sys

sys.path.append(__file__.rsplit("/", 1)[0])


from argparse import Namespace
from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib
from ptlibs.ptprinthelper import ptprint
import importlib
from helpers.helpers import BaseArgs
from modules.graphql.graphql import PtGraphQL
from modules.soap.soap import PtSOAP
from modules.common_tests.common_tests import CommonTests

MODULES = {
    "graphql": PtGraphQL,
    "soap": PtSOAP
}

class PtApitester:
    def __init__(self, args: Namespace, base_request) -> None:
        self.args = args
        self.base_request = base_request


    def run(self) -> None:
        """Main method"""

        if not self.args.module:
            return


        module = importlib.import_module(f"modules.{self.args.module}.{self.args.module}")
        module.main(self.args, CommonTests(self.args, self.base_request))


def get_help():
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
    return [
        {"description": ["PTAPITESTER"]},
        {"usage": ["ptapitester [API_TYPE] <options>"]},
        {"usage_example": [
            "ptapitester -u https://www.example.com",
            "ptapitester GRAPHQL -u https://www.example.com -ts introspection"
        ]},
        {"options": [
            ["GRAPHQL", "<options>", "", "GraphQL testing module"],
            ["", " ", "", ""],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-u", "--url", "<URL>", "Connect to URL"]
        ]
        }]


def parse_args():
    def check_url(url: str) -> str:
        """
        This method edits the provided URL.

        Adds '\\http://' to the begging of the URL if no protocol is provided

        www.example.com:1234 -> \\http://www.example.com:1234

        Doesn't do anything if a protocol is provided

        Also adds trailing '/' if missing

        :return: Edited URL
        """

        if "http://" not in url and "https://" not in url:
            url = "http://" + url

        return url

    if len(sys.argv) == 1:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    # Normalize module name to lowercase (case-insensitive module names)
    if len(sys.argv) >= 2 and not sys.argv[1].startswith("-"):
        sys.argv[1] = sys.argv[1].lower()

    # Case 2: Only module specified without arguments - show module help
    if len(sys.argv) == 2 and sys.argv[1] in MODULES:
        module_name = sys.argv[1]
        module_help = MODULES[module_name].module_args().get_help()
        ptprinthelper.help_print(module_help, f"{SCRIPTNAME} {module_name}", __version__)
        sys.exit(0)

    # Case 2b: Non-existent module (e.g. ptsrvtester FOO) - show banner, error, and our help
    if len(sys.argv) >= 2 and sys.argv[1] not in MODULES and not sys.argv[1].startswith("-"):
        ptprinthelper.print_banner(SCRIPTNAME, __version__, False)
        print(f"\n\033[31m[✗]\033[0m Error: Unknown module '{sys.argv[1]}'")
        print(f"\nAvailable modules: {', '.join(MODULES.keys())}")
        print(f"\nUse 'ptapitester -h' for help.\n")
        sys.exit(2)

    # Case 3: Help flag present
    if "-h" in sys.argv or "--help" in sys.argv or "--h" in sys.argv or "-help" in sys.argv:
        # Check if module is specified
        if len(sys.argv) >= 2 and sys.argv[1] in MODULES:
            # Show module-specific help
            module_name = sys.argv[1]
            module_help = MODULES[module_name].module_args().get_help()
            ptprinthelper.help_print(module_help, f"{SCRIPTNAME} {module_name}", __version__)
            sys.exit(0)
        else:
            # Show main help
            ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
            sys.exit(0)

    # Shared error message storage
    shared_error = {'message': None}

    # Custom ArgumentParser that stores error message
    class CustomArgumentParser(argparse.ArgumentParser):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.error_message = None
            # Override parser_class for subparsers
            if 'parser_class' not in kwargs:
                kwargs['parser_class'] = CustomArgumentParser

        def error(self, message):
            # Store error message in both instance and shared storage
            self.error_message = message
            shared_error['message'] = message
            raise SystemExit(2)

        def parse_args(self, *args, **kwargs):
            try:
                return super().parse_args(*args, **kwargs)
            except argparse.ArgumentError as e:
                # Store the error message before it gets lost
                self.error_message = e.message
                # Re-raise to let argparse handle it normally
                raise

    parser = CustomArgumentParser(add_help=True)

    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}", help="print version"
    )
    parser.add_argument("-j", "--json", action="store_true", help="use Penterep JSON output format")
    parser.add_argument("-vv", "--verbose",        action="store_true")
    parser.add_argument("-u", "--url", type=str, required=False)
    parser.add_argument("-ts", "--tests", type=lambda s: s.lower(), nargs="+")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-H", "--headers", type=ptmisclib.pairs, nargs="+", default={"User-Agent": "Penterep"})

    # Subparser for every application module
    subparsers = parser.add_subparsers(required=False, dest="module", parser_class=CustomArgumentParser)
    for name, module in MODULES.items():
        module.module_args().add_subparser(name, subparsers)
    # Global options must be on each subparser too (subparser parses the remainder of argv)
    for subp in subparsers.choices.values():
        subp.add_argument("-j", "--json", action="store_true", help="use Penterep JSON output format")
        subp.add_argument("-u", "--url", type=str, required=True)
        subp.add_argument("-vv", "--verbose", action="store_true")
        subp.add_argument("-br", "--base_request", default=None)

    # First parse to get the module name, second parse to get the module-specific arguments
    try:
        args = parser.parse_args(namespace=BaseArgs)
        args.url = check_url(args.url)

        # Detect API
        ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
        found_api, base_request = CommonTests(args).identify_api(args.module)
        detected_url = args.url
        ptprint(" ", "TEXT")
        args.base_request = base_request

        if args.module is not None and args.tests is not None:
            temp_test = args.tests
            args.tests = None
            CommonTests(args, base_request).run()
            args.tests = temp_test

        # Adjust argv if no API module was specified
        if found_api and args.module is None:
            if args.tests is None:  # Run all API-specific tests if generic API tests not specified
                sys.argv.insert(1, found_api)
                args.module = found_api
                CommonTests(args, base_request).run()
            if args.tests is not None: # Run only specified generic API tests and exit
                CommonTests(args, base_request).run()
                sys.exit(0)

        args = parser.parse_args(namespace=MODULES[args.module].module_args())
        args.url = detected_url
        args.base_request = base_request

        sys.argv = sys.argv[1:]

        # Reject unknown options: argparse can treat -i as prefix of -ie etc., so check explicitly
        subp = subparsers.choices[args.module]
        known = set()
        takes_value = set()
        for a in subp._actions:
            for opt in getattr(a, "option_strings", ()):
                known.add(opt)
                if getattr(a, "nargs", None) != 0 and (
                        getattr(a, "nargs", None) is not None or getattr(a, "type", None) is not None
                ):
                    takes_value.add(opt)
        argv = sys.argv[2:]
        i = 0
        invalid = []
        while i < len(argv):
            tok = argv[i]
            if tok == "--":
                i += 1
                break
            if not tok.startswith("-") or tok == "-":
                i += 1
                continue
            if tok in known:
                if tok in takes_value and i + 1 < len(argv) and not argv[i + 1].startswith("-") and argv[i + 1] != "--":
                    i += 2
                else:
                    i += 1
                continue
            invalid.append(tok)
            i += 1
        if invalid:
            shared_error["message"] = f"Invalid option(s): {', '.join(invalid)}"
            raise SystemExit(2)
    except (SystemExit, argparse.ArgumentError) as e:
        # Argparse error occurred
        error_code = e.code if isinstance(e, SystemExit) else 2

        if error_code != 0:  # 0 means success (e.g., --version was called)
            # Print banner first
            ptprinthelper.print_banner(SCRIPTNAME, __version__, False)

            # Get error message
            error_msg = None
            if isinstance(e, argparse.ArgumentError):
                error_msg = e.message
            elif isinstance(e, SystemExit):
                # Check shared error message (set by any CustomArgumentParser instance)
                if shared_error['message']:
                    error_msg = shared_error['message']
                # Fallback to parser error message
                elif hasattr(parser, 'error_message') and parser.error_message:
                    error_msg = parser.error_message

            # Make error message user-friendly for invalid options
            if error_msg and "unrecognized arguments:" in error_msg:
                match = re.search(r"unrecognized arguments:\s*(.+)", error_msg)
                invalid = match.group(1).strip() if match else error_msg
                error_msg = f"Invalid option(s): {invalid}"
            elif error_msg and "the following arguments are required:" in error_msg:
                # "required: target" is misleading when user typed invalid option (e.g. -dfsdfs)
                # Only flag as invalid if option looks suspicious: -xxx with >2 letters (not -i, -sd)
                invalid_arg = None
                if len(sys.argv) >= 3 and sys.argv[1] in MODULES:
                    for arg in sys.argv[2:]:
                        if arg.startswith("-") and not arg.startswith("--"):
                            if len(arg) > 4:
                                invalid_arg = arg
                                break
                if invalid_arg:
                    error_msg = f"Invalid option: {invalid_arg}"

            # Always show error message (no help on error)
            if error_msg:
                print(f"\n\033[31m[✗]\033[0m Error: {error_msg}")
            else:
                print(f"\n\033[31m[✗]\033[0m Error: Invalid arguments")
            print()
        sys.exit(error_code)



    return args, base_request


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptapitester"
    args, base_request = parse_args()
    script = PtApitester(args, base_request)
    script.run()


if __name__ == "__main__":
    main()
