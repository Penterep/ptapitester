"""
GraphQL field suggestions module

This module tries to map the GraphQL types by stuffing words in the __type meta field

Contains:
- FieldSuggestions to perform the field suggestions
- run() function as an entry point for running the test
"""
import re
import copy
from http import HTTPStatus

import ptthreads
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.http.http_client import HttpClient
from argparse import Namespace
from ptlibs.ptprinthelper import ptprint
from requests.exceptions import JSONDecodeError
from requests import Response
import os
from ptthreads.ptthreads import ptthreads as PtThreads

__TESTLABEL__ = "GraphQL field suggestions"

FIELD_LIMIT = 1000


# All following regex are taken from the Clairvoyance project:
# https://github.com/nikitastupin/clairvoyance/blob/main/clairvoyance/oracle.py
MAIN_REGEX = r"""[_0-9A-Za-z\.\[\]!]+"""
REQUIRED_BUT_NOT_PROVIDED = r"""required(, but it was not provided| but not provided)?\."""

_FIELD_REGEXES = {
    'SKIP': [
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] must not have a selection since type ['"]""" + MAIN_REGEX + r"""['"] has no subfields\.""",
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] of type ['"]""" + MAIN_REGEX + r"""['"] must not have a sub selection\.""",
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] argument ['"]""" + MAIN_REGEX + r"""['"] of type ['"]""" + MAIN_REGEX + r"""['"] is """ + REQUIRED_BUT_NOT_PROVIDED,
        r"""Cannot query field ['"]""" + MAIN_REGEX + r"""['"] on type ['"]""" + MAIN_REGEX + r"""['"]\.""",
        r"""Cannot query field ['"]""" + MAIN_REGEX + r"""['"] on type ['"](""" + MAIN_REGEX + r""")['"]\. Did you mean to use an inline fragment on ['"]""" + MAIN_REGEX + r"""['"]\?""",
        r"""Cannot query field ['"]""" + MAIN_REGEX + r"""['"] on type ['"](""" + MAIN_REGEX + r""")['"]\. Did you mean to use an inline fragment on ['"]""" + MAIN_REGEX + r"""['"] or ['"]""" + MAIN_REGEX + r"""['"]\?""",
        r"""Cannot query field ['"]""" + MAIN_REGEX + r"""['"] on type ['"](""" + MAIN_REGEX + r""")['"]\. Did you mean to use an inline fragment on (['"]""" + MAIN_REGEX + r"""['"],? )+(or ['"]""" + MAIN_REGEX + r"""['"])?\?"""
    ],
    'VALID_FIELD': [
        r"""Field ['"](?P<field>""" + MAIN_REGEX + r""")['"] of type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"] must have a selection of subfields\. Did you mean ['"]""" + MAIN_REGEX + r"""( \{ \.\.\. \})?['"]\?""",
        r"""Field ['"](?P<field>""" + MAIN_REGEX + r""")['"] of type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"] must have a sub selection\."""
    ],
    'SINGLE_SUGGESTION': [
        r"""Cannot query field ['"](""" + MAIN_REGEX + r""")['"] on type ['"]""" + MAIN_REGEX + r"""['"]\. Did you mean ['"](?P<field>""" + MAIN_REGEX + r""")['"]\?"""
    ],
    'DOUBLE_SUGGESTION': [
        r"""Cannot query field ['"]""" + MAIN_REGEX + r"""['"] on type ['"]""" + MAIN_REGEX + r"""['"]\. Did you mean ['"](?P<one>""" + MAIN_REGEX + r""")['"] or ['"](?P<two>""" + MAIN_REGEX + r""")['"]\?"""
    ],
    'MULTI_SUGGESTION': [
        r"""Cannot query field ['"](""" + MAIN_REGEX + r""")['"] on type ['"]""" + MAIN_REGEX + r"""['"]\. Did you mean (?P<multi>(['"]""" + MAIN_REGEX + r"""['"],? )+)(or ['"](?P<last>""" + MAIN_REGEX + r""")['"])?\?"""
    ],
}

_ARG_REGEXES = {
    'SKIP': [
        r"""Unknown argument ['"]""" + MAIN_REGEX + r"""['"] on field ['"]""" + MAIN_REGEX + r"""['"]\.""",
        r"""Unknown argument ['"]""" + MAIN_REGEX + r"""['"] on field ['"]""" + MAIN_REGEX + r"""['"] of type ['"]""" + MAIN_REGEX + r"""['"]\.""",
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] of type ['"]""" + MAIN_REGEX + r"""['"] must have a selection of subfields\. Did you mean ['"]""" + MAIN_REGEX + r"""( \{ \.\.\. \})?['"]\?""",
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] argument ['"]""" + MAIN_REGEX + r"""['"] of type ['"]""" + MAIN_REGEX + r"""['"] is """ + REQUIRED_BUT_NOT_PROVIDED,
    ],
    'SINGLE_SUGGESTION': [
        r"""Unknown argument ['"]""" + MAIN_REGEX + r"""['"] on field ['"]""" + MAIN_REGEX + r"""['"] of type ['"]""" + MAIN_REGEX + r"""['"]\. Did you mean ['"](?P<arg>""" + MAIN_REGEX + r""")['"]\?""",
        r"""Unknown argument ['"]""" + MAIN_REGEX + r"""['"] on field ['"]""" + MAIN_REGEX + r"""['"]\. Did you mean ['"](?P<arg>""" + MAIN_REGEX + r""")['"]\?"""
    ],
    'DOUBLE_SUGGESTION': [
        r"""Unknown argument ['"]""" + MAIN_REGEX + r"""['"] on field ['"]""" + MAIN_REGEX + r"""['"]( of type ['"]""" + MAIN_REGEX + r"""['"])?\. Did you mean ['"](?P<first>""" + MAIN_REGEX + r""")['"] or ['"](?P<second>""" + MAIN_REGEX + r""")['"]\?"""
    ],
    'MULTI_SUGGESTION': [
        r"""Unknown argument ['"]""" + MAIN_REGEX + r"""['"] on field ['"]""" + MAIN_REGEX + r"""['"]\. Did you mean (?P<multi>(['"]""" + MAIN_REGEX + r"""['"],? )+)(or ['"](?P<last>""" + MAIN_REGEX + r""")['"])?\?""",
        r"""Unknown argument ['"]""" + MAIN_REGEX + r"""['"] on field ['"]""" + MAIN_REGEX + r"""['"] of type ['"]""" + MAIN_REGEX + r"""['"]\. Did you mean (?P<multi>(['"]""" + MAIN_REGEX + r"""['"],? )+)(or ['"](?P<last>""" + MAIN_REGEX + r""")['"])?\?"""
    ],
}

_TYPEREF_REGEXES = {
    'FIELD': [
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] of type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"] must have a selection of subfields\. Did you mean ['"]""" + MAIN_REGEX + r"""( \{ \.\.\. \})?['"]\?""",
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] must not have a selection since type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"] has no subfields\.""",
        r"""Cannot query field ['"]""" + MAIN_REGEX + r"""['"] on type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"]\.""",
        r"""Cannot query field ['"]""" + MAIN_REGEX + r"""['"] on type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"]\. Did you mean [^\?]+\?""",
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] of type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"] must not have a sub selection\.""",
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] of type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"] must have a sub selection\.""",

    ],
    'ARG': [
        r"""Field ['"]""" + MAIN_REGEX + r"""['"] argument ['"]""" + MAIN_REGEX + r"""['"] of type ['"](?P<typeref>""" + MAIN_REGEX + r""")['"] is """ + REQUIRED_BUT_NOT_PROVIDED,
        r"""Expected type (?P<typeref>""" + MAIN_REGEX + r"""), found .+\.""",
    ],
}

WRONG_FIELD_EXAMPLE = 'IAmWrongField'

_WRONG_TYPENAME = [
    r"""Cannot query field ['"]""" + WRONG_FIELD_EXAMPLE + r"""['"] on type ['"](?P<typename>""" + MAIN_REGEX + r""")['"].""",
    r"""Field ['"]""" + MAIN_REGEX + r"""['"] must not have a selection since type ['"](?P<typename>""" + MAIN_REGEX + r""")['"] has no subfields.""",
    r"""Field ['"]""" + MAIN_REGEX + r"""['"] of type ['"](?P<typename>""" + MAIN_REGEX + r""")['"] must not have a sub selection.""",
]

_GENERAL_SKIP = [
    r"""String cannot represent a non string value: .+""",
    r"""Float cannot represent a non numeric value: .+""",
    r"""ID cannot represent a non-string and non-integer value: .+""",
    r"""Enum ['"]""" + MAIN_REGEX + r"""['"] cannot represent non-enum value: .+"""
    r"""Int cannot represent non-integer value: .+""",
    r"""Not authorized""",
]

FIELD_REGEXES = {k: [re.compile(r) for r in v] for k, v in _FIELD_REGEXES.items()}
ARG_REGEXES = {k: [re.compile(r) for r in v] for k, v in _ARG_REGEXES.items()}
TYPEREF_REGEXES = {k: [re.compile(r) for r in v] for k, v in _TYPEREF_REGEXES.items()}
WRONG_TYPENAME = [re.compile(r) for r in _WRONG_TYPENAME]
GENERAL_SKIP = [re.compile(r) for r in _GENERAL_SKIP]

class FieldSuggestions:
    """Class for executing the GraphQL field suggestions test"""

    def __init__(self, args: Namespace, ptjsonlib: PtJsonLib, helpers: object, http_client: HttpClient,
                 supported_methods: set, common_tests: object) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.supported_methods = supported_methods
        self._new_types = set()
        self._found_types = set()
        self._wordlist = list()
        self.common_tests = common_tests

        self.helpers.print_header(__TESTLABEL__)


    def _build_nested_query(self, fields: list, build: str) -> str:
        """
        This method builds a nested query from a list of fields. For example a list of fields ["pastes", "owner"] would
        build a query pastes { owner { %s }}

        Parameters
        ----------
        fields: list
            Fields to build the query from.
        build: str
            String to build.

        Returns
        -------
        str
            Built string.
        """
        new_fields = copy.deepcopy(fields)

        while new_fields:
            build = build % (new_fields.pop(0) + "{ %s }")

        return build


    def _get_JSON(self, response: Response) -> object:
        """Gets JSON from an HTTP response and handles any JSON parsing errors."""
        try:
            response_json = response.json()
        except JSONDecodeError as e:
            ptprint(f"Could not get JSON from response: {e}", "ERROR", not self.args.json, indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return  {}

        if response.status_code not in [HTTPStatus.OK, HTTPStatus.BAD_REQUEST]:
            ptprint(f"Error sending query. Got status code: {response.status_code}", "ERROR", not self.args.json,
                    indent=4)
            ptprint(f"Full response: {response.text}", "ADDITIONS", self.args.verbose, indent=4, colortext=True)
            return {}

        return response_json


    def _field_suggestions(self, parts: list, idt: int) -> set[str]:
        """
        This methods stuffs fields into queries to elicit responses that would expose available queries through suggestions
        in error messages.

        Parameters
        ----------
        parts : list
            Fields and subfields to build a query from

        idt : int
            Indentation
        """
        wordlist = copy.deepcopy(self._wordlist)
        fields = set()

        while wordlist:
            chunk = wordlist[:FIELD_LIMIT]
            wordlist = wordlist[FIELD_LIMIT:]
            que = self._build_nested_query(parts, "{ %s }") % " ".join(chunk)
            query = {"query": que}

            response: Response = self.helpers.send_request(self.supported_methods, query)
            response_json = self._get_JSON(response)

            if not response_json:
                break

            fields.update(self._find_fields(response_json, len(chunk), parts, idt))


        return fields


    def _test_regexes(self, msg: str) -> set[str]:
        """Fetching valid fields using regex heuristics. This method is taken from the Clairvoyance project."""

        valid_fields: set[str] = set()

        for regex in FIELD_REGEXES["SKIP"] + GENERAL_SKIP:
            if regex.fullmatch(msg):
                return valid_fields

        for regex in FIELD_REGEXES["VALID_FIELD"]:
            match = regex.fullmatch(msg)
            if match:
                valid_fields.add(match.group("field"))
                return valid_fields

        for regex in FIELD_REGEXES["SINGLE_SUGGESTION"]:
            match = regex.fullmatch(msg)
            if match:
                valid_fields.add(match.group("field"))
                return valid_fields

        for regex in FIELD_REGEXES["DOUBLE_SUGGESTION"]:
            match = regex.fullmatch(msg)
            if match:
                valid_fields.add(match.group("one"))
                valid_fields.add(match.group("two"))
                return valid_fields

        for regex in FIELD_REGEXES["MULTI_SUGGESTION"]:
            match = regex.fullmatch(msg)
            if match:

                for m in match.group("multi").split(", "):
                    if m:
                        valid_fields.add(m.strip("'\" "))
                if match.group("last"):
                    valid_fields.add(match.group("last"))

                return valid_fields

        return valid_fields


    def _find_fields(self, response_json: object, parts: list, idt: int) -> set[str]:
        """
        This method extracts valid fields from error messages.
        """
        errors = response_json.get("errors", [])
        all_found_fields = set()

        if not errors:
            return all_found_fields

        for error in errors:
            msg = error.get("message", "")

            if msg == "" or msg is None:
                continue

            found_fields = self._test_regexes(msg)

            if not found_fields:
                continue

            if "must have a sub selection" in msg:
                for i in range(len(found_fields)):
                    found_fields_copy = copy.deepcopy(found_fields)
                    field = found_fields_copy.pop()
                    parts.append(field)
                    if field not in self._new_types:
                        ptprint(f"{field}", "INFO", not self.args.json, indent=idt)
                        self._new_types.add(field)

                    new = self._field_suggestions(parts, idt+4)
                    parts.pop()

                    for f in new:
                        ptprint(f"{f}", "INFO", not self.args.json, indent=idt+4)
                        self._new_types.add(f)

            all_found_fields.update(found_fields)

        return all_found_fields


    def _explore(self, field: str) -> None:
        query = {"query": "{%s}" % field}

        response: Response = self.helpers.send_request(self.supported_methods, query)
        response_json = self._get_JSON(response)

        self._find_fields(response_json, 0, [], 4)


    def run(self) -> None:
        """
        Executes the field suggestions test

        The method first verifies if the GraphQL server schema is already mapped and if yes, we only verify if it supports
        __type queries. In the case that the schema is not mapped, we verify if the server supports __type queries and then
        execute field suggestions using the wordlist provided.
        """
        if self.args.schema:
            ptprint(f"GraphQL schema already mapped. Skipping field suggestions", "VULN", not self.args.json,
                    indent=4)
            return

        if not self.args.wordlist_fields:
            ptprint(f"You need to provide a wordlist for the field suggestions module. Please do so with the -wf argument",
                    "ERROR", not self.args.json, indent=4)
            return

        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, self.args.wordlist_fields)

        with open(wordlist_path, "r") as wordlist:
            self._wordlist = [word for word in wordlist.read().split('\n')]

        fields = self._field_suggestions([], idt=4)

        if not fields:
            ptprint("No fields could be extracted", "OK", not self.args.json, indent=4)
            return

        self.ptjsonlib.add_vulnerability("PTV-GRAPHQL-FIELD-SUGGESTIONS")

        for field in fields:

            if field not in self._new_types:
                ptprint(f"{field}", "INFO", not self.args.json, indent=4)
                self._new_types.add(field)

                self._explore(field)

def run(args, ptjsonlib, helpers, http_client, supported_methods, common_tests):
    """Entry point for running the FieldSuggestions test"""
    FieldSuggestions(args, ptjsonlib, helpers, http_client, supported_methods, common_tests).run()
