"""
Helpers module for shared functionality used across test modules.
"""

from ptlibs import ptprint


class Helpers:
    def __init__(self, args: object, ptjsonlib: object, http_client: object):
        """Helpers provides utility methods"""
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = http_client

    def print_header(self, test_label):
        ptprint(f"Testing: {test_label}", "TITLE", not self.args.json, colortext=True)

    def sample_helper(self) -> None:
        """
        This is where you add your helper functions that you can then access from modules with: self.helpers.helper_function()
        """
        ptprint(f"Hello I am a helper function! :-)", "INFO", not self.args.json, indent=4)