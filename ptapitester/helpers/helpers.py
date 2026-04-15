import argparse


class BaseArgs(argparse.Namespace):
    json: bool
    debug: bool
    module: str
