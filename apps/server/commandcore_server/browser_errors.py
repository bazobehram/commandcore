"""Errors shared by the optional Browser gateway and CDP transport."""


class BrowserError(Exception):
    pass


class BrowserManualStepRequired(BrowserError):
    """The action was blocked before dispatch; private human control is required."""
