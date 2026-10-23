"""Isolate the durable UI task database from live state during tests."""

import os
import tempfile
from pathlib import Path


def pytest_configure(config):
    if "COMMANDCORE_UI_TASK_DB" in os.environ:
        return
    directory = tempfile.TemporaryDirectory(prefix="commandcore-pytest-ui-")
    config._commandcore_ui_task_directory = directory
    os.environ["COMMANDCORE_UI_TASK_DB"] = str(
        Path(directory.name) / "ui-tasks.sqlite3"
    )


def pytest_unconfigure(config):
    directory = getattr(config, "_commandcore_ui_task_directory", None)
    if directory is not None:
        os.environ.pop("COMMANDCORE_UI_TASK_DB", None)
        directory.cleanup()
