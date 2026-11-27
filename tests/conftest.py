"""Isolate the durable UI task database from live state during tests."""

import os
import socket
import tempfile
import threading
from pathlib import Path

import pytest


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


@pytest.fixture
def listener_ready(monkeypatch):
    """Signal actual listen completion without making a probe connection.

    bind() publishes the Unix socket path before listen(), so path existence
    alone can race. Patch only this module's socket reference, not the global
    socket class; no production behavior or peer validation is changed.
    """
    from commandcore_server import browser_provision_ipc

    ready = threading.Event()

    class ListeningSocket(socket.socket):
        def listen(self, backlog):
            super().listen(backlog)
            ready.set()

    class SocketModule:
        def __getattr__(self, name):
            return getattr(socket, name)

        socket = ListeningSocket

    monkeypatch.setattr(browser_provision_ipc, "socket", SocketModule())
    return ready
