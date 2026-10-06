from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "release_check.py"


def run_check(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECK), str(path)],
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_release_check_accepts_clean_source_archive(tmp_path):
    archive = tmp_path / "clean.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("commandcore-v0.5.0/README.md", "clean source\n")
        zf.writestr("commandcore-v0.5.0/.env.example", "COMMANDCORE_API_TOKEN=\n")
    result = run_check(archive)
    assert result.returncode == 0, result.stderr
    assert "RELEASE_CHECK PASS" in result.stdout


def test_release_check_rejects_embedded_private_key(tmp_path):
    archive = tmp_path / "secret.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(
            "commandcore-v0.5.0/accidental.txt",
            "-----BEGIN "
            + "PRIVATE KEY-----\nnot-a-real-key\n-----END "
            + "PRIVATE KEY-----\n",
        )
    result = run_check(archive)
    assert result.returncode == 1
    assert "private key block" in result.stderr


def test_release_check_rejects_dotenv_variant(tmp_path):
    archive = tmp_path / "dotenv.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(
            "commandcore-v0.5.0/.env.production", "COMMANDCORE_API_TOKEN=secret\n"
        )
    result = run_check(archive)
    assert result.returncode == 1
    assert "forbidden dotenv secret filename" in result.stderr
