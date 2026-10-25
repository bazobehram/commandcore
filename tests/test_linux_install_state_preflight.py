"""Regression tests for the Linux agent managed-job filesystem trust boundary."""

from pathlib import Path
import subprocess
import os
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / "install" / "linux.sh"


class LinuxInstallStatePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = INSTALLER.read_text()
        cls.preflight = source.split("python3 - \"$state_root\" <<'PY_CHECK_DIR'", 1)[
            1
        ].split("\nPY_CHECK_DIR", 1)[0]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cc-preflight-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.base.chmod(0o700)
        (self.base / "config").mkdir(mode=0o700)
        self.target = self.base / "config" / "commandcore"

    def run_preflight(self, target=None):
        return subprocess.run(
            ["python3", "-c", self.preflight, str(target or self.target)],
            text=True,
            capture_output=True,
            env={**os.environ, "HOME": str(self.base)},
        )

    def test_fresh_install_creates_secure_state(self):
        self.assertEqual(self.run_preflight().returncode, 0)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o700)

    def test_fresh_user_without_config_directory(self):
        (self.base / "config").rmdir()
        self.assertEqual(self.run_preflight().returncode, 0)
        self.assertEqual((self.base / "config").stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o700)

    def test_existing_state_and_jobs_repaired(self):
        self.target.mkdir(mode=0o755)
        jobs = self.target / "managed-jobs"
        jobs.mkdir(mode=0o755)
        device = jobs / "12345678-1234-1234-1234-123456789012"
        device.mkdir(mode=0o755)
        self.assertEqual(self.run_preflight().returncode, 0)
        for folder in (self.target, jobs, device):
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)

    def test_user_config_group_writable_is_repaired(self):
        config = self.base / ".config"
        config.mkdir(mode=0o775)
        target = config / "commandcore"
        result = self.run_preflight(target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(config.stat().st_mode & 0o777, 0o755)

    def test_unrelated_group_writable_parent_is_denied(self):
        (self.base / "config").chmod(0o775)
        self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_legacy_service_check_is_structurally_guarded(self):
        installer = INSTALLER.read_text()
        block = installer.split("<<'PY_UNIT'", 1)[1].split("\nPY_UNIT", 1)[0]
        original = self.base / "commandcore-agent.service"
        install = self.base / "install" / "commandcore-agent"
        install.mkdir(parents=True)
        (install / ".commandcore-install").write_text("commandcore-agent\n")
        state = self.base / "config" / "commandcore"
        exe = f'ExecStart="{install}/current/commandcore-agent" run --state "{state}/agent.json"'
        legacy = bytes.fromhex(
            "23204d616e616765642062792053796e6f76617120436f6d6d616e64436f7265"
        ).decode()
        for first, line, expected in (
            (legacy, exe, True),
            (legacy, "ExecStart=/tmp/other", False),
            ("# Unrelated", exe, False),
        ):
            original.write_text(first + "\n" + line + "\n")
            result = subprocess.run(
                ["python3", "-c", block, str(original), str(install), str(state)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_state_symlink_denied(self):
        safe = self.base / "real"
        safe.mkdir(mode=0o700)
        self.target.symlink_to(safe, target_is_directory=True)
        self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_managed_jobs_symlink_denied(self):
        self.target.mkdir(mode=0o700)
        (self.target / "managed-jobs").symlink_to(self.base, target_is_directory=True)
        self.assertNotEqual(self.run_preflight().returncode, 0)

    def test_signed_manifest_product_compatibility(self):
        source = INSTALLER.read_text()
        product_check = source.split(
            "product=m.get('product'); version=m.get('version')", 1
        )[1].split("if not re.fullmatch", 1)[0]
        for product, version, expected in (
            ("commandcore-agent", "0.9.0-rc8", True),
            (
                bytes.fromhex(
                    "73796e6f7661712d636f6d6d616e64636f72652d6167656e74"
                ).decode(),
                "0.9.0-rc7",
                True,
            ),
            (
                bytes.fromhex(
                    "73796e6f7661712d636f6d6d616e64636f72652d6167656e74"
                ).decode(),
                "0.9.0-rc6",
                False,
            ),
            ("some-other-product", "0.9.0-rc7", False),
        ):
            manifest = {"schema_version": 1, "product": product, "version": version}
            import json

            code = (
                "import json\nimport hashlib\nm=json.loads("
                + repr(json.dumps(manifest))
                + ")\n"
            )
            code += (
                "product=m.get('product'); version=m.get('version')\n" + product_check
            )
            result = subprocess.run(
                ["python3", "-c", code], capture_output=True, text=True
            )
            self.assertEqual(
                result.returncode == 0, expected, (product, version, result.stderr)
            )

    def test_untrusted_parent_denied(self):
        parent = self.base / "config"
        parent.chmod(0o777)
        self.assertNotEqual(self.run_preflight().returncode, 0)


if __name__ == "__main__":
    unittest.main()
