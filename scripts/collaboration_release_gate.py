#!/usr/bin/env python3
"""Read-only, fail-closed staging release-gate report.

The test suite passing does not establish live human approval or delivery.
"""
from __future__ import annotations
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
def present(path):
    return (ROOT / path).is_file()

def run():
    checks = {
        "registration_module_present": present("apps/server/commandcore_server/collaboration_registration_ceremony.py"),
        "review_module_present": present("apps/server/commandcore_server/collaboration_webauthn_review.py"),
        "webauthn_browser_tests_present": all(present(p) for p in (
            "tests/ui/test_webauthn_enroll.cjs",
            "tests/ui/test_webauthn_enroll_success.cjs",
            "tests/ui/test_webauthn_review.cjs",
            "tests/ui/test_webauthn_virtual_authenticator.cjs",
            "tests/ui/verify_webauthn_native_assertion.py",
            "tests/ui/native_registration_begin.py",
            "tests/ui/native_registration_chrome.cjs",
            "tests/ui/native_registration_finish.py")),
        "pinned_fido2_in_lock": "fido2==2.2.1" in (ROOT/"requirements-server.lock").read_text(),
    }
    # These are evidence gates, not guesses. No local unit test may set them true.
    live = {
        "real_authenticator_enrollment_verified": False,
        "explicit_owner_approval_verified": False,
        "signed_delivery_with_gx10_local_confirmation_verified": False,
        "argon_reply_verified": False,
        "production_release_and_rollback_verified": False,
    }
    state = subprocess.run(["git","-c",f"safe.directory={ROOT}","status","--porcelain",
                            "--untracked-files=normal"],cwd=ROOT,text=True,capture_output=True)
    checks["git_status_readable"] = state.returncode == 0
    # Working tree may contain unrelated Rust experiments and local browser
    # dependencies. Only changes to the candidate's release-scoped files
    # should impact source integrity. Never confuse a clean tree with approval.
    scoped_dirty = []
    if state.returncode == 0:
        for line in state.stdout.splitlines():
            path = line[3:]
            if (path.startswith("apps/server/commandcore_server/")
                    or path in {"pyproject.toml", "requirements.txt",
                                "requirements-server.lock", ".github/workflows/ci.yml"}
                    or path.startswith("scripts/collaboration_")
                    or path.startswith("tests/test_collaboration_")
                    or path.startswith("tests/ui/test_webauthn_")
                    or path == "tests/ui/verify_webauthn_native_assertion.py"
                    or path.startswith("tests/ui/native_registration_")):
                scoped_dirty.append(path)
    report = {
        "staging_checks": checks,
        "live_acceptance_evidence": live,
        "uncommitted_git_entries": len(state.stdout.splitlines()) if state.returncode == 0 else None,
        "release_scoped_dirty_files": scoped_dirty,
        "release_ready": all(checks.values()) and all(live.values()) and state.returncode == 0
                         and not scoped_dirty,
    }
    print(json.dumps(report,indent=2,sort_keys=True))
    return 0 if report["release_ready"] else 3

if __name__ == "__main__":
    raise SystemExit(run())
