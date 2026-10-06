"""Scan source and reachable Git history without printing secret values."""

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = (
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(rb"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}"), "GitHub credential"),
    (re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}"), "API credential"),
    (re.compile(rb"\bAKIA[A-Z0-9]{16}\b"), "AWS credential"),
    (
        re.compile(rb"\beyJ[A-Za-z0-9_-]{25,}\.[A-Za-z0-9_-]{25,}\.[A-Za-z0-9_-]{20,}"),
        "serialized JWT",
    ),
    (
        re.compile(rb"auth0\|[a-f0-9]{24}\b|google-oauth2\|[0-9]{15,}"),
        "personal live OAuth subject",
    ),
)
FORBIDDEN = {
    ".env",
    ".envrc",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "agent.json",
    "agent-state.json",
    "credentials.json",
    "enrollment.pending.json",
    "helper.key",
}
FORBIDDEN_SUFFIXES = {".sqlite3", ".db", ".log", ".key", ".p12", ".pfx", ".kdbx"}


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def scan(name, data):
    findings = []
    path = Path(name)
    if (
        path.name in FORBIDDEN
        or path.suffix.lower() in FORBIDDEN_SUFFIXES
        or path.name.startswith("service-account")
        and path.suffix.lower() == ".json"
        or (path.name.startswith(".env.") and path.name != ".env.example")
    ):
        findings.append("deployment state/credential filename")
    for pattern, label in PATTERNS:
        if pattern.search(data):
            findings.append(label)
    return [(name, label) for label in findings]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    findings = []
    names = (
        git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
        .decode()
        .split("\0")
    )
    for name in names:
        if name and (ROOT / name).is_file():
            findings.extend(scan(name, (ROOT / name).read_bytes()))
    commits = []
    if args.history:
        commits = git("rev-list", "--all").decode().splitlines()
        checked = set()
        for commit in commits:
            for line in git("ls-tree", "-rz", commit).split(b"\0"):
                if not line:
                    continue
                info, name = line.split(b"\t", 1)
                oid = info.split()[2].decode()
                if oid in checked:
                    continue
                checked.add(oid)
                filename = name.decode()
                findings.extend(
                    (f"{commit[:8]}:{n}", label)
                    for n, label in scan(filename, git("cat-file", "blob", oid))
                )
    if findings:
        for name, label in findings:
            print(f"FAIL {name}: {label}")
        return 1
    print(
        f"PASS: {len([n for n in names if n])} source paths; {len(commits)} reachable commits. Values never printed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
